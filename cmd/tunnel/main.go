// Copyright 2021 The VPN House Authors. All rights reserved.
// Use of this source code is governed by a AGPL-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"math/rand"
	"time"

	sentryio "github.com/getsentry/sentry-go"
	"github.com/vpnhouse/common-lib-go/auth"
	"github.com/vpnhouse/common-lib-go/control"
	"github.com/vpnhouse/common-lib-go/geoip"
	"github.com/vpnhouse/common-lib-go/ipam"
	"github.com/vpnhouse/common-lib-go/keystore"
	"github.com/vpnhouse/common-lib-go/rapidoc"
	"github.com/vpnhouse/common-lib-go/sentry"
	"github.com/vpnhouse/common-lib-go/version"
	"github.com/vpnhouse/common-lib-go/xdns"
	"github.com/vpnhouse/common-lib-go/xhttp"
	"github.com/vpnhouse/tunnel/internal/admin"
	"github.com/vpnhouse/tunnel/internal/authorizer"
	"github.com/vpnhouse/tunnel/internal/eventlog"
	"github.com/vpnhouse/tunnel/internal/grpc"
	"github.com/vpnhouse/tunnel/internal/httpapi"
	"github.com/vpnhouse/tunnel/internal/ipdiscover"
	"github.com/vpnhouse/tunnel/internal/iprose"
	"github.com/vpnhouse/tunnel/internal/manager"
	"github.com/vpnhouse/tunnel/internal/proxy"
	"github.com/vpnhouse/tunnel/internal/runtime"
	"github.com/vpnhouse/tunnel/internal/settings"
	"github.com/vpnhouse/tunnel/internal/storage"
	"github.com/vpnhouse/tunnel/internal/wireguard"
	"go.uber.org/zap"
)

var adminJWT *auth.JWTMaster

func init() {
	// note: we do not provide any key here: new JWT key generates
	//  on each restart, so the auth token getting expired.
	// By the same reason we keep the global instance that can be reused between soft restarts.
	var err error
	adminJWT, err = auth.NewJWTMaster(nil, nil)
	if err != nil {
		panic(err)
	}
}

func initServices(runtime *runtime.TunnelRuntime) error {
	zap.L().Info("starting tunnel", zap.String("version", version.GetVersion()), zap.Any("features", runtime.Features))
	if runtime.Settings.Sentry != nil {
		if err := sentry.ConfigureGlobal(*runtime.Settings.Sentry, version.GetVersion()); err != nil {
			return err
		}
	}

	if len(runtime.Settings.Wireguard.ServerIPv4) == 0 {
		// it's ok to fail here, ip checking host may not be available
		// or machine may not have access to the internet.
		if publicIP, err := ipdiscover.New().Discover(); err == nil {
			if err := runtime.Settings.SetPublicIP(publicIP); err != nil {
				return err
			}
		}
	}

	// Initialize sqlite storage
	dataStorage, err := storage.New(runtime.Settings.SQLitePath)
	if err != nil {
		return err
	}
	runtime.Services.RegisterService("storage", dataStorage)

	var eventLog eventlog.EventManager = eventlog.NewDummy()
	if runtime.Features.WithEventLog() {
		if runtime.Settings.EventLog != nil {
			eventLog, err = eventlog.New(*runtime.Settings.EventLog)
			if err != nil {
				return err
			}
			runtime.Services.RegisterService("eventLog", eventLog)
		}
	}

	jwtAuthorizer, err := authorizer.NewJWT(dataStorage.AsKeystore())
	if err != nil {
		return err
	}
	runtime.Services.RegisterService("authorizer", jwtAuthorizer)

	// Initialize wireguard controller
	wgcfg := runtime.Settings.Wireguard
	wireguardController, err := wireguard.New(wgcfg)
	if err != nil {
		return err
	}
	runtime.Services.RegisterService("wireguard", wireguardController)

	// Initialize ip addr manager
	netpol := runtime.Settings.GetNetworkAccessPolicy()
	ipv4am, err := ipam.New(ipam.Config{
		Subnet:           wgcfg.Subnet.Unwrap(),
		Interface:        wgcfg.Interface,
		AccessPolicy:     netpol.Access,
		RateLimiter:      netpol.RateLimit,
		PortRestrictions: runtime.Settings.PortRestrictions,
	})
	if err != nil {
		return err
	}
	runtime.Services.RegisterService("ipv4am", ipv4am)

	var geoClient *geoip.Instance
	if runtime.Features.WithGeoip() {
		if runtime.Settings.GeoDBPath == "" {
			zap.L().Warn("geoip db path os not specified")
		} else {
			geoClient, err = geoip.NewGeoip(runtime.Settings.GeoDBPath)
			if err != nil {
				return err
			}
		}
	}

	// Create new peer manager
	sessionManager, err := manager.New(runtime, dataStorage, wireguardController, ipv4am, eventLog, geoClient)
	if err != nil {
		return err
	}
	runtime.Services.RegisterService("manager", sessionManager)

	var keyStore keystore.Keystore = keystore.DenyAllKeystore{}
	if runtime.Features.WithFederation() {
		if k, err := keystore.NewFsKeystore(runtime.Settings.ManagementKeystore); err == nil {
			keyStore = k
		}
	}

	var iproseServer *iprose.Instance
	if runtime.Features.WithIPRose() {
		iproseServer, err = iprose.New(runtime.Settings.IPRose, jwtAuthorizer)
		if err != nil {
			return err
		}
		if iproseServer != nil {
			runtime.Services.RegisterService("iprose", iproseServer)
		} else {
			zap.L().Warn("IPRose servier is not started")
		}
	}

	// Create proxy server
	var proxyServer *proxy.Instance
	if runtime.Features.WithProxy() && runtime.Settings.Proxy != nil {
		proxyServer, err = proxy.New(
			runtime.Settings.Proxy,
			jwtAuthorizer,
			append(
				runtime.Settings.Domain.ExtraNames,
				runtime.Settings.Domain.PrimaryName,
			))
		if err != nil {
			return err
		}

		runtime.Services.RegisterService("proxy", proxyServer)
	}

	// Prepare tunneling HTTP API
	tunnelAPI := httpapi.NewTunnelHandlers(runtime, sessionManager, adminJWT, jwtAuthorizer, dataStorage, keyStore, ipv4am)

	xHttpAddr := runtime.Settings.HTTP.ListenAddr
	xhttpOpts := []xhttp.Option{xhttp.WithLogger()}
	if runtime.Settings.HTTP.Prometheus {
		xhttpOpts = append([]xhttp.Option{xhttp.WithMetrics()}, xhttpOpts...)
	}
	if runtime.Settings.HTTP.CORS {
		xhttpOpts = append([]xhttp.Option{xhttp.WithCORS()}, xhttpOpts...)
	}
	if proxyServer != nil {
		xhttpOpts = append([]xhttp.Option{
			xhttp.WithMiddleware(proxyServer.ProxyHandler),
			xhttp.WithDisableHTTPv2(), // see task 97304 (fix http over httpv2 proxy issue)
		}, xhttpOpts...)
	}

	// assume that config validation does not pass
	// the SSL enabled without the domain name configuration
	if runtime.Settings.SSL != nil {
		redirectOnly := xhttp.NewRedirectToSSL(runtime.Settings.Domain.PrimaryName)
		// we must start the redirect-only server before passing its Router
		// to the certificate issuer.
		if err := redirectOnly.Run(runtime.Settings.HTTP.ListenAddr); err != nil {
			return err
		}
		runtime.Services.RegisterService("httpRedirectServer", redirectOnly)

		opts := &xhttp.CertMasterOpts{
			Email:        runtime.Settings.Domain.Email,
			CacheDir:     runtime.Settings.Domain.Dir,
			NonSSLRouter: redirectOnly.Router(),
			Domains:      append([]string{runtime.Settings.Domain.PrimaryName}, runtime.Settings.Domain.ExtraNames...),
		}

		certMaster, err := xhttp.NewCertMaster(opts)
		if err != nil {
			return err
		}
		runtime.Services.RegisterService("certMaster", certMaster)
		tlsCfg := &tls.Config{
			GetCertificate: certMaster.GetCertificate,
		}

		// store the plaintext http router to use for
		// solve the http01 challenge while updating Settings
		runtime.HttpRouter = redirectOnly.Router()
		xHttpAddr = runtime.Settings.SSL.ListenAddr
		xhttpOpts = append([]xhttp.Option{xhttp.WithSSL(tlsCfg)}, xhttpOpts...)
	}

	xHttpServer := xhttp.New(xhttpOpts...)

	// register handlers of all modules
	tunnelAPI.RegisterHandlers(xHttpServer.Router())
	if runtime.Settings.Rapidoc {
		rapidoc.RegisterHandlers(xHttpServer.Router())
	}

	if iproseServer != nil {
		iproseServer.RegisterHandlers(xHttpServer.Router())
	}

	runtime.ExternalStats.Run()
	runtime.Services.RegisterService("externalStats", runtime.ExternalStats)

	if runtime.Features.WithGRPC() {
		if runtime.Settings.GRPC != nil {
			adminService := admin.New(sessionManager, iproseServer, dataStorage)
			grpcServices, err := grpc.New(*runtime.Settings.GRPC, eventLog, keyStore, dataStorage, adminService)
			if err != nil {
				return fmt.Errorf("failed to create grpc server: %w", err)
			}
			grpcServices.RegisterHandlers(xHttpServer.Router())
			runtime.Services.RegisterService("grpcServices", grpcServices)
			zap.L().Info("gRPC is up and running", zap.String("addr", runtime.Settings.GRPC.Addr))
		} else {
			zap.L().Info("skipping gRPC init - no configuration given")
		}
	}

	// Startup HTTP API
	if err := xHttpServer.Run(xHttpAddr); err != nil {
		return err
	}

	runtime.Services.RegisterService("httpServer", xHttpServer)
	if runtime.HttpRouter == nil {
		runtime.HttpRouter = xHttpServer.Router()
	}

	// note: during the test we DO NOT override the DNS settings for peers.
	if runtime.Settings.DNSFilter != nil {
		filter, err := xdns.NewFilteringServer(*runtime.Settings.DNSFilter)
		if err != nil {
			return err
		}
		runtime.Services.RegisterService("dnsFilter", filter)
	}

	return nil
}

var cfgDirFlag = flag.String("cfg", "", "path to the configuration directory, leave empty for default")

func main() {
	defer sentryio.Flush(2 * time.Second)
	flag.Parse()

	staticConf, err := settings.LoadStatic(*cfgDirFlag)
	if err != nil {
		panic(err)
	}

	rand.Seed(time.Now().UnixNano())
	r := runtime.New(staticConf, initServices)
	control.Exec(r)
}
