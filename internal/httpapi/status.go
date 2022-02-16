// Copyright 2021 The Uranium Authors. All rights reserved.
// Use of this source code is governed by a AGPL-style
// license that can be found in the LICENSE file.

package httpapi

import (
	"net/http"

	adminAPI "github.com/Codename-Uranium/api/go/server/tunnel_admin"
	"github.com/Codename-Uranium/tunnel/pkg/xerror"
	"github.com/Codename-Uranium/tunnel/pkg/xhttp"
)

// AdminGetStatus returns current server status
func (tun *TunnelAPI) AdminGetStatus(w http.ResponseWriter, r *http.Request) {
	xhttp.JSONResponse(w, func() (interface{}, error) {
		flags := tun.runtime.Flags
		status := adminAPI.ServiceStatusResponse{
			RestartRequired: flags.RestartRequired,
		}
		return status, nil
	})
}

func (tun *TunnelAPI) AdminConnectionInfoWireguard(w http.ResponseWriter, r *http.Request) {
	xhttp.JSONResponse(w, func() (interface{}, error) {
		if len(tun.runtime.Settings.Wireguard.ServerIPv4) == 0 {
			return nil, xerror.EInvalidConfiguration(
				"missing server public ipv4 option, please specify it in settings",
				"wireguard_server_ipv4")
		}
		opts := adminAPI.ServerWireguardOptions{
			AllowedIps:      []string{"0.0.0.0/1", "128.0.0.0/1"},
			Subnet:          string(tun.runtime.Settings.Wireguard.Subnet),
			Dns:             tun.runtime.Settings.Wireguard.DNS,
			Keepalive:       tun.runtime.Settings.Wireguard.Keepalive,
			ServerIpv4:      tun.runtime.Settings.Wireguard.ServerIPv4,
			ServerPort:      tun.runtime.Settings.Wireguard.ServerPort,
			ServerPublicKey: tun.runtime.DynamicSettings.GetWireguardPrivateKey().Public().Unwrap().String(),
		}
		return opts, nil
	})
}
