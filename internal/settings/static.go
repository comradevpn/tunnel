// Copyright 2021 The VPN House Authors. All rights reserved.
// Use of this source code is governed by a AGPL-style
// license that can be found in the LICENSE file.

package settings

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/afero"
	adminAPI "github.com/vpnhouse/api/go/server/tunnel_admin"
	"github.com/vpnhouse/common-lib-go/human"
	"github.com/vpnhouse/common-lib-go/ipam"
	"github.com/vpnhouse/common-lib-go/sentry"
	"github.com/vpnhouse/common-lib-go/validator"
	"github.com/vpnhouse/common-lib-go/version"
	"github.com/vpnhouse/common-lib-go/xdns"
	"github.com/vpnhouse/common-lib-go/xerror"
	"github.com/vpnhouse/common-lib-go/xhttp"
	"github.com/vpnhouse/common-lib-go/xnet"
	"github.com/vpnhouse/common-lib-go/xrand"
	"github.com/vpnhouse/tunnel/internal/eventlog"
	"github.com/vpnhouse/tunnel/internal/extstat"
	"github.com/vpnhouse/tunnel/internal/iprose"
	"github.com/vpnhouse/tunnel/internal/proxy"
	"github.com/vpnhouse/tunnel/internal/wireguard"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/hlandau/passlib.v1"
	"gopkg.in/yaml.v3"
)

const (
	defaultConfigDir = "/opt/vpnhouse/tunnel/"
	configFileName   = "config.yaml"
)

type NetworkAccessPolicy struct {
	Access    ipam.NetworkAccess      `yaml:"access"`
	RateLimit *ipam.RateLimiterConfig `yaml:"rate_limit,omitempty"`
}

type GRPCConfig struct {
	// Addr to listen for gRPC connections
	Addr        string             `yaml:"addr"`
	TunnelKey   string             `yaml:"tunnel_key,omitempty"`
	TLSSelfSign *TLSSelfSignConfig `yaml:"tls_self_sign,omitempty"`
}

type TLSSelfSignConfig struct {
	AllowedIPs   []string `yaml:"allowed_ips,omitempty"`
	AllowedNames []string `yaml:"allowed_names,omitempty"`
	// Storage directory is used to keep load self signed certs
	Dir string `yaml:"dir,omitempty"`
}

type Config struct {
	InstanceID string           `yaml:"instance_id"`
	LogLevel   string           `yaml:"log_level"`
	SQLitePath string           `yaml:"sqlite_path" valid:"path,required"`
	Rapidoc    bool             `yaml:"rapidoc"`
	Wireguard  wireguard.Config `yaml:"wireguard"`
	HTTP       HttpConfig       `yaml:"http"`

	// optional configuration
	Proxy              *proxy.Config               `yaml:"proxy,omitempty"`
	ExternalStats      *extstat.Config             `yaml:"external_stats,omitempty"`
	NetworkPolicy      *NetworkAccessPolicy        `yaml:"network,omitempty"`
	SSL                *xhttp.SSLConfig            `yaml:"ssl,omitempty"`
	Domain             *xhttp.DomainConfig         `yaml:"domain,omitempty"`
	AdminAPI           *AdminAPIConfig             `yaml:"admin_api,omitempty"`
	PublicAPI          *PublicAPIConfig            `yaml:"public_api,omitempty"`
	GRPC               *GRPCConfig                 `yaml:"grpc,omitempty"`
	Sentry             *sentry.Config              `yaml:"sentry,omitempty"`
	EventLog           *eventlog.StorageConfig     `yaml:"event_log,omitempty"`
	ManagementKeystore string                      `yaml:"management_keystore,omitempty" valid:"path"`
	DNSFilter          *xdns.Config                `yaml:"dns_filter"`
	PortRestrictions   *ipam.PortRestrictionConfig `yaml:"ports,omitempty"`
	PeerStatistics     *PeerStatisticConfig        `yaml:"peer_statistics,omitempty"`
	GeoDBPath          string                      `yaml:"geo_db_path,omitempty"`
	IPRose             iprose.Config               `yaml:"iprose,omitempty"`

	// path to the config file, or default path in case of safe defaults.
	// Used to override config via the admin API.
	path string

	// mu guards RW access to the Config
	mu sync.RWMutex
}

func (s *Config) GetNetworkAccessPolicy() NetworkAccessPolicy {
	if s.NetworkPolicy == nil || s.NetworkPolicy.Access.DefaultPolicy.Int() == ipam.AccessPolicyDefault {
		return NetworkAccessPolicy{
			Access: ipam.NetworkAccess{DefaultPolicy: ipam.AliasInternetOnly()},
		}
	}

	return *s.NetworkPolicy
}

func (s *Config) ConfigDir() string {
	return filepath.Dir(s.path)
}

// PublicURL returns a URL of this node.
// Use SSL configuration if given, otherwise
// it returns http://wireguard_ip:http_listen_port
func (s *Config) PublicURL() string {
	if s.Domain != nil {
		if s.Domain.Mode == string(adminAPI.DomainConfigModeReverseProxy) {
			return s.Domain.Schema + "://" + s.Domain.PrimaryName
		}
	}

	host := s.Wireguard.ServerIPv4
	if s.Domain != nil {
		host = s.Domain.PrimaryName
	}

	if s.SSL != nil {
		port := ""
		if _, p, _ := net.SplitHostPort(s.SSL.ListenAddr); p != "443" {
			// use non-standard https port
			port = ":" + p
		}
		return "https://" + host + port
	}

	port := ""
	if _, p, _ := net.SplitHostPort(s.HTTP.ListenAddr); p != "80" {
		port = ":" + p
	}

	return "http://" + host + port
}

func (s *Config) GetPublicAPIConfig() *PublicAPIConfig {
	if s.PublicAPI != nil {
		return s.PublicAPI
	}
	return defaultPublicAPIConfig()
}

func (s *Config) GetUpdateStatisticsInterval() human.Interval {
	if s == nil || s.PeerStatistics == nil {
		return human.MustParseInterval(DefaultUpdateStatisticsInterval)
	}
	return s.PeerStatistics.UpdateStatisticsInterval
}

func (s *Config) GetSentEventInterval() human.Interval {
	if s == nil || s.PeerStatistics == nil {
		return human.MustParseInterval(DefaultTrafficChangeSendEventInterval)
	}
	return s.PeerStatistics.TrafficChangeSendEventInterval
}

type HttpConfig struct {
	// ListenAddr for HTTP server, default: ":80"
	ListenAddr string `yaml:"listen_addr" valid:"listen_addr,required"`
	// CORS enables corresponding middleware for the local development
	CORS bool `yaml:"cors"`
	// Enable prometheus metrics on "/metrics" path
	Prometheus bool `yaml:"prometheus"`
}

type AdminAPIConfig struct {
	PasswordHash  string `yaml:"password_hash"`
	StaticRoot    string `yaml:"static_root" valid:"path"`
	TokenLifetime int    `yaml:"token_lifetime" valid:"natural"`
}

func defaultAdminAPIConfig() *AdminAPIConfig {
	return &AdminAPIConfig{
		TokenLifetime: 30 * 60, // 30min,
	}
}

type PublicAPIConfig struct {
	PingInterval int `yaml:"ping_interval" valid:"natural"`
	PeerTTL      int `yaml:"connection_timeout" valid:"natural"`
}

func defaultPublicAPIConfig() *PublicAPIConfig {
	return &PublicAPIConfig{
		PingInterval: 600,  // 10min
		PeerTTL:      3600, // 1h
	}
}

type PeerStatisticConfig struct {
	// Interval to update tunnel (all peers) statistics
	// Min valid value = 1m
	UpdateStatisticsInterval human.Interval `yaml:"update_statistics_interval" valid:"interval"`
	// Min interval to sent updated peers with new traffic counters
	// Interval must be defined in duration format.
	// Valid time units: "ns", "us", "ms", "s", "m", "h".
	// https://pkg.go.dev/time#ParseDuration
	// or
	// be defined as integer in seconds
	// Note: it must be >= UpdateStatisticsInterval
	// = UpdateStatisticsInterval if < UpdateStatisticsInterval
	TrafficChangeSendEventInterval human.Interval `yaml:"traffic_change_send_event_interval" valid:"interval"`
	// Min pace to sent updated peers with new traffic counters
	// Interval must be defined in duration format.
	// Valid size units in human readable format "b", "kb", "mb", "gb"
	// https://pkg.go.dev/time#ParseDuration
	// or
	// be defined as integer in bytes
	// "" or 0 means it's disabled
	MaxUpstreamTrafficChange   human.Size `yaml:"max_upstream_traffic_change" valid:"size"`
	MaxDownstreamTrafficChange human.Size `yaml:"max_downstream_traffic_change" valid:"size"`
}

func defaultPeerStatisticConfig() *PeerStatisticConfig {
	return &PeerStatisticConfig{
		UpdateStatisticsInterval:       human.MustParseInterval(DefaultUpdateStatisticsInterval),
		TrafficChangeSendEventInterval: human.MustParseInterval(DefaultTrafficChangeSendEventInterval),
		MaxUpstreamTrafficChange:       human.MustParseSize(DefaultMaxUpstreamTrafficChange),
		MaxDownstreamTrafficChange:     human.MustParseSize(DefaultMaxDownstreamTrafficChange),
	}
}

func (s *PeerStatisticConfig) validate() {
	if s.UpdateStatisticsInterval.Value() < time.Second {
		s.UpdateStatisticsInterval = human.MustParseInterval(DefaultUpdateStatisticsInterval)
	}

	if s.UpdateStatisticsInterval.Value() > s.TrafficChangeSendEventInterval.Value() {
		s.TrafficChangeSendEventInterval = s.UpdateStatisticsInterval
	}
}

func LoadStatic(configDir string) (*Config, error) {
	return staticConfigFromFS(afero.OsFs{}, configDir)
}

func staticConfigFromFS(fs afero.Fs, configDir string) (*Config, error) {
	if len(configDir) == 0 {
		configDir = defaultConfigDir
	}

	pathToStatic := filepath.Join(configDir, configFileName)
	_, err := fs.Stat(pathToStatic)
	switch {
	case os.IsNotExist(err):
		zap.L().Warn("no static config file, using safe defaults", zap.String("path", pathToStatic))
		return safeDefaults(configDir), nil
	case err == nil:
		return loadStaticConfig(fs, pathToStatic)
	default:
		return nil, xerror.EInternalError("failed to stat the static config path", err, zap.String("path", pathToStatic))
	}
}

func loadStaticConfig(fs afero.Fs, path string) (*Config, error) {
	fd, err := fs.Open(path)
	if err != nil {
		return nil, xerror.EInternalError("failed to open config file "+path, err)
	}

	defer fd.Close()

	c := &Config{
		IPRose: iprose.DefaultConfig,
	}
	if err := yaml.NewDecoder(fd).Decode(c); err != nil {
		return nil, xerror.EInternalError("failed to unmarshal config", err)
	}

	if err := validator.ValidateStruct(c); err != nil {
		return nil, xerror.EInternalError("config validation failed", err)
	}

	if c.AdminAPI == nil {
		c.AdminAPI = defaultAdminAPIConfig()
	}
	c.path = path

	// do extra validation of cross-related fields,
	// all fields (including the private ones!) must be filled.
	if err := c.validate(); err != nil {
		return nil, err
	}

	mustFlush := false
	if len(c.Wireguard.PrivateKey) == 0 {
		// make it auto-deploy-friendly
		pk, _ := wgtypes.GeneratePrivateKey()
		c.Wireguard.PrivateKey = pk.String()
		mustFlush = true
	}

	// apply on-load hooks here
	if err := c.Wireguard.OnLoad(); err != nil {
		return nil, err
	}
	if len(c.InstanceID) == 0 {
		c.InstanceID = uuid.New().String()
		mustFlush = true
	}

	if mustFlush {
		_ = c.flush()
	}

	return c, nil
}

// validate validates dependent fields, prevents from
// logical errors in configurations.
func (s *Config) validate() error {
	if s.Domain != nil {
		if err := s.Domain.Validate(); err != nil {
			return err
		}

		mustIssue := s.Domain.Mode == string(adminAPI.DomainConfigModeDirect) && s.Domain.IssueSSL
		if mustIssue && (s.SSL == nil || len(s.SSL.ListenAddr) == 0) {
			return xerror.EInternalError("domain.issue_ssl is set but no SSL server configuration is given", nil)
		}

		if len(s.Domain.Dir) == 0 {
			s.Domain.Dir = s.ConfigDir()
		}
	}

	if s.SSL != nil {
		if len(s.SSL.ListenAddr) == 0 {
			return xerror.EInternalError("ssl.listen_addr is required", nil)
		}

		if s.Domain == nil || len(s.Domain.PrimaryName) == 0 {
			return xerror.EInternalError("SSL server is enabled, but domain name is not set", nil)
		}
	}

	if s.PeerStatistics != nil {
		s.PeerStatistics.validate()
	}

	return nil
}

// safeDefaults provides safe static config with paths started with the rootDir
func safeDefaults(rootDir string) *Config {
	adminAPIConfig := defaultAdminAPIConfig()
	keystorePath := ""
	if version.IsEnterprise() {
		adminAPIConfig.PasswordHash, _ = generateAdminPasswordHash()
		keystorePath = filepath.Join(rootDir, "keystore/")
	}
	return &Config{
		InstanceID: uuid.New().String(),
		path:       filepath.Join(rootDir, configFileName),

		HTTP: HttpConfig{
			ListenAddr: ":80",
		},
		LogLevel:           "debug",
		Rapidoc:            true,
		SQLitePath:         filepath.Join(rootDir, "db.sqlite3"),
		Wireguard:          wireguard.DefaultConfig(),
		AdminAPI:           adminAPIConfig,
		ManagementKeystore: keystorePath,
		PortRestrictions:   ipam.DefaultPortRestrictions(),
		PeerStatistics:     defaultPeerStatisticConfig(),
		IPRose:             iprose.DefaultConfig,
	}
}

func (s *Config) SetAdminPassword(plain string) error {
	hash, err := validateAndHashPassword(plain)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.AdminAPI.PasswordHash = hash
	return s.flush()
}

func validateAndHashPassword(plain string) (string, error) {
	if len([]rune(plain)) < 6 {
		return "", xerror.EInvalidArgument("too short password given", nil)
	}

	hash, err := passlib.Hash(plain)
	if err != nil {
		return "", xerror.EInternalError("failed to hash password", err)
	}
	return hash, nil
}

func (s *Config) CleanAdminPassword() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.AdminAPI.PasswordHash = ""
	_ = s.flush()
}

func (s *Config) VerifyAdminPassword(given string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := passlib.VerifyNoUpgrade(given, s.AdminAPI.PasswordHash); err != nil {
		return xerror.EAuthenticationFailed("invalid admin password given", nil)
	}
	return nil
}

func (s *Config) InitialSetupRequired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.AdminAPI.PasswordHash) == 0
}

func (s *Config) SetPublicIP(newIP xnet.IP) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Wireguard.ServerIPv4 = newIP.String()
	return s.flush()
}

func (s *Config) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flush()
}

func (s *Config) flush() error {
	bs, _ := yaml.Marshal(s)

	fd, err := os.OpenFile(s.path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return xerror.WInternalError("config", "failed to open config for writing", err, zap.String("path", s.path))
	}

	defer fd.Close()

	fd.Write([]byte("# WARNING\n# This file is managed automatically via the Settings UI.\n# Changes may by overridden.\n\n"))
	fd.Write(bs)

	return nil
}

func generateAdminPasswordHash() (string, error) {
	defaultPassword := xrand.String(12)
	hashedPassword, err := passlib.Hash(defaultPassword)
	if err != nil {
		return "", xerror.EInternalError("can't generate password hash", err)
	}

	// do not rely on zap on any level: it won't work
	// if the log level set to >= "error".
	fmt.Printf("WARN: new password generated: `%s`\n", defaultPassword)
	return hashedPassword, nil
}
