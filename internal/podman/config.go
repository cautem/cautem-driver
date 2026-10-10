package podman

import (
	"crypto/x509"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cautem/cautem-driver/internal/certbundle"
	docker "github.com/cautem/cautem-driver/internal/docker"
)

const defaultHealthCheckIntervalSecs int64 = 10

// IDMapping is a Podman user namespace mapping from a container ID range to a
// host ID range.
type IDMapping struct {
	ContainerID uint32
	HostID      uint32
	Size        uint32
}

// ConfigFromMap decodes supported fields from openshell.drivers.podman. It
// rejects unknown keys so settings never appear accepted without an effect.
func ConfigFromMap(values map[string]any) (Config, error) {
	cfg := Config{HealthCheckIntervalSecs: defaultHealthCheckIntervalSecs}
	for key, value := range values {
		var err error
		switch key {
		case "socket_path":
			cfg.SocketPath, err = stringValue(value)
		case "default_image":
			cfg.DefaultImage, err = stringValue(value)
		case "network_name":
			cfg.NetworkName, err = stringValue(value)
		case "host_gateway_ip":
			cfg.HostGatewayIP, err = stringValue(value)
		case "guest_tls_ca":
			cfg.GuestTLSCA, err = stringValue(value)
		case "guest_tls_cert":
			cfg.GuestTLSCert, err = stringValue(value)
		case "guest_tls_key":
			cfg.GuestTLSKey, err = stringValue(value)
		case "https_proxy":
			cfg.HTTPSProxy, err = nonEmptyProxyString(value, key)
		case "no_proxy":
			cfg.NoProxy, err = nonEmptyProxyString(value, key)
		case "proxy_auth_file":
			cfg.ProxyAuthFile, err = nonEmptyProxyString(value, key)
		case "proxy_auth_allow_insecure":
			cfg.ProxyAuthAllowInsecure, err = optionalBoolValue(value)
		case "proxy_connect_by_hostname":
			cfg.ProxyConnectByHostname, err = optionalBoolValue(value)
		case "proxy_ca_bundle":
			cfg.ProxyCABundle, err = nonEmptyProxyString(value, key)
		case "registry_auth_file":
			cfg.RegistryAuthFile, err = stringValue(value)
		case "egress_ca_bundle":
			cfg.EgressCABundle, err = stringValue(value)
		case "reconcile_data_ownership":
			cfg.ReconcileDataOwnership, err = boolValue(value)
		case "image_pull_policy":
			cfg.ImagePullPolicy, err = stringValue(value)
		case "provider_spiffe_workload_api_socket":
			cfg.ProviderSPIFFEWorkloadAPISocket, err = stringValue(value)
		case "grpc_endpoint":
			cfg.GatewayGRPCEndpoint, err = stringValue(value)
		case "sandbox_ssh_socket_path":
			cfg.SandboxSSHSocketPath, err = stringValue(value)
		case "stop_timeout_secs":
			cfg.StopTimeoutSecs, err = intValue(value)
		case "gateway_port":
			cfg.GatewayGRPCPort, err = intValue(value)
		case "sandbox_pids_limit":
			cfg.PidsLimit, err = int64Value(value)
		case "enable_bind_mounts":
			cfg.EnableBindMounts, err = boolValue(value)
		case "health_check_interval_secs":
			cfg.HealthCheckIntervalSecs, err = int64Value(value)
		case "userns":
			cfg.UsernsMode, err = stringValue(value)
		case "uidmap":
			cfg.UIDMap, err = idMapListValue(key, value)
		case "gidmap":
			cfg.GIDMap, err = idMapListValue(key, value)
		default:
			return Config{}, fmt.Errorf("podman: config field %q is not supported by the Engine API backend", key)
		}
		if err != nil {
			return Config{}, fmt.Errorf("podman: invalid config field %q: %w", key, err)
		}
	}
	if cfg.HostGatewayIP != "" {
		if _, err := netip.ParseAddr(cfg.HostGatewayIP); err != nil {
			return Config{}, fmt.Errorf("podman: invalid host_gateway_ip: %w", err)
		}
	}
	if err := validateGuestTLSPaths(cfg.GuestTLSCA, cfg.GuestTLSCert, cfg.GuestTLSKey); err != nil {
		return Config{}, fmt.Errorf("podman: %w", err)
	}
	if err := validateRegistryAuthFile(cfg.RegistryAuthFile); err != nil {
		return Config{}, fmt.Errorf("podman: %w", err)
	}
	if err := validateEgressCABundle(cfg.EgressCABundle); err != nil {
		return Config{}, fmt.Errorf("podman: %w", err)
	}
	if err := validateProxyConfig(cfg); err != nil {
		return Config{}, err
	}
	if cfg.StopTimeoutSecs < 0 || cfg.PidsLimit < 0 || cfg.GatewayGRPCPort < 0 || cfg.GatewayGRPCPort > 65535 || cfg.HealthCheckIntervalSecs < 0 || cfg.HealthCheckIntervalSecs > math.MaxInt64/1_000_000_000 {
		return Config{}, fmt.Errorf("podman: timeout, PID limit or gateway port is out of range")
	}
	policy, err := docker.NormalizeImagePullPolicy(cfg.ImagePullPolicy)
	if err != nil {
		return Config{}, fmt.Errorf("podman: %w", err)
	}
	cfg.ImagePullPolicy = policy
	canonicalMode, err := canonicalUsernsMode(cfg.UsernsMode)
	if err != nil {
		return Config{}, err
	}
	cfg.UsernsMode = canonicalMode
	privateUserNS := strings.EqualFold(cfg.UsernsMode, "private")
	if privateUserNS && (len(cfg.UIDMap) == 0 || len(cfg.GIDMap) == 0) {
		return Config{}, fmt.Errorf("podman: userns=private requires at least one entry in both uidmap and gidmap")
	}
	if !privateUserNS && (len(cfg.UIDMap) > 0 || len(cfg.GIDMap) > 0) {
		return Config{}, fmt.Errorf("podman: uidmap and gidmap are only valid with userns=private")
	}
	return cfg, nil
}

func validateEgressCABundle(path string) error {
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("egress_ca_bundle must be an absolute clean path")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return fmt.Errorf("egress_ca_bundle must be a readable regular file no larger than 1 MiB")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("egress_ca_bundle is unreadable")
	}
	if err := certbundle.AppendPEM(x509.NewCertPool(), body); err != nil {
		return fmt.Errorf("egress_ca_bundle is invalid: %w", err)
	}
	return nil
}

func canonicalUsernsMode(input string) (string, error) {
	if input == "" {
		return "", nil
	}
	mode, params, hasParams := strings.Cut(input, ":")
	mode = strings.ToLower(mode)
	switch mode {
	case "auto", "keep-id":
		if hasParams && strings.TrimSpace(params) == "" {
			return "", fmt.Errorf("podman: userns mode parameters must not be empty")
		}
	case "host", "nomap", "no-map", "private":
		if hasParams {
			return "", fmt.Errorf("podman: userns mode %q does not accept parameters", mode)
		}
		if mode == "nomap" {
			mode = "no-map"
		}
	default:
		return "", fmt.Errorf("podman: unsupported userns mode %q", mode)
	}
	if hasParams {
		return mode + ":" + params, nil
	}
	return mode, nil
}

func idMapListValue(field string, value any) ([]IDMapping, error) {
	var entries []string
	switch list := value.(type) {
	case []string:
		entries = append(entries, list...)
	case []any:
		entries = make([]string, len(list))
		for i, raw := range list {
			entry, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("%s entries must be strings", field)
			}
			entries[i] = entry
		}
	default:
		return nil, fmt.Errorf("%s must be an array of container_id:host_id:size strings", field)
	}
	mappings := make([]IDMapping, 0, len(entries))
	for i, entry := range entries {
		parts := strings.Split(entry, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("%s entry %d must be container_id:host_id:size", field, i)
		}
		values := [3]uint32{}
		for j, part := range parts {
			value, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("%s entry %d contains an invalid non-negative integer", field, i)
			}
			values[j] = uint32(value)
		}
		if values[2] == 0 {
			return nil, fmt.Errorf("%s entry %d size must be greater than zero", field, i)
		}
		mappings = append(mappings, IDMapping{ContainerID: values[0], HostID: values[1], Size: values[2]})
	}
	return mappings, nil
}

func validateProxyConfig(cfg Config) error {
	proxySecure := false
	if cfg.HTTPSProxy != "" {
		u, err := url.Parse(cfg.HTTPSProxy)
		if err != nil || u.Hostname() == "" || u.Port() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("podman: https_proxy must be an http(s) URL with explicit host/port and no inline credentials")
		}
		proxySecure = u.Scheme == "https"
	}
	if cfg.NoProxy != "" && cfg.HTTPSProxy == "" {
		return fmt.Errorf("podman: no_proxy requires https_proxy")
	}
	if cfg.ProxyAuthFile != "" {
		if !filepath.IsAbs(cfg.ProxyAuthFile) || filepath.Clean(cfg.ProxyAuthFile) != cfg.ProxyAuthFile {
			return fmt.Errorf("podman: proxy_auth_file must be an absolute clean path")
		}
		if cfg.HTTPSProxy == "" {
			return fmt.Errorf("podman: proxy_auth_file requires https_proxy")
		}
		if !proxySecure && (cfg.ProxyAuthAllowInsecure == nil || !*cfg.ProxyAuthAllowInsecure) {
			return fmt.Errorf("podman: proxy_auth_file requires proxy_auth_allow_insecure=true for an http proxy")
		}
		body, err := os.ReadFile(cfg.ProxyAuthFile)
		if err != nil || len(body) > 64*1024 {
			return fmt.Errorf("podman: proxy_auth_file must be readable and no larger than 64 KiB")
		}
		username, password, ok := strings.Cut(strings.TrimSpace(string(body)), ":")
		if !ok || strings.TrimSpace(username) == "" || password == "" {
			return fmt.Errorf("podman: proxy_auth_file must contain user:pass")
		}
	} else if cfg.ProxyAuthAllowInsecure != nil {
		return fmt.Errorf("podman: proxy_auth_allow_insecure requires proxy_auth_file")
	}
	if cfg.ProxyConnectByHostname != nil && cfg.HTTPSProxy == "" {
		return fmt.Errorf("podman: proxy_connect_by_hostname requires https_proxy")
	}
	if cfg.ProxyCABundle != "" {
		if !filepath.IsAbs(cfg.ProxyCABundle) || filepath.Clean(cfg.ProxyCABundle) != cfg.ProxyCABundle {
			return fmt.Errorf("podman: proxy_ca_bundle must be an absolute clean path")
		}
		if cfg.HTTPSProxy == "" {
			return fmt.Errorf("podman: proxy_ca_bundle requires https_proxy")
		}
		body, err := os.ReadFile(cfg.ProxyCABundle)
		if err != nil {
			return fmt.Errorf("podman: proxy_ca_bundle is unreadable")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(body) {
			return fmt.Errorf("podman: proxy_ca_bundle contains no certificates")
		}
	}
	return nil
}

func validateGuestTLSPaths(ca, cert, key string) error {
	configured := 0
	for _, path := range []string{ca, cert, key} {
		if strings.TrimSpace(path) == "" {
			continue
		}
		configured++
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("guest TLS paths must be absolute and clean")
		}
	}
	if configured != 0 && configured != 3 {
		return fmt.Errorf("guest_tls_ca, guest_tls_cert and guest_tls_key must be configured together")
	}
	return nil
}

func stringValue(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("expected string")
	}
	return strings.TrimSpace(s), nil
}

func nonEmptyProxyString(v any, field string) (string, error) {
	s, err := stringValue(v)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", fmt.Errorf("%s must not be empty when set", field)
	}
	return s, nil
}
func boolValue(v any) (bool, error) {
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("expected boolean")
	}
	return b, nil
}
func optionalBoolValue(v any) (*bool, error) {
	b, ok := v.(bool)
	if !ok {
		return nil, fmt.Errorf("expected boolean")
	}
	return &b, nil
}
func intValue(v any) (int, error) {
	n, err := int64Value(v)
	if err != nil || n > int64(math.MaxInt) || n < int64(math.MinInt) {
		return 0, fmt.Errorf("expected integer")
	}
	return int(n), nil
}
func int64Value(v any) (int64, error) {
	switch n := v.(type) {
	case int:
		return int64(n), nil
	case int64:
		return n, nil
	case uint64:
		if n > math.MaxInt64 {
			return 0, fmt.Errorf("integer overflow")
		}
		return int64(n), nil
	case float64:
		if math.Trunc(n) != n || n > math.MaxInt64 || n < math.MinInt64 {
			return 0, fmt.Errorf("expected integer")
		}
		return int64(n), nil
	default:
		return 0, fmt.Errorf("expected integer")
	}
}
