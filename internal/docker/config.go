package docker

import (
	"crypto/x509"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/cautem/cautem-driver/internal/certbundle"
)

// ConfigFromMap decodes the Docker fields currently consumed by the shared
// Engine implementation. Unconsumed OpenShell fields fail closed.
func ConfigFromMap(values map[string]any) (RuntimeConfig, string, error) {
	cfg := RuntimeConfig{SandboxNamespace: "default"}
	socket := ""
	for key, value := range values {
		var err error
		switch key {
		case "socket_path":
			socket, err = configString(value)
		case "default_image":
			cfg.DefaultImage, err = configString(value)
		case "sandbox_namespace":
			cfg.SandboxNamespace, err = configString(value)
		case "guest_tls_ca":
			cfg.GuestTLSCA, err = configString(value)
		case "guest_tls_cert":
			cfg.GuestTLSCert, err = configString(value)
		case "guest_tls_key":
			cfg.GuestTLSKey, err = configString(value)
		case "network_name":
			cfg.NetworkName, err = configString(value)
		case "host_gateway_ip":
			cfg.HostGatewayIP, err = configString(value)
		case "grpc_endpoint":
			cfg.GatewayGRPCEndpoint, err = configString(value)
		case "ssh_socket_path":
			cfg.SandboxSSHSocketPath, err = configString(value)
		case "cautem_internal_cleanup_manifest_dir":
			cfg.CleanupManifestDir, err = configString(value)
		case "sandbox_pids_limit":
			cfg.PidsLimit, err = configInt64(value)
		case "stop_timeout_secs":
			cfg.StopTimeoutSecs, err = configInt(value)
		case "gateway_port":
			cfg.GatewayGRPCPort, err = configInt(value)
		case "enable_bind_mounts":
			cfg.EnableBindMounts, err = configBool(value)
		case "provider_spiffe_workload_api_socket":
			cfg.ProviderSPIFFEWorkloadAPISocket, err = configString(value)
		case "image_pull_policy":
			cfg.ImagePullPolicy, err = configString(value)
		case "https_proxy":
			cfg.UpstreamProxyURL, err = nonEmptyProxyString(value, key)
		case "no_proxy":
			cfg.UpstreamProxyNoProxy, err = nonEmptyProxyString(value, key)
		case "proxy_auth_file":
			cfg.UpstreamProxyAuthFile, err = nonEmptyProxyString(value, key)
		case "proxy_auth_allow_insecure":
			cfg.UpstreamProxyAuthAllowInsecure, err = configBool(value)
		case "proxy_connect_by_hostname":
			cfg.UpstreamProxyConnectByHostname, err = configBool(value)
		case "proxy_ca_bundle":
			cfg.UpstreamProxyCABundle, err = nonEmptyProxyString(value, key)
		case "egress_ca_bundle":
			cfg.EgressCABundle, err = configString(value)
		case "reconcile_data_ownership":
			cfg.ReconcileDataOwnership, err = configBool(value)
		default:
			return RuntimeConfig{}, "", fmt.Errorf("docker: config field %q is not supported by the Engine API backend", key)
		}
		if err != nil {
			return RuntimeConfig{}, "", fmt.Errorf("docker: invalid config field %q", key)
		}
	}
	if cfg.HostGatewayIP != "" && net.ParseIP(cfg.HostGatewayIP) == nil {
		return RuntimeConfig{}, "", fmt.Errorf("docker: host_gateway_ip must be an IP address")
	}
	if strings.TrimSpace(cfg.SandboxNamespace) == "" {
		return RuntimeConfig{}, "", fmt.Errorf("docker: sandbox_namespace must not be empty")
	}
	if cfg.CleanupManifestDir != "" && (!filepath.IsAbs(cfg.CleanupManifestDir) || filepath.Clean(cfg.CleanupManifestDir) != cfg.CleanupManifestDir) {
		return RuntimeConfig{}, "", fmt.Errorf("docker: cleanup manifest directory must be an absolute clean path")
	}
	if err := validateGuestTLSPaths(cfg.GuestTLSCA, cfg.GuestTLSCert, cfg.GuestTLSKey); err != nil {
		return RuntimeConfig{}, "", fmt.Errorf("docker: %w", err)
	}
	if err := validateUpstreamProxyConfig(cfg); err != nil {
		return RuntimeConfig{}, "", fmt.Errorf("docker: %w", err)
	}
	if err := validateEgressCABundle(cfg.EgressCABundle); err != nil {
		return RuntimeConfig{}, "", fmt.Errorf("docker: %w", err)
	}
	if cfg.PidsLimit < 0 || cfg.StopTimeoutSecs < 0 || cfg.GatewayGRPCPort < 0 || cfg.GatewayGRPCPort > 65535 {
		return RuntimeConfig{}, "", fmt.Errorf("docker: config value out of range")
	}
	policy, err := NormalizeImagePullPolicy(cfg.ImagePullPolicy)
	if err != nil {
		return RuntimeConfig{}, "", fmt.Errorf("docker: %w", err)
	}
	cfg.ImagePullPolicy = policy
	if socket != "" && !strings.Contains(socket, "://") {
		socket = "unix://" + socket
	}
	return cfg, socket, nil
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
	roots := x509.NewCertPool()
	if err := certbundle.AppendPEM(roots, body); err != nil {
		return fmt.Errorf("egress_ca_bundle is invalid: %w", err)
	}
	return nil
}

// NormalizeImagePullPolicy accepts OpenShell's canonical values plus the
// common if-not-present spellings and returns one stable runtime value.
func NormalizeImagePullPolicy(value string) (string, error) {
	switch policy := strings.ToLower(strings.TrimSpace(value)); policy {
	case "":
		return "", nil
	case "missing", "ifnotpresent", "if-not-present", "if_not_present":
		return "missing", nil
	case "always", "never", "newer":
		return policy, nil
	default:
		return "", fmt.Errorf("image_pull_policy must be missing|always|never|newer")
	}
}

func validateUpstreamProxyConfig(cfg RuntimeConfig) error {
	secure := false
	if cfg.UpstreamProxyURL != "" {
		u, err := url.Parse(cfg.UpstreamProxyURL)
		if err != nil || u.Hostname() == "" || u.Port() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("https_proxy must be an http(s) URL with explicit host/port and no inline credentials")
		}
		secure = u.Scheme == "https"
	}
	if cfg.UpstreamProxyNoProxy != "" && cfg.UpstreamProxyURL == "" {
		return fmt.Errorf("no_proxy requires https_proxy")
	}
	if cfg.UpstreamProxyAuthFile != "" {
		if !filepath.IsAbs(cfg.UpstreamProxyAuthFile) || filepath.Clean(cfg.UpstreamProxyAuthFile) != cfg.UpstreamProxyAuthFile {
			return fmt.Errorf("proxy_auth_file must be an absolute clean path")
		}
		if cfg.UpstreamProxyURL == "" {
			return fmt.Errorf("proxy_auth_file requires https_proxy")
		}
		if !secure && !cfg.UpstreamProxyAuthAllowInsecure {
			return fmt.Errorf("proxy_auth_file requires proxy_auth_allow_insecure=true for an http proxy")
		}
		body, err := os.ReadFile(cfg.UpstreamProxyAuthFile)
		if err != nil || len(body) > 64*1024 {
			return fmt.Errorf("proxy_auth_file must be readable and no larger than 64 KiB")
		}
		username, password, ok := strings.Cut(strings.TrimSpace(string(body)), ":")
		if !ok || strings.TrimSpace(username) == "" || password == "" {
			return fmt.Errorf("proxy_auth_file must contain user:pass")
		}
	} else if cfg.UpstreamProxyAuthAllowInsecure {
		return fmt.Errorf("proxy_auth_allow_insecure requires proxy_auth_file")
	}
	if cfg.UpstreamProxyConnectByHostname && cfg.UpstreamProxyURL == "" {
		return fmt.Errorf("proxy_connect_by_hostname requires https_proxy")
	}
	if cfg.UpstreamProxyCABundle != "" {
		if !filepath.IsAbs(cfg.UpstreamProxyCABundle) || filepath.Clean(cfg.UpstreamProxyCABundle) != cfg.UpstreamProxyCABundle {
			return fmt.Errorf("proxy_ca_bundle must be an absolute clean path")
		}
		if cfg.UpstreamProxyURL == "" {
			return fmt.Errorf("proxy_ca_bundle requires https_proxy")
		}
		body, err := os.ReadFile(cfg.UpstreamProxyCABundle)
		if err != nil {
			return fmt.Errorf("proxy_ca_bundle is unreadable")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(body) {
			return fmt.Errorf("proxy_ca_bundle contains no certificates")
		}
	}
	return nil
}

func validateGuestTLSPaths(ca, cert, key string) error {
	configured := 0
	for _, path := range []string{ca, cert, key} {
		if strings.TrimSpace(path) != "" {
			configured++
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return fmt.Errorf("guest TLS paths must be absolute and clean")
			}
		}
	}
	if configured != 0 && configured != 3 {
		return fmt.Errorf("guest_tls_ca, guest_tls_cert and guest_tls_key must be configured together")
	}
	return nil
}

func configString(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("expected string")
	}
	return strings.TrimSpace(s), nil
}

func nonEmptyProxyString(v any, field string) (string, error) {
	s, err := configString(v)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", fmt.Errorf("%s must not be empty when set", field)
	}
	return s, nil
}
func configBool(v any) (bool, error) {
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("expected boolean")
	}
	return b, nil
}
func configInt(v any) (int, error) {
	n, e := configInt64(v)
	if e != nil || n > int64(math.MaxInt) || n < int64(math.MinInt) {
		return 0, fmt.Errorf("expected integer")
	}
	return int(n), nil
}
func configInt64(v any) (int64, error) {
	switch n := v.(type) {
	case int:
		return int64(n), nil
	case int64:
		return n, nil
	case uint64:
		if n > math.MaxInt64 {
			return 0, fmt.Errorf("overflow")
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
