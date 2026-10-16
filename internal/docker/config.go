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

	"github.com/cautem/cautem-core/resourceadmission"
	"github.com/cautem/quarshell-driver/internal/certbundle"
)

// ConfigFromMap decodes the Docker fields currently consumed by the shared
// Engine implementation. Unconsumed OpenShell fields fail closed.
func ConfigFromMap(values map[string]any) (RuntimeConfig, string, error) {
	cfg := RuntimeConfig{SandboxNamespace: "default"}
	sandboxNamespaceConfigured := false
	stopTimeoutConfigured := false
	proxyAuthAllowInsecureConfigured := false
	proxyConnectByHostnameConfigured := false
	guestTLSCAConfigured := false
	guestTLSClientCertConfigured := false
	guestTLSClientKeyConfigured := false
	socket := ""
	for key, value := range values {
		var err error
		switch key {
		case "socket_path":
			socket, err = configString(value)
			if err == nil && socket == "" {
				err = fmt.Errorf("socket_path must not be empty when set")
			}
		case "default_image":
			cfg.DefaultImage, err = configString(value)
			if err == nil && cfg.DefaultImage == "" {
				err = fmt.Errorf("default_image must not be empty when set")
			}
		case "app_armor_profile":
			var profile string
			profile, err = configString(value)
			if err == nil {
				cfg.AppArmorProfile, err = ParseAppArmorProfile(profile)
			}
		case "allow_driver_config":
			cfg.AllowDriverConfig, err = configBool(value)
		case "resource_admission":
			var policy resourceadmission.Config
			policy, err = resourceAdmissionConfig(value)
			if err == nil {
				cfg.ResourceAdmission = &policy
			}
		case "sandbox_namespace":
			if sandboxNamespaceConfigured {
				return RuntimeConfig{}, "", fmt.Errorf("docker: set only one of sandbox_label and sandbox_namespace")
			}
			cfg.SandboxNamespace, err = configString(value)
			sandboxNamespaceConfigured = true
		case "sandbox_label":
			if sandboxNamespaceConfigured {
				return RuntimeConfig{}, "", fmt.Errorf("docker: set only one of sandbox_label and sandbox_namespace")
			}
			cfg.SandboxNamespace, err = configString(value)
			sandboxNamespaceConfigured = true
		case "guest_tls_ca":
			cfg.GuestTLSCA, err = configString(value)
			guestTLSCAConfigured = err == nil
		case "guest_tls_cert":
			cfg.GuestTLSCert, err = configString(value)
			guestTLSClientCertConfigured = err == nil
		case "guest_tls_key":
			cfg.GuestTLSKey, err = configString(value)
			guestTLSClientKeyConfigured = err == nil
		case "network_name":
			cfg.NetworkName, err = configString(value)
		case "host_gateway_ip":
			cfg.HostGatewayIP, err = configString(value)
		case "grpc_endpoint":
			cfg.GatewayGRPCEndpoint, err = configString(value)
		case "ssh_socket_path":
			cfg.SandboxSSHSocketPath, err = configString(value)
			if err == nil && cfg.SandboxSSHSocketPath == "" {
				err = fmt.Errorf("ssh_socket_path must not be empty when set")
			}
		case "cautem_internal_cleanup_manifest_dir":
			cfg.CleanupManifestDir, err = configString(value)
		case "sandbox_pids_limit":
			cfg.PidsLimit, err = configInt64(value)
			if err == nil && cfg.PidsLimit == 0 {
				err = fmt.Errorf("sandbox_pids_limit must be positive when set")
			}
		case "stop_timeout_secs":
			cfg.StopTimeoutSecs, err = configInt(value)
			stopTimeoutConfigured = err == nil
			if err == nil && (cfg.StopTimeoutSecs < 0 || uint64(cfg.StopTimeoutSecs) > uint64(^uint32(0))) {
				err = fmt.Errorf("stop_timeout_secs must fit in an unsigned 32-bit integer")
			}
		case "gateway_port":
			cfg.GatewayGRPCPort, err = configInt(value)
		case "enable_bind_mounts":
			cfg.EnableBindMounts, err = configBool(value)
		case "provider_spiffe_workload_api_socket":
			cfg.ProviderSPIFFEWorkloadAPISocket, err = configString(value)
			if err == nil && cfg.ProviderSPIFFEWorkloadAPISocket == "" {
				err = fmt.Errorf("provider_spiffe_workload_api_socket must not be empty when set")
			}
		case "image_pull_policy":
			cfg.ImagePullPolicy, err = configString(value)
			if err == nil && cfg.ImagePullPolicy == "" {
				err = fmt.Errorf("image_pull_policy must not be empty when set")
			}
		case "https_proxy":
			cfg.UpstreamProxyURL, err = nonEmptyProxyString(value, key)
		case "no_proxy":
			cfg.UpstreamProxyNoProxy, err = nonEmptyProxyString(value, key)
		case "proxy_auth_file":
			cfg.UpstreamProxyAuthFile, err = nonEmptyProxyString(value, key)
		case "proxy_auth_allow_insecure":
			cfg.UpstreamProxyAuthAllowInsecure, err = configBool(value)
			proxyAuthAllowInsecureConfigured = err == nil
		case "proxy_connect_by_hostname":
			cfg.UpstreamProxyConnectByHostname, err = configBool(value)
			proxyConnectByHostnameConfigured = err == nil
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
	cfg.StopTimeoutConfigured = stopTimeoutConfigured
	cfg.UpstreamProxyAuthAllowInsecureConfigured = proxyAuthAllowInsecureConfigured
	cfg.UpstreamProxyConnectByHostnameConfigured = proxyConnectByHostnameConfigured
	if guestTLSClientCertConfigured || guestTLSClientKeyConfigured {
		return RuntimeConfig{}, "", fmt.Errorf("docker: guest_tls_cert and guest_tls_key are no longer supported; sandboxes authenticate to the gateway with bearer tokens")
	}
	if guestTLSCAConfigured && cfg.GuestTLSCA == "" {
		return RuntimeConfig{}, "", fmt.Errorf("docker: guest_tls_ca must not be empty when set")
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
	if policy == "newer" {
		return RuntimeConfig{}, "", fmt.Errorf("docker: image_pull_policy newer is supported only by Podman")
	}
	cfg.ImagePullPolicy = policy
	if socket != "" && !strings.Contains(socket, "://") {
		socket = "unix://" + socket
	}
	return cfg, socket, nil
}

func resourceAdmissionConfig(value any) (resourceadmission.Config, error) {
	fields, ok := value.(map[string]any)
	if !ok || fields == nil {
		return resourceadmission.Config{}, fmt.Errorf("expected table")
	}
	policy := resourceadmission.Default()
	for key, raw := range fields {
		switch key {
		case "enabled":
			var ok bool
			policy.Enabled, ok = raw.(bool)
			if !ok {
				return resourceadmission.Config{}, fmt.Errorf("enabled must be boolean")
			}
		case "required_labels":
			labels, ok := raw.(map[string]any)
			if !ok || labels == nil {
				return resourceadmission.Config{}, fmt.Errorf("required_labels must be a table")
			}
			policy.RequiredLabels = make(map[string]string, len(labels))
			for label, rawValue := range labels {
				value, ok := rawValue.(string)
				if !ok {
					return resourceadmission.Config{}, fmt.Errorf("required_labels values must be strings")
				}
				policy.RequiredLabels[label] = value
			}
		default:
			return resourceadmission.Config{}, fmt.Errorf("unknown field %q", key)
		}
	}
	if err := policy.Validate(); err != nil {
		return resourceadmission.Config{}, err
	}
	return policy, nil
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
	} else if cfg.UpstreamProxyAuthAllowInsecure || cfg.UpstreamProxyAuthAllowInsecureConfigured {
		return fmt.Errorf("proxy_auth_allow_insecure requires proxy_auth_file")
	}
	if (cfg.UpstreamProxyConnectByHostname || cfg.UpstreamProxyConnectByHostnameConfigured) && cfg.UpstreamProxyURL == "" {
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
	if strings.TrimSpace(cert) != "" || strings.TrimSpace(key) != "" {
		return fmt.Errorf("guest_tls_cert and guest_tls_key are no longer supported; sandboxes authenticate to the gateway with bearer tokens")
	}
	if strings.TrimSpace(ca) != "" && (!filepath.IsAbs(ca) || filepath.Clean(ca) != ca) {
		return fmt.Errorf("guest_tls_ca must be an absolute clean path")
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
