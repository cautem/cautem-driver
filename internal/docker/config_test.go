package docker

import (
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigFromMapAppliesSupportedGatewayEngineFields(t *testing.T) {
	cfg, socket, err := ConfigFromMap(map[string]any{"socket_path": "/var/run/docker.sock", "default_image": "alpine:3.22", "sandbox_label": "team-a", "network_name": "openshell", "host_gateway_ip": "127.0.0.1", "sandbox_pids_limit": int64(512), "enable_bind_mounts": true, "grpc_endpoint": "http://gateway:7443", "ssh_socket_path": "/run/cautem/ssh.sock"})
	if err != nil {
		t.Fatal(err)
	}
	if socket != "unix:///var/run/docker.sock" || cfg.DefaultImage != "alpine:3.22" || cfg.SandboxNamespace != "team-a" || cfg.NetworkName != "openshell" || cfg.HostGatewayIP != "127.0.0.1" || cfg.PidsLimit != 512 || !cfg.EnableBindMounts || cfg.GatewayGRPCEndpoint != "http://gateway:7443" || cfg.SandboxSSHSocketPath != "/run/cautem/ssh.sock" {
		t.Fatalf("config=%+v socket=%q", cfg, socket)
	}
}

func TestConfigFromMapRejectsConflictingSandboxLabelAliases(t *testing.T) {
	if _, _, err := ConfigFromMap(map[string]any{"sandbox_label": "upstream", "sandbox_namespace": "legacy"}); err == nil {
		t.Fatal("accepted conflicting sandbox label aliases")
	}
}

func TestConfigFromMapAcceptsOnlyAbsoluteCleanupManifestDirectory(t *testing.T) {
	manifestDir := filepath.Join(t.TempDir(), "cleanup")
	cfg, _, err := ConfigFromMap(map[string]any{"cautem_internal_cleanup_manifest_dir": manifestDir})
	if err != nil || cfg.CleanupManifestDir != manifestDir {
		t.Fatalf("cleanup manifest config=%q err=%v", cfg.CleanupManifestDir, err)
	}
	if _, _, err := ConfigFromMap(map[string]any{"cautem_internal_cleanup_manifest_dir": "relative/cleanup"}); err == nil {
		t.Fatal("accepted relative cleanup manifest directory")
	}
}

func TestNormalizeImagePullPolicyCanonicalizesAliases(t *testing.T) {
	for _, input := range []string{"missing", "Missing", "ifnotpresent", "if-not-present", "if_not_present"} {
		if got, err := NormalizeImagePullPolicy(input); err != nil || got != "missing" {
			t.Fatalf("NormalizeImagePullPolicy(%q)=(%q,%v), want missing", input, got, err)
		}
	}
	if _, err := NormalizeImagePullPolicy("sometimes"); err == nil {
		t.Fatal("accepted unsupported image pull policy")
	}
}

func TestConfigFromMapRejectsUnconsumedAndInvalidFields(t *testing.T) {
	for _, input := range []map[string]any{{"sandbox_runtime_image": "example.invalid/runtime"}, {"supervisor_bin": "/opt/supervisor"}, {"supervisor_image": "example.invalid/supervisor"}, {"socket_path": ""}, {"default_image": ""}, {"ssh_socket_path": ""}, {"provider_spiffe_workload_api_socket": ""}, {"sandbox_pids_limit": -1}, {"sandbox_pids_limit": 0}, {"sandbox_pids_limit": ""}, {"stop_timeout_secs": int64(^uint32(0)) + 1}, {"stop_timeout_secs": ""}, {"host_gateway_ip": "not-an-ip"}, {"image_pull_policy": ""}, {"image_pull_policy": "sometimes"}, {"image_pull_policy": "newer"}} {
		if _, _, err := ConfigFromMap(input); err == nil {
			t.Errorf("ConfigFromMap(%v) unexpectedly succeeded", input)
		}
	}
}

func TestConfigFromMapRejectsExplicitNullForEverySupportedField(t *testing.T) {
	fields := []string{
		"socket_path", "default_image", "sandbox_label", "sandbox_namespace", "guest_tls_ca", "guest_tls_cert", "guest_tls_key",
		"network_name", "host_gateway_ip", "grpc_endpoint", "ssh_socket_path", "cautem_internal_cleanup_manifest_dir",
		"sandbox_pids_limit", "stop_timeout_secs", "gateway_port", "enable_bind_mounts",
		"provider_spiffe_workload_api_socket", "image_pull_policy", "https_proxy", "no_proxy", "proxy_auth_file",
		"proxy_auth_allow_insecure", "proxy_connect_by_hostname", "proxy_ca_bundle", "egress_ca_bundle", "reconcile_data_ownership", "app_armor_profile", "allow_driver_config", "resource_admission",
	}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			if _, _, err := ConfigFromMap(map[string]any{field: nil}); err == nil {
				t.Fatalf("explicit null for supported field %q was silently accepted", field)
			}
		})
	}
}

func TestConfigFromMapParsesDriverConfigAdmissionPolicy(t *testing.T) {
	cfg, _, err := ConfigFromMap(map[string]any{
		"allow_driver_config": true,
		"resource_admission": map[string]any{
			"enabled":         false,
			"required_labels": map[string]any{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AllowDriverConfig || cfg.ResourceAdmission == nil || cfg.ResourceAdmission.Enabled || len(cfg.ResourceAdmission.RequiredLabels) != 0 {
		t.Fatalf("driver admission config=%+v", cfg)
	}
	for _, value := range []any{
		nil,
		map[string]any{"unknown": true},
		map[string]any{"enabled": "false"},
		map[string]any{"required_labels": map[string]any{}},
		map[string]any{"required_labels": map[string]any{"example.com/approval": 1}},
	} {
		if _, _, err := ConfigFromMap(map[string]any{"resource_admission": value}); err == nil {
			t.Errorf("accepted invalid resource_admission value %#v", value)
		}
	}
}

func TestConfigFromMapParsesAppArmorProfiles(t *testing.T) {
	for _, value := range []string{"RuntimeDefault", "Unconfined", "Localhost/openshell-supervisor"} {
		cfg, _, err := ConfigFromMap(map[string]any{"app_armor_profile": value})
		if err != nil || cfg.AppArmorProfile != AppArmorProfile(value) {
			t.Errorf("app_armor_profile %q parsed as %q, err=%v", value, cfg.AppArmorProfile, err)
		}
	}
	for _, value := range []string{"", "default", "Localhost/", "Localhost/profile name"} {
		if _, _, err := ConfigFromMap(map[string]any{"app_armor_profile": value}); err == nil {
			t.Errorf("invalid app_armor_profile %q was accepted", value)
		}
	}
}

func TestConfigFromMapAcceptsGuestTLSCAAndRejectsClientCertificates(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "ca.pem"), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")}
	cfg, _, err := ConfigFromMap(map[string]any{"guest_tls_ca": paths[0]})
	if err != nil || cfg.GuestTLSCA != paths[0] {
		t.Fatalf("CA-only TLS config=%+v err=%v", cfg, err)
	}
	for _, input := range []map[string]any{
		{"guest_tls_ca": "relative/ca.pem"},
		{"guest_tls_ca": ""},
		{"guest_tls_cert": paths[1]},
		{"guest_tls_cert": ""},
		{"guest_tls_key": paths[2]},
		{"guest_tls_key": ""},
		{"guest_tls_ca": paths[0], "guest_tls_cert": paths[1], "guest_tls_key": paths[2]},
	} {
		if _, _, err := ConfigFromMap(input); err == nil {
			t.Errorf("accepted invalid or unsupported guest TLS config: %#v", input)
		}
	}
}

func TestConfigFromMapAppliesAndValidatesUpstreamProxySettings(t *testing.T) {
	cfg, _, err := ConfigFromMap(map[string]any{
		"https_proxy":               "https://proxy.example.test:8443",
		"no_proxy":                  "localhost,.svc.cluster.local",
		"proxy_connect_by_hostname": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UpstreamProxyURL != "https://proxy.example.test:8443" || cfg.UpstreamProxyNoProxy != "localhost,.svc.cluster.local" || !cfg.UpstreamProxyConnectByHostname {
		t.Fatalf("proxy config=%+v", cfg)
	}
	configuredFalse, _, err := ConfigFromMap(map[string]any{
		"https_proxy":               "https://proxy.example.test:8443",
		"proxy_connect_by_hostname": false,
	})
	if err != nil || !configuredFalse.UpstreamProxyConnectByHostnameConfigured || configuredFalse.UpstreamProxyConnectByHostname {
		t.Fatalf("explicit proxy_connect_by_hostname=false config=%+v err=%v", configuredFalse, err)
	}
	for _, input := range []map[string]any{
		{"https_proxy": ""},
		{"https_proxy": "  "},
		{"no_proxy": " "},
		{"proxy_auth_file": ""},
		{"proxy_ca_bundle": ""},
		{"proxy_auth_allow_insecure": false},
		{"proxy_connect_by_hostname": false},
		{"no_proxy": "localhost"},
		{"proxy_connect_by_hostname": true},
		{"https_proxy": "http://proxy.example.test:8080", "proxy_auth_file": "/tmp/auth"},
	} {
		if _, _, err := ConfigFromMap(input); err == nil {
			t.Errorf("accepted invalid proxy config: %#v", input)
		}
	}
}

func TestConfigFromMapAcceptsReadableProxyAuthAndCABundle(t *testing.T) {
	proxy := httptest.NewTLSServer(nil)
	defer proxy.Close()
	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth")
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(authPath, []byte("robot:s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := ConfigFromMap(map[string]any{
		"https_proxy":               "https://proxy.example.test:8443",
		"proxy_auth_file":           authPath,
		"proxy_auth_allow_insecure": false,
		"proxy_ca_bundle":           caPath,
		"no_proxy":                  "localhost,.svc.cluster.local",
		"proxy_connect_by_hostname": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.UpstreamProxyAuthAllowInsecureConfigured || cfg.UpstreamProxyAuthAllowInsecure {
		t.Fatalf("explicit proxy_auth_allow_insecure=false was lost: %+v", cfg)
	}
	if cfg.UpstreamProxyAuthFile != authPath || cfg.UpstreamProxyCABundle != caPath || cfg.UpstreamProxyNoProxy != "localhost,.svc.cluster.local" {
		t.Fatalf("proxy credential config=%+v", cfg)
	}
	if _, err := x509.ParseCertificate(proxy.Certificate().Raw); err != nil {
		t.Fatal(err)
	}
}
