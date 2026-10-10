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
	cfg, socket, err := ConfigFromMap(map[string]any{"socket_path": "/var/run/docker.sock", "default_image": "alpine:3.22", "sandbox_namespace": "team-a", "network_name": "openshell", "host_gateway_ip": "127.0.0.1", "sandbox_pids_limit": int64(512), "enable_bind_mounts": true, "grpc_endpoint": "http://gateway:7443", "ssh_socket_path": "/run/cautem/ssh.sock"})
	if err != nil {
		t.Fatal(err)
	}
	if socket != "unix:///var/run/docker.sock" || cfg.DefaultImage != "alpine:3.22" || cfg.SandboxNamespace != "team-a" || cfg.NetworkName != "openshell" || cfg.HostGatewayIP != "127.0.0.1" || cfg.PidsLimit != 512 || !cfg.EnableBindMounts || cfg.GatewayGRPCEndpoint != "http://gateway:7443" || cfg.SandboxSSHSocketPath != "/run/cautem/ssh.sock" {
		t.Fatalf("config=%+v socket=%q", cfg, socket)
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
	for _, input := range []map[string]any{{"supervisor_image": "example.invalid/supervisor"}, {"sandbox_pids_limit": -1}, {"host_gateway_ip": "not-an-ip"}, {"image_pull_policy": "sometimes"}} {
		if _, _, err := ConfigFromMap(input); err == nil {
			t.Errorf("ConfigFromMap(%v) unexpectedly succeeded", input)
		}
	}
}

func TestConfigFromMapValidatesGuestTLSAsAnAllOrNonePathSet(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "ca.pem"), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")}
	cfg, _, err := ConfigFromMap(map[string]any{"guest_tls_ca": paths[0], "guest_tls_cert": paths[1], "guest_tls_key": paths[2]})
	if err != nil || cfg.GuestTLSCA != paths[0] || cfg.GuestTLSCert != paths[1] || cfg.GuestTLSKey != paths[2] {
		t.Fatalf("TLS config=%+v err=%v", cfg, err)
	}
	for _, input := range []map[string]any{
		{"guest_tls_ca": paths[0]},
		{"guest_tls_ca": "relative/ca.pem", "guest_tls_cert": paths[1], "guest_tls_key": paths[2]},
	} {
		if _, _, err := ConfigFromMap(input); err == nil {
			t.Errorf("accepted incomplete/unsafe guest TLS paths: %#v", input)
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
	for _, input := range []map[string]any{
		{"https_proxy": ""},
		{"https_proxy": "  "},
		{"no_proxy": " "},
		{"proxy_auth_file": ""},
		{"proxy_ca_bundle": ""},
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
		"proxy_ca_bundle":           caPath,
		"no_proxy":                  "localhost,.svc.cluster.local",
		"proxy_connect_by_hostname": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UpstreamProxyAuthFile != authPath || cfg.UpstreamProxyCABundle != caPath || cfg.UpstreamProxyNoProxy != "localhost,.svc.cluster.local" {
		t.Fatalf("proxy credential config=%+v", cfg)
	}
	if _, err := x509.ParseCertificate(proxy.Certificate().Raw); err != nil {
		t.Fatal(err)
	}
}
