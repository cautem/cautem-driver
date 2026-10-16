package podman

import (
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestSocketCandidatesOrder(t *testing.T) {
	t.Setenv("CAUTEM_PODMAN_SOCKET", "/tmp/cautem-podman-test.sock")
	t.Setenv("XDG_RUNTIME_DIR", "/tmp/xdg-runtime-test")
	c := socketCandidates()
	if len(c) < 2 {
		t.Fatalf("candidates=%v", c)
	}
	if c[0] != "/tmp/cautem-podman-test.sock" {
		t.Fatalf("first=%q", c[0])
	}
	wantXDG := filepath.Join("/tmp/xdg-runtime-test", "podman", "podman.sock")
	found := slices.Contains(c, wantXDG)
	if !found {
		t.Fatalf("missing xdg candidate in %v", c)
	}
}

func TestResolveHostPrefersDOCKER_HOST(t *testing.T) {
	t.Setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
	t.Setenv("CONTAINER_HOST", "unix:///ignored")
	h, err := ResolveHost()
	if err != nil || h != "unix:///var/run/docker.sock" {
		t.Fatalf("host=%q err=%v", h, err)
	}
}

func TestConfigFromMapAcceptsAbsoluteCleanupManifestDirectory(t *testing.T) {
	manifestDir := filepath.Join(t.TempDir(), "cleanup")
	cfg, err := ConfigFromMap(map[string]any{"cautem_internal_cleanup_manifest_dir": manifestDir})
	if err != nil || cfg.CleanupManifestDir != manifestDir {
		t.Fatalf("cleanup manifest config=%q err=%v", cfg.CleanupManifestDir, err)
	}
	if _, err := ConfigFromMap(map[string]any{"cautem_internal_cleanup_manifest_dir": "relative/cleanup"}); err == nil {
		t.Fatal("accepted relative cleanup manifest directory")
	}
}

func TestNewWithConfigRejectsUnsupportedRuntimeSettings(t *testing.T) {
	if _, err := NewWithConfig(Config{HostGatewayIP: "not-an-ip"}); err == nil {
		t.Fatal("invalid host_gateway_ip was accepted")
	}
	if _, err := NewWithConfig(Config{ImagePullPolicy: "mystery"}); err == nil {
		t.Fatal("unknown image_pull_policy was accepted")
	}
	if cfg, err := ConfigFromMap(map[string]any{"image_pull_policy": "missing"}); err != nil || cfg.ImagePullPolicy != "missing" {
		t.Fatalf("OpenShell image_pull_policy=missing config=%+v err=%v", cfg, err)
	}
	if cfg, err := ConfigFromMap(map[string]any{"image_pull_policy": "newer"}); err != nil || cfg.ImagePullPolicy != "newer" {
		t.Fatalf("Podman image_pull_policy=newer config=%+v err=%v", cfg, err)
	}
	if _, err := NewWithConfig(Config{StopTimeoutSecs: -1}); err == nil {
		t.Fatal("negative stop timeout was accepted")
	}
	if _, err := NewWithConfig(Config{GuestTLSCert: "/tmp/client.crt"}); err == nil {
		t.Fatal("deprecated guest client certificate was accepted")
	}
}

func TestConfigFromMapAppliesSupportedCompatFieldsAndRejectsInertFields(t *testing.T) {
	cfg, err := ConfigFromMap(map[string]any{
		"default_image": "sandbox:test", "network_name": "ws-net", "image_pull_policy": "Missing",
		"host_gateway_ip": "10.0.0.2", "stop_timeout_secs": int64(15), "sandbox_pids_limit": int64(1024),
		"enable_bind_mounts": true, "gateway_port": int64(7443),
		"health_check_interval_secs": int64(30), "userns": "auto:size=65536",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultImage != "sandbox:test" || cfg.NetworkName != "ws-net" || cfg.ImagePullPolicy != "missing" || cfg.StopTimeoutSecs != 15 || !cfg.StopTimeoutConfigured || cfg.PidsLimit != 1024 || !cfg.EnableBindMounts || cfg.GatewayGRPCPort != 7443 || cfg.HealthCheckIntervalSecs != 30 || cfg.UsernsMode != "auto:size=65536" {
		t.Fatalf("config=%+v", cfg)
	}
	if cfg, err := ConfigFromMap(nil); err != nil || cfg.HealthCheckIntervalSecs != defaultHealthCheckIntervalSecs || cfg.StopTimeoutSecs != defaultStopTimeoutSecs || cfg.StopTimeoutConfigured {
		t.Fatalf("default config=%+v err=%v", cfg, err)
	}
	for _, value := range []any{"auto", "auto:size=65536", "keep-id:uid=1000,gid=1000", "host", "nomap", "no-map"} {
		if _, err := ConfigFromMap(map[string]any{"userns": value}); err != nil {
			t.Errorf("userns %q rejected: %v", value, err)
		}
	}
	for input, want := range map[string]string{"AUTO:size=65536": "auto:size=65536", "KEEP-ID:uid=1000": "keep-id:uid=1000", "nomap": "no-map", "NO-MAP": "no-map", "HOST": "host"} {
		cfg, err := ConfigFromMap(map[string]any{"userns": input})
		if err != nil || cfg.UsernsMode != want {
			t.Errorf("userns %q canonicalized to %q, err=%v; want %q", input, cfg.UsernsMode, err, want)
		}
	}
	for _, input := range []map[string]any{{"userns": "unknown"}, {"userns": ""}, {"userns": "private"}, {"socket_path": ""}, {"default_image": ""}, {"ssh_socket_path": ""}, {"provider_spiffe_workload_api_socket": ""}, {"sandbox_pids_limit": int64(0)}, {"sandbox_pids_limit": ""}, {"stop_timeout_secs": int64(^uint32(0)) + 1}, {"stop_timeout_secs": ""}, {"health_check_interval_secs": int64(-1)}, {"health_check_interval_secs": int64(0)}, {"health_check_interval_secs": int64(9_223_372_037)}, {"health_check_interval_secs": ""}, {"image_pull_policy": ""}, {"uidmap": []any{"0:0:1"}}, {"gidmap": []string{"0:0:1"}}, {"userns": "private", "uidmap": []string{"0:0:1"}}, {"userns": "private", "uidmap": []string{"0:0:1"}, "gidmap": []string{"0:0:0"}}, {"userns": "private", "uidmap": []string{"0:0:1:2"}, "gidmap": []string{"0:0:1"}}, {"userns": "private", "uidmap": []string{"4294967296:0:1"}, "gidmap": []string{"0:0:1"}}} {
		if _, err := ConfigFromMap(input); err == nil {
			t.Errorf("unsupported or invalid settings accepted: %#v", input)
		}
	}
	cfg, err = ConfigFromMap(map[string]any{"userns": "private", "uidmap": []any{"0:100000:65536", "65536:200000:1"}, "gidmap": []string{"0:100000:65536"}})
	if err != nil {
		t.Fatalf("valid explicit ID mappings rejected: %v", err)
	}
	if len(cfg.UIDMap) != 2 || cfg.UIDMap[0] != (IDMapping{ContainerID: 0, HostID: 100000, Size: 65536}) || len(cfg.GIDMap) != 1 || cfg.GIDMap[0] != (IDMapping{ContainerID: 0, HostID: 100000, Size: 65536}) {
		t.Fatalf("ID mappings decoded incorrectly: %+v", cfg)
	}
	emptyMaps, err := ConfigFromMap(map[string]any{"uidmap": []any{}, "gidmap": []string{}})
	if err != nil || len(emptyMaps.UIDMap) != 0 || len(emptyMaps.GIDMap) != 0 {
		t.Fatalf("explicit empty ID maps should preserve the no-mapping effect: config=%+v err=%v", emptyMaps, err)
	}
	for _, field := range []string{"sandbox_runtime_image", "supervisor_image"} {
		if _, err := ConfigFromMap(map[string]any{field: "ghcr.io/example/runtime"}); err == nil {
			t.Fatalf("unsupported %s silently accepted", field)
		}
	}
}

func TestConfigFromMapRejectsExplicitNullForEverySupportedField(t *testing.T) {
	fields := []string{
		"socket_path", "default_image", "network_name", "host_gateway_ip", "guest_tls_ca", "guest_tls_cert", "guest_tls_key",
		"https_proxy", "no_proxy", "proxy_auth_file", "proxy_auth_allow_insecure", "proxy_connect_by_hostname", "proxy_ca_bundle",
		"registry_auth_file", "egress_ca_bundle", "reconcile_data_ownership", "image_pull_policy", "provider_spiffe_workload_api_socket",
		"grpc_endpoint", "ssh_socket_path", "sandbox_ssh_socket_path", "cautem_internal_cleanup_manifest_dir", "stop_timeout_secs", "gateway_port",
		"sandbox_pids_limit", "enable_bind_mounts", "health_check_interval_secs", "userns", "uidmap", "gidmap",
		"app_armor_profile", "allow_driver_config", "resource_admission",
	}
	for _, input := range []map[string]any{{"guest_tls_ca": ""}, {"guest_tls_cert": ""}, {"guest_tls_key": ""}} {
		if _, err := ConfigFromMap(input); err == nil {
			t.Errorf("accepted explicitly empty guest TLS setting: %#v", input)
		}
	}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			if _, err := ConfigFromMap(map[string]any{field: nil}); err == nil {
				t.Fatalf("explicit null for supported field %q was silently accepted", field)
			}
		})
	}
}

func TestConfigFromMapUsesPinnedSSHSocketFieldAndRejectsConflictingAlias(t *testing.T) {
	cfg, err := ConfigFromMap(map[string]any{"ssh_socket_path": "/run/quarshell/ssh.sock"})
	if err != nil || cfg.SandboxSSHSocketPath != "/run/quarshell/ssh.sock" {
		t.Fatalf("pinned ssh_socket_path=%q err=%v", cfg.SandboxSSHSocketPath, err)
	}
	if _, err := ConfigFromMap(map[string]any{"ssh_socket_path": "/run/quarshell/ssh.sock", "sandbox_ssh_socket_path": "/run/legacy/ssh.sock"}); err == nil {
		t.Fatal("accepted conflicting SSH socket path aliases")
	}
}

func TestConfigFromMapPreservesExplicitZeroStopTimeout(t *testing.T) {
	cfg, err := ConfigFromMap(map[string]any{"stop_timeout_secs": int64(0)})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StopTimeoutSecs != 0 || !cfg.StopTimeoutConfigured {
		t.Fatalf("explicit stop_timeout_secs=0 config=%+v", cfg)
	}
}

func TestConfigFromMapParsesDriverConfigAdmissionPolicy(t *testing.T) {
	cfg, err := ConfigFromMap(map[string]any{
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
		if _, err := ConfigFromMap(map[string]any{"resource_admission": value}); err == nil {
			t.Errorf("accepted invalid resource_admission value %#v", value)
		}
	}
}

func TestConfigFromMapAcceptsGuestTLSCAAndRejectsClientCertificates(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "ca.pem"), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")}
	cfg, err := ConfigFromMap(map[string]any{"guest_tls_ca": paths[0]})
	if err != nil || cfg.GuestTLSCA != paths[0] {
		t.Fatalf("CA-only TLS config=%+v err=%v", cfg, err)
	}
	for _, input := range []map[string]any{{"guest_tls_ca": "relative/ca.pem"}, {"guest_tls_cert": paths[1]}, {"guest_tls_key": paths[2]}, {"guest_tls_ca": paths[0], "guest_tls_cert": paths[1], "guest_tls_key": paths[2]}} {
		if _, err := ConfigFromMap(input); err == nil {
			t.Errorf("accepted invalid or unsupported guest TLS config: %#v", input)
		}
	}
}

func TestConfigFromMapValidatesAndAppliesUpstreamProxySettings(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), "proxy-auth")
	if err := os.WriteFile(authFile, []byte("robot:s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewTLSServer(nil)
	defer proxy.Close()
	caFile := filepath.Join(t.TempDir(), "proxy-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	connectByHostname := true
	cfg, err := ConfigFromMap(map[string]any{
		"https_proxy":               "https://proxy.example.test:8443",
		"no_proxy":                  "localhost,.svc.cluster.local",
		"proxy_auth_file":           authFile,
		"proxy_ca_bundle":           caFile,
		"proxy_connect_by_hostname": connectByHostname,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPSProxy != "https://proxy.example.test:8443" || cfg.NoProxy != "localhost,.svc.cluster.local" || cfg.ProxyAuthFile != authFile || cfg.ProxyCABundle != caFile || cfg.ProxyConnectByHostname == nil || !*cfg.ProxyConnectByHostname {
		t.Fatalf("proxy config=%+v", cfg)
	}
	if _, err := x509.ParseCertificate(proxy.Certificate().Raw); err != nil {
		t.Fatal(err)
	}
	for _, input := range []map[string]any{
		{"https_proxy": ""},
		{"https_proxy": "  "},
		{"no_proxy": " "},
		{"proxy_auth_file": ""},
		{"proxy_ca_bundle": ""},
		{"https_proxy": "http://user:pass@proxy.example.test:8080"},
		{"https_proxy": "http://proxy.example.test"},
		{"no_proxy": "localhost"},
		{"https_proxy": "http://proxy.example.test:8080", "proxy_auth_file": authFile},
		{"proxy_auth_allow_insecure": true},
		{"proxy_connect_by_hostname": true},
		{"proxy_ca_bundle": filepath.Join(t.TempDir(), "ca.pem")},
	} {
		if _, err := ConfigFromMap(input); err == nil {
			t.Errorf("accepted invalid proxy config %#v", input)
		}
	}
}

func TestDiscoverSocketMissing(t *testing.T) {
	t.Setenv("CAUTEM_PODMAN_SOCKET", "/tmp/definitely-missing-cautem-podman.sock")
	t.Setenv("XDG_RUNTIME_DIR", "/tmp/xdg-missing-"+t.Name())
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("CONTAINER_HOST", "")
	// Avoid HOME machine sockets by pointing HOME at empty dir
	home := t.TempDir()
	t.Setenv("HOME", home)
	_, err := DiscoverSocket()
	if err == nil {
		// podman CLI may still succeed on developer machines — accept either
		if _, lookErr := os.Stat("/tmp/definitely-missing-cautem-podman.sock"); lookErr == nil {
			t.Fatal("unexpected")
		}
	}
}
