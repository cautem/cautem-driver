//go:build darwin || linux

package vm

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cautem/cautem-driver/driver"
)

func TestValidateSupportedSpecRejectsUnimplementedCapabilities(t *testing.T) {
	tests := []struct {
		name  string
		field string
		set   func(*driver.Spec)
	}{
		{"workspace", "workspace", func(spec *driver.Spec) { spec.Workspace = "/workspace" }},
		{"gateway identity", "gateway_id", func(spec *driver.Spec) { spec.GatewayID = "gateway" }},
		{"mount override", "i_know", func(spec *driver.Spec) { spec.IKnow = true }},
		{"hardening override", "no_harden", func(spec *driver.Spec) { spec.NoHarden = true }},
		{"display mode", "display_mode", func(spec *driver.Spec) { spec.DisplayMode = "novnc" }},
		{"display port", "display_port", func(spec *driver.Spec) { spec.DisplayPort = 5900 }},
		{"display password", "display_password", func(spec *driver.Spec) { spec.DisplayPassword = "secret" }},
		{"labels", "labels", func(spec *driver.Spec) { spec.Labels = map[string]string{"team": "test"} }},
		{"extra hosts", "extra_hosts", func(spec *driver.Spec) { spec.ExtraHosts = []string{"host:127.0.0.1"} }},
		{"gateway URL", "gateway_url", func(spec *driver.Spec) { spec.GatewayURL = "https://gateway" }},
		{"persistent volume", "persist_volume", func(spec *driver.Spec) { spec.PersistVolume = true }},
		{"GPU", "gpu", func(spec *driver.Spec) { spec.GPU = true }},
		{"GPU count", "gpu", func(spec *driver.Spec) { spec.GPUCount = 1 }},
		{"CDI devices", "gpu", func(spec *driver.Spec) { spec.CDIDevices = []string{"nvidia.com/gpu=0"} }},
		{"PID limit", "pids_limit", func(spec *driver.Spec) { spec.PidsLimit = 128 }},
		{"proxy image", "proxy_image", func(spec *driver.Spec) { spec.ProxyImage = "proxy:latest" }},
		{"published ports", "publish_ports", func(spec *driver.Spec) { spec.PublishPorts = []driver.PortPublish{{Host: 8080, Guest: 80}} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := driver.Spec{Name: "sandbox", Image: "fixture:latest"}
			tt.set(&spec)
			err := validateSupportedSpec(spec)
			if err == nil || !strings.Contains(err.Error(), "unsupported spec fields: "+tt.field) {
				t.Fatalf("validateSupportedSpec() error = %v, want unsupported field %q", err, tt.field)
			}
		})
	}
}

func TestValidateResourceLimitsRejectsValuesThatWouldBeChanged(t *testing.T) {
	tests := []struct {
		name      string
		cpu       float64
		memory    int64
		wantError string
	}{
		{name: "negative cpu", cpu: -0.5, wantError: "CPU limit must be finite and non-negative"},
		{name: "nan cpu", cpu: math.NaN(), wantError: "CPU limit must be finite and non-negative"},
		{name: "infinite cpu", cpu: math.Inf(1), wantError: "CPU limit must be finite and non-negative"},
		{name: "cpu rounds above uint8", cpu: 255.01, wantError: "exceeds libkrun maximum"},
		{name: "negative memory", memory: -1, wantError: "memory limit must be non-negative"},
		{name: "memory exceeds uint32 mebibytes", memory: int64(^uint32(0))*(1<<20) + 1, wantError: "memory limit exceeds libkrun maximum"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateResourceLimits(tt.cpu, tt.memory)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("validateResourceLimits(%v, %d) error = %v, want %q", tt.cpu, tt.memory, err, tt.wantError)
			}
		})
	}
}

func TestValidateResourceLimitsAllowsDefaultsAndRepresentableValues(t *testing.T) {
	for _, tt := range []struct {
		cpu    float64
		memory int64
	}{{0, 0}, {0.1, 1}, {255, int64(^uint32(0)) * (1 << 20)}} {
		if err := validateResourceLimits(tt.cpu, tt.memory); err != nil {
			t.Errorf("validateResourceLimits(%v, %d) error = %v", tt.cpu, tt.memory, err)
		}
	}
}

func TestValidateSupportedSpecAllowsImplementedFields(t *testing.T) {
	spec := driver.Spec{
		Name: "sandbox", Image: "fixture:latest", Command: []string{"/bin/sh"},
		Env: []string{"LANG=C"}, CPU: 2, MemoryBytes: 1 << 30,
		DriverConfigJSON: `{"rootfs_tar_path":"/var/lib/cautem/rootfs.tar"}`,
		ProxyBin:         "/usr/bin/cautem", PolicyPath: "/var/lib/cautem/policy.yaml", ProxyPort: 3128,
		InitBin: "/usr/bin/cautem-init", SupervisorBin: "/usr/bin/cautem-supervisor",
		EnableSSH: true, SSHBin: "/usr/bin/cautem-sshd",
	}
	if err := validateSupportedSpec(spec); err != nil {
		t.Fatalf("validateSupportedSpec() error = %v", err)
	}
}

func TestValidateSupportedSpecAllowsPolicyBrokerFields(t *testing.T) {
	spec := driver.Spec{
		Name: "sandbox", ProxyBin: "/usr/bin/cautem", PolicyPath: "/var/lib/cautem/policy.yaml",
		ProxyEnv: []string{"CAUTEM_SANDBOX_TOKEN=secret"}, ProxyPort: 3128,
	}
	if err := validateSupportedSpec(spec); err != nil {
		t.Fatalf("validateSupportedSpec() rejected policy broker fields: %v", err)
	}
}

func TestValidateNetworkBrokerSpecRequiresPairedConfigAndSafeEnvironment(t *testing.T) {
	for _, spec := range []driver.Spec{
		{ProxyBin: "/usr/bin/cautem"},
		{PolicyPath: "/var/lib/cautem/policy.yaml"},
		{ProxyEnv: []string{"TOKEN=secret"}},
		{ProxyPort: 3128},
	} {
		if err := validateNetworkBrokerSpec(spec); err == nil || !strings.Contains(err.Error(), "requires both proxy_bin and policy_path") {
			t.Errorf("validateNetworkBrokerSpec(%+v) error = %v", spec, err)
		}
	}
	if err := validateNetworkBrokerEnvironment([]string{"LD_PRELOAD=/tmp/evil.so"}); err == nil || !strings.Contains(err.Error(), "dynamic loader") {
		t.Fatalf("unsafe broker environment error = %v", err)
	}
	if err := validateNetworkBrokerEnvironment([]string{"TOKEN=one", "TOKEN=two"}); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("duplicate broker environment error = %v", err)
	}
}

func TestValidateNetworkBrokerSpecAcceptsPrivatePolicyAndExecutable(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "cautem")
	if err := os.WriteFile(binary, []byte("proxy executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := driver.Spec{ProxyBin: binary, PolicyPath: policy, ProxyEnv: []string{"TOKEN=secret"}}
	if err := validateNetworkBrokerSpec(spec); err != nil {
		t.Fatalf("validateNetworkBrokerSpec() error = %v", err)
	}
	spec.ProxyPort = 65536
	if err := validateNetworkBrokerSpec(spec); err == nil || !strings.Contains(err.Error(), "between 1 and 65535") {
		t.Fatalf("invalid proxy port error = %v", err)
	}
}

func TestValidateGuestRuntimeAssetsRequiresCompleteSupervisorAndSSHContracts(t *testing.T) {
	dir := t.TempDir()
	makeExecutable := func(name string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("binary"), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	proxy := makeExecutable("cautem")
	init := makeExecutable("cautem-init")
	supervisor := makeExecutable("cautem-supervisor")
	sshd := makeExecutable("cautem-sshd")
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := driver.Spec{ProxyBin: proxy, PolicyPath: policy, InitBin: init}
	if err := validateGuestRuntimeAssets(base); err == nil || !strings.Contains(err.Error(), "requires supervisor_bin or SSH relay") {
		t.Fatalf("unused init asset error = %v", err)
	}
	base.SupervisorBin = supervisor
	if err := validateGuestRuntimeAssets(base); err != nil {
		t.Fatalf("complete supervisor assets rejected: %v", err)
	}
	base.EnableSSH = true
	if err := validateGuestRuntimeAssets(base); err == nil || !strings.Contains(err.Error(), "both ssh=true and ssh_bin") {
		t.Fatalf("incomplete SSH config error = %v", err)
	}
	base.SSHBin = sshd
	if err := validateGuestRuntimeAssets(base); err != nil {
		t.Fatalf("complete SSH assets rejected: %v", err)
	}
	base.Name = "sandbox"
	base.Command = []string{"/bin/sh", "-c", "sleep infinity"}
	base.DriverConfigJSON = `{"rootfs_tar_path":"/var/lib/cautem/rootfs.tar"}`
	base.MainProcessRestartPolicy = "on-failure"
	if err := New().ValidateSpec(base); err != nil {
		t.Fatalf("complete supervisor/SSH VM spec with restart policy rejected: %v", err)
	}
	base.SupervisorBin = ""
	if err := New().ValidateSpec(base); err == nil || !strings.Contains(err.Error(), "restart policy requires supervisor_bin") {
		t.Fatalf("restart policy without supervisor error = %v", err)
	}
	base.MainProcessRestartPolicy = "sometimes"
	if err := New().ValidateSpec(base); err == nil || !strings.Contains(err.Error(), "must be never, on-failure, or always") {
		t.Fatalf("invalid restart policy error = %v", err)
	}
}

func TestValidateGatewayRuntimeListsMissingIntegrations(t *testing.T) {
	err := New().ValidateGatewayRuntime()
	for _, capability := range []string{"workspace mounts"} {
		if err == nil || !strings.Contains(err.Error(), capability) {
			t.Fatalf("ValidateGatewayRuntime() error = %v, want %q", err, capability)
		}
	}
}

func TestValidateSpecAcceptsOCIReferencesWithoutRootfsUpload(t *testing.T) {
	d := New()
	spec := driver.Spec{Name: "registry-image", Image: "registry.example/team/sandbox:stable"}
	if err := d.ValidateSpec(spec); err != nil {
		t.Fatalf("ValidateSpec() rejected registry image: %v", err)
	}
	spec.Image = "https://registry.example/team/sandbox:stable"
	if err := d.ValidateSpec(spec); err == nil || !strings.Contains(err.Error(), "invalid OCI image reference") {
		t.Fatalf("ValidateSpec() invalid image reference error = %v", err)
	}
}
