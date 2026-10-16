package kubernetes

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/cautem/quarshell-driver/driver"
)

func TestCreateRequiresTrustedRuntimeConfiguration(t *testing.T) {
	d := New()
	_, err := d.Create(context.Background(), driver.Spec{Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "internal Gateway ID") {
		t.Fatalf("err=%v", err)
	}
}

func TestValidateSpecRejectsUnsupportedGatewayRuntimeControls(t *testing.T) {
	tests := []struct {
		name string
		spec driver.Spec
		want string
	}{
		{name: "pids limit", spec: driver.Spec{PidsLimit: 512}, want: "pids limit"},
		{name: "CDI devices", spec: driver.Spec{CDIDevices: []string{"nvidia.com/gpu=0"}}, want: "CDI device IDs"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := New().ValidateSpec(test.spec); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateSpec() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDriverCreateRunsCautemCreateSequence(t *testing.T) {
	workspace := "team-a"
	policyPath := t.TempDir() + "/policy.yaml"
	if err := os.WriteFile(policyPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatalf("write policy fixture: %v", err)
	}
	config := EngineConfig{
		GatewayID: "gateway-1", ProxyImage: "ghcr.io/cautem/cautem-proxy@sha256:" + strings.Repeat("a", 64),
		SandboxRuntimeImage: "ghcr.io/cautem/runtime@sha256:" + strings.Repeat("b", 64),
		GRPCEndpoint:        "gateway.example:7443",
	}
	config.applyDefaults()
	backend := newFakeAgentSandboxCreateBackend()
	backend.useRequestedCautemPods = true
	backend.sandboxID = "team-a-demo"
	d := newWithClient(newFakeAgentSandboxDynamicClient(), config.GatewayID)
	d.runtimeConfig = config
	d.apiVersions.version = sandboxAPIVersionV1Beta1
	d.createBackend = backend
	spec := driver.Spec{
		Name: "team-a-demo", Image: "registry.example/sandbox:v1", PolicyPath: policyPath,
		GatewayID: config.GatewayID, GatewayURL: "http://gateway.example:7443",
		Command: []string{"/bin/sh"},
		ProxyEnv: []string{
			"CAUTEM_GATEWAY_URL=http://gateway.example:7443",
			"CAUTEM_SANDBOX=team-a-demo",
			"CAUTEM_SANDBOX_TOKEN=test-sandbox-token",
		},
		Labels: map[string]string{driver.WorkspaceLabel: workspace, driver.GatewayIDLabel: config.GatewayID},
	}
	handle, err := d.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !strings.HasPrefix(string(handle.ID), kubernetesRuntimeIDPrefix) || handle.Name != spec.Name || handle.Image != spec.Image {
		t.Fatalf("Create() handle = %#v", handle)
	}
	if len(backend.createdSecrets) != 3 || backend.calls[len(backend.calls)-1] != "mark-runtime-released" {
		t.Fatalf("Create() secrets/calls = %d/%#v", len(backend.createdSecrets), backend.calls)
	}
}

func TestKubernetesEngineRegistrationUsesValidatedConfig(t *testing.T) {
	engine, err := driver.OpenEngineWithConfig("kubernetes", map[string]any{
		internalGatewayIDConfigKey: "gateway-1",
		"proxy_image":              "ghcr.io/cautem/proxy@sha256:" + strings.Repeat("a", 64),
		"sandbox_runtime_image":    "ghcr.io/cautem/runtime@sha256:" + strings.Repeat("b", 64),
		"grpc_endpoint":            "gateway.example:7443",
	})
	if err != nil {
		t.Fatalf("OpenEngineWithConfig(kubernetes) error = %v", err)
	}
	if _, ok := engine.(*Driver); !ok {
		t.Fatalf("kubernetes Engine type = %T; want *Driver", engine)
	}
	if _, err := driver.OpenEngineWithConfig("kubernetes", map[string]any{"unknown": true}); err == nil {
		t.Fatal("OpenEngineWithConfig accepted an unknown Kubernetes setting")
	}
}

func TestKubernetesImageReferenceMatcherRequiresSameDigest(t *testing.T) {
	requested := "registry.example/runtime@sha256:" + strings.Repeat("a", 64)
	if !imageReferenceMatches("docker-pullable://registry.example/runtime@sha256:"+strings.Repeat("a", 64), requested) {
		t.Fatal("image matcher rejected the same digest with Kubernetes pullable prefix")
	}
	if imageReferenceMatches("registry.example/other@sha256:"+strings.Repeat("a", 64), requested) {
		t.Fatal("image matcher accepted a different repository with the same digest")
	}
	if imageReferenceMatches("registry.example/runtime:latest", requested) {
		t.Fatal("image matcher accepted an unpinned tag for a digest reference")
	}
}
