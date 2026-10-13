package kubernetes

import (
	"fmt"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestRenderCautemProxyPodUsesSplitControlListenAndWorkloadTarget(t *testing.T) {
	params := testCautemProxyPodRenderParams()
	pod, err := renderCautemProxyPod(params)
	if err != nil {
		t.Fatalf("renderCautemProxyPod() error = %v", err)
	}
	metadata := renderMap(t, pod["metadata"], "proxy metadata")
	if metadata["name"] != "os-supervisor-sandbox-123" || metadata["namespace"] != params.Namespace {
		t.Fatalf("proxy Pod identity = %#v", metadata)
	}
	owner := renderList(t, metadata["ownerReferences"], "proxy owner references")
	if len(owner) != 1 || renderMap(t, owner[0], "proxy owner")["uid"] != params.SandboxResourceUID {
		t.Fatalf("proxy Pod owner = %#v", owner)
	}
	podSpec := renderMap(t, pod["spec"], "proxy Pod spec")
	if podSpec["automountServiceAccountToken"] != false || podSpec["hostNetwork"] != false || podSpec["hostPID"] != false || podSpec["hostIPC"] != false {
		t.Fatalf("proxy Pod isolation fields = %#v", podSpec)
	}
	container := renderMap(t, renderList(t, podSpec["containers"], "proxy containers")[0], "proxy container")
	if container["image"] != params.ProxyImage {
		t.Fatalf("proxy image = %v; want pinned image", container["image"])
	}
	command := renderList(t, container["command"], "proxy command")
	if len(command) == 0 || command[1] != "proxy" {
		t.Fatalf("proxy command = %#v", command)
	}
	security := renderMap(t, container["securityContext"], "proxy security context")
	if security["runAsUser"] != params.ControlUID || security["runAsNonRoot"] != true || security["readOnlyRootFilesystem"] != true || security["allowPrivilegeEscalation"] != false {
		t.Fatalf("proxy security context = %#v", security)
	}
	if hasEnv(container, "CAUTEM_SANDBOX_TOKEN") || !hasEnv(container, "CAUTEM_SANDBOX_TOKEN_FILE") {
		t.Fatalf("proxy token must be read from a Secret file: %#v", container["env"])
	}
	if !hasEnv(container, "CAUTEM_SUPERVISOR_CONTROL_LISTEN") || hasEnv(container, "CAUTEM_SUPERVISOR_CONTROL_ENDPOINT") {
		t.Fatalf("proxy must use a local listen address distinct from workload client endpoint: %#v", container["env"])
	}
	if got := renderEnvValue(t, container, "CAUTEM_RELAY_TARGET_ENDPOINT"); got != fmt.Sprintf("%s:%d", runtimeServiceFQDN("os-boundary-"+params.SandboxID, params.Namespace), params.BoundaryPort) {
		t.Fatalf("relay target endpoint = %q", got)
	}
	for _, key := range []string{"CAUTEM_GUEST_TLS_CA", "CAUTEM_GUEST_TLS_CERT", "CAUTEM_GUEST_TLS_KEY"} {
		if !hasEnv(container, key) {
			t.Fatalf("HTTPS proxy is missing guest TLS path %s", key)
		}
	}
	envFrom := renderList(t, container["envFrom"], "proxy envFrom")
	secretRef := renderMap(t, renderMap(t, envFrom[0], "proxy envFrom item")["secretRef"], "proxy env Secret ref")
	if secretRef["name"] != generationSecretName(proxyEnvSecretPrefix, params.SandboxID, params.Generation) {
		t.Fatalf("proxy credentials Secret = %#v", secretRef)
	}
	volumes := renderList(t, podSpec["volumes"], "proxy volumes")
	runtime := findRenderMap(t, volumes, "runtime")
	secret := renderMap(t, runtime["secret"], "proxy runtime Secret volume")
	if secret["secretName"] != generationSecretName("os-supervisor", params.SandboxID, params.Generation) {
		t.Fatalf("proxy runtime Secret = %#v", secret)
	}
}

func TestCautemProxyPodIdentityVerifiesAdmittedContainerAndSecretReferences(t *testing.T) {
	proxyParams := testCautemProxyPodRenderParams()
	pod, err := renderCautemProxyPod(proxyParams)
	if err != nil {
		t.Fatalf("renderCautemProxyPod() error = %v", err)
	}
	metadata := renderMap(t, pod["metadata"], "proxy metadata")
	metadata["uid"] = "proxy-pod-uid"
	identity := supervisorIdentityFromPod(&unstructured.Unstructured{Object: pod}, pod)
	runtimeParams := testAgentSandboxRuntimeRenderParams()
	runtimeParams.CautemProxyImage = proxyParams.ProxyImage
	runtimeParams.CautemGatewayURL = proxyParams.GatewayURL
	runtimeParams.CautemGatewayGRPCEndpoint = proxyParams.GatewayGRPCEndpoint
	runtimeParams.CautemGatewayTLS = proxyParams.GatewayTLS
	if err := validateAgentSandboxSupervisorIdentity(identity, runtimeParams, proxyParams.SandboxResourceUID); err != nil {
		t.Fatalf("validateAgentSandboxSupervisorIdentity() error = %v", err)
	}

	containers := renderList(t, renderMap(t, pod["spec"], "proxy spec")["containers"], "proxy containers")
	container := renderMap(t, containers[0], "proxy container")
	container["env"] = append(renderList(t, container["env"], "proxy env"), map[string]any{"name": "CAUTEM_SANDBOX_TOKEN", "value": "raw-token"})
	metadata["uid"] = "proxy-pod-uid-2"
	identity = supervisorIdentityFromPod(&unstructured.Unstructured{Object: pod}, pod)
	if err := validateAgentSandboxSupervisorIdentity(identity, runtimeParams, proxyParams.SandboxResourceUID); err == nil {
		t.Fatal("proxy Pod with raw bearer token env passed identity validation")
	}
}

func TestRenderCautemProxyPodRejectsMutableImagesAndInvalidEndpoints(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*cautemProxyPodRenderParams)
	}{
		{name: "mutable image", mutate: func(params *cautemProxyPodRenderParams) { params.ProxyImage = "ghcr.io/cautem/cautem-proxy:latest" }},
		{name: "malformed image digest", mutate: func(params *cautemProxyPodRenderParams) {
			params.ProxyImage = "ghcr.io/cautem/cautem-proxy@sha256:latest"
		}},
		{name: "invalid gateway url", mutate: func(params *cautemProxyPodRenderParams) { params.GatewayURL = "https://user:secret@gateway.example" }},
		{name: "invalid grpc endpoint", mutate: func(params *cautemProxyPodRenderParams) { params.GatewayGRPCEndpoint = "https://gateway.example:7443" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			params := testCautemProxyPodRenderParams()
			test.mutate(&params)
			if _, err := renderCautemProxyPod(params); err == nil {
				t.Fatal("renderCautemProxyPod() succeeded; want validation error")
			}
		})
	}
}

func testCautemProxyPodRenderParams() cautemProxyPodRenderParams {
	namespace, _ := workspaceNamespaceName("gateway-1", "team-a")
	return cautemProxyPodRenderParams{
		Namespace: namespace, SandboxResourceName: "team-a-demo",
		SandboxResourceAPIVersion: sandboxAPIGroup + "/" + sandboxAPIVersionV1Beta1,
		SandboxResourceUID:        "cr-uid-123", SandboxID: "sandbox-123", SandboxName: "demo", Generation: "gen7",
		ProxyImage:         "ghcr.io/cautem/cautem-proxy@sha256:" + strings.Repeat("a", 64),
		ServiceAccountName: "sandbox-driver", ImagePullSecrets: []string{"registry-auth"},
		GatewayURL: "https://gateway.example:443", GatewayGRPCEndpoint: "gateway.example:7443", GatewayTLS: true,
		BoundaryPort: 5500, ControlUID: 10001, ControlGID: 10001,
	}
}

func renderEnvValue(t *testing.T, container map[string]any, key string) string {
	t.Helper()
	for _, raw := range renderList(t, container["env"], "container env") {
		entry := renderMap(t, raw, "env entry")
		if entry["name"] == key {
			value, _ := entry["value"].(string)
			return value
		}
	}
	t.Fatalf("environment key %q not found", key)
	return ""
}
