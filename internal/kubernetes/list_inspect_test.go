package kubernetes

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic/fake"
)

func TestKubernetesListScopesSandboxesAndReturnsStableRuntimeIDs(t *testing.T) {
	client := newFakeAgentSandboxCreateDynamicClient()
	workspaceNamespace := seedWorkspaceNamespace(t, client, "gateway-a", "workspace-a")
	seedWorkspaceNamespace(t, client, "gateway-b", "workspace-b")
	seedWorkspaceNamespaceWithPhase(t, client, "gateway-a", "workspace-terminating", "Terminating")
	seedListedSandbox(t, client, workspaceNamespace, "workspace-a", "resource-a", "uid-a", "gateway-a", "demo", "registry.example/agent:v1", "Running")
	seedListedSandbox(t, client, workspaceNamespace, "workspace-a", "resource-foreign", "uid-foreign", "gateway-b", "foreign", "attacker/image", "Running")
	seedListedSandbox(t, client, workspaceNamespace, "workspace-b", "resource-wrong-workspace", "uid-wrong-workspace", "gateway-a", "wrong-workspace", "attacker/image", "Running")
	seedListedSandbox(t, client, workspaceNamespace, "workspace-a", "resource-unmanaged", "uid-unmanaged", "gateway-a", "unmanaged", "attacker/image", "Running")

	driver := newWithClient(client, "gateway-a")
	items, err := driver.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("List() returned %d items; want only the Gateway-owned sandbox: %#v", len(items), items)
	}
	got := items[0]
	if got.Name != "demo" || got.Network != workspaceNamespace || got.Image != "registry.example/agent:v1" || got.Status != "Running" {
		t.Fatalf("List() info = %#v; unexpected fields", got)
	}
	identity, err := parseSandboxRuntimeID(string(got.ID))
	if err != nil {
		t.Fatalf("parse List() runtime ID: %v", err)
	}
	if identity != (sandboxRuntimeIdentity{Namespace: workspaceNamespace, Name: "resource-a", UID: "uid-a"}) {
		t.Fatalf("runtime identity = %#v; want namespace/name/UID for the listed Sandbox", identity)
	}
	if kubernetesRuntimeID(identity) != string(got.ID) {
		t.Fatalf("runtime ID did not round trip: %q", got.ID)
	}
}

func TestKubernetesInspectByRuntimeIDRevalidatesOwnershipAndUID(t *testing.T) {
	client := newFakeAgentSandboxCreateDynamicClient()
	namespace := seedWorkspaceNamespace(t, client, "gateway-a", "workspace-a")
	seedListedSandbox(t, client, namespace, "workspace-a", "resource-a", "uid-a", "gateway-a", "demo", "agent:v1", "")
	driver := newWithClient(client, "gateway-a")
	items, err := driver.List(context.Background())
	if err != nil || len(items) != 1 {
		t.Fatalf("List() = %#v, %v; want one sandbox", items, err)
	}

	// A fresh driver instance models Gateway restart: the opaque ID contains
	// enough Kubernetes identity to resolve the resource without local state.
	restartedDriver := newWithClient(client, "gateway-a")
	got, err := restartedDriver.Inspect(context.Background(), string(items[0].ID))
	if err != nil {
		t.Fatalf("Inspect(runtime ID) error = %v", err)
	}
	if got.ID != items[0].ID || got.Name != "demo" || got.Status != "Starting" {
		t.Fatalf("Inspect(runtime ID) = %#v; want the current object and desired Starting state", got)
	}

	gvr := agentSandboxGVR(sandboxAPIVersionV1Beta1)
	if err := client.Tracker().Delete(gvr, namespace, "resource-a"); err != nil {
		t.Fatalf("delete old Sandbox: %v", err)
	}
	seedListedSandbox(t, client, namespace, "workspace-a", "resource-a", "uid-replacement", "gateway-a", "demo", "agent:v2", "Running")
	if _, err := restartedDriver.Inspect(context.Background(), string(items[0].ID)); err == nil || !strings.Contains(err.Error(), "UID changed") {
		t.Fatalf("Inspect(stale runtime ID) error = %v; want stale UID error", err)
	}
}

func TestKubernetesInspectRejectsForeignNamespaceAndAmbiguousName(t *testing.T) {
	client := newFakeAgentSandboxCreateDynamicClient()
	firstNamespace := seedWorkspaceNamespace(t, client, "gateway-a", "workspace-a")
	secondNamespace := seedWorkspaceNamespace(t, client, "gateway-a", "workspace-b")
	foreignNamespace := seedWorkspaceNamespace(t, client, "gateway-b", "workspace-c")
	seedListedSandbox(t, client, firstNamespace, "workspace-a", "demo-a", "uid-a", "gateway-a", "duplicate", "agent:v1", "Running")
	seedListedSandbox(t, client, secondNamespace, "workspace-b", "demo-b", "uid-b", "gateway-a", "duplicate", "agent:v1", "Running")
	seedListedSandbox(t, client, foreignNamespace, "workspace-c", "demo-c", "uid-c", "gateway-b", "foreign", "agent:v1", "Running")
	driver := newWithClient(client, "gateway-a")
	if _, err := driver.Inspect(context.Background(), "duplicate"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("Inspect(duplicate name) error = %v; want ambiguity error", err)
	}
	foreignID := kubernetesRuntimeID(sandboxRuntimeIdentity{Namespace: foreignNamespace, Name: "demo-c", UID: "uid-c"})
	if _, err := driver.Inspect(context.Background(), foreignID); err == nil || !strings.Contains(err.Error(), "outside this Gateway") {
		t.Fatalf("Inspect(foreign runtime ID) error = %v; want Gateway namespace rejection", err)
	}
}

func TestKubernetesListAndInspectRequireGatewayIdentity(t *testing.T) {
	driver := newWithClient(newFakeAgentSandboxCreateDynamicClient(), " ")
	if _, err := driver.List(context.Background()); err == nil || !strings.Contains(err.Error(), "Gateway ID") {
		t.Fatalf("List() without Gateway ID error = %v; want scoped identity error", err)
	}
	if _, err := driver.Inspect(context.Background(), "demo"); err == nil || !strings.Contains(err.Error(), "Gateway ID") {
		t.Fatalf("Inspect() without Gateway ID error = %v; want scoped identity error", err)
	}
}

func TestKubernetesRuntimeIDRejectsMalformedFields(t *testing.T) {
	for _, id := range []string{"k8s:", "k8s:***", kubernetesRuntimeID(sandboxRuntimeIdentity{Namespace: "bad_namespace", Name: "sandbox", UID: "uid"})} {
		if _, err := parseSandboxRuntimeID(id); err == nil {
			t.Errorf("parseSandboxRuntimeID(%q) succeeded; want validation error", id)
		}
	}
}

func TestKubernetesSandboxStatusAccountsForDesiredAndObservedState(t *testing.T) {
	tests := []struct {
		name   string
		spec   map[string]any
		status map[string]any
		want   string
	}{
		{name: "suspended while old phase is running", spec: map[string]any{"operatingMode": "Suspended"}, status: map[string]any{"phase": "Running"}, want: "Stopping"},
		{name: "suspended while ready condition is true", spec: map[string]any{"operatingMode": "Suspended"}, status: map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}, want: "Stopping"},
		{name: "suspended after workload stops", spec: map[string]any{"operatingMode": "Suspended"}, status: map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "False"}}}, want: "Stopped"},
		{name: "running and ready", spec: map[string]any{"operatingMode": "Running"}, status: map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}, want: "Running"},
		{name: "running before ready", spec: map[string]any{"operatingMode": "Running"}, want: "Starting"},
		{name: "alpha replicas stopped", spec: map[string]any{"replicas": int64(0)}, want: "Stopped"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object := &unstructured.Unstructured{Object: map[string]any{"spec": test.spec}}
			if test.status != nil {
				object.Object["status"] = test.status
			}
			if got := sandboxStatus(object); got != test.want {
				t.Fatalf("sandboxStatus() = %q; want %q", got, test.want)
			}
		})
	}
}

func seedWorkspaceNamespace(t *testing.T, client *fake.FakeDynamicClient, gatewayID, workspace string) string {
	t.Helper()
	return seedWorkspaceNamespaceWithPhase(t, client, gatewayID, workspace, "")
}

func seedWorkspaceNamespaceWithPhase(t *testing.T, client *fake.FakeDynamicClient, gatewayID, workspace, phase string) string {
	t.Helper()
	name, resource, _, err := renderWorkspaceIsolationResources(gatewayID, workspace)
	if err != nil {
		t.Fatalf("render workspace namespace: %v", err)
	}
	object := &unstructured.Unstructured{Object: resource}
	if phase != "" {
		if err := unstructured.SetNestedField(object.Object, phase, "status", "phase"); err != nil {
			t.Fatalf("set namespace phase: %v", err)
		}
	}
	if err := client.Tracker().Create(coreV1GVR("namespaces"), object, ""); err != nil {
		t.Fatalf("seed workspace namespace: %v", err)
	}
	return name
}

func seedListedSandbox(t *testing.T, client *fake.FakeDynamicClient, namespace, workspace, resourceName, uid, gatewayID, sandboxName, image, phase string) {
	t.Helper()
	labels := map[string]any{labelManagedBy: managedByValue, labelGatewayID: gatewayID, labelSandboxWorkspace: workspace, labelSandboxName: sandboxName, labelSandboxID: "sandbox-" + resourceName}
	if gatewayID == "gateway-a" && sandboxName == "unmanaged" {
		labels[labelManagedBy] = "someone-else"
	}
	resource := map[string]any{
		"apiVersion": sandboxAPIGroup + "/" + sandboxAPIVersionV1Beta1,
		"kind":       "Sandbox",
		"metadata": map[string]any{
			"name": resourceName, "namespace": namespace, "uid": uid, "labels": labels,
		},
		"spec": map[string]any{
			"operatingMode": "Running",
			"podTemplate": map[string]any{"spec": map[string]any{"containers": []any{
				map[string]any{"name": "agent", "image": image},
			}}},
		},
	}
	if phase != "" {
		resource["status"] = map[string]any{"phase": phase}
	}
	if err := client.Tracker().Create(agentSandboxGVR(sandboxAPIVersionV1Beta1), &unstructured.Unstructured{Object: resource}, namespace); err != nil {
		t.Fatalf("seed Agent Sandbox: %v", err)
	}
}
