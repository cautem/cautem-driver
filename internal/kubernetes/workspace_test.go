package kubernetes

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8stesting "k8s.io/client-go/testing"
)

func TestWorkspaceNamespaceIsStableOpaqueAndGatewayScoped(t *testing.T) {
	first, err := workspaceNamespaceName("gateway-a", "private-team-name")
	if err != nil {
		t.Fatal(err)
	}
	if len(first) > 63 || strings.Contains(first, "private-team-name") {
		t.Fatalf("namespace %q leaks workspace identity or exceeds DNS length", first)
	}
	repeated, err := workspaceNamespaceName("gateway-a", "private-team-name")
	if err != nil || repeated != first {
		t.Fatalf("stable namespace = %q, %v; want %q", repeated, err, first)
	}
	otherGateway, err := workspaceNamespaceName("gateway-b", "private-team-name")
	if err != nil || otherGateway == first {
		t.Fatalf("different gateway namespace = %q, %v; want distinct from %q", otherGateway, err, first)
	}
	otherWorkspace, err := workspaceNamespaceName("gateway-a", "another-team")
	if err != nil || otherWorkspace == first {
		t.Fatalf("different workspace namespace = %q, %v; want distinct from %q", otherWorkspace, err, first)
	}
}

func TestWorkspaceNamespaceRejectsSurroundingWhitespace(t *testing.T) {
	if _, err := workspaceNamespaceName("gateway-a", " workspace-a"); err == nil {
		t.Fatal("workspace identity with surrounding whitespace was accepted")
	}
}

func TestEnsureWorkspaceIsolationCreatesNamespaceAndDefaultDeny(t *testing.T) {
	fake := newFakeAgentSandboxCreateDynamicClient()
	backend := newDynamicAgentSandboxCreateBackend(fake)
	name, namespace, denyAll, err := renderWorkspaceIsolationResources("gateway-a", "workspace-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.EnsureWorkspaceIsolation(context.Background(), name, "gateway-a", "workspace-a", namespace, denyAll); err != nil {
		t.Fatalf("EnsureWorkspaceIsolation() error = %v", err)
	}
	observedNamespace, err := fake.Resource(coreV1GVR("namespaces")).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("read workspace Namespace: %v", err)
	}
	if !workspaceNamespaceMatches(observedNamespace.Object, namespace) {
		t.Fatalf("workspace Namespace does not match expected identity: %#v", observedNamespace.Object)
	}
	observedPolicy, err := fake.Resource(networkPolicyV1GVR).Namespace(name).Get(context.Background(), workspaceIsolationPolicy, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("read default-deny NetworkPolicy: %v", err)
	}
	if err := validateNetworkPolicyMatches(observedPolicy, denyAll); err != nil {
		t.Fatalf("workspace default-deny NetworkPolicy mismatch: %v", err)
	}
}

func TestEnsureWorkspaceIsolationRejectsForeignNamespaceAndForgedManifest(t *testing.T) {
	name, namespace, denyAll, err := renderWorkspaceIsolationResources("gateway-a", "workspace-a")
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeAgentSandboxCreateDynamicClient()
	foreign := (&unstructured.Unstructured{Object: namespace}).DeepCopy()
	foreignLabels := foreign.GetLabels()
	foreignLabels[workspaceGatewayHashLabel] = "foreign-gateway"
	foreign.SetLabels(foreignLabels)
	if err := fake.Tracker().Create(coreV1GVR("namespaces"), foreign, ""); err != nil {
		t.Fatalf("seed foreign namespace: %v", err)
	}
	backend := newDynamicAgentSandboxCreateBackend(fake)
	if err := backend.EnsureWorkspaceIsolation(context.Background(), name, "gateway-a", "workspace-a", namespace, denyAll); err == nil || !strings.Contains(err.Error(), "different gateway/workspace identity") {
		t.Fatalf("foreign namespace error = %v; want identity mismatch", err)
	}
	forged := (&unstructured.Unstructured{Object: namespace}).DeepCopy()
	forged.SetName("cautem-ws-forged")
	if err := backend.EnsureWorkspaceIsolation(context.Background(), name, "gateway-a", "workspace-a", forged.Object, denyAll); err == nil {
		t.Fatal("forged Namespace manifest was accepted")
	}
}

func TestListWorkspaceNamespacesScopesToGatewayAndSkipsTerminating(t *testing.T) {
	fake := newFakeAgentSandboxCreateDynamicClient()
	for _, identity := range []struct{ gateway, workspace string }{
		{"gateway-a", "workspace-a"},
		{"gateway-a", "workspace-b"},
		{"gateway-b", "workspace-c"},
	} {
		name, resource, _, err := renderWorkspaceIsolationResources(identity.gateway, identity.workspace)
		if err != nil {
			t.Fatal(err)
		}
		object := &unstructured.Unstructured{Object: resource}
		object.SetName(name)
		if err := fake.Tracker().Create(coreV1GVR("namespaces"), object, ""); err != nil {
			t.Fatalf("seed namespace %s: %v", name, err)
		}
	}
	terminatingName, terminatingResource, _, err := renderWorkspaceIsolationResources("gateway-a", "workspace-terminating")
	if err != nil {
		t.Fatal(err)
	}
	terminating := &unstructured.Unstructured{Object: terminatingResource}
	terminating.SetName(terminatingName)
	if err := unstructured.SetNestedField(terminating.Object, "Terminating", "status", "phase"); err != nil {
		t.Fatal(err)
	}
	if err := fake.Tracker().Create(coreV1GVR("namespaces"), terminating, ""); err != nil {
		t.Fatalf("seed terminating namespace: %v", err)
	}
	for _, malformedHash := range []string{"", "not-a-workspace-hash"} {
		name, resource, _, err := renderWorkspaceIsolationResources("gateway-a", "workspace-malformed-"+strings.ReplaceAll(malformedHash, "-", "x"))
		if err != nil {
			t.Fatal(err)
		}
		malformed := &unstructured.Unstructured{Object: resource}
		malformed.SetName(name)
		labels := malformed.GetLabels()
		if malformedHash == "" {
			delete(labels, workspaceIdentityHashLabel)
		} else {
			labels[workspaceIdentityHashLabel] = malformedHash
		}
		malformed.SetLabels(labels)
		if err := fake.Tracker().Create(coreV1GVR("namespaces"), malformed, ""); err != nil {
			t.Fatalf("seed namespace with malformed workspace identity hash: %v", err)
		}
	}

	namespaces, err := newDynamicAgentSandboxCreateBackend(fake).ListWorkspaceNamespaces(context.Background(), "gateway-a")
	if err != nil {
		t.Fatalf("ListWorkspaceNamespaces() error = %v", err)
	}
	want := []string{}
	for _, workspace := range []string{"workspace-a", "workspace-b"} {
		name, err := workspaceNamespaceName("gateway-a", workspace)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, name)
	}
	sort.Strings(want)
	if !reflect.DeepEqual(namespaces, want) {
		t.Fatalf("workspace namespaces = %#v; want %#v", namespaces, want)
	}

	actions := fake.Actions()
	if len(actions) == 0 {
		t.Fatal("expected a Kubernetes namespace list request")
	}
	listAction, ok := actions[len(actions)-1].(k8stesting.ListAction)
	if !ok || listAction.GetResource().Resource != "namespaces" || listAction.GetNamespace() != "" {
		t.Fatalf("last action = %#v; want cluster-scoped namespace list", actions[len(actions)-1])
	}
	selector, err := workspaceNamespaceSelector("gateway-a")
	if err != nil {
		t.Fatal(err)
	}
	if got := listAction.GetListRestrictions().Labels.String(); got != selector {
		t.Fatalf("namespace selector = %q; want %q", got, selector)
	}
}

func TestWorkspaceNamespaceSelectorRejectsInvalidGatewayID(t *testing.T) {
	for _, gatewayID := range []string{"", " gateway-a", "gateway-a "} {
		if selector, err := workspaceNamespaceSelector(gatewayID); err == nil || selector != "" {
			t.Errorf("workspaceNamespaceSelector(%q) = (%q, %v); want error", gatewayID, selector, err)
		}
	}
}
