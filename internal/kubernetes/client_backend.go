package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const (
	annotationRuntimeBootstrapping    = "openshell.ai/sandbox-runtime-bootstrapping"
	annotationRuntimeBootstrapPhase   = "openshell.ai/sandbox-runtime-bootstrap-phase"
	annotationRuntimeWorkloadUID      = "openshell.ai/sandbox-runtime-workload-uid"
	annotationRuntimeSupervisorUID    = "openshell.ai/sandbox-runtime-supervisor-uid"
	annotationRuntimeNetworkPolicyUID = "openshell.ai/sandbox-runtime-network-policy-uid"
	annotationRuntimeNetworkPolicyGen = "openshell.ai/sandbox-runtime-network-policy-generation"
)

var (
	coreV1GVR = func(resource string) schema.GroupVersionResource {
		return schema.GroupVersionResource{Version: "v1", Resource: resource}
	}
	networkPolicyV1GVR = schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
)

// dynamicAgentSandboxCreateBackend uses Kubernetes' normal client-go dynamic
// API for CRs and built-in resources. It does not add a gateway REST surface.
type dynamicAgentSandboxCreateBackend struct {
	client dynamic.Interface
}

func newDynamicAgentSandboxCreateBackend(client dynamic.Interface) *dynamicAgentSandboxCreateBackend {
	return &dynamicAgentSandboxCreateBackend{client: client}
}

func (backend *dynamicAgentSandboxCreateBackend) EnsureWorkspaceIsolation(
	ctx context.Context,
	namespace, gatewayID, workspace string,
	namespaceResource, denyAllPolicy map[string]any,
) error {
	wantNamespace, wantNamespaceResource, wantDenyAllPolicy, err := renderWorkspaceIsolationResources(gatewayID, workspace)
	if err != nil {
		return err
	}
	if namespace != wantNamespace || !reflect.DeepEqual(namespaceResource, wantNamespaceResource) || !reflect.DeepEqual(denyAllPolicy, wantDenyAllPolicy) {
		return fmt.Errorf("workspace isolation resources do not match their trusted gateway/workspace identity")
	}
	if err := backend.ensureWorkspaceNamespace(ctx, namespaceResource); err != nil {
		return err
	}
	if _, err := backend.ensureNetworkPolicy(ctx, namespace, denyAllPolicy); err != nil {
		return fmt.Errorf("ensure workspace default-deny NetworkPolicy: %w", err)
	}
	return nil
}

// ListWorkspaceNamespaces returns only non-terminating namespaces owned by
// this Gateway installation. It is the discovery boundary used by driver
// recovery; the raw Gateway ID is never sent to Kubernetes as a label.
func (backend *dynamicAgentSandboxCreateBackend) ListWorkspaceNamespaces(ctx context.Context, gatewayID string) ([]string, error) {
	if backend == nil || backend.client == nil {
		return nil, fmt.Errorf("kubernetes dynamic client is nil")
	}
	selector, err := workspaceNamespaceSelector(gatewayID)
	if err != nil {
		return nil, err
	}
	namespaces, err := backend.client.Resource(coreV1GVR("namespaces")).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, fmt.Errorf("list workspace namespaces for this Gateway: %w", err)
	}
	wantGatewayHash, _ := workspaceGatewayHash(gatewayID)
	result := make([]string, 0, len(namespaces.Items))
	for i := range namespaces.Items {
		namespace := &namespaces.Items[i]
		labels := namespace.GetLabels()
		if labels[workspaceManagedByLabel] != "cautem" || labels[workspaceGatewayHashLabel] != wantGatewayHash || !validWorkspaceIdentityHash(labels[workspaceIdentityHashLabel]) {
			continue
		}
		phase, _, _ := unstructured.NestedString(namespace.Object, "status", "phase")
		if phase == "Terminating" {
			continue
		}
		name := namespace.GetName()
		if name == "" {
			continue
		}
		if err := requireDNS1123Label("workspace Namespace", name); err != nil {
			return nil, err
		}
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

func (backend *dynamicAgentSandboxCreateBackend) ensureWorkspaceNamespace(ctx context.Context, expected map[string]any) error {
	if backend == nil || backend.client == nil {
		return fmt.Errorf("kubernetes dynamic client is nil")
	}
	if expected["apiVersion"] != "v1" || expected["kind"] != "Namespace" {
		return fmt.Errorf("invalid rendered workspace Namespace")
	}
	name, _, _ := unstructured.NestedString(expected, "metadata", "name")
	if name == "" {
		return fmt.Errorf("rendered workspace Namespace has no name")
	}
	resource := backend.client.Resource(coreV1GVR("namespaces"))
	actual, err := resource.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		created, createErr := resource.Create(ctx, &unstructured.Unstructured{Object: expected}, metav1.CreateOptions{})
		if createErr != nil {
			observed, getErr := resource.Get(ctx, name, metav1.GetOptions{})
			if getErr != nil {
				return errors.Join(fmt.Errorf("create workspace Namespace %s: %w", name, createErr), getErr)
			}
			actual = observed
		} else {
			actual = created
		}
	} else if err != nil {
		return fmt.Errorf("get workspace Namespace %s: %w", name, err)
	}
	if actual == nil {
		return fmt.Errorf("kubernetes API returned an empty workspace Namespace %s", name)
	}
	if !workspaceNamespaceMatches(actual.Object, expected) {
		return fmt.Errorf("workspace Namespace %s exists with a different gateway/workspace identity or is terminating", name)
	}
	return nil
}

func workspaceNamespaceMatches(actual, expected map[string]any) bool {
	actualName, _, _ := unstructured.NestedString(actual, "metadata", "name")
	expectedName, _, _ := unstructured.NestedString(expected, "metadata", "name")
	actualPhase, _, _ := unstructured.NestedString(actual, "status", "phase")
	actualLabels, _, _ := unstructured.NestedStringMap(actual, "metadata", "labels")
	expectedLabels, _, _ := unstructured.NestedStringMap(expected, "metadata", "labels")
	if actualName != expectedName || actualPhase == "Terminating" {
		return false
	}
	for key, value := range expectedLabels {
		if actualLabels[key] != value {
			return false
		}
	}
	return true
}

func (backend *dynamicAgentSandboxCreateBackend) ApplyAndObserveRuntimeFence(
	ctx context.Context,
	namespace string,
	workloadPolicy, supervisorPolicy map[string]any,
) (agentSandboxFenceEvidence, error) {
	workload, err := backend.ensureNetworkPolicy(ctx, namespace, workloadPolicy)
	if err != nil {
		return agentSandboxFenceEvidence{}, fmt.Errorf("ensure workload NetworkPolicy fence: %w", err)
	}
	if _, err := backend.ensureNetworkPolicy(ctx, namespace, supervisorPolicy); err != nil {
		return agentSandboxFenceEvidence{}, fmt.Errorf("ensure supervisor NetworkPolicy: %w", err)
	}
	uid := workload.GetUID()
	resourceVersion := workload.GetResourceVersion()
	generation, _, _ := unstructured.NestedInt64(workload.Object, "metadata", "generation")
	if uid == "" || resourceVersion == "" || generation < 1 {
		return agentSandboxFenceEvidence{}, fmt.Errorf("observed workload NetworkPolicy is missing UID, generation, or resourceVersion")
	}
	return agentSandboxFenceEvidence{PolicyUID: string(uid), Generation: generation, ResourceVersion: resourceVersion}, nil
}

func (backend *dynamicAgentSandboxCreateBackend) ensureNetworkPolicy(ctx context.Context, namespace string, expected map[string]any) (*unstructured.Unstructured, error) {
	if expected["kind"] != "NetworkPolicy" || expected["apiVersion"] != "networking.k8s.io/v1" {
		return nil, fmt.Errorf("invalid rendered NetworkPolicy")
	}
	name, _, _ := unstructured.NestedString(expected, "metadata", "name")
	if name == "" {
		return nil, fmt.Errorf("rendered NetworkPolicy has no name")
	}
	resource, err := backend.namespacedResource(networkPolicyV1GVR, namespace)
	if err != nil {
		return nil, err
	}
	actual, err := resource.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, createErr := resource.Create(ctx, &unstructured.Unstructured{Object: expected}, metav1.CreateOptions{})
		if createErr != nil && !apierrors.IsAlreadyExists(createErr) {
			// A timed-out Create can still have reached the apiserver. Read the
			// stable name and accept it only if its complete policy matches.
			observed, getErr := resource.Get(ctx, name, metav1.GetOptions{})
			if getErr != nil {
				return nil, errors.Join(createErr, getErr)
			}
			actual = observed
		} else {
			actual, err = resource.Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return nil, fmt.Errorf("read back NetworkPolicy %s: %w", name, err)
			}
		}
	} else if err != nil {
		return nil, fmt.Errorf("get NetworkPolicy %s: %w", name, err)
	}
	if err := validateNetworkPolicyMatches(actual, expected); err != nil {
		return nil, fmt.Errorf("network policy %s exists but does not match the required fence: %w", name, err)
	}
	return actual, nil
}

func validateNetworkPolicyMatches(actual *unstructured.Unstructured, expected map[string]any) error {
	if actual == nil {
		return fmt.Errorf("observed object is nil")
	}
	actualSpec, _, _ := unstructured.NestedMap(actual.Object, "spec")
	expectedSpec, _, _ := unstructured.NestedMap(expected, "spec")
	if !reflect.DeepEqual(normalizeEmptyPolicyRules(actualSpec), normalizeEmptyPolicyRules(expectedSpec)) {
		return fmt.Errorf("policy spec mismatch")
	}
	actualLabels := actual.GetLabels()
	expectedLabels, _, _ := unstructured.NestedStringMap(expected, "metadata", "labels")
	for key, value := range expectedLabels {
		if actualLabels[key] != value {
			return fmt.Errorf("required ownership label %q is missing or changed", key)
		}
	}
	return nil
}

func normalizeEmptyPolicyRules(spec map[string]any) map[string]any {
	copy := make(map[string]any, len(spec))
	for key, value := range spec {
		if rules, ok := value.([]any); ok && len(rules) == 0 && (key == "ingress" || key == "egress") {
			continue
		}
		copy[key] = value
	}
	return copy
}

func (backend *dynamicAgentSandboxCreateBackend) createOrObserveNamespaced(ctx context.Context, gvr schema.GroupVersionResource, expected map[string]any) (*unstructured.Unstructured, error) {
	if backend == nil || backend.client == nil {
		return nil, fmt.Errorf("kubernetes dynamic client is nil")
	}
	name, _, _ := unstructured.NestedString(expected, "metadata", "name")
	namespace, _, _ := unstructured.NestedString(expected, "metadata", "namespace")
	resource, err := backend.namespacedResource(gvr, namespace)
	if err != nil {
		return nil, err
	}
	created, createErr := resource.Create(ctx, &unstructured.Unstructured{Object: expected}, metav1.CreateOptions{})
	if createErr != nil {
		observed, getErr := resource.Get(ctx, name, metav1.GetOptions{})
		if getErr != nil {
			return nil, errors.Join(createErr, getErr)
		}
		if !sameOwnedGenerationResource(observed.Object, expected) {
			return nil, createErr
		}
		return observed, nil
	}
	if created == nil {
		return nil, fmt.Errorf("kubernetes API returned an empty create response for %s %s", gvr.Resource, name)
	}
	if !sameOwnedGenerationResource(created.Object, expected) {
		return nil, fmt.Errorf("created %s %s does not match its requested owner and security contract", gvr.Resource, name)
	}
	return created, nil
}

func sameOwnedGenerationResource(actual, expected map[string]any) bool {
	actualName, _, _ := unstructured.NestedString(actual, "metadata", "name")
	actualNamespace, _, _ := unstructured.NestedString(actual, "metadata", "namespace")
	expectedName, _, _ := unstructured.NestedString(expected, "metadata", "name")
	expectedNamespace, _, _ := unstructured.NestedString(expected, "metadata", "namespace")
	actualOwner, _ := firstOwnerReference(actual)
	expectedOwner, _ := firstOwnerReference(expected)
	if actualName != expectedName || actualNamespace != expectedNamespace || actualOwner == nil || expectedOwner == nil ||
		actualOwner["kind"] != expectedOwner["kind"] || actualOwner["apiVersion"] != expectedOwner["apiVersion"] ||
		actualOwner["name"] != expectedOwner["name"] || actualOwner["uid"] == "" || actualOwner["uid"] != expectedOwner["uid"] ||
		actualOwner["blockOwnerDeletion"] != expectedOwner["blockOwnerDeletion"] || actualOwner["controller"] != expectedOwner["controller"] {
		return false
	}
	actualLabels, _, _ := unstructured.NestedStringMap(actual, "metadata", "labels")
	expectedLabels, _, _ := unstructured.NestedStringMap(expected, "metadata", "labels")
	for key, value := range expectedLabels {
		if actualLabels[key] != value {
			return false
		}
	}

	switch expected["kind"] {
	case "Service":
		actualSpec, _, _ := unstructured.NestedMap(actual, "spec")
		actualSelector, _, _ := unstructured.NestedStringMap(actual, "spec", "selector")
		expectedSelector, _, _ := unstructured.NestedStringMap(expected, "spec", "selector")
		actualPorts, _, _ := unstructured.NestedSlice(actual, "spec", "ports")
		expectedPorts, _, _ := unstructured.NestedSlice(expected, "spec", "ports")
		serviceType := stringValue(actualSpec["type"])
		return (serviceType == "" || serviceType == "ClusterIP") && stringValue(actualSpec["externalName"]) == "" &&
			len(sliceValue(actualSpec["externalIPs"])) == 0 && reflect.DeepEqual(actualSelector, expectedSelector) && reflect.DeepEqual(actualPorts, expectedPorts)
	case "Pod":
		actualSpec, _, _ := unstructured.NestedMap(actual, "spec")
		expectedSpec, _, _ := unstructured.NestedMap(expected, "spec")
		actualContainer := namedContainer(actualSpec, "containers", "supervisor")
		expectedContainer := namedContainer(expectedSpec, "containers", "supervisor")
		actualSecret := podSecretReference(actualSpec, "bootstrap")
		expectedSecret := podSecretReference(expectedSpec, "bootstrap")
		actualProjected, actualAudience := projectedServiceAccountToken(actualSpec)
		expectedProjected, expectedAudience := projectedServiceAccountToken(expectedSpec)
		actualSecurity := containerSecurity(actualContainer)
		expectedSecurity := containerSecurity(expectedContainer)
		return actualSecret == expectedSecret && actualProjected == expectedProjected && actualAudience == expectedAudience &&
			actualSpec["serviceAccountName"] == expectedSpec["serviceAccountName"] &&
			reflect.DeepEqual(actualSpec["securityContext"], expectedSpec["securityContext"]) &&
			containerSpecMatches(actualContainer, expectedContainer) &&
			initContainerListsMatch(sliceValue(actualSpec["initContainers"]), sliceValue(expectedSpec["initContainers"])) &&
			podVolumeSourcesMatch(sliceValue(actualSpec["volumes"]), sliceValue(expectedSpec["volumes"])) &&
			imagePullSecretRefsMatch(actualSpec["imagePullSecrets"], expectedSpec["imagePullSecrets"]) &&
			boolValue(actualSpec["automountServiceAccountToken"]) == boolValue(expectedSpec["automountServiceAccountToken"]) &&
			reflect.DeepEqual(actualSpec["schedulingGates"], expectedSpec["schedulingGates"]) &&
			actualSecurity["runAsUser"] == expectedSecurity["runAsUser"] && actualSecurity["runAsGroup"] == expectedSecurity["runAsGroup"] &&
			actualSecurity["runAsNonRoot"] == expectedSecurity["runAsNonRoot"] && actualSecurity["readOnlyRootFilesystem"] == expectedSecurity["readOnlyRootFilesystem"] &&
			actualSecurity["allowPrivilegeEscalation"] == expectedSecurity["allowPrivilegeEscalation"] &&
			containerDropsAllCapabilities(actualSecurity) == containerDropsAllCapabilities(expectedSecurity) &&
			podUsesRuntimeDefaultSeccomp(actualSpec) == podUsesRuntimeDefaultSeccomp(expectedSpec)
	case "Secret":
		actualData, _, _ := unstructured.NestedMap(actual, "data")
		expectedData, _, _ := unstructured.NestedMap(expected, "data")
		dataMatches := reflect.DeepEqual(actualData, expectedData) || len(actualData) == 0 && len(expectedData) == 0
		actualImmutable, _, _ := unstructured.NestedBool(actual, "immutable")
		expectedImmutable, _, _ := unstructured.NestedBool(expected, "immutable")
		actualType, _, _ := unstructured.NestedString(actual, "type")
		expectedType, _, _ := unstructured.NestedString(expected, "type")
		return actualImmutable && expectedImmutable && actualType == expectedType && dataMatches
	default:
		actualSpec, _, _ := unstructured.NestedMap(actual, "spec")
		expectedSpec, _, _ := unstructured.NestedMap(expected, "spec")
		return reflect.DeepEqual(actualSpec, expectedSpec)
	}
}

func firstOwnerReference(object map[string]any) (map[string]any, bool) {
	owners, _, _ := unstructured.NestedSlice(object, "metadata", "ownerReferences")
	if len(owners) != 1 {
		return nil, false
	}
	owner, _ := owners[0].(map[string]any)
	return owner, owner != nil
}

func ownerSandboxUID(object *unstructured.Unstructured) string {
	owners, _, _ := unstructured.NestedSlice(object.Object, "metadata", "ownerReferences")
	for _, value := range owners {
		owner, _ := value.(map[string]any)
		if owner["kind"] == "Sandbox" {
			uid, _ := owner["uid"].(string)
			return uid
		}
	}
	return ""
}

func (backend *dynamicAgentSandboxCreateBackend) namespacedResource(gvr schema.GroupVersionResource, namespace string) (dynamic.ResourceInterface, error) {
	if backend == nil || backend.client == nil {
		return nil, fmt.Errorf("kubernetes dynamic client is nil")
	}
	if namespace == "" {
		return nil, fmt.Errorf("kubernetes namespace is required")
	}
	return backend.client.Resource(gvr).Namespace(namespace), nil
}

var _ agentSandboxCreateSequenceBackend = (*dynamicAgentSandboxCreateBackend)(nil)
