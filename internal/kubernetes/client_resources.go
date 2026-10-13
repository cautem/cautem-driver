package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func (backend *dynamicAgentSandboxCreateBackend) CreateSuspendedSandbox(ctx context.Context, resource map[string]any) (agentSandboxResourceIdentity, error) {
	apiVersion, _ := resource["apiVersion"].(string)
	version := strings.TrimPrefix(apiVersion, sandboxAPIGroup+"/")
	if version == apiVersion || (version != sandboxAPIVersionV1Beta1 && version != sandboxAPIVersionV1Alpha1) {
		return agentSandboxResourceIdentity{}, fmt.Errorf("unsupported Agent Sandbox apiVersion %q", apiVersion)
	}
	namespace, _, _ := unstructured.NestedString(resource, "metadata", "namespace")
	name, _, _ := unstructured.NestedString(resource, "metadata", "name")
	api, err := backend.namespacedResource(agentSandboxGVR(version), namespace)
	if err != nil {
		return agentSandboxResourceIdentity{}, err
	}
	created, createErr := api.Create(ctx, &unstructured.Unstructured{Object: resource}, metav1.CreateOptions{})
	if createErr != nil {
		observed, getErr := api.Get(ctx, name, metav1.GetOptions{})
		if getErr != nil {
			return agentSandboxResourceIdentity{}, errors.Join(createErr, getErr)
		}
		if !sameSandboxCreateGeneration(observed.Object, resource) {
			return agentSandboxResourceIdentity{}, createErr
		}
		created = observed
	}
	return sandboxResourceIdentityFromObject(created, version, resource), nil
}

func sameSandboxCreateGeneration(actual, expected map[string]any) bool {
	if actual["apiVersion"] != expected["apiVersion"] || actual["kind"] != "Sandbox" {
		return false
	}
	actualName, _, _ := unstructured.NestedString(actual, "metadata", "name")
	actualNamespace, _, _ := unstructured.NestedString(actual, "metadata", "namespace")
	expectedName, _, _ := unstructured.NestedString(expected, "metadata", "name")
	expectedNamespace, _, _ := unstructured.NestedString(expected, "metadata", "namespace")
	actualGeneration, _, _ := unstructured.NestedString(actual, "metadata", "annotations", annotationRuntimeGeneration)
	expectedGeneration, _, _ := unstructured.NestedString(expected, "metadata", "annotations", annotationRuntimeGeneration)
	actualSandboxID, _, _ := unstructured.NestedString(actual, "metadata", "labels", labelSandboxID)
	expectedSandboxID, _, _ := unstructured.NestedString(expected, "metadata", "labels", labelSandboxID)
	actualSpec, _, _ := unstructured.NestedMap(actual, "spec")
	expectedSpec, _, _ := unstructured.NestedMap(expected, "spec")
	return actualName == expectedName && actualNamespace == expectedNamespace && actualGeneration != "" && actualGeneration == expectedGeneration && actualSandboxID == expectedSandboxID &&
		metadataStringMapMatches(actual, expected, "labels") && metadataStringMapMatches(actual, expected, "annotations") && reflect.DeepEqual(actualSpec, expectedSpec)
}

func metadataStringMapMatches(actual, expected map[string]any, field string) bool {
	actualValues, _, _ := unstructured.NestedStringMap(actual, "metadata", field)
	expectedValues, _, _ := unstructured.NestedStringMap(expected, "metadata", field)
	for key, expectedValue := range expectedValues {
		if actualValues[key] != expectedValue {
			return false
		}
	}
	return true
}

func sandboxResourceIdentityFromObject(object *unstructured.Unstructured, version string, expected map[string]any) agentSandboxResourceIdentity {
	namespace := object.GetNamespace()
	name := object.GetName()
	uid := string(object.GetUID())
	suspended := false
	if version == sandboxAPIVersionV1Beta1 {
		mode, _, _ := unstructured.NestedString(object.Object, "spec", "operatingMode")
		suspended = mode == "Suspended"
	} else {
		replicas, _, _ := unstructured.NestedInt64(object.Object, "spec", "replicas")
		suspended = replicas == 0
	}
	actualPodTemplate, _, _ := unstructured.NestedMap(object.Object, "spec", "podTemplate")
	expectedPodTemplate, _, _ := unstructured.NestedMap(expected, "spec", "podTemplate")
	return agentSandboxResourceIdentity{
		Namespace: namespace, Name: name, APIVersion: sandboxAPIGroup + "/" + version, UID: uid, Suspended: suspended,
		PodTemplateMatches:    reflect.DeepEqual(actualPodTemplate, expectedPodTemplate),
		CreateMetadataMatches: metadataStringMapMatches(object.Object, expected, "labels") && metadataStringMapMatches(object.Object, expected, "annotations"),
	}
}

func (backend *dynamicAgentSandboxCreateBackend) CreateBoundaryService(ctx context.Context, resource map[string]any) (agentSandboxServiceIdentity, error) {
	return backend.createService(ctx, resource)
}

func (backend *dynamicAgentSandboxCreateBackend) CreateSupervisorControlService(ctx context.Context, resource map[string]any) (agentSandboxServiceIdentity, error) {
	return backend.createService(ctx, resource)
}

func (backend *dynamicAgentSandboxCreateBackend) CreateProxyService(ctx context.Context, resource map[string]any) (agentSandboxServiceIdentity, error) {
	return backend.createService(ctx, resource)
}

func (backend *dynamicAgentSandboxCreateBackend) createService(ctx context.Context, resource map[string]any) (agentSandboxServiceIdentity, error) {
	created, err := backend.createOrObserveNamespaced(ctx, coreV1GVR("services"), resource)
	if err != nil {
		return agentSandboxServiceIdentity{}, err
	}
	clusterIP, _, _ := unstructured.NestedString(created.Object, "spec", "clusterIP")
	pair, _, _ := unstructured.NestedString(created.Object, "spec", "selector", labelBoundaryPair)
	role, _, _ := unstructured.NestedString(created.Object, "spec", "selector", labelBoundaryRole)
	return agentSandboxServiceIdentity{
		ClusterIP: clusterIP, OwnerSandboxUID: ownerSandboxUID(created),
		SelectorBoundaryPair: pair, SelectorBoundaryRole: role,
	}, nil
}

func (backend *dynamicAgentSandboxCreateBackend) CreateGatedSupervisor(ctx context.Context, resource map[string]any) (agentSandboxPodIdentity, error) {
	created, err := backend.createOrObserveNamespaced(ctx, coreV1GVR("pods"), resource)
	if err != nil {
		return agentSandboxPodIdentity{}, err
	}
	return supervisorIdentityFromPod(created, resource), nil
}

func supervisorIdentityFromPod(pod *unstructured.Unstructured, requestedPod map[string]any) agentSandboxPodIdentity {
	labels, _, _ := unstructured.NestedStringMap(pod.Object, "metadata", "labels")
	spec, _, _ := unstructured.NestedMap(pod.Object, "spec")
	requestedSpec, _ := requestedPod["spec"].(map[string]any)
	cautem := namedContainer(spec, "containers", cautemProxyImageName)
	containerName := "supervisor"
	if cautem != nil {
		containerName = cautemProxyImageName
	}
	container := namedContainer(spec, "containers", containerName)
	bootstrapVolume := "bootstrap"
	if containerName == cautemProxyImageName {
		bootstrapVolume = "runtime"
	}
	bootstrapSecret := podSecretReference(spec, bootstrapVolume)
	projected, audience := projectedServiceAccountToken(spec)
	containerSecurity, _ := container["securityContext"].(map[string]any)
	serviceAccountName, _ := spec["serviceAccountName"].(string)
	requestedContainer := namedContainer(requestedSpec, "containers", containerName)
	requestedVolumes, _ := requestedSpec["volumes"].([]any)
	actualVolumes, _ := spec["volumes"].([]any)
	return agentSandboxPodIdentity{
		Name: pod.GetName(), UID: string(pod.GetUID()), OwnerSandboxUID: ownerSandboxUID(pod),
		ServiceAccountName: serviceAccountName, Image: stringValue(container["image"]), Command: stringSlice(container["command"]),
		BoundaryPair: labels[labelBoundaryPair], BoundaryRole: labels[labelBoundaryRole],
		BootstrapSecretName: bootstrapSecret, ProjectedTokenAudience: audience,
		ProviderEnvSecretName:           containerEnvFromSecretReference(container),
		BootstrapGatePresent:            hasSchedulingGate(spec, sandboxRuntimeBootstrapGate),
		ServiceAccountAutomountDisabled: spec["automountServiceAccountToken"] == false,
		HasProjectedServiceAccountToken: projected,
		HasRawGatewayCredentialEnv:      containerHasRawSupervisorCredentialEnv(container),
		HostNamespacesIsolated:          podNamespacesAreIsolated(spec),
		RunAsNonRoot:                    boolValue(containerSecurity["runAsNonRoot"]),
		ReadOnlyRootFilesystem:          boolValue(containerSecurity["readOnlyRootFilesystem"]),
		RuntimeDefaultSeccomp:           podUsesRuntimeDefaultSeccomp(spec),
		DropAllCapabilities:             containerDropsAllCapabilities(containerSecurity),
		PrivilegeEscalationDisabled:     containerSecurity["allowPrivilegeEscalation"] == false,
		AdditionalContainers:            len(sliceValue(spec["containers"])) != 1 || len(sliceValue(spec["initContainers"])) != 0,
		CautemContainerMatches:          containerSpecMatches(container, requestedContainer),
		CautemVolumeSourcesMatch:        podVolumeSourcesMatch(actualVolumes, requestedVolumes),
		CautemHasRawTokenEnv:            containerHasRawCautemTokenEnv(container),
	}
}

func containerEnvFromSecretReference(container map[string]any) string {
	envFrom, _ := container["envFrom"].([]any)
	if len(envFrom) != 1 {
		return ""
	}
	entry, _ := envFrom[0].(map[string]any)
	secretRef, _ := entry["secretRef"].(map[string]any)
	name, _ := secretRef["name"].(string)
	return name
}

func containerHasRawCautemTokenEnv(container map[string]any) bool {
	env, _ := container["env"].([]any)
	for _, value := range env {
		item, _ := value.(map[string]any)
		if item["name"] == "CAUTEM_SANDBOX_TOKEN" {
			return true
		}
	}
	return false
}

func (backend *dynamicAgentSandboxCreateBackend) ActivateSandboxController(ctx context.Context, namespace, version, name, sandboxUID string) error {
	version = strings.TrimPrefix(version, sandboxAPIGroup+"/")
	fields, err := sandboxDesiredStateFields(version, true)
	if err != nil {
		return err
	}
	resource, err := backend.namespacedResource(agentSandboxGVR(version), namespace)
	if err != nil {
		return err
	}
	return patchDynamicResourceWithResourceVersion(ctx, resource, name, sandboxUID, func(resourceVersion string) map[string]any {
		return map[string]any{"metadata": map[string]any{"resourceVersion": resourceVersion}, "spec": fields}
	})
}
