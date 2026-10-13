package kubernetes

import (
	"context"
	"fmt"
	"reflect"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func (backend *dynamicAgentSandboxCreateBackend) WaitForGatedWorkload(ctx context.Context, namespace, name, sandboxUID string, requestedResource map[string]any) (agentSandboxWorkloadIdentity, error) {
	resource, err := backend.namespacedResource(coreV1GVR("pods"), namespace)
	if err != nil {
		return agentSandboxWorkloadIdentity{}, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, sandboxAPITimeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		pod, err := resource.Get(waitCtx, name, metav1.GetOptions{})
		if err == nil {
			return workloadIdentityFromPod(pod, requestedResource), nil
		}
		if !apierrors.IsNotFound(err) {
			return agentSandboxWorkloadIdentity{}, fmt.Errorf("get gated workload Pod %s: %w", name, err)
		}
		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				return agentSandboxWorkloadIdentity{}, ctx.Err()
			}
			return agentSandboxWorkloadIdentity{}, fmt.Errorf("timed out waiting for gated workload Pod %s owned by Sandbox UID %s", name, sandboxUID)
		case <-ticker.C:
		}
	}
}

func workloadIdentityFromPod(pod *unstructured.Unstructured, requestedResource map[string]any) agentSandboxWorkloadIdentity {
	labels, _, _ := unstructured.NestedStringMap(pod.Object, "metadata", "labels")
	spec, _, _ := unstructured.NestedMap(pod.Object, "spec")
	agent := namedContainer(spec, "containers", "agent")
	bootstrap := namedContainer(spec, "initContainers", sandboxBootstrapVolume)
	secret := podSecretReference(spec, sandboxBootstrapVolume)
	cautemSecret := podSecretReference(spec, cautemWorkloadCredentialName)
	if cautemSecret != "" {
		secret = cautemSecret
	}
	projected, _ := projectedServiceAccountToken(spec)
	requestedSpec, _, _ := unstructured.NestedMap(requestedResource, "spec", "podTemplate", "spec")
	expectedAgent := namedContainer(requestedSpec, "containers", "agent")
	actualSSHD := namedContainer(spec, "containers", cautemWorkloadSSHDName)
	expectedSSHD := namedContainer(requestedSpec, "containers", cautemWorkloadSSHDName)
	expectedSecurityContext, _, _ := unstructured.NestedMap(requestedSpec, "securityContext")
	expectedVolumes := sandboxPodVolumesWithClaimTemplates(requestedResource, requestedSpec)
	actualInit := sliceValue(spec["initContainers"])
	expectedInit := sliceValue(requestedSpec["initContainers"])
	return agentSandboxWorkloadIdentity{
		Name: pod.GetName(), UID: string(pod.GetUID()), OwnerSandboxUID: ownerSandboxUID(pod),
		Image: stringValue(agent["image"]), Command: stringSlice(agent["command"]),
		BoundaryPair: labels[labelBoundaryPair], BoundaryRole: labels[labelBoundaryRole],
		SandboxBootstrapSecret:                  secret,
		SupervisorSecretReferences:              supervisorSecretReferences(spec),
		BootstrapGatePresent:                    hasSchedulingGate(spec, sandboxRuntimeBootstrapGate),
		SchedulingGatesMatch:                    onlyBootstrapSchedulingGate(spec),
		ServiceAccountAutomountDisabled:         spec["automountServiceAccountToken"] == false,
		HasProjectedServiceAccountToken:         projected,
		HasGatewayCredentialEnv:                 podHasGatewayCredentialEnv(spec),
		AgentMountsBootstrapSecret:              containerMountsVolume(agent, sandboxBootstrapVolume),
		TrustedInitMountsBootstrapSecret:        containerMountsVolume(bootstrap, sandboxBootstrapVolume),
		HostNamespacesIsolated:                  podNamespacesAreIsolated(spec),
		RunAsNonRoot:                            workloadRunsAsNonRoot(spec, agent),
		RuntimeDefaultSeccomp:                   podUsesRuntimeDefaultSeccomp(spec),
		DropAllCapabilities:                     containerDropsAllCapabilities(containerSecurity(agent)),
		PrivilegeEscalationDisabled:             containerSecurity(agent)["allowPrivilegeEscalation"] == false,
		AdditionalApplicationContainers:         !workloadContainerNamesMatch(sliceValue(spec["containers"]), cautemSecret != ""),
		OtherInitContainersMountBootstrapSecret: otherInitContainerMountsSecret(spec, sandboxBootstrapVolume),
		CautemAgentMountsPrivateSecret:          containerMountsVolume(agent, cautemWorkloadCredentialName),
		CautemInitMountsPrivateSecret:           anyInitContainerMountsVolume(spec, cautemWorkloadCredentialName),
		CautemSSHDContainerMatches:              cautemSecret != "" && containerSpecMatches(actualSSHD, expectedSSHD),
		InitContainerNames:                      initContainerNames(spec),
		AgentContainerMatches:                   containerSpecMatches(agent, expectedAgent),
		InitContainerSpecsMatch:                 initContainerListsMatch(actualInit, expectedInit),
		PodVolumeSourcesMatch:                   podVolumeSourcesMatch(sliceValue(spec["volumes"]), expectedVolumes),
		PodSecurityContextMatches:               podSecurityContextsMatch(spec["securityContext"], expectedSecurityContext),
		ServiceAccountMatches:                   spec["serviceAccountName"] == requestedSpec["serviceAccountName"],
	}
}

func workloadContainerNamesMatch(containers []any, cautem bool) bool {
	if !cautem {
		return len(containers) == 1 && namedContainer(map[string]any{"containers": containers}, "containers", "agent") != nil
	}
	if len(containers) != 2 {
		return false
	}
	return namedContainer(map[string]any{"containers": containers}, "containers", "agent") != nil &&
		namedContainer(map[string]any{"containers": containers}, "containers", cautemWorkloadSSHDName) != nil
}

func anyInitContainerMountsVolume(podSpec map[string]any, volumeName string) bool {
	for _, value := range sliceValue(podSpec["initContainers"]) {
		container, _ := value.(map[string]any)
		if containerMountsVolume(container, volumeName) {
			return true
		}
	}
	return false
}

func initContainerListsMatch(actual, expected []any) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		actualContainer, _ := actual[index].(map[string]any)
		expectedContainer, _ := expected[index].(map[string]any)
		if !containerSpecMatches(actualContainer, expectedContainer) {
			return false
		}
	}
	return true
}

func containerSpecMatches(actual, expected map[string]any) bool {
	if actual == nil || expected == nil {
		return actual == nil && expected == nil
	}
	for key, expectedValue := range expected {
		if key == "env" {
			if !containerEnvMatches(actual[key], expectedValue) {
				return false
			}
			continue
		}
		if !reflect.DeepEqual(actual[key], expectedValue) {
			return false
		}
	}
	for key := range actual {
		if _, exists := expected[key]; exists {
			continue
		}
		switch key {
		case "imagePullPolicy", "terminationMessagePath", "terminationMessagePolicy":
			// The API server defaults these fields and they do not change the
			// workload's credentials, mounts, or execution command.
		case "resources":
			// Kubernetes persists an empty resource requirements object when
			// none was requested. It carries no workload configuration.
			resources, ok := actual[key].(map[string]any)
			if !ok || len(resources) != 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func imagePullSecretRefsMatch(actual, expected any) bool {
	actualRefs, _ := actual.([]any)
	expectedRefs, _ := expected.([]any)
	if len(actualRefs) == 0 && len(expectedRefs) == 0 {
		return true
	}
	return reflect.DeepEqual(actualRefs, expectedRefs)
}

func containerEnvMatches(actual, expected any) bool {
	actualEnv, ok := actual.([]any)
	if !ok {
		return false
	}
	expectedEnv, ok := expected.([]any)
	if !ok || len(actualEnv) != len(expectedEnv) {
		return false
	}
	for index := range expectedEnv {
		actualVariable, _ := actualEnv[index].(map[string]any)
		expectedVariable, _ := expectedEnv[index].(map[string]any)
		if actualVariable == nil || expectedVariable == nil {
			return false
		}
		actualCopy := cloneAnyMap(actualVariable)
		expectedCopy := cloneAnyMap(expectedVariable)
		if expectedCopy["value"] == "" && actualCopy["value"] == nil {
			delete(expectedCopy, "value")
		}
		if !reflect.DeepEqual(actualCopy, expectedCopy) {
			return false
		}
	}
	return true
}

func sandboxPodVolumesWithClaimTemplates(resource, requestedSpec map[string]any) []any {
	volumes := append([]any(nil), sliceValue(requestedSpec["volumes"])...)
	resourceSpec, _, _ := unstructured.NestedMap(resource, "spec")
	resourceName, _, _ := unstructured.NestedString(resource, "metadata", "name")
	for _, value := range sliceValue(resourceSpec["volumeClaimTemplates"]) {
		template, _ := value.(map[string]any)
		name, _, _ := unstructured.NestedString(template, "metadata", "name")
		if name == "" || resourceName == "" {
			continue
		}
		volumes = append(volumes, map[string]any{
			"name":                  name,
			"persistentVolumeClaim": map[string]any{"claimName": name + "-" + resourceName},
		})
	}
	return volumes
}

func podSecurityContextsMatch(actual, expected any) bool {
	actualContext, actualOK := actual.(map[string]any)
	expectedContext, expectedOK := expected.(map[string]any)
	if !actualOK || !expectedOK {
		return actual == nil && expected == nil
	}
	actualCopy := cloneAnyMap(actualContext)
	expectedCopy := cloneAnyMap(expectedContext)
	if len(sliceValue(actualCopy["supplementalGroups"])) == 0 {
		delete(actualCopy, "supplementalGroups")
	}
	if len(sliceValue(expectedCopy["supplementalGroups"])) == 0 {
		delete(expectedCopy, "supplementalGroups")
	}
	return reflect.DeepEqual(actualCopy, expectedCopy)
}

func cloneAnyMap(values map[string]any) map[string]any {
	copy := make(map[string]any, len(values))
	for key, value := range values {
		copy[key] = value
	}
	return copy
}

func podVolumeSourcesMatch(actual, expected []any) bool {
	if len(actual) != len(expected) {
		return false
	}
	actualByName := make(map[string]map[string]any, len(actual))
	for _, value := range actual {
		volume, _ := value.(map[string]any)
		name := stringValue(volume["name"])
		if name == "" || actualByName[name] != nil {
			return false
		}
		actualByName[name] = volume
	}
	for _, value := range expected {
		volume, _ := value.(map[string]any)
		name := stringValue(volume["name"])
		actualVolume := actualByName[name]
		if name == "" || actualVolume == nil || !reflect.DeepEqual(actualVolume, volume) {
			return false
		}
		delete(actualByName, name)
	}
	return len(actualByName) == 0
}

func otherInitContainerMountsSecret(podSpec map[string]any, volumeName string) bool {
	initContainers := sliceValue(podSpec["initContainers"])
	for _, value := range initContainers {
		container, _ := value.(map[string]any)
		if container["name"] == volumeName {
			continue
		}
		if containerMountsVolume(container, volumeName) {
			return true
		}
	}
	return false
}

func sliceValue(value any) []any {
	slice, _ := value.([]any)
	return slice
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func stringSlice(value any) []string {
	items, _ := value.([]any)
	if items == nil {
		strings, _ := value.([]string)
		return append([]string(nil), strings...)
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil
		}
		result = append(result, text)
	}
	return result
}
