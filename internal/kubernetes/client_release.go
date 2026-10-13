package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

func (backend *dynamicAgentSandboxCreateBackend) RecordRuntimePairEvidence(ctx context.Context, identity agentSandboxCreateIdentity) error {
	resource, err := backend.namespacedResource(agentSandboxGVR(versionFromAPIVersion(identity.APIVersion)), identity.Namespace)
	if err != nil {
		return err
	}
	return patchDynamicResourceWithResourceVersion(ctx, resource, identity.SandboxName, identity.SandboxUID, func(resourceVersion string) map[string]any {
		return map[string]any{
			"metadata": map[string]any{
				"resourceVersion": resourceVersion,
				"annotations": map[string]any{
					annotationRuntimeWorkloadUID:      identity.WorkloadUID,
					annotationRuntimeSupervisorUID:    identity.SupervisorUID,
					annotationRuntimeNetworkPolicyUID: identity.Fence.PolicyUID,
					annotationRuntimeNetworkPolicyGen: fmt.Sprint(identity.Fence.Generation),
				},
			},
		}
	})
}

func (backend *dynamicAgentSandboxCreateBackend) CreateBootstrapSecrets(ctx context.Context, secrets []map[string]any) error {
	for _, expected := range secrets {
		_, err := backend.createOrObserveNamespaced(ctx, coreV1GVR("secrets"), expected)
		if err != nil {
			return fmt.Errorf("create immutable generation bootstrap Secret: %w", err)
		}
	}
	return nil
}

// SetSandboxRuntimeGeneration switches a suspended workload's private Secret
// reference and generation annotation together. The sandbox UID and current
// generation are checked on every retry so a stale lifecycle request cannot
// overwrite a newer runtime template.
func (backend *dynamicAgentSandboxCreateBackend) SetSandboxRuntimeGeneration(
	ctx context.Context,
	identity agentSandboxCreateIdentity,
	newGeneration string,
) (*unstructured.Unstructured, error) {
	if err := validateCautemSecretIdentity(identity); err != nil {
		return nil, err
	}
	if generationSuffix(newGeneration) == "" || newGeneration == identity.Generation {
		return nil, fmt.Errorf("replacement runtime generation is invalid")
	}
	resource, err := backend.namespacedResource(agentSandboxGVR(versionFromAPIVersion(identity.APIVersion)), identity.Namespace)
	if err != nil {
		return nil, err
	}
	oldSecret := generationSecretName("os-sandbox", identity.SandboxID, identity.Generation)
	newSecret := generationSecretName("os-sandbox", identity.SandboxID, newGeneration)
	for attempt := 0; attempt < 5; attempt++ {
		object, err := resource.Get(ctx, identity.SandboxName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("get Agent Sandbox before generation rotation: %w", err)
		}
		if string(object.GetUID()) != identity.SandboxUID {
			return nil, fmt.Errorf("agent Sandbox UID changed before runtime generation rotation")
		}
		annotations := object.GetAnnotations()
		currentGeneration := annotations[annotationRuntimeGeneration]
		if currentGeneration == newGeneration {
			if err := requireSandboxWorkloadSecretReference(object, newSecret); err != nil {
				return nil, err
			}
			return object, nil
		}
		if currentGeneration != identity.Generation {
			return nil, fmt.Errorf("agent Sandbox runtime generation changed during credential rotation")
		}
		if !sandboxIsSuspended(object, versionFromAPIVersion(identity.APIVersion)) {
			return nil, fmt.Errorf("agent Sandbox must be suspended before runtime generation rotation")
		}
		podTemplate, found, _ := unstructured.NestedMap(object.Object, "spec", "podTemplate")
		if !found {
			return nil, fmt.Errorf("agent Sandbox workload Pod template is missing")
		}
		podSpec, found, _ := unstructured.NestedMap(podTemplate, "spec")
		if !found {
			return nil, fmt.Errorf("agent Sandbox workload Pod spec is missing")
		}
		volumes, found, _ := unstructured.NestedSlice(podSpec, "volumes")
		if !found {
			return nil, fmt.Errorf("agent Sandbox workload Pod volumes are missing")
		}
		updated := false
		for _, raw := range volumes {
			volume, _ := raw.(map[string]any)
			if volume["name"] != cautemWorkloadCredentialName {
				continue
			}
			secret, _ := volume["secret"].(map[string]any)
			if secret["secretName"] != oldSecret {
				return nil, fmt.Errorf("agent Sandbox private Secret reference does not match its current runtime generation")
			}
			secret["secretName"] = newSecret
			updated = true
		}
		if !updated {
			return nil, fmt.Errorf("agent Sandbox private credential volume is missing")
		}
		if err := unstructured.SetNestedSlice(podSpec, volumes, "volumes"); err != nil {
			return nil, err
		}
		if err := unstructured.SetNestedMap(podTemplate, podSpec, "spec"); err != nil {
			return nil, err
		}
		if err := unstructured.SetNestedMap(object.Object, podTemplate, "spec", "podTemplate"); err != nil {
			return nil, err
		}
		annotations[annotationRuntimeGeneration] = newGeneration
		object.SetAnnotations(annotations)
		updatedObject, err := resource.Update(ctx, object, metav1.UpdateOptions{})
		if err == nil {
			return updatedObject, nil
		}
		if apierrors.IsConflict(err) {
			continue
		}
		// An API timeout can be ambiguous. Observe whether the generation
		// switch committed before reporting the write as failed.
		observed, getErr := resource.Get(ctx, identity.SandboxName, metav1.GetOptions{})
		if getErr == nil && string(observed.GetUID()) == identity.SandboxUID && observed.GetAnnotations()[annotationRuntimeGeneration] == newGeneration {
			if refErr := requireSandboxWorkloadSecretReference(observed, newSecret); refErr == nil {
				return observed, nil
			}
		}
		return nil, fmt.Errorf("update Agent Sandbox runtime generation: %w", err)
	}
	return nil, fmt.Errorf("agent Sandbox changed repeatedly during runtime generation rotation")
}

func requireSandboxWorkloadSecretReference(object *unstructured.Unstructured, secretName string) error {
	volumes, found, _ := unstructured.NestedSlice(object.Object, "spec", "podTemplate", "spec", "volumes")
	if !found {
		return fmt.Errorf("agent Sandbox workload Pod volumes are missing")
	}
	for _, raw := range volumes {
		volume, _ := raw.(map[string]any)
		if volume["name"] != cautemWorkloadCredentialName {
			continue
		}
		secret, _ := volume["secret"].(map[string]any)
		if secret["secretName"] == secretName {
			return nil
		}
		return fmt.Errorf("agent Sandbox private Secret reference does not match its runtime generation")
	}
	return fmt.Errorf("agent Sandbox private credential volume is missing")
}

func sandboxIsSuspended(object *unstructured.Unstructured, version string) bool {
	if version == sandboxAPIVersionV1Beta1 {
		mode, _, _ := unstructured.NestedString(object.Object, "spec", "operatingMode")
		return mode == "Suspended"
	}
	replicas, found, _ := unstructured.NestedInt64(object.Object, "spec", "replicas")
	return found && replicas == 0
}

// DeleteCautemGenerationSecrets removes only the three immutable Secrets owned
// by the expected Agent Sandbox UID. UID preconditions protect against name
// reuse while a restart cleanup is in flight.
func (backend *dynamicAgentSandboxCreateBackend) DeleteCautemGenerationSecrets(ctx context.Context, identity agentSandboxCreateIdentity) error {
	if err := validateCautemSecretIdentity(identity); err != nil {
		return err
	}
	resource, err := backend.namespacedResource(coreV1GVR("secrets"), identity.Namespace)
	if err != nil {
		return err
	}
	names := []string{
		generationSecretName("os-sandbox", identity.SandboxID, identity.Generation),
		generationSecretName("os-supervisor", identity.SandboxID, identity.Generation),
		generationSecretName(proxyEnvSecretPrefix, identity.SandboxID, identity.Generation),
	}
	var failures []error
	for _, name := range names {
		secret, err := resource.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("get Cautem runtime Secret %s before cleanup: %w", name, err))
			continue
		}
		if !cautemSecretOwnedBySandbox(secret, identity) {
			failures = append(failures, fmt.Errorf("refusing to delete Cautem runtime Secret %s with a different owner", name))
			continue
		}
		uid := types.UID(secret.GetUID())
		if err := resource.Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil && !apierrors.IsNotFound(err) {
			failures = append(failures, fmt.Errorf("delete Cautem runtime Secret %s: %w", name, err))
		}
	}
	return errors.Join(failures...)
}

func cautemSecretOwnedBySandbox(secret *unstructured.Unstructured, identity agentSandboxCreateIdentity) bool {
	if secret.GetNamespace() != identity.Namespace || secret.GetLabels()[labelSandboxID] != identity.SandboxID {
		return false
	}
	owners := secret.GetOwnerReferences()
	return len(owners) == 1 && owners[0].APIVersion == identity.APIVersion && owners[0].Kind == "Sandbox" &&
		owners[0].Name == identity.SandboxName && string(owners[0].UID) == identity.SandboxUID &&
		(owners[0].Controller == nil || !*owners[0].Controller) &&
		(owners[0].BlockOwnerDeletion == nil || !*owners[0].BlockOwnerDeletion)
}

func (backend *dynamicAgentSandboxCreateBackend) ReleaseSchedulingGate(ctx context.Context, namespace, podName, podUID string) error {
	resource, err := backend.namespacedResource(coreV1GVR("pods"), namespace)
	if err != nil {
		return err
	}
	operationCtx, cancel := context.WithTimeout(ctx, sandboxAPITimeout)
	defer cancel()
	retryDelay := 10 * time.Millisecond
	for {
		pod, err := resource.Get(operationCtx, podName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get Pod %s before releasing scheduling gate: %w", podName, err)
		}
		if string(pod.GetUID()) != podUID {
			return fmt.Errorf("pod %s UID changed before scheduling gate release", podName)
		}
		podSpec, _, _ := unstructured.NestedMap(pod.Object, "spec")
		if !onlyBootstrapSchedulingGate(podSpec) {
			return fmt.Errorf("pod %s no longer has the bootstrap scheduling gate", podName)
		}
		if pod.GetResourceVersion() == "" {
			return fmt.Errorf("pod %s has no resourceVersion before scheduling gate release", podName)
		}
		patch, err := json.Marshal(map[string]any{
			"metadata": map[string]any{"resourceVersion": pod.GetResourceVersion()},
			"spec":     map[string]any{"schedulingGates": []any{}},
		})
		if err != nil {
			return err
		}
		_, err = resource.Patch(operationCtx, podName, types.MergePatchType, patch, metav1.PatchOptions{})
		if err == nil {
			return nil
		}
		if !apierrors.IsConflict(err) {
			return fmt.Errorf("release scheduling gate on Pod %s: %w", podName, err)
		}
		if err := waitForPatchRetry(operationCtx, retryDelay); err != nil {
			return sandboxPatchContextError(ctx, operationCtx, podName)
		}
		retryDelay = nextPatchRetryDelay(retryDelay)
	}
}

func (backend *dynamicAgentSandboxCreateBackend) MarkRuntimeReleased(ctx context.Context, namespace, apiVersion, sandboxName, sandboxUID string) error {
	resource, err := backend.namespacedResource(agentSandboxGVR(versionFromAPIVersion(apiVersion)), namespace)
	if err != nil {
		return err
	}
	return patchDynamicResourceWithResourceVersion(ctx, resource, sandboxName, sandboxUID, func(resourceVersion string) map[string]any {
		return map[string]any{
			"metadata": map[string]any{
				"resourceVersion": resourceVersion,
				"annotations":     map[string]any{annotationRuntimeBootstrapPhase: "released", annotationRuntimeBootstrapping: "true"},
			},
		}
	})
}

func (backend *dynamicAgentSandboxCreateBackend) DeleteSandbox(ctx context.Context, namespace, apiVersion, sandboxName, sandboxUID string) error {
	if strings.TrimSpace(sandboxUID) == "" {
		return fmt.Errorf("uID precondition is required when deleting an Agent Sandbox")
	}
	version := versionFromAPIVersion(apiVersion)
	if version != sandboxAPIVersionV1Beta1 && version != sandboxAPIVersionV1Alpha1 {
		return fmt.Errorf("unsupported Agent Sandbox apiVersion %q for rollback", apiVersion)
	}
	resource, err := backend.namespacedResource(agentSandboxGVR(version), namespace)
	if err != nil {
		return err
	}
	object, err := resource.Get(ctx, sandboxName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if string(object.GetUID()) != sandboxUID {
		return fmt.Errorf("refusing to delete Agent Sandbox %s: UID precondition does not match", sandboxName)
	}
	uid := types.UID(sandboxUID)
	err = resource.Delete(ctx, sandboxName, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func patchDynamicResourceWithResourceVersion(
	ctx context.Context,
	resource dynamic.ResourceInterface,
	name string,
	expectedUID string,
	build func(resourceVersion string) map[string]any,
) error {
	operationCtx, cancel := context.WithTimeout(ctx, sandboxAPITimeout)
	defer cancel()
	retryDelay := 10 * time.Millisecond
	for {
		if err := operationCtx.Err(); err != nil {
			return sandboxPatchContextError(ctx, operationCtx, name)
		}
		object, err := resource.Get(operationCtx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get Kubernetes resource %s before patch: %w", name, err)
		}
		if expectedUID != "" && string(object.GetUID()) != expectedUID {
			return fmt.Errorf("kubernetes resource %s UID changed before patch", name)
		}
		if object.GetResourceVersion() == "" {
			return fmt.Errorf("kubernetes resource %s has no resourceVersion before patch", name)
		}
		patchObject := build(object.GetResourceVersion())
		patch, err := json.Marshal(patchObject)
		if err != nil {
			return fmt.Errorf("encode Kubernetes resource %s merge patch: %w", name, err)
		}
		_, err = resource.Patch(operationCtx, name, types.MergePatchType, patch, metav1.PatchOptions{})
		if err == nil {
			return nil
		}
		if !apierrors.IsConflict(err) {
			return fmt.Errorf("patch Kubernetes resource %s: %w", name, err)
		}
		if err := waitForPatchRetry(operationCtx, retryDelay); err != nil {
			return sandboxPatchContextError(ctx, operationCtx, name)
		}
		retryDelay = nextPatchRetryDelay(retryDelay)
	}
}

func waitForPatchRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func nextPatchRetryDelay(delay time.Duration) time.Duration {
	const maximumDelay = 250 * time.Millisecond
	if delay >= maximumDelay/2 {
		return maximumDelay
	}
	return delay * 2
}

func versionFromAPIVersion(apiVersion string) string {
	return strings.TrimPrefix(apiVersion, sandboxAPIGroup+"/")
}
