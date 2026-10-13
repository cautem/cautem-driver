package kubernetes

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

func (backend *dynamicAgentSandboxCreateBackend) SuspendSandboxController(ctx context.Context, namespace, version, name, sandboxUID string) error {
	version = versionFromAPIVersion(version)
	fields, err := sandboxDesiredStateFields(version, false)
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

func (backend *dynamicAgentSandboxCreateBackend) MarkRuntimeSuspended(ctx context.Context, namespace, apiVersion, sandboxName, sandboxUID string) error {
	resource, err := backend.namespacedResource(agentSandboxGVR(versionFromAPIVersion(apiVersion)), namespace)
	if err != nil {
		return err
	}
	return patchDynamicResourceWithResourceVersion(ctx, resource, sandboxName, sandboxUID, func(resourceVersion string) map[string]any {
		return map[string]any{
			"metadata": map[string]any{
				"resourceVersion": resourceVersion,
				"annotations": map[string]any{
					annotationRuntimeBootstrapPhase:   "suspended",
					annotationRuntimeBootstrapping:    "true",
					annotationRuntimeWorkloadUID:      nil,
					annotationRuntimeSupervisorUID:    nil,
					annotationRuntimeNetworkPolicyUID: nil,
					annotationRuntimeNetworkPolicyGen: nil,
				},
			},
		}
	})
}

func (backend *dynamicAgentSandboxCreateBackend) DeleteRuntimePod(ctx context.Context, namespace, name, sandboxUID string) (string, error) {
	resource, err := backend.namespacedResource(coreV1GVR("pods"), namespace)
	if err != nil {
		return "", err
	}
	pod, err := resource.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get runtime Pod %s before deletion: %w", name, err)
	}
	labels := pod.GetLabels()
	uid := string(pod.GetUID())
	if uid == "" || ownerSandboxUID(pod) != sandboxUID || labels[labelManagedBy] != managedByValue {
		return "", fmt.Errorf("refusing to delete runtime Pod %s without the expected Agent Sandbox owner", name)
	}
	uidPrecondition := types.UID(uid)
	err = resource.Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uidPrecondition}})
	if apierrors.IsNotFound(err) {
		return uid, nil
	}
	if err != nil {
		return "", fmt.Errorf("delete runtime Pod %s: %w", name, err)
	}
	return uid, nil
}

func (backend *dynamicAgentSandboxCreateBackend) WaitForRuntimePodAbsent(ctx context.Context, namespace, name, sandboxUID string) error {
	resource, err := backend.namespacedResource(coreV1GVR("pods"), namespace)
	if err != nil {
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, sandboxAPITimeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		pod, err := resource.Get(waitCtx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("observe runtime Pod %s deletion: %w", name, err)
		}
		if ownerSandboxUID(pod) != sandboxUID {
			return fmt.Errorf("runtime Pod name %s was reused by a different Agent Sandbox", name)
		}
		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("timed out waiting for runtime Pod %s to be deleted", name)
		case <-ticker.C:
		}
	}
}

func (backend *dynamicAgentSandboxCreateBackend) WaitForOwnedWorkloadAbsent(ctx context.Context, namespace, name, sandboxUID string) error {
	resource, err := backend.namespacedResource(coreV1GVR("pods"), namespace)
	if err != nil {
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, sandboxAPITimeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		pod, err := resource.Get(waitCtx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("observe workload Pod %s suspension: %w", name, err)
		}
		if ownerSandboxUID(pod) != sandboxUID {
			return fmt.Errorf("workload Pod name %s was reused by a different Agent Sandbox", name)
		}
		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("timed out waiting for workload Pod %s to stop", name)
		case <-ticker.C:
		}
	}
}

func (backend *dynamicAgentSandboxCreateBackend) WaitForRuntimePodsReady(ctx context.Context, namespace, supervisorName, supervisorUID, workloadName, workloadUID, sandboxUID string) error {
	resource, err := backend.namespacedResource(coreV1GVR("pods"), namespace)
	if err != nil {
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, sandboxAPITimeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready := true
		for _, expected := range []struct{ name, uid string }{{supervisorName, supervisorUID}, {workloadName, workloadUID}} {
			pod, err := resource.Get(waitCtx, expected.name, metav1.GetOptions{})
			if err != nil {
				if apierrors.IsNotFound(err) {
					ready = false
					break
				}
				return fmt.Errorf("read runtime Pod %s readiness: %w", expected.name, err)
			}
			if string(pod.GetUID()) != expected.uid || ownerSandboxUID(pod) != sandboxUID {
				return fmt.Errorf("runtime Pod %s UID or owner changed before readiness", expected.name)
			}
			if pod.GetDeletionTimestamp() != nil || !podReadyCondition(pod) {
				ready = false
				break
			}
		}
		if ready {
			return nil
		}
		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("timed out waiting for Cautem runtime Pods to become Ready")
		case <-ticker.C:
		}
	}
}

func podReadyCondition(pod *unstructured.Unstructured) bool {
	conditions, _, _ := unstructured.NestedSlice(pod.Object, "status", "conditions")
	for _, raw := range conditions {
		condition, _ := raw.(map[string]any)
		if condition["type"] == "Ready" {
			return condition["status"] == "True"
		}
	}
	return false
}

func (backend *dynamicAgentSandboxCreateBackend) ReadCautemGenerationSecrets(ctx context.Context, identity agentSandboxCreateIdentity) ([]map[string]any, error) {
	if err := validateCautemSecretIdentity(identity); err != nil {
		return nil, err
	}
	resource, err := backend.namespacedResource(coreV1GVR("secrets"), identity.Namespace)
	if err != nil {
		return nil, err
	}
	names := []string{
		generationSecretName("os-sandbox", identity.SandboxID, identity.Generation),
		generationSecretName("os-supervisor", identity.SandboxID, identity.Generation),
		generationSecretName(proxyEnvSecretPrefix, identity.SandboxID, identity.Generation),
	}
	secrets := make([]map[string]any, 0, len(names))
	for _, name := range names {
		secret, err := resource.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("read Cautem runtime Secret %s: %w", name, err)
		}
		secrets = append(secrets, secret.Object)
	}
	if err := validateCautemGenerationSecrets(secrets, identity); err != nil {
		return nil, fmt.Errorf("validate stored Cautem runtime Secrets: %w", err)
	}
	return secrets, nil
}
