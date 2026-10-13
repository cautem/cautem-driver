package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestOpenShellDynamicCreateBackendAppliesAndReadsBackBothFences(t *testing.T) {
	fake := newFakeAgentSandboxCreateDynamicClient()
	fake.PrependReactor("create", "networkpolicies", func(action k8stesting.Action) (bool, runtime.Object, error) {
		create := action.(k8stesting.CreateAction)
		object := create.GetObject().(*unstructured.Unstructured).DeepCopy()
		object.SetUID(types.UID("uid-" + object.GetName()))
		object.SetResourceVersion("rv-" + object.GetName())
		object.SetGeneration(4)
		if err := fake.Tracker().Create(networkPolicyV1GVR, object, create.GetNamespace()); err != nil {
			return true, nil, err
		}
		return true, object, nil
	})
	backend := newDynamicAgentSandboxCreateBackend(fake)
	workloadFence, supervisorFence, err := renderAgentSandboxRuntimeFence("team-a", "sandbox-a", 5500)
	if err != nil {
		t.Fatalf("renderAgentSandboxRuntimeFence() error = %v", err)
	}
	evidence, err := backend.ApplyAndObserveRuntimeFence(context.Background(), "team-a", workloadFence, supervisorFence)
	if err != nil {
		t.Fatalf("ApplyAndObserveRuntimeFence() error = %v", err)
	}
	wantWorkloadFence, wantSupervisorFence := runtimeFenceNames("sandbox-a")
	if evidence.PolicyUID != "uid-"+wantWorkloadFence || evidence.Generation != 4 || evidence.ResourceVersion != "rv-"+wantWorkloadFence {
		t.Fatalf("fence evidence = %#v", evidence)
	}
	var created []string
	for _, action := range fake.Actions() {
		if action.GetVerb() == "create" && action.GetResource() == networkPolicyV1GVR {
			created = append(created, action.(k8stesting.CreateAction).GetObject().(*unstructured.Unstructured).GetName())
		}
	}
	if len(created) != 2 || created[0] != wantWorkloadFence || created[1] != wantSupervisorFence {
		t.Fatalf("created NetworkPolicies = %#v; want workload fence before supervisor egress policy", created)
	}
}

func TestOpenShellDynamicCreateBackendRefusesMismatchedExistingFence(t *testing.T) {
	fake := newFakeAgentSandboxCreateDynamicClient()
	workloadFence, supervisorFence, err := renderAgentSandboxRuntimeFence("team-a", "sandbox-a", 5500)
	if err != nil {
		t.Fatalf("renderAgentSandboxRuntimeFence() error = %v", err)
	}
	existing := (&unstructured.Unstructured{Object: workloadFence}).DeepCopy()
	existing.SetUID("existing-fence-uid")
	existing.SetResourceVersion("9")
	existing.SetGeneration(1)
	_ = unstructured.SetNestedSlice(existing.Object, []any{map[string]any{}}, "spec", "egress")
	if err := fake.Tracker().Create(networkPolicyV1GVR, existing, "team-a"); err != nil {
		t.Fatalf("seed mismatched NetworkPolicy: %v", err)
	}
	backend := newDynamicAgentSandboxCreateBackend(fake)
	if _, err := backend.ApplyAndObserveRuntimeFence(context.Background(), "team-a", workloadFence, supervisorFence); err == nil || !strings.Contains(err.Error(), "spec mismatch") {
		t.Fatalf("ApplyAndObserveRuntimeFence() error = %v; want mismatched policy rejection", err)
	}
	for _, action := range fake.Actions() {
		if action.GetVerb() == "create" && action.GetResource() == networkPolicyV1GVR {
			t.Fatalf("backend must not overwrite or add a conflicting NetworkPolicy: %#v", fake.Actions())
		}
	}
}

func TestOpenShellDynamicCreateBackendRejectsMutatedSupervisorOnSuccessfulCreate(t *testing.T) {
	fake := newFakeAgentSandboxCreateDynamicClient()
	params := testAgentSandboxRuntimeRenderParams()
	resources, err := renderAgentSandboxRuntimeResources(params)
	if err != nil {
		t.Fatalf("renderAgentSandboxRuntimeResources() error = %v", err)
	}
	fake.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		object := action.(k8stesting.CreateAction).GetObject().(*unstructured.Unstructured).DeepCopy()
		object.SetUID("supervisor-pod-uid")
		_ = unstructured.SetNestedField(object.Object, true, "spec", "automountServiceAccountToken")
		return true, object, nil
	})
	_, err = newDynamicAgentSandboxCreateBackend(fake).CreateGatedSupervisor(context.Background(), resources["supervisorPod"].(map[string]any))
	if err == nil || !strings.Contains(err.Error(), "security contract") {
		t.Fatalf("CreateGatedSupervisor() error = %v; want mutated create response rejected", err)
	}
}

func TestOpenShellDynamicCreateBackendCreatesSuspendedAgentSandbox(t *testing.T) {
	fake := newFakeAgentSandboxCreateDynamicClient()
	fake.PrependReactor("create", "sandboxes", func(action k8stesting.Action) (bool, runtime.Object, error) {
		create := action.(k8stesting.CreateAction)
		object := create.GetObject().(*unstructured.Unstructured).DeepCopy()
		object.SetUID("sandbox-created-uid")
		object.SetResourceVersion("21")
		object.SetGeneration(1)
		if err := fake.Tracker().Create(agentSandboxGVR(sandboxAPIVersionV1Beta1), object, create.GetNamespace()); err != nil {
			return true, nil, err
		}
		return true, object, nil
	})
	params := testAgentSandboxRenderParams()
	resource, err := renderAgentSandboxResource(SandboxDriverConfig{}, params)
	if err != nil {
		t.Fatalf("renderAgentSandboxResource() error = %v", err)
	}
	identity, err := newDynamicAgentSandboxCreateBackend(fake).CreateSuspendedSandbox(context.Background(), resource)
	if err != nil {
		t.Fatalf("CreateSuspendedSandbox() error = %v", err)
	}
	if identity.UID != "sandbox-created-uid" || identity.Name != "team-a-demo" || identity.APIVersion != "agents.x-k8s.io/v1beta1" || !identity.Suspended {
		t.Fatalf("created Sandbox identity = %#v", identity)
	}
}

func TestOpenShellDynamicCreateBackendReportsMutatedSandboxTemplate(t *testing.T) {
	fake := newFakeAgentSandboxCreateDynamicClient()
	fake.PrependReactor("create", "sandboxes", func(action k8stesting.Action) (bool, runtime.Object, error) {
		object := action.(k8stesting.CreateAction).GetObject().(*unstructured.Unstructured).DeepCopy()
		object.SetUID("sandbox-created-uid")
		object.SetResourceVersion("21")
		_ = unstructured.SetNestedField(object.Object, "attacker/image", "spec", "podTemplate", "spec", "containers")
		return true, object, nil
	})
	params := testAgentSandboxRenderParams()
	resource, err := renderAgentSandboxResource(SandboxDriverConfig{}, params)
	if err != nil {
		t.Fatalf("renderAgentSandboxResource() error = %v", err)
	}
	identity, err := newDynamicAgentSandboxCreateBackend(fake).CreateSuspendedSandbox(context.Background(), resource)
	if err != nil {
		t.Fatalf("CreateSuspendedSandbox() error = %v", err)
	}
	if identity.PodTemplateMatches {
		t.Fatalf("mutated Sandbox podTemplate should not match: %#v", identity)
	}
}

func TestOpenShellDynamicCreateBackendPatchesOperatingStateWithUIDAndResourceVersion(t *testing.T) {
	fake := newFakeAgentSandboxCreateDynamicClient()
	seedSandboxObject(t, fake, "sandbox-a", "sandbox-uid-a", "rv-42", sandboxAPIVersionV1Beta1)
	var observedPatch map[string]any
	fake.PrependReactor("patch", "sandboxes", func(action k8stesting.Action) (bool, runtime.Object, error) {
		patchAction := action.(k8stesting.PatchAction)
		if patchAction.GetPatchType() != types.MergePatchType {
			return true, nil, errors.New("unexpected patch type")
		}
		return true, nil, json.Unmarshal(patchAction.GetPatch(), &observedPatch)
	})
	err := newDynamicAgentSandboxCreateBackend(fake).ActivateSandboxController(context.Background(), "team-a", sandboxAPIVersionV1Beta1, "sandbox-a", "sandbox-uid-a")
	if err != nil {
		t.Fatalf("ActivateSandboxController() error = %v", err)
	}
	metadata := observedPatch["metadata"].(map[string]any)
	if metadata["resourceVersion"] != "rv-42" || observedPatch["spec"].(map[string]any)["operatingMode"] != "Running" {
		t.Fatalf("operating state merge patch = %#v", observedPatch)
	}
}

func TestOpenShellDynamicCreateBackendRereadsResourceVersionAfterConflict(t *testing.T) {
	fake := newFakeAgentSandboxCreateDynamicClient()
	seedSandboxObject(t, fake, "sandbox-a", "sandbox-uid-a", "rv-42", sandboxAPIVersionV1Beta1)
	var observedVersions []string
	fake.PrependReactor("patch", "sandboxes", func(action k8stesting.Action) (bool, runtime.Object, error) {
		patchAction := action.(k8stesting.PatchAction)
		var patch map[string]any
		if err := json.Unmarshal(patchAction.GetPatch(), &patch); err != nil {
			return true, nil, err
		}
		metadata := patch["metadata"].(map[string]any)
		observedVersions = append(observedVersions, metadata["resourceVersion"].(string))
		if len(observedVersions) == 1 {
			object, err := fake.Tracker().Get(agentSandboxGVR(sandboxAPIVersionV1Beta1), "team-a", "sandbox-a")
			if err != nil {
				return true, nil, err
			}
			updated := object.(*unstructured.Unstructured).DeepCopy()
			updated.SetResourceVersion("rv-43")
			if err := fake.Tracker().Update(agentSandboxGVR(sandboxAPIVersionV1Beta1), updated, "team-a"); err != nil {
				return true, nil, err
			}
			return true, nil, apierrors.NewConflict(schema.GroupResource{Group: sandboxAPIGroup, Resource: "sandboxes"}, "sandbox-a", errors.New("stale resourceVersion"))
		}
		return true, nil, nil
	})
	if err := newDynamicAgentSandboxCreateBackend(fake).ActivateSandboxController(context.Background(), "team-a", sandboxAPIVersionV1Beta1, "sandbox-a", "sandbox-uid-a"); err != nil {
		t.Fatalf("ActivateSandboxController() error = %v", err)
	}
	if !reflect.DeepEqual(observedVersions, []string{"rv-42", "rv-43"}) {
		t.Fatalf("resourceVersion patch sequence = %#v; want fresh read after conflict", observedVersions)
	}
}

func TestOpenShellDynamicCreateBackendRefusesUIDChangedBeforePatch(t *testing.T) {
	fake := newFakeAgentSandboxCreateDynamicClient()
	seedSandboxObject(t, fake, "sandbox-a", "replacement-uid", "rv-42", sandboxAPIVersionV1Beta1)
	err := newDynamicAgentSandboxCreateBackend(fake).ActivateSandboxController(context.Background(), "team-a", sandboxAPIVersionV1Beta1, "sandbox-a", "original-uid")
	if err == nil || !strings.Contains(err.Error(), "UID changed") {
		t.Fatalf("ActivateSandboxController() error = %v; want UID replacement rejection", err)
	}
	for _, action := range fake.Actions() {
		if action.GetVerb() == "patch" {
			t.Fatalf("UID replacement must prevent patch: %#v", fake.Actions())
		}
	}
}

func TestOpenShellDynamicCreateBackendReleasesPodGateWithResourceVersion(t *testing.T) {
	fake := newFakeAgentSandboxCreateDynamicClient()
	pod := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "team-a-demo", "namespace": "team-a", "uid": "workload-uid", "resourceVersion": "rv-77"},
		"spec":     map[string]any{"schedulingGates": []any{map[string]any{"name": sandboxRuntimeBootstrapGate}}},
	}}
	if err := fake.Tracker().Create(coreV1GVR("pods"), pod, "team-a"); err != nil {
		t.Fatalf("seed gated Pod: %v", err)
	}
	var observedPatch map[string]any
	fake.PrependReactor("patch", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		patchAction := action.(k8stesting.PatchAction)
		return true, nil, json.Unmarshal(patchAction.GetPatch(), &observedPatch)
	})
	if err := newDynamicAgentSandboxCreateBackend(fake).ReleaseSchedulingGate(context.Background(), "team-a", "team-a-demo", "workload-uid"); err != nil {
		t.Fatalf("ReleaseSchedulingGate() error = %v", err)
	}
	if observedPatch["metadata"].(map[string]any)["resourceVersion"] != "rv-77" || len(observedPatch["spec"].(map[string]any)["schedulingGates"].([]any)) != 0 {
		t.Fatalf("scheduling gate patch = %#v", observedPatch)
	}
}

func TestOpenShellDynamicCreateBackendDeleteUsesUIDPrecondition(t *testing.T) {
	fake := newFakeAgentSandboxCreateDynamicClient()
	seedSandboxObject(t, fake, "sandbox-a", "sandbox-uid-a", "rv-42", sandboxAPIVersionV1Beta1)
	var precondition types.UID
	fake.PrependReactor("delete", "sandboxes", func(action k8stesting.Action) (bool, runtime.Object, error) {
		deleteAction := action.(interface{ GetDeleteOptions() metav1.DeleteOptions })
		if deleteAction.GetDeleteOptions().Preconditions != nil && deleteAction.GetDeleteOptions().Preconditions.UID != nil {
			precondition = *deleteAction.GetDeleteOptions().Preconditions.UID
		}
		return true, nil, nil
	})
	if err := newDynamicAgentSandboxCreateBackend(fake).DeleteSandbox(context.Background(), "team-a", sandboxAPIGroup+"/"+sandboxAPIVersionV1Beta1, "sandbox-a", "sandbox-uid-a"); err != nil {
		t.Fatalf("DeleteSandbox() error = %v", err)
	}
	if precondition != "sandbox-uid-a" {
		t.Fatalf("Delete UID precondition = %q; want sandbox-uid-a", precondition)
	}
}

func TestOpenShellDynamicCreateBackendDoesNotDeleteReplacementSandbox(t *testing.T) {
	fake := newFakeAgentSandboxCreateDynamicClient()
	seedSandboxObject(t, fake, "sandbox-a", "replacement-uid", "rv-42", sandboxAPIVersionV1Beta1)
	err := newDynamicAgentSandboxCreateBackend(fake).DeleteSandbox(context.Background(), "team-a", sandboxAPIGroup+"/"+sandboxAPIVersionV1Beta1, "sandbox-a", "sandbox-uid-a")
	if err == nil || !strings.Contains(err.Error(), "UID precondition") {
		t.Fatalf("DeleteSandbox() error = %v; want replacement UID refusal", err)
	}
	for _, action := range fake.Actions() {
		if action.GetVerb() == "delete" {
			t.Fatalf("replacement sandbox must not be deleted: %#v", fake.Actions())
		}
	}
}

func TestOpenShellDynamicWorkloadObservationMatchesRenderedPodAndRejectsAdmissionChanges(t *testing.T) {
	input := testAgentSandboxCreateSequenceInput()
	expectedSpec, _, _ := unstructured.NestedMap(input.SandboxResource, "spec", "podTemplate", "spec")
	labels, _, _ := unstructured.NestedMap(input.SandboxResource, "spec", "podTemplate", "metadata", "labels")
	owner := map[string]any{
		"apiVersion": input.RuntimeParams.SandboxResourceAPIVersion,
		"kind":       "Sandbox", "name": input.RuntimeParams.SandboxResourceName, "uid": "sandbox-cr-uid",
		"blockOwnerDeletion": false,
	}
	newPod := func() *unstructured.Unstructured {
		podSpec := runtime.DeepCopyJSON(expectedSpec)
		podSpec["volumes"] = sandboxPodVolumesWithClaimTemplates(input.SandboxResource, expectedSpec)
		return &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{
				"name": input.RuntimeParams.SandboxResourceName, "namespace": input.RuntimeParams.Namespace,
				"uid": "workload-pod-uid", "labels": labels, "ownerReferences": []any{owner},
			},
			"spec": podSpec,
		}}
	}
	identity := workloadIdentityFromPod(newPod(), input.SandboxResource)
	if err := validateAgentSandboxWorkloadIdentity(identity, input.RuntimeParams, "sandbox-cr-uid", input.SandboxResource); err != nil {
		t.Fatalf("rendered workload Pod observation should validate: %v", err)
	}
	t.Run("Kubernetes API defaults and generated workspace claim", func(t *testing.T) {
		pod := newPod()
		containers, _, _ := unstructured.NestedSlice(pod.Object, "spec", "containers")
		agent := containers[0].(map[string]any)
		env := sliceValue(agent["env"])
		delete(env[0].(map[string]any), "value") // API omits an empty EnvVar value.
		agent["resources"] = map[string]any{}    // API persists an empty requirements object.
		_ = unstructured.SetNestedSlice(pod.Object, containers, "spec", "containers")
		security, _, _ := unstructured.NestedMap(pod.Object, "spec", "securityContext")
		delete(security, "supplementalGroups") // API omits an empty group list.
		_ = unstructured.SetNestedMap(pod.Object, security, "spec", "securityContext")

		identity := workloadIdentityFromPod(pod, input.SandboxResource)
		if err := validateAgentSandboxWorkloadIdentity(identity, input.RuntimeParams, "sandbox-cr-uid", input.SandboxResource); err != nil {
			t.Fatalf("Kubernetes defaults and controller generated workspace PVC should validate: %v", err)
		}
	})
	t.Run("changed generated workspace claim", func(t *testing.T) {
		pod := newPod()
		volumes := sliceValue(pod.Object["spec"].(map[string]any)["volumes"])
		for _, value := range volumes {
			volume := value.(map[string]any)
			if volume["name"] == workspaceVolumeName {
				volume["persistentVolumeClaim"].(map[string]any)["claimName"] = "attacker-pvc"
			}
		}
		_ = unstructured.SetNestedSlice(pod.Object, volumes, "spec", "volumes")
		identity := workloadIdentityFromPod(pod, input.SandboxResource)
		if err := validateAgentSandboxWorkloadIdentity(identity, input.RuntimeParams, "sandbox-cr-uid", input.SandboxResource); err == nil {
			t.Fatal("workload Pod with a changed generated workspace claim should be rejected")
		}
	})

	t.Run("extra init container", func(t *testing.T) {
		pod := newPod()
		initContainers, _, _ := unstructured.NestedSlice(pod.Object, "spec", "initContainers")
		initContainers = append(initContainers, map[string]any{"name": "injected", "image": "attacker"})
		_ = unstructured.SetNestedSlice(pod.Object, initContainers, "spec", "initContainers")
		identity := workloadIdentityFromPod(pod, input.SandboxResource)
		if err := validateAgentSandboxWorkloadIdentity(identity, input.RuntimeParams, "sandbox-cr-uid", input.SandboxResource); err == nil {
			t.Fatal("admitted workload with an injected init container should be rejected")
		}
	})
	t.Run("host path volume", func(t *testing.T) {
		pod := newPod()
		volumes, _, _ := unstructured.NestedSlice(pod.Object, "spec", "volumes")
		volumes = append(volumes, map[string]any{"name": "host", "hostPath": map[string]any{"path": "/"}})
		_ = unstructured.SetNestedSlice(pod.Object, volumes, "spec", "volumes")
		identity := workloadIdentityFromPod(pod, input.SandboxResource)
		if err := validateAgentSandboxWorkloadIdentity(identity, input.RuntimeParams, "sandbox-cr-uid", input.SandboxResource); err == nil {
			t.Fatal("admitted workload with a hostPath volume should be rejected")
		}
	})
}

func newFakeAgentSandboxCreateDynamicClient() *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		agentSandboxGVR(sandboxAPIVersionV1Beta1):  "SandboxList",
		agentSandboxGVR(sandboxAPIVersionV1Alpha1): "SandboxList",
		coreV1GVR("namespaces"):                    "NamespaceList",
		coreV1GVR("services"):                      "ServiceList",
		coreV1GVR("pods"):                          "PodList",
		coreV1GVR("secrets"):                       "SecretList",
		networkPolicyV1GVR:                         "NetworkPolicyList",
	})
}

func seedSandboxObject(t *testing.T, fake *dynamicfake.FakeDynamicClient, name, uid, resourceVersion, version string) {
	t.Helper()
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": sandboxAPIGroup + "/" + version,
		"kind":       "Sandbox",
		"metadata": map[string]any{
			"name": name, "namespace": "team-a", "uid": uid, "resourceVersion": resourceVersion,
		},
		"spec": map[string]any{"operatingMode": "Suspended"},
	}}
	if err := fake.Tracker().Create(agentSandboxGVR(version), object, "team-a"); err != nil {
		t.Fatalf("seed Agent Sandbox: %v", err)
	}
}
