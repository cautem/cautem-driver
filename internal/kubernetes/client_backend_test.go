package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestSameOwnedGenerationResourceAcceptsEmptySecretDataOmission(t *testing.T) {
	owner := map[string]any{"apiVersion": "v1", "kind": "Pod", "name": "proxy", "uid": "pod-uid", "blockOwnerDeletion": false}
	expected := map[string]any{
		"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "immutable": true,
		"metadata": map[string]any{
			"name": "provider-env", "namespace": "workspace",
			"ownerReferences": []any{owner}, "labels": map[string]any{"role": "proxy"},
		},
		"data": map[string]any{},
	}
	actual := map[string]any{
		"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "immutable": true,
		"metadata": map[string]any{
			"name": "provider-env", "namespace": "workspace",
			"ownerReferences": []any{owner}, "labels": map[string]any{"role": "proxy"},
		},
	}
	if !sameOwnedGenerationResource(actual, expected) {
		t.Fatal("Kubernetes Secret with omitted empty data was rejected")
	}
	actual["data"] = map[string]any{"unexpected": "Zm9v"}
	if sameOwnedGenerationResource(actual, expected) {
		t.Fatal("Kubernetes Secret with unexpected data was accepted")
	}
}

func TestOpenShellDynamicClientDiscoversAlphaAfterBetaNotFound(t *testing.T) {
	fake := newFakeAgentSandboxDynamicClient()
	gvr := agentSandboxGVR(sandboxAPIVersionV1Beta1)
	fake.PrependReactor("list", "sandboxes", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetResource().Version == sandboxAPIVersionV1Beta1 {
			return true, nil, apierrors.NewNotFound(gvr.GroupResource(), "")
		}
		return false, nil, nil
	})

	client := newDynamicAgentSandboxAPIClient(fake)
	version, err := detectSandboxAPIVersion(context.Background(), client, "openshell")
	if err != nil {
		t.Fatalf("detectSandboxAPIVersion() error = %v", err)
	}
	if version != sandboxAPIVersionV1Alpha1 {
		t.Fatalf("selected version = %q; want %q", version, sandboxAPIVersionV1Alpha1)
	}

	actions := fake.Actions()
	if len(actions) != 2 {
		t.Fatalf("dynamic client actions = %#v; want beta and alpha list", actions)
	}
	for i, wantVersion := range []string{sandboxAPIVersionV1Beta1, sandboxAPIVersionV1Alpha1} {
		if got := actions[i].GetResource().Version; got != wantVersion {
			t.Fatalf("action[%d] version = %q; want %q", i, got, wantVersion)
		}
		if got := actions[i].GetNamespace(); got != "openshell" {
			t.Fatalf("action[%d] namespace = %q; want openshell", i, got)
		}
		listAction, ok := actions[i].(interface{ GetListOptions() metav1.ListOptions })
		if !ok || listAction.GetListOptions().Limit != 1 {
			t.Fatalf("action[%d] list options = %#v; want limit=1", i, actions[i])
		}
	}
}

func TestOpenShellDynamicClientListAndWatchUseAgentSandboxResourceVersion(t *testing.T) {
	fake := newFakeAgentSandboxDynamicClient()
	fake.PrependWatchReactor("sandboxes", func(action k8stesting.Action) (bool, watch.Interface, error) {
		return true, watch.NewFake(), nil
	})
	client := newDynamicAgentSandboxAPIClient(fake)

	if _, err := client.ListSandboxObjects(context.Background(), sandboxAPIVersionV1Beta1, "openshell"); err != nil {
		t.Fatalf("ListSandboxObjects() error = %v", err)
	}
	watcher, err := client.WatchSandboxObjects(context.Background(), sandboxAPIVersionV1Beta1, "openshell", "73")
	if err != nil {
		t.Fatalf("WatchSandboxObjects() error = %v", err)
	}
	watcher.Stop()

	actions := fake.Actions()
	if len(actions) != 2 {
		t.Fatalf("dynamic client actions = %#v; want one LIST and one WATCH", actions)
	}
	for i, action := range actions {
		if action.GetResource() != agentSandboxGVR(sandboxAPIVersionV1Beta1) {
			t.Fatalf("action[%d] resource = %#v; want Agent Sandbox beta GVR", i, action.GetResource())
		}
		if action.GetNamespace() != "openshell" {
			t.Fatalf("action[%d] namespace = %q; want openshell", i, action.GetNamespace())
		}
	}
	watchAction, ok := actions[1].(k8stesting.WatchAction)
	if !ok {
		t.Fatalf("second action type = %T; want WatchAction", actions[1])
	}
	if got := watchAction.GetWatchRestrictions().ResourceVersion; got != "73" {
		t.Fatalf("watch resourceVersion = %q; want 73", got)
	}
}

func TestOpenShellDynamicClientRetriesResourceVersionConflict(t *testing.T) {
	fake := newFakeAgentSandboxDynamicClient()
	resource := fake.Resource(agentSandboxGVR(sandboxAPIVersionV1Beta1)).Namespace("openshell")
	_, err := resource.Create(context.Background(), sandboxObject("40"), metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("seed fake sandbox: %v", err)
	}

	getCount := 0
	fake.PrependReactor("get", "sandboxes", func(action k8stesting.Action) (bool, runtime.Object, error) {
		getCount++
		return true, sandboxObject(fmt.Sprintf("%d", 39+getCount)), nil
	})

	patchCount := 0
	var observedPatches []map[string]any
	fake.PrependReactor("patch", "sandboxes", func(action k8stesting.Action) (bool, runtime.Object, error) {
		patchAction, ok := action.(k8stesting.PatchAction)
		if !ok {
			return true, nil, fmt.Errorf("unexpected patch action type %T", action)
		}
		if patchAction.GetPatchType() != types.MergePatchType {
			return true, nil, fmt.Errorf("patch type = %q; want %q", patchAction.GetPatchType(), types.MergePatchType)
		}
		var patch map[string]any
		if err := json.Unmarshal(patchAction.GetPatch(), &patch); err != nil {
			return true, nil, err
		}
		observedPatches = append(observedPatches, patch)
		patchCount++
		if patchCount == 1 {
			return true, nil, apierrors.NewConflict(
				agentSandboxGVR(sandboxAPIVersionV1Beta1).GroupResource(),
				"sandbox-a",
				errors.New("resourceVersion changed"),
			)
		}
		return true, nil, nil
	})

	client := newDynamicAgentSandboxAPIClient(fake)
	err = patchSandboxWithResourceVersionRetry(
		context.Background(),
		client,
		sandboxAPIVersionV1Beta1,
		"openshell",
		"sandbox-a",
		func(resourceVersion string) (map[string]any, error) {
			fields, err := sandboxDesiredStateFields(sandboxAPIVersionV1Beta1, true)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"metadata": map[string]any{"resourceVersion": resourceVersion},
				"spec":     fields,
			}, nil
		},
	)
	if err != nil {
		t.Fatalf("patchSandboxWithResourceVersionRetry() error = %v", err)
	}
	if getCount != 2 || patchCount != 2 {
		t.Fatalf("GET/PATCH counts = %d/%d; want 2/2 after one conflict", getCount, patchCount)
	}
	if len(observedPatches) != 2 {
		t.Fatalf("observed patches = %#v; want two", observedPatches)
	}
	for i, wantVersion := range []string{"40", "41"} {
		metadata, _ := observedPatches[i]["metadata"].(map[string]any)
		if got := metadata["resourceVersion"]; got != wantVersion {
			t.Fatalf("patch[%d] resourceVersion = %#v; want %q", i, got, wantVersion)
		}
		if got := observedPatches[i]["spec"].(map[string]any)["operatingMode"]; got != "Running" {
			t.Fatalf("patch[%d] operatingMode = %#v; want Running", i, got)
		}
	}
}

func TestOpenShellDynamicClientStopsConflictRetryOnCancellation(t *testing.T) {
	fake := newFakeAgentSandboxDynamicClient()
	ctx, cancel := context.WithCancel(context.Background())
	getCount := 0
	fake.PrependReactor("get", "sandboxes", func(action k8stesting.Action) (bool, runtime.Object, error) {
		getCount++
		return true, sandboxObject("40"), nil
	})
	patchCount := 0
	fake.PrependReactor("patch", "sandboxes", func(action k8stesting.Action) (bool, runtime.Object, error) {
		patchCount++
		cancel()
		return true, nil, apierrors.NewConflict(
			agentSandboxGVR(sandboxAPIVersionV1Beta1).GroupResource(),
			"sandbox-a",
			errors.New("resourceVersion changed"),
		)
	})
	client := newDynamicAgentSandboxAPIClient(fake)

	err := patchSandboxWithResourceVersionRetry(
		ctx,
		client,
		sandboxAPIVersionV1Beta1,
		"openshell",
		"sandbox-a",
		func(resourceVersion string) (map[string]any, error) {
			return map[string]any{"metadata": map[string]any{"resourceVersion": resourceVersion}}, nil
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("patchSandboxWithResourceVersionRetry() error = %v; want context.Canceled", err)
	}
	if getCount != 1 || patchCount != 1 {
		t.Fatalf("GET/PATCH counts = %d/%d; want 1/1 after cancellation", getCount, patchCount)
	}
}

func newFakeAgentSandboxDynamicClient() *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			agentSandboxGVR(sandboxAPIVersionV1Beta1):  "SandboxList",
			agentSandboxGVR(sandboxAPIVersionV1Alpha1): "SandboxList",
		},
	)
}

func sandboxObject(resourceVersion string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": sandboxAPIGroup + "/" + sandboxAPIVersionV1Beta1,
		"kind":       "Sandbox",
		"metadata": map[string]any{
			"name":            "sandbox-a",
			"namespace":       "openshell",
			"resourceVersion": resourceVersion,
		},
		"spec": map[string]any{"operatingMode": "Suspended"},
	}}
}
