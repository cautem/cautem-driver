package kubernetes

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// These render cases port the driver_config_pvc_subpath_mounts_render_in_pod_template
// and scheduling/resource projection contracts from the pinned OpenShell source:
// tools/upstream/openshell/crates/openshell-driver-kubernetes/src/driver.rs at
// 77c5ff6e20c98b3674616ecf35b2464f2b8e57ca.
func TestCompatDriverConfigRendersPVCSubpathMounts(t *testing.T) {
	config, err := ParseSandboxDriverConfig(`{
		"volumes": [{
			"name": "user-data",
			"persistent_volume_claim": {"claim_name": "pvc-user-data-123", "read_only": false}
		}],
		"containers": {"agent": {"volume_mounts": [
			{"name": "user-data", "mount_path": "/sandbox/.openshell/workspace", "sub_path": "workspace", "read_only": false},
			{"name": "user-data", "mount_path": "/sandbox/.openshell/memory", "sub_path": "memory"}
		]}}
	}`)
	if err != nil {
		t.Fatalf("ParseSandboxDriverConfig() error = %v", err)
	}

	got, err := renderDriverConfigFragment(config)
	if err != nil {
		t.Fatalf("renderDriverConfigFragment() error = %v", err)
	}
	want := map[string]any{
		"spec": map[string]any{
			"containers": []any{map[string]any{
				"name": "agent",
				"volumeMounts": []any{
					map[string]any{"name": "user-data", "mountPath": "/sandbox/.openshell/workspace", "subPath": "workspace", "readOnly": false},
					map[string]any{"name": "user-data", "mountPath": "/sandbox/.openshell/memory", "subPath": "memory", "readOnly": true},
				},
			}},
			"volumes": []any{map[string]any{
				"name":                  "user-data",
				"persistentVolumeClaim": map[string]any{"claimName": "pvc-user-data-123", "readOnly": false},
			}},
		},
	}
	assertJSONEqual(t, got, want)
}

func TestCompatDriverConfigRendersSchedulingAndAgentResources(t *testing.T) {
	config, err := ParseSandboxDriverConfig(`{
		"pod": {
			"node_selector": {"pool": "sandbox", "zone": "west"},
			"runtime_class_name": "gvisor",
			"tolerations": [{"key": "sandbox", "operator": "Exists", "effect": "NoSchedule"}],
			"priority_class_name": "sandbox-low"
		},
		"containers": {"agent": {
			"resources": {"requests": {"cpu": "250m", "memory": "256Mi"}, "limits": {"cpu": "1", "memory": "1Gi"}}
		}}
	}`)
	if err != nil {
		t.Fatalf("ParseSandboxDriverConfig() error = %v", err)
	}

	got, err := renderDriverConfigFragment(config)
	if err != nil {
		t.Fatalf("renderDriverConfigFragment() error = %v", err)
	}
	want := map[string]any{
		"spec": map[string]any{
			"nodeSelector":      map[string]any{"pool": "sandbox", "zone": "west"},
			"runtimeClassName":  "gvisor",
			"tolerations":       []any{map[string]any{"key": "sandbox", "operator": "Exists", "effect": "NoSchedule"}},
			"priorityClassName": "sandbox-low",
			"containers": []any{map[string]any{
				"name": "agent",
				"resources": map[string]any{
					"requests": map[string]any{"cpu": "250m", "memory": "256Mi"},
					"limits":   map[string]any{"cpu": "1", "memory": "1Gi"},
				},
				"volumeMounts": []any{},
			}},
			"volumes": []any{},
		},
	}
	assertJSONEqual(t, got, want)
}

func TestCompatDriverConfigSuppressesDefaultWorkspaceForSandboxMount(t *testing.T) {
	config, err := ParseSandboxDriverConfig(`{
		"volumes": [{"name": "workspace-data", "persistent_volume_claim": {"claim_name": "pvc-workspace"}}],
		"containers": {"agent": {"volume_mounts": [
			{"name": "workspace-data", "mount_path": "/sandbox/.openshell/workspace", "sub_path": "workspace"}
		]}}
	}`)
	if err != nil {
		t.Fatalf("ParseSandboxDriverConfig() error = %v", err)
	}
	if shouldInjectDefaultWorkspace(config) {
		t.Fatal("default workspace PVC should be suppressed when driver_config owns /sandbox storage")
	}

	config, err = ParseSandboxDriverConfig(`{"volumes":[{"name":"user-data","persistent_volume_claim":{"claim_name":"pvc-user-data"}}]}`)
	if err != nil {
		t.Fatalf("ParseSandboxDriverConfig() without mounts error = %v", err)
	}
	if !shouldInjectDefaultWorkspace(config) {
		t.Fatal("default workspace PVC should be injected when driver_config does not mount under /sandbox")
	}
}

func TestRenderDriverConfigFragmentRevalidatesTypedConfig(t *testing.T) {
	_, err := renderDriverConfigFragment(SandboxDriverConfig{
		Volumes: []VolumeDriverConfig{{
			Name: "workspace",
			PersistentVolumeClaim: PersistentVolumeClaimConfig{
				ClaimName: "pvc-user-data",
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "reserved for OpenShell-managed volumes") {
		t.Fatalf("renderDriverConfigFragment() error = %v; want reserved managed volume error", err)
	}
}

func assertJSONEqual(t *testing.T, got, want any) {
	t.Helper()

	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal rendered fragment: %v", err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal expected fragment: %v", err)
	}
	var gotValue, wantValue any
	if err := json.Unmarshal(gotJSON, &gotValue); err != nil {
		t.Fatalf("decode rendered fragment: %v", err)
	}
	if err := json.Unmarshal(wantJSON, &wantValue); err != nil {
		t.Fatalf("decode expected fragment: %v", err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("rendered fragment mismatch:\n got: %s\nwant: %s", gotJSON, wantJSON)
	}
}
