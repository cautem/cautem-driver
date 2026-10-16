package kubernetes

import (
	"context"
	"strings"
	"testing"

	"github.com/cautem/quarshell-driver/driver"
)

// These cases translate OpenShell's driver_config_* tests in
// crates/openshell-driver-kubernetes/src/driver.rs (pinned upstream commit
// 77c5ff6e20c98b3674616ecf35b2464f2b8e57ca). Runtime provisioning remains a
// separate unimplemented contract.
func TestCompatDriverConfigValidationContract(t *testing.T) {
	tests := []struct {
		name, config, want string
	}{
		{
			name:   "invalid shape",
			config: `{"pod":"not-an-object"}`,
			want:   "invalid kubernetes driver_config",
		},
		{
			name:   "null shape",
			config: `null`,
			want:   "must be an object",
		},
		{
			name:   "null nested object",
			config: `{"pod":null}`,
			want:   "pod must be an object",
		},
		{
			name:   "unknown field",
			config: `{"cdi_devices":["nvidia.com/gpu=0"]}`,
			want:   "unknown field",
		},
		{
			name:   "duplicate PVC volume names",
			config: `{"volumes":[{"name":"user-data","persistent_volume_claim":{"claim_name":"pvc-a"}},{"name":"user-data","persistent_volume_claim":{"claim_name":"pvc-b"}}]}`,
			want:   "duplicate kubernetes driver_config volume",
		},
		{
			name:   "duplicate mount targets",
			config: `{"volumes":[{"name":"user-data","persistent_volume_claim":{"claim_name":"pvc-user-data"}}],"containers":{"agent":{"volume_mounts":[{"name":"user-data","mount_path":"/sandbox/.openshell/workspace"},{"name":"user-data","mount_path":"/sandbox/.openshell/workspace"}]}}}`,
			want:   "duplicate kubernetes driver_config mount target",
		},
		{
			name:   "duplicate normalized mount targets",
			config: `{"volumes":[{"name":"user-data","persistent_volume_claim":{"claim_name":"pvc-user-data"}}],"containers":{"agent":{"volume_mounts":[{"name":"user-data","mount_path":"/sandbox/.openshell/workspace"},{"name":"user-data","mount_path":"/sandbox/.openshell/workspace/"}]}}}`,
			want:   "duplicate kubernetes driver_config mount target",
		},
		{
			name:   "unknown nested field",
			config: `{"pod":{"runtime_class":"untrusted"}}`,
			want:   "unknown field",
		},
		{
			name:   "invalid volume DNS label",
			config: `{"volumes":[{"name":"User_Data","persistent_volume_claim":{"claim_name":"pvc-data"}}]}`,
			want:   "DNS-1123 label",
		},
		{
			name:   "invalid PVC claim DNS name",
			config: `{"volumes":[{"name":"user-data","persistent_volume_claim":{"claim_name":"Pvc_User_Data"}}]}`,
			want:   "DNS-1123 subdomain",
		},
		{
			name:   "unknown mounted volume",
			config: `{"containers":{"agent":{"volume_mounts":[{"name":"missing","mount_path":"/sandbox/data"}]}}}`,
			want:   "unknown kubernetes driver_config volume",
		},
		{
			name:   "read-only PVC cannot become writable",
			config: `{"volumes":[{"name":"user-data","persistent_volume_claim":{"claim_name":"pvc-data"}}],"containers":{"agent":{"volume_mounts":[{"name":"user-data","mount_path":"/sandbox/data","read_only":false}]}}}`,
			want:   "cannot set read_only=false",
		},
		{
			name:   "subpath traversal",
			config: `{"volumes":[{"name":"user-data","persistent_volume_claim":{"claim_name":"pvc-data"}}],"containers":{"agent":{"volume_mounts":[{"name":"user-data","mount_path":"/sandbox/data","sub_path":"../secrets"}]}}}`,
			want:   "subpath must be relative",
		},
		{
			name:   "mount path dot segment",
			config: `{"volumes":[{"name":"user-data","persistent_volume_claim":{"claim_name":"pvc-data"}}],"containers":{"agent":{"volume_mounts":[{"name":"user-data","mount_path":"/sandbox/data/../secrets"}]}}}`,
			want:   "must be normalized",
		},
		{
			name:   "protected service account path",
			config: `{"volumes":[{"name":"user-data","persistent_volume_claim":{"claim_name":"pvc-data"}}],"containers":{"agent":{"volume_mounts":[{"name":"user-data","mount_path":"/var/run/secrets/openshell/custom"}]}}}`,
			want:   "/var/run/secrets/openshell",
		},
		{
			name:   "reserved runtime volume name",
			config: `{"volumes":[{"name":"openshell-runtime","persistent_volume_claim":{"claim_name":"pvc-data"}}]}`,
			want:   "reserved for OpenShell-managed volumes",
		},
		{
			name:   "trusted runtime image override",
			config: `{"sandbox_runtime_image":"registry.example.com/untrusted:latest"}`,
			want:   "unknown field",
		},
		{
			name:   "trailing JSON value",
			config: `{} {}`,
			want:   "must be an object",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New().Create(context.Background(), driver.Spec{
				Name:             "contract-sandbox",
				Image:            "cautem-sandbox:local",
				DriverConfigJSON: tt.config,
			})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Create() error = %v; want error containing %q", err, tt.want)
			}
		})
	}
}

func TestCompatDriverConfigDefaultsPVCAndMountsToReadOnly(t *testing.T) {
	config, err := ParseSandboxDriverConfig(`{"volumes":[{"name":"user-data","persistent_volume_claim":{"claim_name":"pvc.user-data.123"}}],"containers":{"agent":{"volume_mounts":[{"name":"user-data","mount_path":"/sandbox/.openshell/workspace","sub_path":"workspace"}]}}}`)
	if err != nil {
		t.Fatalf("ParseSandboxDriverConfig() error = %v", err)
	}
	if len(config.Volumes) != 1 || !defaultReadOnly(config.Volumes[0].PersistentVolumeClaim.ReadOnly) {
		t.Fatalf("PVC defaults = %#v; want one read-only volume", config.Volumes)
	}
	if len(config.Containers.Agent.VolumeMounts) != 1 || !defaultReadOnly(config.Containers.Agent.VolumeMounts[0].ReadOnly) {
		t.Fatalf("mount defaults = %#v; want one read-only mount", config.Containers.Agent.VolumeMounts)
	}
}

func TestCompatDriverConfigAcceptsDNSSubdomainClaimAndTrailingMountSlash(t *testing.T) {
	config, err := ParseSandboxDriverConfig(`{"volumes":[{"name":"user-data","persistent_volume_claim":{"claim_name":"pvc.user-data.123"}}],"containers":{"agent":{"volume_mounts":[{"name":"user-data","mount_path":"/sandbox/.openshell/workspace/"}]}}}`)
	if err != nil {
		t.Fatalf("ParseSandboxDriverConfig() error = %v; OpenShell accepts a trailing mount slash", err)
	}
	if got := config.Volumes[0].PersistentVolumeClaim.ClaimName; got != "pvc.user-data.123" {
		t.Fatalf("PVC claim name = %q; want DNS-1123 subdomain", got)
	}
}

func TestCompatDriverConfigAcceptsReadWritePVCWithMultipleSubpathMounts(t *testing.T) {
	config, err := ParseSandboxDriverConfig(`{"volumes":[{"name":"user-data","persistent_volume_claim":{"claim_name":"pvc-user-data","read_only":false}}],"containers":{"agent":{"volume_mounts":[{"name":"user-data","mount_path":"/sandbox/.openshell/workspace","sub_path":"workspace","read_only":false},{"name":"user-data","mount_path":"/sandbox/.openshell/memory","sub_path":"memory","read_only":false},{"name":"user-data","mount_path":"/sandbox/.openshell/sessions","sub_path":"sessions","read_only":false}]}}}`)
	if err != nil {
		t.Fatalf("ParseSandboxDriverConfig() error = %v; want writable PVC with multiple subpaths", err)
	}
	if len(config.Volumes) != 1 || defaultReadOnly(config.Volumes[0].PersistentVolumeClaim.ReadOnly) {
		t.Fatalf("PVC config = %#v; want one writable PVC", config.Volumes)
	}
	if len(config.Containers.Agent.VolumeMounts) != 3 {
		t.Fatalf("mount count = %d; want 3", len(config.Containers.Agent.VolumeMounts))
	}
	for _, mount := range config.Containers.Agent.VolumeMounts {
		if defaultReadOnly(mount.ReadOnly) || mount.SubPath == "" {
			t.Fatalf("mount = %#v; want writable subpath mount", mount)
		}
	}
}

func TestCompatDriverConfigRejectsEveryManagedVolumeName(t *testing.T) {
	for _, name := range []string{
		"openshell-client-tls",
		"openshell-upstream-proxy-auth",
		"openshell-sa-token",
		"spiffe-workload-api",
		"openshell-runtime",
		"openshell-runtime-state",
		"openshell-sandbox-bootstrap",
		"openshell-pod-identity",
		"openshell-run",
		"workspace",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseSandboxDriverConfig(`{"volumes":[{"name":"` + name + `","persistent_volume_claim":{"claim_name":"pvc-user-data"}}]}`)
			if err == nil || !strings.Contains(err.Error(), "reserved for OpenShell-managed volumes") {
				t.Fatalf("ParseSandboxDriverConfig(%q) error = %v; want reserved-volume error", name, err)
			}
		})
	}
}
