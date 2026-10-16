package docker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cautem/cautem-core/resourceadmission"
	"github.com/cautem/cautem-driver/driver"
	"github.com/moby/moby/api/types/container"
	enginemount "github.com/moby/moby/api/types/mount"
	volumetypes "github.com/moby/moby/api/types/volume"
)

func TestCreateRejectsCallerDriverConfigBeforeEngineMutation(t *testing.T) {
	requests := 0
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		t.Errorf("unexpected Engine request before caller driver_config authorization: %s %s", r.Method, r.URL)
		http.NotFound(w, r)
	})
	_, err := d.Create(context.Background(), driver.Spec{
		Name: "unauthorized-config", Image: "alpine:3.22", Workspace: t.TempDir(),
		DriverConfigJSON: `{"mounts":[]}`,
	})
	if err == nil || !strings.Contains(err.Error(), "allow_driver_config") {
		t.Fatalf("Create() error=%v; want explicit operator gate failure", err)
	}
	if requests != 0 {
		t.Fatalf("Create made %d Engine requests before rejecting config", requests)
	}
}

func TestBackendValidateCreateRunsContextAwareDriverPreflight(t *testing.T) {
	requests := 0
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		t.Errorf("unexpected Engine request before backend preflight rejection: %s %s", r.Method, r.URL)
		http.NotFound(w, r)
	})
	backend, err := driver.AdaptLegacyEngine("docker", d)
	if err != nil {
		t.Fatal(err)
	}
	err = backend.ValidateCreate(context.Background(), driver.BackendCreateRequest{
		SandboxID: "preflight",
		Name:      "preflight",
		Workspace: driver.WorkspaceTarget{ID: "team-a", HostPath: t.TempDir()},
		Workload:  driver.WorkloadSpec{Image: "alpine:3.22"},
		Labels:    map[string]string{driver.WorkspaceLabel: "team-a"},
		Config:    map[string]any{"mounts": []any{}},
	})
	if err == nil || !strings.Contains(err.Error(), "allow_driver_config") {
		t.Fatalf("Backend.ValidateCreate() error=%v; want context-aware operator gate failure", err)
	}
	if requests != 0 {
		t.Fatalf("Backend.ValidateCreate made %d Engine requests for an unauthorized config", requests)
	}
}

func TestValidateExternalDriverMountsRequiresWorkspaceApproval(t *testing.T) {
	for _, workspaceLabel := range []string{"team-a", "team-b"} {
		t.Run(workspaceLabel, func(t *testing.T) {
			d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1.41/volumes/cache" || r.Method != http.MethodGet {
					t.Errorf("unexpected Engine request: %s %s", r.Method, r.URL)
					http.NotFound(w, r)
					return
				}
				_, _ = io.WriteString(w, `{"Name":"cache","Driver":"local","CreatedAt":"2026-10-16T00:00:00Z","Mountpoint":"/var/lib/docker/volumes/cache/_data","Labels":{"openshell.ai/sandbox-attachable":"true","openshell.ai/sandbox-attachable-workspace":"`+workspaceLabel+`"},"Options":{}}`)
			})
			spec := driver.Spec{Labels: map[string]string{driver.WorkspaceLabel: "team-a"}}
			identities, err := d.validateExternalDriverMounts(context.Background(), spec, []enginemount.Mount{{Type: enginemount.TypeVolume, Source: "cache"}}, resourceadmission.Default())
			if workspaceLabel == "team-a" {
				if err != nil || identities["cache"] == "" {
					t.Fatalf("approved volume identities=%v err=%v", identities, err)
				}
			} else if err == nil {
				t.Fatal("cross-workspace volume was admitted")
			}
		})
	}
}

func TestValidateExternalDriverMountsRejectsUnlabelableBind(t *testing.T) {
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected Engine request for bind mount admission: %s %s", r.Method, r.URL)
		http.NotFound(w, r)
	})
	_, err := d.validateExternalDriverMounts(context.Background(), driver.Spec{}, []enginemount.Mount{{Type: enginemount.TypeBind}}, resourceadmission.Default())
	if err == nil || !strings.Contains(err.Error(), "no trusted label resolver") {
		t.Fatalf("bind admission error=%v; want fail-closed policy denial", err)
	}
}

func TestStartRevalidatesExternalVolumeLabelsAndIdentity(t *testing.T) {
	for _, workspaceLabel := range []string{"team-a", "team-b"} {
		t.Run(workspaceLabel, func(t *testing.T) {
			volume := volumetypes.Volume{
				Name: "cache", Driver: "local", CreatedAt: "2026-10-16T00:00:00Z",
				Mountpoint: "/var/lib/docker/volumes/cache/_data",
				Labels: map[string]string{
					"openshell.ai/sandbox-attachable":           "true",
					"openshell.ai/sandbox-attachable-workspace": workspaceLabel,
				},
				Options: map[string]string{},
			}
			serverVolume, err := json.Marshal(volume)
			if err != nil {
				t.Fatal(err)
			}
			d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1.41/volumes/cache" || r.Method != http.MethodGet {
					t.Errorf("unexpected Engine request: %s %s", r.Method, r.URL)
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write(serverVolume)
			})
			d.runtimeConfig.AllowDriverConfig = true
			expected, _ := json.Marshal(map[string]string{"cache": dockerVolumeIdentity(volumetypes.Volume{
				Name: volume.Name, Driver: volume.Driver, CreatedAt: volume.CreatedAt,
				Mountpoint: volume.Mountpoint,
				Labels:     map[string]string{"openshell.ai/sandbox-attachable": "true", "openshell.ai/sandbox-attachable-workspace": "team-a"},
				Options:    map[string]string{},
			})})
			inspect := container.InspectResponse{
				Config: &container.Config{Labels: map[string]string{
					labelName: "sandbox", driver.WorkspaceLabel: "team-a",
					labelDriverConfigUsed: "true", labelDriverConfigUnlabelable: "false",
					labelResourceIdentities: string(expected),
				}},
				Mounts: []container.MountPoint{{Type: enginemount.TypeVolume, Name: "cache"}},
			}
			err = d.validateExistingResourceAdmission(context.Background(), inspect)
			if workspaceLabel == "team-a" && err != nil {
				t.Fatalf("valid volume admission record rejected: %v", err)
			}
			if workspaceLabel != "team-a" && err == nil {
				t.Fatal("volume relabeled for another workspace remained admitted")
			}
		})
	}
}
