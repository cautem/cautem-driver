package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/cautem/cautem-core/resourceadmission"
	"github.com/cautem/cautem-driver/driver"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

const (
	labelDriverConfigUsed        = "cautem.internal/driver-config-used"
	labelDriverConfigUnlabelable = "cautem.internal/driver-config-unlabelable"
	labelResourceIdentities      = "cautem.internal/resource-admission-identities"
)

func (d *Driver) resourceAdmissionPolicy() resourceadmission.Config {
	if d != nil && d.runtimeConfig.ResourceAdmission != nil {
		return *d.runtimeConfig.ResourceAdmission
	}
	return resourceadmission.Default()
}

// validateExistingResourceAdmission rechecks backend-owned volume identity and
// labels before a stopped sandbox is started again. It fails closed when a
// runtime predates the admission record or its attached resources have changed.
func (d *Driver) validateExistingResourceAdmission(ctx context.Context, inspect container.InspectResponse) error {
	if inspect.Config == nil {
		return errors.New("sandbox admission metadata is unavailable")
	}
	labels := inspect.Config.Labels
	usedValue, hasUsed := labels[labelDriverConfigUsed]
	if !hasUsed || usedValue != "true" && usedValue != "false" {
		return errors.New("sandbox lacks valid caller driver_config provenance")
	}
	if usedValue == "true" && !d.runtimeConfig.AllowDriverConfig {
		return errors.New("sandbox uses caller driver_config disabled by current gateway policy; recreate it")
	}
	policy := d.resourceAdmissionPolicy()
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("invalid resource admission policy: %w", err)
	}
	if d.runtimeConfig.AllowDriverConfig && !policy.Enabled {
		return nil
	}
	if !policy.Enabled {
		return nil
	}
	if labels[labelDriverConfigUnlabelable] == "true" {
		return policy.RejectUnlabelable("previously admitted bind or image mount")
	}
	if labels[labelDriverConfigUnlabelable] != "false" {
		return errors.New("sandbox lacks unlabelable mount provenance")
	}
	var expected map[string]string
	if raw := labels[labelResourceIdentities]; raw == "" || json.Unmarshal([]byte(raw), &expected) != nil || expected == nil {
		return errors.New("sandbox lacks a valid external resource identity record")
	}
	workspace := strings.TrimSpace(labels[driver.WorkspaceLabel])
	if len(expected) > 0 && workspace == "" {
		return errors.New("sandbox lacks verified workspace identity")
	}
	if len(expected) == 0 {
		// No caller supplied named resources were admitted at create. This also
		// leaves OCI image VOLUME declarations to the engine's private anonymous
		// volume behavior instead of treating them as caller attachments.
		return nil
	}
	actual := make(map[string]string, len(expected))
	sandboxName := labels[labelName]
	for _, mount := range inspect.Mounts {
		switch string(mount.Type) {
		case "volume":
			if mount.Name == "" {
				return errors.New("mounted volume lacks an identity")
			}
			volume, err := d.cli.VolumeInspect(ctx, mount.Name, client.VolumeInspectOptions{})
			if err != nil {
				return fmt.Errorf("inspect attached volume %q: %w", mount.Name, err)
			}
			if isManagedSandboxVolume(mount.Name, sandboxName, volume.Volume.Labels) {
				continue
			}
			identity, recorded := expected[mount.Name]
			if !recorded {
				return fmt.Errorf("external volume attachment %q changed; recreate the sandbox", mount.Name)
			}
			if err := policy.Admit(workspace, volume.Volume.Labels); err != nil {
				return fmt.Errorf("attached volume %q: %w", mount.Name, err)
			}
			if !d.enableBindMounts && dockerVolumeIsBindBacked(volume.Volume.Driver, volume.Volume.Options) {
				return fmt.Errorf("attached volume %q is backed by a host bind mount that is disabled", mount.Name)
			}
			current := dockerVolumeIdentity(volume.Volume)
			if current != identity {
				return fmt.Errorf("attached volume %q identity changed; recreate the sandbox", mount.Name)
			}
			actual[mount.Name] = current
		case "tmpfs", "bind":
			// The create record distinguishes trusted driver binds from caller
			// binds. Caller binds were recorded above and are rejected if policy
			// is enabled now.
		default:
			if err := policy.RejectUnlabelable("effective container mount"); err != nil {
				return err
			}
		}
	}
	if !maps.Equal(actual, expected) {
		return errors.New("external volume attachment inventory changed; recreate the sandbox")
	}
	return nil
}

func isManagedSandboxVolume(volumeName, sandboxName string, labels map[string]string) bool {
	for _, role := range []string{roleVolumeData, roleVolumeCA, roleVolumeSSH} {
		if volumeOwnershipLabelsValid(volumeName, sandboxName, role, labels) {
			return true
		}
	}
	return false
}
