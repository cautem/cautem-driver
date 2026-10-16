package docker

import (
	"context"
	"fmt"

	"github.com/cautem/cautem-core/resourceadmission"
	"github.com/cautem/cautem-driver/driver"
	enginemount "github.com/moby/moby/api/types/mount"
)

type validatedCreate struct {
	cdiDevices         []string
	hasCDIDevices      bool
	mounts             []enginemount.Mount
	binds              []string
	resourceIdentities map[string]string
	configUsed         bool
}

// ValidateSpecContext performs cancellable, read-only checks needed before
// the Gateway commits a create request to durable state.
func (d *Driver) ValidateSpecContext(ctx context.Context, spec driver.Spec) error {
	_, err := d.validateCreate(ctx, spec)
	return err
}

func (d *Driver) validateCreate(ctx context.Context, spec driver.Spec) (validatedCreate, error) {
	if d == nil || d.cli == nil {
		return validatedCreate{}, fmt.Errorf("docker driver: client not initialized")
	}
	if err := ctx.Err(); err != nil {
		return validatedCreate{}, err
	}
	if err := d.validateAppArmor(ctx); err != nil {
		return validatedCreate{}, err
	}
	if err := ValidateGPURequest(spec); err != nil {
		return validatedCreate{}, fmt.Errorf("docker gpu: %w", err)
	}
	configUsed, err := validateDriverConfigAllowed(spec.DriverConfigJSON, d.runtimeConfig.AllowDriverConfig)
	if err != nil {
		return validatedCreate{}, err
	}
	cdiDevices, hasCDIDevices, mounts, binds, err := parseDockerSandboxDriverConfig(spec.DriverConfigJSON, d.enableBindMounts)
	if err != nil {
		return validatedCreate{}, err
	}
	policy := resourceadmission.Default()
	if configured := d.runtimeConfig.ResourceAdmission; configured != nil {
		policy = *configured
	}
	identities, err := d.validateExternalDriverMounts(ctx, spec, mounts, policy)
	if err != nil {
		return validatedCreate{}, err
	}
	if err := ctx.Err(); err != nil {
		return validatedCreate{}, err
	}
	return validatedCreate{
		cdiDevices: cdiDevices, hasCDIDevices: hasCDIDevices, mounts: mounts,
		binds: binds, resourceIdentities: identities, configUsed: configUsed,
	}, nil
}

var _ driver.ContextSpecValidator = (*Driver)(nil)
