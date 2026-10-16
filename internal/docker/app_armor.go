package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/moby/moby/client"
)

// AppArmorProfile is the runtime profile requested by backend configuration.
// Empty means that the backend keeps its own default behavior.
type AppArmorProfile string

const (
	AppArmorRuntimeDefault AppArmorProfile = "RuntimeDefault"
	AppArmorUnconfined     AppArmorProfile = "Unconfined"
)

// ParseAppArmorProfile parses the pinned OCI profile vocabulary.
func ParseAppArmorProfile(value string) (AppArmorProfile, error) {
	profile := AppArmorProfile(value)
	if profile == "" {
		return "", fmt.Errorf("app_armor_profile must not be empty")
	}
	if err := profile.Validate(); err != nil {
		return "", err
	}
	return profile, nil
}

// Validate rejects malformed or unknown profile values.
func (profile AppArmorProfile) Validate() error {
	switch profile {
	case "", AppArmorRuntimeDefault, AppArmorUnconfined:
		return nil
	default:
		if strings.HasPrefix(string(profile), "Localhost/") && len(profile) > len("Localhost/") && !strings.ContainsAny(string(profile), " \t\r\n") {
			return nil
		}
		return fmt.Errorf("app_armor_profile must be RuntimeDefault, Unconfined, or Localhost/<profile-name>")
	}
}

// RequiresHostSupport reports whether the requested profile depends on the
// host having AppArmor enabled. Unconfined is intentionally usable without it.
func (profile AppArmorProfile) RequiresHostSupport() bool {
	return profile == AppArmorRuntimeDefault || strings.HasPrefix(string(profile), "Localhost/")
}

// OCISecurityOption returns the Engine security option for profiles that need
// an explicit override. RuntimeDefault is represented by omitting the option.
func (profile AppArmorProfile) OCISecurityOption() (string, bool) {
	switch profile {
	case AppArmorUnconfined:
		return "apparmor=unconfined", true
	case AppArmorRuntimeDefault, "":
		return "", false
	default:
		if strings.HasPrefix(string(profile), "Localhost/") && len(profile) > len("Localhost/") {
			return "apparmor=" + strings.TrimPrefix(string(profile), "Localhost/"), true
		}
		return "", false
	}
}

func validateAppArmorSecurityOptions(profile AppArmorProfile, securityOptions []string) error {
	if !profile.RequiresHostSupport() {
		return nil
	}
	for _, option := range securityOptions {
		if strings.Contains(strings.ToLower(option), "apparmor") {
			return nil
		}
	}
	return fmt.Errorf("app_armor_profile %q requires AppArmor, but the Engine reports it is unavailable", profile)
}

func (d *Driver) validateAppArmor(ctx context.Context) error {
	profile := d.runtimeConfig.AppArmorProfile
	if err := profile.Validate(); err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	if !profile.RequiresHostSupport() {
		return nil
	}
	if d.runtimeConfig.AppArmorSupportValidated {
		return nil
	}
	info, err := d.cli.Info(ctx, client.InfoOptions{})
	if err != nil {
		return fmt.Errorf("docker: inspect AppArmor support: %w", err)
	}
	if err := validateAppArmorSecurityOptions(profile, info.Info.SecurityOptions); err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	return nil
}
