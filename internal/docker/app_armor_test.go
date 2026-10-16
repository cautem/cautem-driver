package docker

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cautem/cautem-driver/driver"
)

func TestAppArmorProfileOCITranslationAndHostRequirement(t *testing.T) {
	cases := []struct {
		profile      AppArmorProfile
		option       string
		hasOption    bool
		requiresHost bool
	}{
		{profile: AppArmorRuntimeDefault, requiresHost: true},
		{profile: AppArmorUnconfined, option: "apparmor=unconfined", hasOption: true},
		{profile: AppArmorProfile("Localhost/openshell-supervisor"), option: "apparmor=openshell-supervisor", hasOption: true, requiresHost: true},
	}
	for _, tc := range cases {
		option, hasOption := tc.profile.OCISecurityOption()
		if option != tc.option || hasOption != tc.hasOption || tc.profile.RequiresHostSupport() != tc.requiresHost {
			t.Errorf("profile %q => option=%q/%v requiresHost=%v", tc.profile, option, hasOption, tc.profile.RequiresHostSupport())
		}
	}
}

func TestValidateAppArmorRequiresHostSupportBeforeContainerMutation(t *testing.T) {
	requests := 0
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/v1.41/info" || r.Method != http.MethodGet {
			t.Errorf("unexpected Engine request before AppArmor validation: %s %s", r.Method, r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"SecurityOptions":[]}`)
	})
	d.runtimeConfig.AppArmorProfile = AppArmorRuntimeDefault
	_, err := d.Create(context.Background(), driver.Spec{Name: "apparmor-negative", Image: "alpine", Workspace: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "requires AppArmor") {
		t.Fatalf("Create error=%v; want unavailable AppArmor error", err)
	}
	if requests != 1 {
		t.Fatalf("Engine requests=%d; AppArmor rejection must happen before container/network mutation", requests)
	}
}

func TestValidateAppArmorSecurityOptions(t *testing.T) {
	if err := validateAppArmorSecurityOptions(AppArmorRuntimeDefault, []string{"name=seccomp,profile=default", "name=apparmor"}); err != nil {
		t.Fatalf("AppArmor support was not detected: %v", err)
	}
	if err := validateAppArmorSecurityOptions(AppArmorRuntimeDefault, []string{"name=seccomp,profile=default"}); err == nil {
		t.Fatal("missing AppArmor host support was accepted")
	}
	if err := validateAppArmorSecurityOptions(AppArmorUnconfined, nil); err != nil {
		t.Fatalf("Unconfined should not require host AppArmor: %v", err)
	}
}
