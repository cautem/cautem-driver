package podman

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	docker "github.com/cautem/cautem-driver/internal/docker"
)

func TestConfigFromMapParsesAppArmorProfiles(t *testing.T) {
	for _, value := range []string{"RuntimeDefault", "Unconfined", "Localhost/openshell-supervisor"} {
		cfg, err := ConfigFromMap(map[string]any{"app_armor_profile": value})
		if err != nil || cfg.AppArmorProfile != docker.AppArmorProfile(value) {
			t.Errorf("app_armor_profile %q parsed as %q, err=%v", value, cfg.AppArmorProfile, err)
		}
	}
	for _, value := range []string{"", "default", "Localhost/", "Localhost/profile name"} {
		if _, err := ConfigFromMap(map[string]any{"app_armor_profile": value}); err == nil {
			t.Errorf("invalid app_armor_profile %q was accepted", value)
		}
	}
}

func TestValidatePodmanAppArmorSupportUsesLibpodInfo(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		wantErr bool
	}{
		{name: "enabled", payload: `{"host":{"security":{"apparmorEnabled":true}}}`},
		{name: "disabled", payload: `{"host":{"security":{"apparmorEnabled":false}}}`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodGet || r.URL.Path != "/v5.0.0/libpod/info" {
					t.Errorf("request=%s %s", r.Method, r.URL)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.payload))
			}))
			defer server.Close()

			err := validatePodmanAppArmorSupport(server.URL, docker.AppArmorRuntimeDefault)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validation error=%v wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "requires AppArmor") {
				t.Fatalf("validation error=%v; want unavailable AppArmor diagnostic", err)
			}
			if requests != 1 {
				t.Fatalf("Libpod info requests=%d; want 1", requests)
			}
		})
	}
}

func TestUnconfinedAppArmorDoesNotRequirePodmanHostProbe(t *testing.T) {
	if err := validatePodmanAppArmorSupport("unsupported://endpoint", docker.AppArmorUnconfined); err != nil {
		t.Fatalf("Unconfined unexpectedly required a Podman host probe: %v", err)
	}
}
