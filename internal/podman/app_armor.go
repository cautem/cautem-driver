package podman

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	docker "github.com/cautem/quarshell-driver/internal/docker"
)

const podmanAPIVersion = "v5.0.0"

func validatePodmanAppArmorSupport(host string, profile docker.AppArmorProfile) error {
	if !profile.RequiresHostSupport() {
		return nil
	}
	endpoint, err := nativeEndpoint(host)
	if err != nil {
		return err
	}
	endpoint.Path += "/" + podmanAPIVersion + "/libpod/info"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return fmt.Errorf("podman: build AppArmor info request: %w", err)
	}
	client, err := nativeHTTPClient(host, endpoint)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("podman: inspect AppArmor support: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("podman: inspect AppArmor support returned %s", response.Status)
	}
	var info struct {
		Host struct {
			Security struct {
				AppArmorEnabled bool `json:"apparmorEnabled"`
			} `json:"security"`
		} `json:"host"`
	}
	if err := json.NewDecoder(response.Body).Decode(&info); err != nil {
		return fmt.Errorf("podman: decode AppArmor system info: %w", err)
	}
	if !info.Host.Security.AppArmorEnabled {
		return fmt.Errorf("podman: app_armor_profile %q requires AppArmor, but Podman reports it is unavailable", profile)
	}
	return nil
}
