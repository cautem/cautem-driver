// Package docker implements driver.ComputeDriver via the Docker Engine API.
package docker

import (
	"context"
	"fmt"

	"github.com/moby/moby/client"
)

func (d *Driver) ensureNetwork(ctx context.Context, netName, sandboxName string, internal bool) (bool, error) {
	if internal && d.runtimeConfig.NativeNetworkCreate != nil && d.runtimeConfig.NativeNetworkVerify == nil {
		return false, fmt.Errorf("network %s: native backend cannot verify host-gateway isolation", netName)
	}
	inspected, err := d.cli.NetworkInspect(ctx, netName, client.NetworkInspectOptions{})
	if err == nil {
		labels := inspected.Network.Labels
		if labels[labelSandbox] != "1" || labels[labelName] != sandboxName || (labels[labelRole] != "" && labels[labelRole] != roleNetwork) {
			return false, fmt.Errorf("docker network %s is not owned by sandbox %s", netName, sandboxName)
		}
		if internal && !inspected.Network.Internal {
			return false, fmt.Errorf("docker network %s already exists but is not internal; refusing proxy-isolated sandbox", netName)
		}
		if internal && d.runtimeConfig.BackendID == "docker" && !inspected.Network.EnableIPv6 {
			return false, fmt.Errorf("docker network %s does not enable IPv6; refusing proxy-isolated sandbox", netName)
		}
		if internal && d.runtimeConfig.NativeNetworkVerify == nil && (inspected.Network.Options["com.docker.network.bridge.gateway_mode_ipv4"] != "isolated" || inspected.Network.Options["com.docker.network.bridge.gateway_mode_ipv6"] != "isolated") {
			return false, fmt.Errorf("docker network %s does not isolate its host gateway; refusing proxy-isolated sandbox", netName)
		}
		if internal && d.runtimeConfig.NativeNetworkVerify != nil {
			if err := d.runtimeConfig.NativeNetworkVerify(ctx, netName, true); err != nil {
				return false, fmt.Errorf("network %s lacks verified host-gateway isolation: %w", netName, err)
			}
		}
		return false, nil
	}
	if d.runtimeConfig.NativeNetworkCreate != nil {
		if err := d.runtimeConfig.NativeNetworkCreate(ctx, netName, internal, map[string]string{labelSandbox: "1", labelName: sandboxName, labelRole: roleNetwork}); err != nil {
			return false, fmt.Errorf("native network create %s: %w", netName, err)
		}
		if internal && d.runtimeConfig.NativeNetworkVerify != nil {
			if err := d.runtimeConfig.NativeNetworkVerify(ctx, netName, true); err != nil {
				_, _ = d.cli.NetworkRemove(ctx, netName, client.NetworkRemoveOptions{})
				return false, fmt.Errorf("network %s lacks verified host-gateway isolation: %w", netName, err)
			}
		}
		return true, nil
	}
	options := map[string]string(nil)
	var enableIPv6 *bool
	if internal {
		// Internal=true blocks routed egress but still leaves the bridge gateway
		// reachable from containers. Isolated gateway mode removes the host-side
		// bridge address so sandbox traffic cannot bypass the policy proxy.
		options = map[string]string{
			"com.docker.network.bridge.gateway_mode_ipv4": "isolated",
			"com.docker.network.bridge.gateway_mode_ipv6": "isolated",
		}
		if d.runtimeConfig.BackendID == "docker" {
			enabled := true
			enableIPv6 = &enabled
		}
	}
	_, err = d.cli.NetworkCreate(ctx, netName, client.NetworkCreateOptions{
		Driver:     "bridge",
		EnableIPv6: enableIPv6,
		Internal:   internal, // fail-closed when proxy sidecar is enabled
		Options:    options,
		Labels: map[string]string{
			labelSandbox: "1",
			labelName:    sandboxName,
			labelRole:    roleNetwork,
		},
	})
	if err != nil {
		return false, fmt.Errorf("docker network create %s: %w", netName, err)
	}
	return true, nil
}
