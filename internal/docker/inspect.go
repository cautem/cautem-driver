// Package docker implements driver.ComputeDriver via the Docker Engine API.
package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/moby/moby/client"

	core "github.com/cautem/cautem-core"
	"github.com/cautem/quarshell-driver/driver"
)

// List returns cautem sandbox containers (excludes proxy sidecars).
func (d *Driver) List(ctx context.Context) ([]driver.Info, error) {
	f := client.Filters{}
	f.Add("label", labelSandbox+"=1")
	list, err := d.cli.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: f})
	if err != nil {
		return nil, err
	}
	out := make([]driver.Info, 0, len(list.Items))
	for _, c := range list.Items {
		if c.Labels[labelRole] == roleProxy {
			continue
		}
		name := c.Labels[labelName]
		if name == "" && len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		out = append(out, driver.Info{
			ID:      core.ID(c.ID),
			Name:    name,
			Network: c.Labels[labelNetwork],
			Image:   c.Image,
			Status:  c.Status,
		})
	}
	return out, nil
}

// Inspect resolves by sandbox name or container id/prefix.

// Inspect resolves by sandbox name or container id/prefix.
func (d *Driver) Inspect(ctx context.Context, nameOrID string) (driver.Info, error) {
	nameOrID = strings.TrimSpace(nameOrID)
	if nameOrID == "" {
		return driver.Info{}, fmt.Errorf("docker inspect: empty name")
	}
	// Try container name cautem-<name>
	candidates := []string{nameOrID, "cautem-" + nameOrID}
	for _, id := range candidates {
		c, err := d.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
		if err != nil {
			continue
		}
		if c.Container.Config.Labels[labelSandbox] != "1" && !strings.HasPrefix(strings.TrimPrefix(c.Container.Name, "/"), "cautem-") {
			continue
		}
		name := c.Container.Config.Labels[labelName]
		if name == "" {
			name = strings.TrimPrefix(c.Container.Name, "/")
			name = strings.TrimPrefix(name, "cautem-")
		}
		return driver.Info{
			ID:      core.ID(c.Container.ID),
			Name:    name,
			Network: c.Container.Config.Labels[labelNetwork],
			Image:   c.Container.Config.Image,
			Status:  string(c.Container.State.Status),
		}, nil
	}
	return driver.Info{}, fmt.Errorf("docker inspect: sandbox %q not found", nameOrID)
}

// ContainerIP returns the sandbox container IP on its cautem network.

// ContainerIP returns the sandbox container IP on its cautem network.
func (d *Driver) ContainerIP(ctx context.Context, containerID, networkName string) (string, error) {
	if d == nil || d.cli == nil {
		return "", fmt.Errorf("docker driver: client not initialized")
	}
	c, err := d.cli.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return "", err
	}
	if networkName == "" && c.Container.Config != nil {
		networkName = c.Container.Config.Labels[labelNetwork]
	}
	if networkName != "" && c.Container.NetworkSettings != nil {
		if n, ok := c.Container.NetworkSettings.Networks[networkName]; ok && n.IPAddress.IsValid() {
			return n.IPAddress.String(), nil
		}
		return "", fmt.Errorf("docker: no IP for container on network %q", networkName)
	}
	if c.Container.NetworkSettings != nil {
		for _, n := range c.Container.NetworkSettings.Networks {
			if n.IPAddress.IsValid() {
				return n.IPAddress.String(), nil
			}
		}
	}
	return "", fmt.Errorf("docker: no IP for container on network %q", networkName)
}

// ParseMemoryBytes parses Docker-style memory strings (512m, 4g, …).
