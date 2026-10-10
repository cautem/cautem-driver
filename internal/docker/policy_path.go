package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/moby/moby/client"
)

// PolicyHostPath returns the host path of the sandbox policy bind (label cautem.policy_path).
func (d *Driver) PolicyHostPath(ctx context.Context, nameOrID string) (string, error) {
	if d == nil || d.cli == nil {
		return "", fmt.Errorf("docker driver: client not initialized")
	}
	name := sanitizeName(nameOrID)
	for _, ctr := range []string{"cautem-proxy-" + name, "cautem-" + name} {
		ins, err := d.cli.ContainerInspect(ctx, ctr, client.ContainerInspectOptions{})
		if err != nil {
			continue
		}
		if p := strings.TrimSpace(ins.Container.Config.Labels[labelPolicy]); p != "" {
			return p, nil
		}
		for _, m := range ins.Container.Mounts {
			if m.Destination == "/cautem/policy.yaml" && m.Source != "" {
				return m.Source, nil
			}
		}
	}
	f := client.Filters{}
	f.Add("label", labelSandbox+"=1")
	f.Add("label", labelName+"="+name)
	list, err := d.cli.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: f})
	if err != nil {
		return "", fmt.Errorf("docker policy path: %w", err)
	}
	for _, c := range list.Items {
		if p := strings.TrimSpace(c.Labels[labelPolicy]); p != "" {
			return p, nil
		}
	}
	return "", fmt.Errorf("docker policy path: no policy bind for sandbox %q (create with --policy)", nameOrID)
}
