package kubernetes

import (
	"encoding/json"
	"fmt"
	"strings"
)

// renderDriverConfigFragment ports the OpenShell driver_config projection into
// the subset of a Kubernetes Pod spec owned by this driver. It is deliberately
// not a complete Pod renderer: the workload/supervisor boundary, bootstrap,
// NetworkPolicy, identity and lifecycle fields must be rendered together before
// a Pod can be submitted to a cluster.
func renderDriverConfigFragment(config SandboxDriverConfig) (map[string]any, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid kubernetes driver_config: %w", err)
	}

	spec := make(map[string]any)
	if len(config.Pod.NodeSelector) != 0 {
		spec["nodeSelector"] = cloneStringMap(config.Pod.NodeSelector)
	}
	if config.Pod.RuntimeClassName != "" {
		spec["runtimeClassName"] = config.Pod.RuntimeClassName
	}
	if len(config.Pod.Tolerations) != 0 {
		tolerations := make([]any, 0, len(config.Pod.Tolerations))
		for i, raw := range config.Pod.Tolerations {
			var toleration any
			if err := json.Unmarshal(raw, &toleration); err != nil {
				return nil, fmt.Errorf("decode pod.tolerations[%d]: %w", i, err)
			}
			tolerations = append(tolerations, toleration)
		}
		spec["tolerations"] = tolerations
	}
	if config.Pod.PriorityClassName != "" {
		spec["priorityClassName"] = config.Pod.PriorityClassName
	}

	container := map[string]any{
		"name":         "agent",
		"volumeMounts": renderDriverVolumeMounts(config.Containers.Agent.VolumeMounts),
	}
	resources := renderDriverResources(config.Containers.Agent.Resources)
	if len(resources) != 0 {
		container["resources"] = resources
	}
	spec["containers"] = []any{container}
	spec["volumes"] = renderDriverVolumes(config.Volumes)

	return map[string]any{"spec": spec}, nil
}

func renderDriverVolumeMounts(configs []VolumeMountConfig) []any {
	mounts := make([]any, 0, len(configs))
	for _, config := range configs {
		mount := map[string]any{
			"name":      config.Name,
			"mountPath": config.MountPath,
			"readOnly":  defaultReadOnly(config.ReadOnly),
		}
		if config.SubPath != "" {
			mount["subPath"] = config.SubPath
		}
		mounts = append(mounts, mount)
	}
	return mounts
}

func renderDriverVolumes(configs []VolumeDriverConfig) []any {
	volumes := make([]any, 0, len(configs))
	for _, config := range configs {
		volumes = append(volumes, map[string]any{
			"name": config.Name,
			"persistentVolumeClaim": map[string]any{
				"claimName": config.PersistentVolumeClaim.ClaimName,
				"readOnly":  defaultReadOnly(config.PersistentVolumeClaim.ReadOnly),
			},
		})
	}
	return volumes
}

func renderDriverResources(config ContainerResourceConfig) map[string]any {
	resources := make(map[string]any, 2)
	if len(config.Requests) != 0 {
		resources["requests"] = renderResourceValues(config.Requests)
	}
	if len(config.Limits) != 0 {
		resources["limits"] = renderResourceValues(config.Limits)
	}
	return resources
}

func renderResourceValues(values map[string]string) map[string]any {
	result := make(map[string]any, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneStringMap(values map[string]string) map[string]string {
	copy := make(map[string]string, len(values))
	for key, value := range values {
		copy[key] = value
	}
	return copy
}

// shouldInjectDefaultWorkspace follows OpenShell's explicit /sandbox mount
// ownership rule. The validation pass has already rejected paths at or above
// /sandbox and normalized path segments, so only nested mounts suppress the
// default workspace PVC and its seed init container.
func shouldInjectDefaultWorkspace(config SandboxDriverConfig) bool {
	for _, mount := range config.Containers.Agent.VolumeMounts {
		mountPath := strings.TrimSuffix(mount.MountPath, "/")
		if mountPath == "/sandbox" || strings.HasPrefix(mountPath, "/sandbox/") {
			return false
		}
	}
	return true
}
