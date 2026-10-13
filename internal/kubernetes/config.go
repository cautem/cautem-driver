package kubernetes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

const nvidiaGPUResourceName = "nvidia.com/gpu"

// SandboxDriverConfig is the selected Kubernetes driver's strict subset of the
// OpenShell sandbox driver_config schema. It is deliberately local to this
// backend; the gateway must not interpret Kubernetes fields.
type SandboxDriverConfig struct {
	Pod        PodDriverConfig        `json:"pod"`
	Containers ContainersDriverConfig `json:"containers"`
	Volumes    []VolumeDriverConfig   `json:"volumes"`

	// gatewayGPUResources is set only after the trusted Gateway GPU request is
	// applied. It is not JSON-decodable and cannot be set through driver_config.
	gatewayGPUResources bool
}

type PodDriverConfig struct {
	NodeSelector      map[string]string `json:"node_selector"`
	RuntimeClassName  string            `json:"runtime_class_name"`
	Tolerations       []json.RawMessage `json:"tolerations"`
	PriorityClassName string            `json:"priority_class_name"`
}

type ContainersDriverConfig struct {
	Agent ContainerDriverConfig `json:"agent"`
}

type ContainerDriverConfig struct {
	Resources    ContainerResourceConfig `json:"resources"`
	VolumeMounts []VolumeMountConfig     `json:"volume_mounts"`
}

type ContainerResourceConfig struct {
	Requests map[string]string `json:"requests"`
	Limits   map[string]string `json:"limits"`
}

type VolumeDriverConfig struct {
	Name                  string                      `json:"name"`
	PersistentVolumeClaim PersistentVolumeClaimConfig `json:"persistent_volume_claim"`
}

type PersistentVolumeClaimConfig struct {
	ClaimName string `json:"claim_name"`
	ReadOnly  *bool  `json:"read_only"`
}

type VolumeMountConfig struct {
	Name      string `json:"name"`
	MountPath string `json:"mount_path"`
	SubPath   string `json:"sub_path"`
	ReadOnly  *bool  `json:"read_only"`
}

var dns1123Label = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)

var reservedVolumeNames = map[string]struct{}{
	"openshell-client-tls":          {},
	"openshell-upstream-proxy-auth": {},
	"openshell-sa-token":            {},
	"spiffe-workload-api":           {},
	"openshell-runtime":             {},
	"openshell-runtime-state":       {},
	"openshell-sandbox-bootstrap":   {},
	"openshell-pod-identity":        {},
	"openshell-run":                 {},
	"workspace":                     {},
	"cautem-runtime":                {},
	"cautem-private":                {},
	"cautem-run":                    {},
}

var protectedMountRoots = []string{
	"/opt/openshell",
	"/etc/openshell",
	"/etc/openshell-tls",
	"/run/openshell",
	"/run/openshell-sidecar",
	"/run/netns",
	"/var/run/netns",
	"/proc",
	"/sys",
	"/dev",
	"/var/run/secrets/openshell",
	"/cautem",
	"/run/cautem",
	"/var/run/cautem",
}

// ParseSandboxDriverConfig strictly decodes and validates the backend-owned
// driver_config object. Empty input means the OpenShell defaults.
func ParseSandboxDriverConfig(raw string) (SandboxDriverConfig, error) {
	var config SandboxDriverConfig
	if strings.TrimSpace(raw) == "" {
		return config, nil
	}
	if err := validateConfigJSONShape([]byte(raw)); err != nil {
		return SandboxDriverConfig{}, fmt.Errorf("invalid kubernetes driver_config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return SandboxDriverConfig{}, fmt.Errorf("invalid kubernetes driver_config: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return SandboxDriverConfig{}, fmt.Errorf("invalid kubernetes driver_config: %w", err)
	}
	if err := config.Validate(); err != nil {
		return SandboxDriverConfig{}, fmt.Errorf("invalid kubernetes driver_config: %w", err)
	}
	return config, nil
}

func validateConfigJSONShape(raw []byte) error {
	root, err := decodeObject(raw, "driver_config")
	if err != nil {
		return err
	}
	if err := checkFieldType(root, "pod", "object"); err != nil {
		return err
	}
	if err := checkFieldType(root, "containers", "object"); err != nil {
		return err
	}
	if err := checkFieldType(root, "volumes", "array"); err != nil {
		return err
	}
	if pod, ok := root["pod"]; ok {
		obj, _ := decodeObject(pod, "pod")
		for field, kind := range map[string]string{"node_selector": "object", "runtime_class_name": "string", "tolerations": "array", "priority_class_name": "string"} {
			if err := checkFieldType(obj, field, kind); err != nil {
				return err
			}
		}
		if value, ok := obj["node_selector"]; ok {
			if err := checkStringMap(value, "pod.node_selector"); err != nil {
				return err
			}
		}
	}
	if containers, ok := root["containers"]; ok {
		obj, _ := decodeObject(containers, "containers")
		if err := checkFieldType(obj, "agent", "object"); err != nil {
			return err
		}
		if agent, ok := obj["agent"]; ok {
			agentObj, _ := decodeObject(agent, "containers.agent")
			if err := checkFieldType(agentObj, "resources", "object"); err != nil {
				return err
			}
			if err := checkFieldType(agentObj, "volume_mounts", "array"); err != nil {
				return err
			}
			if resources, ok := agentObj["resources"]; ok {
				resourceObj, _ := decodeObject(resources, "containers.agent.resources")
				for _, field := range []string{"requests", "limits"} {
					if err := checkFieldType(resourceObj, field, "object"); err != nil {
						return err
					}
					if values, ok := resourceObj[field]; ok {
						if err := checkStringMap(values, "containers.agent.resources."+field); err != nil {
							return err
						}
					}
				}
			}
			if mounts, ok := agentObj["volume_mounts"]; ok {
				items, _ := decodeArray(mounts, "containers.agent.volume_mounts")
				for i, item := range items {
					mount, err := decodeObject(item, fmt.Sprintf("containers.agent.volume_mounts[%d]", i))
					if err != nil {
						return err
					}
					for field, kind := range map[string]string{"name": "string", "mount_path": "string", "read_only": "boolean"} {
						if err := checkFieldType(mount, field, kind); err != nil {
							return err
						}
					}
					if err := checkFieldTypeAllowNull(mount, "sub_path", "string"); err != nil {
						return err
					}
				}
			}
		}
	}
	if volumes, ok := root["volumes"]; ok {
		items, _ := decodeArray(volumes, "volumes")
		for i, item := range items {
			volume, err := decodeObject(item, fmt.Sprintf("volumes[%d]", i))
			if err != nil {
				return err
			}
			if err := checkFieldType(volume, "name", "string"); err != nil {
				return err
			}
			if err := checkFieldType(volume, "persistent_volume_claim", "object"); err != nil {
				return err
			}
			if claim, ok := volume["persistent_volume_claim"]; ok {
				claimObj, _ := decodeObject(claim, "persistent_volume_claim")
				if err := checkFieldType(claimObj, "claim_name", "string"); err != nil {
					return err
				}
				if err := checkFieldType(claimObj, "read_only", "boolean"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func decodeObject(raw json.RawMessage, field string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("%s must be an object", field)
	}
	if err := json.Unmarshal(trimmed, &object); err != nil {
		return nil, fmt.Errorf("%s must be an object: %w", field, err)
	}
	return object, nil
}

func decodeArray(raw json.RawMessage, field string) ([]json.RawMessage, error) {
	var items []json.RawMessage
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, fmt.Errorf("%s must be an array", field)
	}
	if err := json.Unmarshal(trimmed, &items); err != nil {
		return nil, fmt.Errorf("%s must be an array: %w", field, err)
	}
	return items, nil
}

func checkFieldType(object map[string]json.RawMessage, field, kind string) error {
	raw, exists := object[field]
	if !exists {
		return nil
	}
	return checkJSONType(raw, field, kind)
}

func checkFieldTypeAllowNull(object map[string]json.RawMessage, field, kind string) error {
	raw, exists := object[field]
	if !exists || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	return checkJSONType(raw, field, kind)
}

func checkJSONType(raw json.RawMessage, field, kind string) error {
	trimmed := bytes.TrimSpace(raw)
	valid := false
	switch kind {
	case "object":
		valid = len(trimmed) > 0 && trimmed[0] == '{'
	case "array":
		valid = len(trimmed) > 0 && trimmed[0] == '['
	case "string":
		valid = len(trimmed) > 0 && trimmed[0] == '"'
	case "boolean":
		valid = bytes.Equal(trimmed, []byte("true")) || bytes.Equal(trimmed, []byte("false"))
	}
	if !valid {
		descriptor := map[string]string{"object": "an object", "array": "an array", "string": "a string", "boolean": "a boolean"}[kind]
		return fmt.Errorf("%s must be %s", field, descriptor)
	}
	return nil
}

func checkStringMap(raw json.RawMessage, field string) error {
	object, err := decodeObject(raw, field)
	if err != nil {
		return err
	}
	for key, value := range object {
		if err := checkJSONType(value, field+"["+key+"]", "string"); err != nil {
			return err
		}
	}
	return nil
}

func (config *SandboxDriverConfig) Validate() error {
	if !config.gatewayGPUResources {
		for _, resources := range []map[string]string{config.Containers.Agent.Resources.Requests, config.Containers.Agent.Resources.Limits} {
			for name := range resources {
				if strings.HasPrefix(name, "nvidia.com/") {
					return fmt.Errorf("GPU resource %q must be requested through the Gateway GPU resource field", name)
				}
			}
		}
	}
	volumes := make(map[string]bool, len(config.Volumes))
	for _, volume := range config.Volumes {
		if err := validateDNS1123Label(volume.Name, "volumes[].name"); err != nil {
			return err
		}
		if _, reserved := reservedVolumeNames[volume.Name]; reserved {
			return fmt.Errorf("volume name %q is reserved for OpenShell-managed volumes", volume.Name)
		}
		if _, exists := volumes[volume.Name]; exists {
			return fmt.Errorf("duplicate kubernetes driver_config volume %q", volume.Name)
		}
		volumes[volume.Name] = defaultReadOnly(volume.PersistentVolumeClaim.ReadOnly)
		if err := validateDNS1123Subdomain(volume.PersistentVolumeClaim.ClaimName, "volumes[].persistent_volume_claim.claim_name"); err != nil {
			return err
		}
	}

	mountPaths := make(map[string]struct{}, len(config.Containers.Agent.VolumeMounts))
	for _, mount := range config.Containers.Agent.VolumeMounts {
		if err := validateDNS1123Label(mount.Name, "containers.agent.volume_mounts[].name"); err != nil {
			return err
		}
		volumeReadOnly, exists := volumes[mount.Name]
		if !exists {
			return fmt.Errorf("volume mount references unknown kubernetes driver_config volume %q", mount.Name)
		}
		if volumeReadOnly && !defaultReadOnly(mount.ReadOnly) {
			return fmt.Errorf("volume mount %q cannot set read_only=false because the PVC volume is read_only=true", mount.Name)
		}
		if err := validateMountPath(mount.MountPath); err != nil {
			return err
		}
		for _, protected := range protectedMountRoots {
			if pathsOverlap(mount.MountPath, protected) {
				return fmt.Errorf("mount path %q conflicts with protected OpenShell path %q", mount.MountPath, protected)
			}
		}
		if pathIsParentOrEqual("/sandbox", mount.MountPath) {
			return fmt.Errorf("mount target %q is reserved for the OpenShell workspace", mount.MountPath)
		}
		normalized := path.Clean(mount.MountPath)
		if _, exists := mountPaths[normalized]; exists {
			return fmt.Errorf("duplicate kubernetes driver_config mount target %q", normalized)
		}
		mountPaths[normalized] = struct{}{}
		if mount.SubPath != "" {
			if err := validateSubPath(mount.SubPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return fmt.Errorf("unexpected value after JSON object")
}

func validateDNS1123Label(value, field string) error {
	if !dns1123Label.MatchString(value) {
		return fmt.Errorf("%s must be a DNS-1123 label", field)
	}
	return nil
}

func validateDNS1123Subdomain(value, field string) error {
	if len(value) > 253 || value == "" {
		return fmt.Errorf("%s must be a DNS-1123 subdomain", field)
	}
	for _, part := range strings.Split(value, ".") {
		if !dns1123Label.MatchString(part) {
			return fmt.Errorf("%s must be a DNS-1123 subdomain", field)
		}
	}
	return nil
}

func validateMountPath(value string) error {
	if value == "" || !path.IsAbs(value) || strings.TrimSpace(value) != value || strings.ContainsRune(value, '\x00') || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return fmt.Errorf("mount path %q must be an absolute normalized path", value)
	}
	if value == "/" {
		return fmt.Errorf("mount path %q must not be the container root", value)
	}
	segments := strings.Split(strings.TrimPrefix(value, "/"), "/")
	for i, segment := range segments {
		if (segment == "" && i != len(segments)-1) || segment == "." || segment == ".." {
			return fmt.Errorf("mount path %q must be normalized without empty, '.' or '..' path segments", value)
		}
	}
	return nil
}

func validateSubPath(value string) error {
	if value == "" || strings.TrimSpace(value) != value || path.IsAbs(value) || strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("mount subpath must be relative and must not contain '..'")
	}
	for _, part := range strings.Split(strings.ReplaceAll(value, `\`, "/"), "/") {
		if part == ".." {
			return fmt.Errorf("mount subpath must be relative and must not contain '..'")
		}
	}
	return nil
}

func defaultReadOnly(value *bool) bool { return value == nil || *value }

func pathsOverlap(left, right string) bool {
	left, right = path.Clean(left), path.Clean(right)
	return left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

func pathIsParentOrEqual(candidate, target string) bool {
	candidate, target = path.Clean(candidate), path.Clean(target)
	return candidate == target || strings.HasPrefix(candidate, target+"/")
}
