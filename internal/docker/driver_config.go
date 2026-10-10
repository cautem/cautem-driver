package docker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/cautem/cautem-driver/internal/mounts"
	enginemount "github.com/moby/moby/api/types/mount"
)

func parseDockerSandboxDriverConfig(raw string, enableBindMounts bool) ([]string, bool, []enginemount.Mount, []string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false, nil, nil, nil
	}
	data := []byte(raw)
	if !json.Valid(data) || len(data) == 0 || data[0] != '{' {
		return nil, false, nil, nil, fmt.Errorf("docker driver_config must be a JSON object")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, false, nil, nil, fmt.Errorf("invalid docker driver_config: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, false, nil, nil, err
	}
	for key := range fields {
		if key != "cdi_devices" && key != "mounts" {
			return nil, false, nil, nil, fmt.Errorf("invalid docker driver_config: unknown field %q", key)
		}
	}
	var devices []string
	hasDevices := false
	if value, ok := fields["cdi_devices"]; ok {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, &devices) != nil || len(devices) == 0 {
			return nil, false, nil, nil, fmt.Errorf("invalid docker driver_config.cdi_devices: expected non-empty string array")
		}
		for i, device := range devices {
			if strings.TrimSpace(device) == "" {
				return nil, false, nil, nil, fmt.Errorf("invalid docker driver_config.cdi_devices[%d]: must be a non-empty string", i)
			}
		}
		hasDevices = true
	}
	var engineMounts []enginemount.Mount
	var bindMounts []string
	if value, ok := fields["mounts"]; ok {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false, nil, nil, fmt.Errorf("invalid docker driver_config.mounts: expected array")
		}
		var configs []map[string]json.RawMessage
		if json.Unmarshal(value, &configs) != nil || configs == nil {
			return nil, false, nil, nil, fmt.Errorf("invalid docker driver_config.mounts: expected array")
		}
		seen := map[string]bool{}
		for i, cfg := range configs {
			m, bind, target, err := parseDockerMount(cfg, enableBindMounts)
			if err != nil {
				return nil, false, nil, nil, fmt.Errorf("invalid docker driver_config.mounts[%d]: %w", i, err)
			}
			if seen[target] {
				return nil, false, nil, nil, fmt.Errorf("invalid docker driver_config.mounts[%d]: duplicate target %q", i, target)
			}
			seen[target] = true
			if bind != "" {
				bindMounts = append(bindMounts, bind)
			} else {
				engineMounts = append(engineMounts, m)
			}
		}
	}
	return devices, hasDevices, engineMounts, bindMounts, nil
}

func parseDockerMount(fields map[string]json.RawMessage, enableBindMounts bool) (enginemount.Mount, string, string, error) {
	var kind string
	if json.Unmarshal(fields["type"], &kind) != nil {
		return enginemount.Mount{}, "", "", fmt.Errorf("type is required")
	}
	allowed := map[string]bool{"type": true, "target": true, "read_only": true}
	for _, k := range []string{"source", "selinux_label", "subpath", "options", "size_bytes", "mode"} {
		allowed[k] = true
	}
	for k := range fields {
		if !allowed[k] {
			return enginemount.Mount{}, "", "", fmt.Errorf("unknown field %q", k)
		}
	}
	var target string
	if json.Unmarshal(fields["target"], &target) != nil {
		return enginemount.Mount{}, "", "", fmt.Errorf("target is required")
	}
	target = strings.TrimSuffix(target, "/")
	if !path.IsAbs(target) || target == "/" || path.Clean(target) != target || strings.ContainsAny(target, "\x00\\") || strings.TrimSpace(target) != target {
		return enginemount.Mount{}, "", "", fmt.Errorf("target must be a normalized absolute non-root path")
	}
	for _, part := range strings.Split(target, "/") {
		if part == "." || part == ".." {
			return enginemount.Mount{}, "", "", fmt.Errorf("target contains a traversal component")
		}
	}
	if err := mounts.ValidateContainerMountTarget(target); err != nil {
		return enginemount.Mount{}, "", "", err
	}
	for _, protected := range []string{"/opt/openshell", "/etc/openshell", "/etc/openshell-tls", "/run/openshell", "/run/openshell-sidecar", "/run/netns", "/var/run/netns"} {
		if target == protected || strings.HasPrefix(target, protected+"/") {
			return enginemount.Mount{}, "", "", fmt.Errorf("target overlaps protected path %q", protected)
		}
	}
	var readOnly bool
	if v, ok := fields["read_only"]; ok {
		if json.Unmarshal(v, &readOnly) != nil {
			return enginemount.Mount{}, "", "", fmt.Errorf("read_only must be boolean")
		}
	} else {
		readOnly = true
	}
	str := func(k string, required bool) (string, error) {
		var v string
		b, ok := fields[k]
		if !ok {
			if required {
				return "", fmt.Errorf("%s is required", k)
			}
			return "", nil
		}
		if json.Unmarshal(b, &v) != nil || strings.TrimSpace(v) != v || strings.ContainsRune(v, 0) || required && v == "" {
			return "", fmt.Errorf("%s is invalid", k)
		}
		return v, nil
	}
	switch kind {
	case "bind":
		if !enableBindMounts {
			return enginemount.Mount{}, "", "", fmt.Errorf("bind mounts require Docker enable_bind_mounts")
		}
		source, err := str("source", true)
		if err != nil {
			return enginemount.Mount{}, "", "", err
		}
		if !filepath.IsAbs(source) {
			return enginemount.Mount{}, "", "", fmt.Errorf("bind source must be absolute")
		}
		if _, err := os.Stat(source); err != nil {
			return enginemount.Mount{}, "", "", fmt.Errorf("bind source is unavailable: %w", err)
		}
		label, err := str("selinux_label", false)
		if err != nil {
			return enginemount.Mount{}, "", "", err
		}
		if label != "" && label != "shared" && label != "private" {
			return enginemount.Mount{}, "", "", fmt.Errorf("selinux_label must be shared or private")
		}
		suffix := ":rw"
		if readOnly {
			suffix = ":ro"
		}
		if label == "shared" {
			suffix += ",z"
		}
		if label == "private" {
			suffix += ",Z"
		}
		return enginemount.Mount{}, source + ":" + target + suffix, target, nil
	case "volume":
		source, err := str("source", true)
		if err != nil {
			return enginemount.Mount{}, "", "", err
		}
		subpath, err := str("subpath", false)
		if err != nil {
			return enginemount.Mount{}, "", "", err
		}
		if subpath != "" && (path.IsAbs(subpath) || path.Clean(subpath) != subpath || strings.ContainsAny(subpath, "\\ ")) {
			return enginemount.Mount{}, "", "", fmt.Errorf("subpath must be a safe relative path")
		}
		return enginemount.Mount{Type: enginemount.TypeVolume, Source: source, Target: target, ReadOnly: readOnly, VolumeOptions: &enginemount.VolumeOptions{Subpath: subpath}}, "", target, nil
	case "tmpfs":
		var options []string
		if v, ok := fields["options"]; ok && json.Unmarshal(v, &options) != nil {
			return enginemount.Mount{}, "", "", fmt.Errorf("options must be a string array")
		}
		parsed := make([][]string, 0, len(options))
		for _, option := range options {
			if option == "" {
				return enginemount.Mount{}, "", "", fmt.Errorf("options cannot contain empty values")
			}
			pair := strings.SplitN(option, "=", 2)
			if len(pair) == 2 && (pair[0] == "" || pair[1] == "") {
				return enginemount.Mount{}, "", "", fmt.Errorf("invalid tmpfs option %q", option)
			}
			parsed = append(parsed, pair)
		}
		var size, mode int64
		if v, ok := fields["size_bytes"]; ok && json.Unmarshal(v, &size) != nil || size < 0 {
			return enginemount.Mount{}, "", "", fmt.Errorf("size_bytes must be a non-negative integer")
		}
		if v, ok := fields["mode"]; ok && json.Unmarshal(v, &mode) != nil || mode < 0 {
			return enginemount.Mount{}, "", "", fmt.Errorf("mode must be a non-negative integer")
		}
		return enginemount.Mount{Type: enginemount.TypeTmpfs, Target: target, ReadOnly: readOnly, TmpfsOptions: &enginemount.TmpfsOptions{Options: parsed, SizeBytes: size, Mode: os.FileMode(mode)}}, "", target, nil
	case "image":
		return enginemount.Mount{}, "", "", fmt.Errorf("image mounts are unsupported by pinned Docker Engine API")
	default:
		return enginemount.Mount{}, "", "", fmt.Errorf("unknown mount type %q", kind)
	}
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var parseValue func() error
	parseValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key := keyToken.(string)
				if _, ok := seen[key]; ok {
					return fmt.Errorf("duplicate field %q", key)
				}
				seen[key] = struct{}{}
				if err := parseValue(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := parseValue(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		}
		return fmt.Errorf("unexpected delimiter %q", delim)
	}
	if err := parseValue(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("multiple JSON values")
	}
	return nil
}
