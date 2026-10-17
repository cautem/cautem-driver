package vm

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/cautem/quarshell-driver/driver"
)

// ValidateSpec reports unsupported VM guarantees and missing static VM
// configuration before Gateway lifecycle state is persisted.
func (d *Driver) ValidateSpec(spec driver.Spec) error {
	if d == nil {
		return fmt.Errorf("vm driver: driver is nil")
	}
	config, err := ParseSandboxDriverConfig(spec.DriverConfigJSON)
	if err != nil {
		return err
	}
	if err := validateMainProcessRestartPolicy(spec); err != nil {
		return err
	}
	if err := validateGPURequest(spec.GPU, config); err != nil {
		return err
	}
	if err := validateResourceLimits(spec.CPU, spec.MemoryBytes); err != nil {
		return err
	}
	if spec.PidsLimit < -1 || spec.PidsLimit > 1_000_000 {
		return fmt.Errorf("vm driver: PID limit must be -1 or between 0 and 1000000")
	}
	if spec.PidsLimit > 0 && spec.SupervisorBin == "" {
		return fmt.Errorf("vm driver: a positive PID limit requires supervisor_bin")
	}
	if err := validateNetworkBrokerSpec(spec); err != nil {
		return err
	}
	if err := validateGuestRuntimeAssets(spec); err != nil {
		return err
	}
	if err := validateSupportedSpec(spec); err != nil {
		return err
	}
	if config.RootfsTarPath == "" && strings.TrimSpace(spec.Image) == "" {
		return fmt.Errorf("vm driver: image or rootfs_tar_path is required")
	}
	if config.RootfsTarPath == "" {
		if _, err := parseOCIImageReference(spec.Image); err != nil {
			return fmt.Errorf("vm driver: %w", err)
		}
	}
	return nil
}

func validateMainProcessRestartPolicy(spec driver.Spec) error {
	policy, err := driver.NormalizeMainProcessRestartPolicy(spec.MainProcessRestartPolicy)
	if err != nil {
		return fmt.Errorf("vm driver: %w", err)
	}
	if policy != "never" && spec.SupervisorBin == "" {
		return fmt.Errorf("vm driver: main process restart policy requires supervisor_bin")
	}
	return nil
}

// validateResourceLimits ensures requested resources can be represented by
// libkrun's public VM configuration without silently changing the request.
func validateResourceLimits(cpu float64, memoryBytes int64) error {
	if math.IsNaN(cpu) || math.IsInf(cpu, 0) || cpu < 0 {
		return fmt.Errorf("vm driver: CPU limit must be finite and non-negative")
	}
	if cpu > 0 && math.Ceil(cpu) > float64(^uint8(0)) {
		return fmt.Errorf("vm driver: CPU limit %.3g exceeds libkrun maximum of %d vCPUs", cpu, ^uint8(0))
	}
	if memoryBytes < 0 {
		return fmt.Errorf("vm driver: memory limit must be non-negative")
	}
	if memoryBytes > 0 {
		const mebibyte = uint64(1 << 20)
		maxBytes := uint64(^uint32(0)) * mebibyte
		if uint64(memoryBytes) > maxBytes {
			return fmt.Errorf("vm driver: memory limit exceeds libkrun maximum of %d MiB", ^uint32(0))
		}
	}
	return nil
}

// ValidateGatewayRuntime reports the Gateway lifecycle guarantees that this
// experimental backend cannot currently provide. Keeping this preflight
// separate from per-spec validation lets the Gateway reject before consuming
// a one-shot rootfs upload or writing sandbox state. Keep the reasons aligned
// with the supported-spec checks and the documented production gates.
func (d *Driver) ValidateGatewayRuntime() error {
	if d == nil {
		return fmt.Errorf("vm driver: driver is nil")
	}
	return fmt.Errorf("vm driver: Gateway runtime is unsupported: shared workspace data plane (ownership, persistence, and recovery) is unavailable; VM workers do not have a dedicated host identity; Gateway-to-VM end-to-end acceptance is incomplete")
}

func validateNetworkBrokerSpec(spec driver.Spec) error {
	configured := spec.ProxyBin != "" || spec.PolicyPath != "" || spec.ProxyPort != 0 || len(spec.ProxyEnv) != 0
	if !configured {
		return nil
	}
	if spec.ProxyBin == "" || spec.PolicyPath == "" {
		return fmt.Errorf("vm driver: policy network broker requires both proxy_bin and policy_path")
	}
	if spec.ProxyPort < 0 || spec.ProxyPort > 65535 {
		return fmt.Errorf("vm driver: policy proxy port must be between 1 and 65535")
	}
	if !filepath.IsAbs(spec.ProxyBin) || filepath.Clean(spec.ProxyBin) != spec.ProxyBin {
		return fmt.Errorf("vm driver: policy proxy binary path must be a clean absolute path")
	}
	if _, err := validateExecutablePath(spec.ProxyBin); err != nil {
		return fmt.Errorf("vm driver: policy proxy binary: %w", err)
	}
	if !filepath.IsAbs(spec.PolicyPath) || filepath.Clean(spec.PolicyPath) != spec.PolicyPath {
		return fmt.Errorf("vm driver: policy path must be a clean absolute path")
	}
	policyInfo, err := os.Lstat(spec.PolicyPath)
	if err != nil {
		return fmt.Errorf("vm driver: inspect policy file: %w", err)
	}
	if !policyInfo.Mode().IsRegular() || policyInfo.Mode()&os.ModeSymlink != 0 || policyInfo.Size() == 0 || policyInfo.Size() > 4<<20 || policyInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("vm driver: policy file must be a non-empty regular file no larger than 4 MiB and not writable by group or others")
	}
	if err := validateNetworkBrokerEnvironment(spec.ProxyEnv); err != nil {
		return err
	}
	return nil
}

func validateNetworkBrokerEnvironment(entries []string) error {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !validBrokerEnvKey(key) || strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("vm driver: policy proxy environment contains an invalid entry")
		}
		if strings.HasPrefix(key, "LD_") || strings.HasPrefix(key, "DYLD_") || key == "PATH" || key == "HOME" {
			return fmt.Errorf("vm driver: policy proxy environment may not override %s or dynamic loader settings", key)
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("vm driver: policy proxy environment contains duplicate key %s", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateGuestRuntimeAssets(spec driver.Spec) error {
	supervisorConfigured := spec.SupervisorBin != ""
	sshConfigured := spec.EnableSSH || spec.SSHBin != ""
	if !supervisorConfigured && !sshConfigured {
		if spec.InitBin != "" {
			return fmt.Errorf("vm driver: init_bin requires supervisor_bin or SSH relay")
		}
		return nil
	}
	if spec.InitBin == "" {
		return fmt.Errorf("vm driver: hardened init binary is required for supervisor and SSH relay")
	}
	if sshConfigured && !supervisorConfigured {
		return fmt.Errorf("vm driver: SSH relay requires the workload supervisor")
	}
	if spec.ProxyBin == "" || spec.PolicyPath == "" {
		return fmt.Errorf("vm driver: supervisor and SSH relay require the per-VM policy proxy")
	}
	for label, path := range map[string]string{"hardened init": spec.InitBin} {
		if _, err := validateExecutablePath(path); err != nil {
			return fmt.Errorf("vm driver: %s binary: %w", label, err)
		}
	}
	if supervisorConfigured {
		if _, err := validateExecutablePath(spec.SupervisorBin); err != nil {
			return fmt.Errorf("vm driver: supervisor binary: %w", err)
		}
	}
	if sshConfigured {
		if !spec.EnableSSH || spec.SSHBin == "" {
			return fmt.Errorf("vm driver: SSH relay requires both ssh=true and ssh_bin")
		}
		if _, err := validateExecutablePath(spec.SSHBin); err != nil {
			return fmt.Errorf("vm driver: SSH daemon binary: %w", err)
		}
	}
	return nil
}

func validBrokerEnvKey(key string) bool {
	if key == "" || key[0] == '=' {
		return false
	}
	for i, char := range key {
		isLetter := char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z'
		isDigit := i > 0 && char >= '0' && char <= '9'
		if char != '_' && !isLetter && !isDigit {
			return false
		}
	}
	return true
}

// validateSupportedSpec prevents the VM backend from silently accepting
// compute guarantees that it does not implement. Keep this list explicit so
// adding fields to driver.Spec requires an intentional VM capability decision.
func validateSupportedSpec(spec driver.Spec) error {
	unsupported := make([]string, 0, 24)
	add := func(enabled bool, field string) {
		if enabled {
			unsupported = append(unsupported, field)
		}
	}
	add(spec.Workspace != "", "workspace")
	add(spec.GatewayID != "", "gateway_id")
	add(spec.IKnow, "i_know")
	add(spec.NoHarden, "no_harden")
	// Supervisor and SSH binaries are copied into the per-sandbox overlay and
	// run through the guest control agent when their complete contracts validate.
	add(spec.DisplayMode != "", "display_mode")
	add(spec.DisplayPort != 0, "display_port")
	add(spec.DisplayPassword != "", "display_password")
	add(len(spec.Labels) != 0, "labels")
	add(len(spec.ExtraHosts) != 0, "extra_hosts")
	add(spec.GatewayURL != "", "gateway_url")
	add(spec.PersistVolume, "persist_volume")
	add(spec.GPU || spec.GPUCount != 0 || len(spec.CDIDevices) != 0, "gpu")
	add(spec.ProxyImage != "", "proxy_image")
	add(len(spec.PublishPorts) != 0, "publish_ports")
	if len(unsupported) != 0 {
		return fmt.Errorf("vm driver: unsupported spec fields: %s", strings.Join(unsupported, ", "))
	}
	return nil
}
