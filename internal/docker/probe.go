// Package docker implements driver.ComputeDriver via the Docker Engine API.
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/docker/go-units"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"

	"github.com/cautem/quarshell-driver/driver"
)

// ParseMemoryBytes parses Docker-style memory strings (512m, 4g, …).
func ParseMemoryBytes(s string) (int64, error) {
	return units.RAMInBytes(s)
}

// Logs streams stdout/stderr from the sandbox container and, when present, the
// egress proxy sidecar (where OCSF agent-observation events are emitted).
// When follow is true, starts from the last 500 lines per container.

func sanitizeName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}

// RunProbe runs cautem-init --probe in a one-shot helper container (Landlock ABI).

// RunProbe runs cautem-init --probe in a one-shot helper container (Landlock ABI).
func (d *Driver) RunProbe(ctx context.Context, initBin string) (string, error) {
	if d == nil || d.cli == nil {
		return "", fmt.Errorf("docker client not initialized")
	}
	if err := d.ensureImage(ctx, defaultImage); err != nil {
		return "", err
	}
	cfg := &container.Config{
		Image:      defaultImage,
		Cmd:        []string{"/cautem/cautem-init", "--probe"},
		WorkingDir: "/",
	}
	host := &container.HostConfig{
		Binds: []string{initBin + ":/cautem/cautem-init:ro"},
		// AutoRemove handled after wait
	}
	resp, err := d.cli.ContainerCreate(ctx, client.ContainerCreateOptions{Config: cfg, HostConfig: host, NetworkingConfig: nil, Name: ""})
	if err != nil {
		return "", fmt.Errorf("probe create: %w", err)
	}
	id := resp.ID
	defer func() { _, _ = d.cli.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true}) }()
	if _, err := d.cli.ContainerStart(ctx, id, client.ContainerStartOptions{}); err != nil {
		return "", fmt.Errorf("probe start: %w", err)
	}
	wait := d.cli.ContainerWait(ctx, id, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case err := <-wait.Error:
		if err != nil {
			return "", err
		}
	case <-wait.Result:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	logs, err := d.cli.ContainerLogs(ctx, id, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return "", err
	}
	defer logs.Close()
	var buf strings.Builder
	_, _ = stdcopy.StdCopy(&buf, &buf, logs)
	out := strings.TrimSpace(buf.String())
	if out == "" {
		return "empty probe output", nil
	}
	// Compact one-line summary if JSON
	if strings.Contains(out, "LandlockABI") {
		return summarizeProbeJSON(out), nil
	}
	return out, nil
}

func summarizeProbeJSON(raw string) string {
	raw = strings.TrimSpace(raw)
	// Prefer a one-line human summary when JSON decode works.
	var m struct {
		LandlockABI                        int    `json:"LandlockABI"`
		LandlockFilesystemRulesAvailable   bool   `json:"LandlockFilesystemRulesAvailable"`
		LandlockDeniedAccessAuditAvailable bool   `json:"LandlockDeniedAccessAuditAvailable"`
		LandlockProfileMaxABI              int    `json:"LandlockProfileMaxABI"`
		LandlockError                      string `json:"LandlockError"`
	}
	if err := json.Unmarshal([]byte(raw), &m); err == nil {
		if m.LandlockABI > 0 {
			profile := m.LandlockProfileMaxABI
			if profile == 0 {
				profile = m.LandlockABI
				if profile > 7 {
					profile = 7
				} else if profile > 5 {
					profile = 5
				}
			}
			features := "filesystem rules unavailable"
			if m.LandlockFilesystemRulesAvailable {
				features = "filesystem rules available"
			}
			if m.LandlockDeniedAccessAuditAvailable {
				features += "; denied-access audit available through kernel audit"
			} else {
				features += "; denied-access audit unavailable"
			}
			return fmt.Sprintf("abi=%d (profile up to V%d; %s)", m.LandlockABI, profile, features)
		}
		if m.LandlockError != "" {
			return fmt.Sprintf("abi=0 (%s)", m.LandlockError)
		}
		return "abi=0"
	}
	return strings.ReplaceAll(strings.ReplaceAll(raw, "\n", " "), "  ", " ")
}

// Health probes the daemon (Ping + ServerVersion + Info).

// Health probes the daemon (Ping + ServerVersion + Info).
func (d *Driver) Health(ctx context.Context) driver.Probe {
	runtimeContext := ""
	if d != nil {
		runtimeContext = d.runtimeConfig.RuntimeContext
	}
	if runtimeContext == "" {
		runtimeContext = dockerContextName()
	}
	p := driver.Probe{
		Context:      runtimeContext,
		HostGOOS:     runtime.GOOS,
		Capabilities: d.capabilities(),
	}
	if d == nil || d.cli == nil {
		p.Error = "docker client not initialized"
		return p
	}
	if _, err := d.cli.Ping(ctx, client.PingOptions{}); err != nil {
		p.Error = err.Error()
		return p
	}
	ver, err := d.cli.ServerVersion(ctx, client.ServerVersionOptions{})
	if err != nil {
		p.Error = err.Error()
		return p
	}
	p.ServerVersion = ver.Version
	p.APIVersion = ver.APIVersion
	p.OperatingSystem = ver.Os
	p.Architecture = ver.Arch

	info, err := d.cli.Info(ctx, client.InfoOptions{})
	if err == nil {
		if info.Info.OperatingSystem != "" {
			p.OperatingSystem = info.Info.OperatingSystem
		}
		if info.Info.Architecture != "" {
			p.Architecture = info.Info.Architecture
		}
		p.Isolation = classifyIsolation(runtime.GOOS, info.Info.OperatingSystem, info.Info.OSType)
		p.SecurityOptions = append([]string(nil), info.Info.SecurityOptions...)
		for _, option := range info.Info.SecurityOptions {
			if strings.Contains(strings.ToLower(option), "rootless") {
				p.Rootless = "yes"
				break
			}
		}
		if p.Rootless == "" {
			p.Rootless = "no or unreported"
		}
	} else {
		p.Isolation = classifyIsolation(runtime.GOOS, p.OperatingSystem, ver.Os)
	}
	p.OK = true
	return p
}

func (d *Driver) capabilities() []string {
	if d != nil && len(d.runtimeConfig.Capabilities) > 0 {
		return append([]string(nil), d.runtimeConfig.Capabilities...)
	}
	return []string{"cdi"}
}

func dockerContextName() string {
	if v := strings.TrimSpace(os.Getenv("DOCKER_CONTEXT")); v != "" {
		return v
	}
	return "default"
}

func classifyIsolation(hostGOOS, _, _ string) string {
	if hostGOOS == "darwin" || hostGOOS == "windows" {
		return "docker-desktop-vm"
	}
	if hostGOOS == "linux" {
		return "native-linux"
	}
	return "unknown"
}
