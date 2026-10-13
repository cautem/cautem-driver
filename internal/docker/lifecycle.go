// Package docker implements driver.ComputeDriver via the Docker Engine API.
package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	core "github.com/cautem/cautem-core"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

// Start starts a created workload and its policy proxy, if configured.
func (d *Driver) Start(ctx context.Context, id core.ID) error {
	info, err := d.cli.ContainerInspect(ctx, string(id), client.ContainerInspectOptions{})
	if err != nil {
		if isNotFound(err) {
			manifest, manifestErr := d.loadCleanupManifest(string(id))
			if errors.Is(manifestErr, os.ErrNotExist) {
				return nil
			}
			if manifestErr != nil {
				return fmt.Errorf("docker start load cleanup manifest: %w", manifestErr)
			}
			proxyID, _, found, proxyErr := d.inspectProxy(ctx, manifest.SandboxName)
			if proxyErr != nil {
				return fmt.Errorf("docker start orphan proxy inspect: %w", proxyErr)
			}
			if found {
				if proxyErr := d.stopContainerIfRunning(ctx, proxyID); proxyErr != nil {
					return fmt.Errorf("docker start stop orphan proxy: %w", proxyErr)
				}
			}
			return fmt.Errorf("docker start: sandbox workload no longer exists")
		}
		return fmt.Errorf("docker start inspect: %w", err)
	}
	if info.Container.Config == nil {
		return fmt.Errorf("docker start: container config is unavailable")
	}
	labels := info.Container.Config.Labels
	name := labels[labelName]
	proxyID, proxyPort, hasProxy, err := d.ensureProxyRunning(ctx, name)
	if err != nil {
		return err
	}
	proxyExpected := labels["cautem.ca_volume"] != ""
	if proxyExpected && !hasProxy {
		return fmt.Errorf("docker start: configured policy proxy sidecar is missing")
	}
	if hasProxy {
		if labels["cautem.ca_volume"] != "" {
			if err := d.waitProxyCA(ctx, proxyID, readinessTimeout); err != nil {
				_ = d.stopContainerIfRunning(context.WithoutCancel(ctx), proxyID)
				return fmt.Errorf("docker start proxy CA: %w", err)
			}
		}
		if err := d.waitProxyListening(ctx, proxyID, proxyPort, readinessTimeout); err != nil {
			_ = d.stopContainerIfRunning(context.WithoutCancel(ctx), proxyID)
			return fmt.Errorf("docker start proxy readiness: %w", err)
		}
	}
	if info.Container.State == nil || info.Container.State.Status != "running" {
		if err := d.startContainerIfStopped(ctx, string(id)); err != nil {
			if hasProxy {
				_ = d.stopContainerIfRunning(context.WithoutCancel(ctx), proxyID)
			}
			return fmt.Errorf("docker start workload: %w", err)
		}
	}
	if err := d.ensureGuestLayout(ctx, string(id)); err != nil {
		_ = d.stopContainerIfRunning(context.WithoutCancel(ctx), string(id))
		if hasProxy {
			_ = d.stopContainerIfRunning(context.WithoutCancel(ctx), proxyID)
		}
		return fmt.Errorf("docker start guest layout: %w", err)
	}
	if labels[labelSSH] == "1" {
		if err := d.EnsureSSHDaemon(ctx, id); err != nil {
			_ = d.stopContainerIfRunning(context.WithoutCancel(ctx), string(id))
			if hasProxy {
				_ = d.stopContainerIfRunning(context.WithoutCancel(ctx), proxyID)
			}
			return fmt.Errorf("docker start ssh relay: %w", err)
		}
	}
	return nil
}

// ensureGuestLayout creates durable home/bin under GuestData for agent installs.
// Uses a raw docker exec (no cautem-init wrap) so layout works before harden paths matter.

// ensureGuestLayout creates durable home/bin under GuestData for agent installs.
// Uses a raw docker exec (no cautem-init wrap) so layout works before harden paths matter.
func (d *Driver) ensureGuestLayout(ctx context.Context, id string) error {
	info, err := d.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil || info.Container.Config == nil {
		return err
	}
	if info.Container.Config.Labels[labelRole] == roleProxy {
		return nil
	}
	if info.Container.Config.Labels[labelVolume] == "" {
		return nil
	}
	script := "mkdir -p " + guestHomePath + "/.local/bin " + guestBinPath + " && " +
		"printf '%s\\n' 'export PATH=\"" + guestHomePath + "/.local/bin:" + guestBinPath + ":$PATH\"' > " + guestHomePath + "/.profile && " +
		"printf '%s\\n' 'export PATH=\"" + guestHomePath + "/.local/bin:" + guestBinPath + ":$PATH\"' > " + guestHomePath + "/.bashrc"
	execID, err := d.cli.ExecCreate(ctx, id, client.ExecCreateOptions{
		Cmd:          []string{"/bin/sh", "-c", script},
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   "/",
		Env:          []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
	})
	if err != nil {
		return fmt.Errorf("guest layout exec create: %w", err)
	}
	attach, err := d.cli.ExecAttach(ctx, execID.ID, client.ExecAttachOptions{})
	if err != nil {
		return fmt.Errorf("guest layout exec attach: %w", err)
	}
	defer attach.Close()
	var stdout, stderr bytes.Buffer
	_, _ = stdcopy.StdCopy(&stdout, &stderr, io.LimitReader(attach.Reader, 64<<10))
	output := strings.TrimSpace(stderr.String())
	if output == "" {
		output = strings.TrimSpace(stdout.String())
	}
	insp, err := d.cli.ExecInspect(ctx, execID.ID, client.ExecInspectOptions{})
	if err != nil {
		return err
	}
	if insp.ExitCode != 0 {
		state := "unknown"
		daemonError := ""
		if info, inspectErr := d.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{}); inspectErr == nil && info.Container.State != nil {
			state = string(info.Container.State.Status)
			daemonError = strings.TrimSpace(info.Container.State.Error)
		}
		if daemonError != "" {
			return fmt.Errorf("guest layout exit %d (container state=%s: %s, output=%q)", insp.ExitCode, state, daemonError, output)
		}
		return fmt.Errorf("guest layout exit %d (container state=%s, output=%q)", insp.ExitCode, state, output)
	}
	return nil
}

// Stop stops the workload and its policy proxy so no companion retains
// credentials or network access while the sandbox is stopped.

// Stop stops the workload and its policy proxy so no companion retains
// credentials or network access while the sandbox is stopped.
func (d *Driver) Stop(ctx context.Context, id core.ID) error {
	info, err := d.cli.ContainerInspect(ctx, string(id), client.ContainerInspectOptions{})
	if err != nil {
		if isNotFound(err) {
			manifest, manifestErr := d.loadCleanupManifest(string(id))
			if errors.Is(manifestErr, os.ErrNotExist) {
				return nil
			}
			if manifestErr != nil {
				return fmt.Errorf("docker stop load cleanup manifest: %w", manifestErr)
			}
			proxyID, _, found, proxyErr := d.inspectProxy(ctx, manifest.SandboxName)
			if proxyErr != nil {
				return fmt.Errorf("docker stop orphan proxy inspect: %w", proxyErr)
			}
			if found {
				if proxyErr := d.stopContainerIfRunning(ctx, proxyID); proxyErr != nil {
					return fmt.Errorf("docker stop orphan proxy: %w", proxyErr)
				}
			}
			return nil
		}
		return fmt.Errorf("docker stop inspect: %w", err)
	}
	var stopErrs []error
	if info.Container.State == nil || info.Container.State.Status == "running" {
		if err := d.stopContainerIfRunning(ctx, string(id)); err != nil {
			stopErrs = append(stopErrs, fmt.Errorf("docker stop workload: %w", err))
		}
	}
	if info.Container.Config == nil {
		stopErrs = append(stopErrs, fmt.Errorf("docker stop: container config is unavailable"))
		return errors.Join(stopErrs...)
	}
	name := info.Container.Config.Labels[labelName]
	proxyID, _, found, err := d.inspectProxy(ctx, name)
	if err != nil {
		stopErrs = append(stopErrs, fmt.Errorf("docker stop proxy inspect: %w", err))
	} else if found {
		if err := d.stopContainerIfRunning(ctx, proxyID); err != nil {
			stopErrs = append(stopErrs, fmt.Errorf("docker stop proxy: %w", err))
		}
	}
	return errors.Join(stopErrs...)
}

// Exec runs a command in the container. With TTY, attaches stdin/stdout in raw mode.
// When the sandbox was created with cautem-init, argv is wrapped: cautem-init -- <cmd>.
//
// Docker ExecCreate Env replaces the process environment when non-empty.
// We always merge the container's Config.Env first so HTTP_PROXY / CA / HOME from
// create survive (otherwise `cautem exec` / create `-- agent` cannot reach the sidecar).

// Delete removes sandbox container, proxy sidecar, cautem network, and data volume.
func (d *Driver) Delete(ctx context.Context, id core.ID) error {
	info, err := d.cli.ContainerInspect(ctx, string(id), client.ContainerInspectOptions{})
	var manifest cleanupManifest
	if err == nil {
		if info.Container.Config == nil {
			return fmt.Errorf("docker delete: workload container config is unavailable")
		}
		manifest, err = cleanupManifestFromLabels(string(id), info.Container.Config.Labels)
		if err != nil {
			return err
		}
		if err := d.saveCleanupManifest(manifest); err != nil {
			return err
		}
	} else if isNotFound(err) {
		manifest, err = d.loadCleanupManifest(string(id))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("docker delete load cleanup manifest: %w", err)
		}
	} else {
		return fmt.Errorf("docker delete inspect: %w", err)
	}

	var proxyErr error
	if manifest.SandboxName != "" {
		proxyErr = d.removeProxySidecar(ctx, manifest.SandboxName)
	}
	_, workloadErr := d.cli.ContainerRemove(ctx, string(id), client.ContainerRemoveOptions{Force: true})
	if isNotFound(workloadErr) {
		workloadErr = nil
	}
	if workloadErr != nil {
		if proxyErr != nil {
			return errors.Join(fmt.Errorf("docker delete proxy: %w", proxyErr), fmt.Errorf("docker delete workload: %w", workloadErr))
		}
		return fmt.Errorf("docker delete workload: %w", workloadErr)
	}
	if proxyErr != nil {
		return fmt.Errorf("docker delete proxy: %w", proxyErr)
	}
	var deleteErrs []error
	if manifest.Network != "" {
		if err := d.removeManagedNetwork(ctx, manifest); err != nil {
			deleteErrs = append(deleteErrs, fmt.Errorf("docker delete network %s: %w", manifest.Network, err))
		}
	}
	for _, volume := range []struct{ name, role string }{
		{manifest.DataVolume, roleVolumeData},
		{manifest.CAVolume, roleVolumeCA},
		{manifest.SSHVolume, roleVolumeSSH},
	} {
		if volume.name == "" {
			continue
		}
		if err := d.removeManagedVolume(ctx, manifest, volume.name, volume.role); err != nil {
			deleteErrs = append(deleteErrs, fmt.Errorf("docker delete volume %s: %w", volume.name, err))
		}
	}
	if err := errors.Join(deleteErrs...); err != nil {
		return err
	}
	return d.removeCleanupManifest(string(id))
}

// List returns cautem sandbox containers (excludes proxy sidecars).

func (d *Driver) stopContainerIfRunning(ctx context.Context, id string) error {
	info, err := d.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Container.State != nil && info.Container.State.Status != "running" {
		return nil
	}
	timeout := d.stopTimeoutSecs()
	_, err = d.cli.ContainerStop(ctx, id, client.ContainerStopOptions{Timeout: &timeout})
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		// The process can exit between inspect and stop. Treat that race as an
		// idempotent stop only after confirming the runtime now observes it stopped.
		after, inspectErr := d.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
		if inspectErr == nil && after.Container.State != nil && after.Container.State.Status != "running" {
			return nil
		}
	}
	return err
}

func (d *Driver) startContainerIfStopped(ctx context.Context, id string) error {
	info, err := d.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return err
	}
	if info.Container.State != nil && info.Container.State.Status == "running" {
		return nil
	}
	if _, err := d.cli.ContainerStart(ctx, id, client.ContainerStartOptions{}); err != nil {
		after, inspectErr := d.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
		if inspectErr == nil && after.Container.State != nil && after.Container.State.Status == "running" {
			return nil
		}
		return err
	}
	return nil
}
