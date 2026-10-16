// Package docker implements driver.ComputeDriver via the Docker Engine API.
package docker

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/moby/moby/client"

	"github.com/cautem/quarshell-core/defaults"
)

// ImagePresent reports whether ref exists locally (no pull).
func (d *Driver) ImagePresent(ctx context.Context, ref string) bool {
	if d == nil || d.cli == nil || strings.TrimSpace(ref) == "" {
		return false
	}
	_, err := d.cli.ImageInspect(ctx, ref)
	return err == nil
}

func (d *Driver) ensureImage(ctx context.Context, ref string) error {
	policy := strings.ToLower(strings.TrimSpace(d.runtimeConfig.ImagePullPolicy))
	if policy == "always" || policy == "newer" {
		return d.pullImage(ctx, ref)
	}
	_, err := d.cli.ImageInspect(ctx, ref)
	if err == nil {
		return nil
	}
	if policy == "never" {
		return fmt.Errorf("docker image %s is not available locally and image_pull_policy is never", ref)
	}
	low := strings.ToLower(ref)
	if low == localSandboxImage || low == guiSandboxImage || low == gpuSandboxImage || low == guiGPUSandboxImage || strings.HasPrefix(low, "cautem-sandbox:") {
		remote, published := defaults.PublishedImage(low)
		var pullErr error
		if published && !strings.EqualFold(os.Getenv(defaults.EnvImagePull), "never") {
			if pullErr = d.pullAs(ctx, remote, ref); pullErr == nil {
				return nil
			}
		}
		hint := "task runtime:image:cli"
		switch {
		case strings.Contains(low, "cursor"):
			hint = "task docker:agent:cursor"
		case strings.Contains(low, "claude"):
			hint = "task docker:agent:claude"
		case strings.Contains(low, "codex"):
			hint = "task docker:agent:codex"
		case low == guiGPUSandboxImage || strings.Contains(low, "gui-gpu"):
			hint = "task runtime:image:gui-gpu"
		case low == guiSandboxImage || strings.Contains(low, "gui"):
			hint = "task runtime:image:gui"
		case low == gpuSandboxImage || strings.Contains(low, "gpu"):
			hint = "task runtime:image:gpu"
		}
		if pullErr != nil {
			return fmt.Errorf("docker image %s not found locally and %w; build with: %s", ref, pullErr, hint)
		}
		if published {
			return fmt.Errorf("docker image %s not found locally; build with: %s (or unset %s=never to pull %s)", ref, hint, defaults.EnvImagePull, remote)
		}
		return fmt.Errorf("docker image %s not found locally; build with: %s", ref, hint)
	}
	return d.pullImage(ctx, ref)
}

func (d *Driver) pullImage(ctx context.Context, ref string) error {
	auth, err := d.registryAuth(ref)
	if err != nil {
		return err
	}
	rc, err := d.cli.ImagePull(ctx, ref, client.ImagePullOptions{RegistryAuth: auth})
	if err != nil {
		return fmt.Errorf("docker pull %s: %w", ref, err)
	}
	defer rc.Close()
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return fmt.Errorf("docker pull %s: %w", ref, err)
	}
	return nil
}

// pullAs pulls a published image and tags it with the local name the rest of
// the driver keys on (embedded init, GUI detection).

// pullAs pulls a published image and tags it with the local name the rest of
// the driver keys on (embedded init, GUI detection).
func (d *Driver) pullAs(ctx context.Context, remote, local string) error {
	fmt.Fprintf(os.Stderr, "docker: pulling %s (for %s)…\n", remote, local)
	auth, err := d.registryAuth(remote)
	if err != nil {
		return err
	}
	rc, err := d.cli.ImagePull(ctx, remote, client.ImagePullOptions{RegistryAuth: auth})
	if err != nil {
		return fmt.Errorf("pull %s failed: %w", remote, err)
	}
	_, _ = io.Copy(io.Discard, rc)
	_ = rc.Close()
	if _, err := d.cli.ImageTag(ctx, client.ImageTagOptions{Source: remote, Target: local}); err != nil {
		return fmt.Errorf("pull %s failed: %w", remote, err)
	}
	return nil
}

func (d *Driver) defaultSandboxImage(ctx context.Context, displayMode string, gpu bool) string {
	if d == nil || d.cli == nil {
		return localSandboxImage
	}
	if strings.EqualFold(strings.TrimSpace(displayMode), "novnc") && gpu {
		return guiGPUSandboxImage
	}
	if strings.EqualFold(strings.TrimSpace(displayMode), "novnc") {
		if _, err := d.cli.ImageInspect(ctx, guiSandboxImage); err == nil {
			return guiSandboxImage
		}
		return guiSandboxImage // ensureImage will fail with a clear pull error; task runtime:image:gui preferred
	}
	if gpu {
		if _, err := d.cli.ImageInspect(ctx, gpuSandboxImage); err == nil {
			return gpuSandboxImage
		}
		return gpuSandboxImage
	}
	// The generic Debian base lacks the sandbox account and cautem-init
	// required by the default hardening policy. Let ensureImage pull the
	// published cautem base when it is not already available locally.
	return localSandboxImage
}

func usesEmbeddedInit(img string) bool {
	img = strings.TrimSpace(strings.ToLower(img))
	return img == localSandboxImage || img == guiSandboxImage || strings.HasPrefix(img, "cautem-sandbox:")
}

func imageHasGUI(img string) bool {
	img = strings.TrimSpace(strings.ToLower(img))
	if img == guiSandboxImage || img == guiGPUSandboxImage || strings.Contains(img, ":gui") {
		return true
	}
	ref := img
	if before, _, ok := strings.Cut(ref, "@"); ok {
		ref = before
	}
	leaf := ref
	if i := strings.LastIndexByte(leaf, '/'); i >= 0 {
		leaf = leaf[i+1:]
	}
	flavor := strings.SplitN(leaf, ":", 2)[0]
	if flavor == "gui" || flavor == "gui-gpu" {
		return true
	}
	// Heuristic: inspect for cautem-gui-boot via missing path is hard; require known tags.
	return false
}

// SeccompNote documents the MVP harden posture for health / spike notes.

// SeccompNote documents the MVP harden posture for health / spike notes.
func SeccompNote() string {
	return "docker-default + no-new-privileges + CapDrop=NET_RAW (in-process filter later)"
}
