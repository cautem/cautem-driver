package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/moby/moby/client"
)

const cleanupManifestVersion = 1

// cleanupManifest preserves the names and ownership identity of daemon
// resources so Delete can resume after the workload container is gone.
type cleanupManifest struct {
	Version     int    `json:"version"`
	ContainerID string `json:"container_id"`
	SandboxName string `json:"sandbox_name"`
	Network     string `json:"network,omitempty"`
	DataVolume  string `json:"data_volume,omitempty"`
	CAVolume    string `json:"ca_volume,omitempty"`
	SSHVolume   string `json:"ssh_volume,omitempty"`
}

func (d *Driver) cleanupManifestPath(id string) (string, error) {
	dir := d.runtimeConfig.CleanupManifestDir
	if dir == "" {
		return "", nil
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return "", fmt.Errorf("docker cleanup manifest directory must be an absolute clean path")
	}
	if id == "" || filepath.Base(id) != id || strings.ContainsAny(id, `/\\`) || id == "." || id == ".." {
		return "", fmt.Errorf("docker cleanup manifest has invalid container ID")
	}
	return filepath.Join(dir, id+".json"), nil
}

func (d *Driver) saveCleanupManifest(manifest cleanupManifest) error {
	if d.runtimeConfig.CleanupManifestDir == "" {
		return nil
	}
	path, err := d.cleanupManifestPath(manifest.ContainerID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d.runtimeConfig.CleanupManifestDir, 0o700); err != nil {
		return fmt.Errorf("create Docker cleanup manifest directory: %w", err)
	}
	dirInfo, err := os.Lstat(d.runtimeConfig.CleanupManifestDir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 || dirInfo.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("docker cleanup manifest directory is not a real directory")
	}
	if err := syncDirectory(filepath.Dir(d.runtimeConfig.CleanupManifestDir)); err != nil {
		return fmt.Errorf("sync Docker cleanup manifest parent directory: %w", err)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode Docker cleanup manifest: %w", err)
	}
	if existing, err := readCleanupManifest(path, manifest.ContainerID); err == nil {
		if existing != manifest {
			return fmt.Errorf("docker cleanup manifest for container %s already contains different ownership data", manifest.ContainerID)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(d.runtimeConfig.CleanupManifestDir, ".cleanup-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary Docker cleanup manifest: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("protect temporary Docker cleanup manifest: %w", err)
	}
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write Docker cleanup manifest: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync Docker cleanup manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close Docker cleanup manifest: %w", err)
	}
	// Link publishes atomically without replacing an existing manifest. If a
	// competing delete won the race, only accept byte-for-byte identical data.
	if err := os.Link(tmpPath, path); err != nil {
		if existing, readErr := readCleanupManifest(path, manifest.ContainerID); readErr == nil && existing == manifest {
			return nil
		}
		return fmt.Errorf("publish Docker cleanup manifest: %w", err)
	}
	if err := syncDirectory(d.runtimeConfig.CleanupManifestDir); err != nil {
		return fmt.Errorf("sync Docker cleanup manifest directory: %w", err)
	}
	return nil
}

func (d *Driver) loadCleanupManifest(id string) (cleanupManifest, error) {
	path, err := d.cleanupManifestPath(id)
	if err != nil {
		return cleanupManifest{}, err
	}
	if path == "" {
		return cleanupManifest{}, os.ErrNotExist
	}
	return readCleanupManifest(path, id)
}

func readCleanupManifest(path, expectedID string) (cleanupManifest, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return cleanupManifest{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return cleanupManifest{}, fmt.Errorf("docker cleanup manifest is not a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return cleanupManifest{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64*1024))
	decoder.DisallowUnknownFields()
	var manifest cleanupManifest
	if err := decoder.Decode(&manifest); err != nil {
		return cleanupManifest{}, fmt.Errorf("decode Docker cleanup manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return cleanupManifest{}, fmt.Errorf("docker cleanup manifest has trailing data")
	}
	if manifest.Version != cleanupManifestVersion || manifest.ContainerID != expectedID || manifest.SandboxName == "" {
		return cleanupManifest{}, fmt.Errorf("docker cleanup manifest ownership or version mismatch")
	}
	return manifest, nil
}

func (d *Driver) removeCleanupManifest(id string) error {
	path, err := d.cleanupManifestPath(id)
	if err != nil || path == "" {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove Docker cleanup manifest: %w", err)
	}
	return syncDirectory(d.runtimeConfig.CleanupManifestDir)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func cleanupManifestFromLabels(id string, labels map[string]string) (cleanupManifest, error) {
	if labels[labelSandbox] != "1" || labels[labelRole] != roleSandbox {
		return cleanupManifest{}, fmt.Errorf("docker delete: container %s is not a managed sandbox workload", id)
	}
	name := labels[labelName]
	if name == "" || sanitizeName(name) != name {
		return cleanupManifest{}, fmt.Errorf("docker delete: workload has an invalid sandbox ownership label")
	}
	manifest := cleanupManifest{
		Version:     cleanupManifestVersion,
		ContainerID: id,
		SandboxName: name,
		Network:     labels[labelNetwork],
		DataVolume:  labels[labelVolume],
		CAVolume:    labels["cautem.ca_volume"],
		SSHVolume:   labels[labelSSHVol],
	}
	if manifest.Network != "" && (strings.ContainsAny(manifest.Network, `/\\`) || strings.TrimSpace(manifest.Network) != manifest.Network) {
		return cleanupManifest{}, fmt.Errorf("docker delete: workload has an invalid network ownership label")
	}
	for _, volume := range []struct{ name, role string }{
		{manifest.DataVolume, roleVolumeData},
		{manifest.CAVolume, roleVolumeCA},
		{manifest.SSHVolume, roleVolumeSSH},
	} {
		if volume.name != "" && volume.name != expectedVolumeName(name, volume.role) {
			return cleanupManifest{}, fmt.Errorf("docker delete: workload has an invalid volume ownership label")
		}
	}
	return manifest, nil
}

func (d *Driver) removeManagedNetwork(ctx context.Context, manifest cleanupManifest) error {
	inspected, err := d.cli.NetworkInspect(ctx, manifest.Network, client.NetworkInspectOptions{})
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	labels := inspected.Network.Labels
	if labels[labelSandbox] != "1" || labels[labelName] != manifest.SandboxName || (labels[labelRole] != "" && labels[labelRole] != roleNetwork) {
		return fmt.Errorf("network is not owned by sandbox %s", manifest.SandboxName)
	}
	_, err = d.cli.NetworkRemove(ctx, manifest.Network, client.NetworkRemoveOptions{})
	if isNotFound(err) {
		return nil
	}
	return err
}

func (d *Driver) removeManagedVolume(ctx context.Context, manifest cleanupManifest, name, role string) error {
	if name != expectedVolumeName(manifest.SandboxName, role) {
		return fmt.Errorf("volume name does not match sandbox ownership")
	}
	inspected, err := d.cli.VolumeInspect(ctx, name, client.VolumeInspectOptions{})
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !volumeOwnershipLabelsValid(name, manifest.SandboxName, role, inspected.Volume.Labels) {
		return fmt.Errorf("volume is not owned by sandbox %s", manifest.SandboxName)
	}
	_, err = d.cli.VolumeRemove(ctx, name, client.VolumeRemoveOptions{Force: true})
	if isNotFound(err) {
		return nil
	}
	return err
}
