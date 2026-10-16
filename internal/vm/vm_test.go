package vm

import (
	"archive/tar"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cautem/cautem-core"
	"github.com/cautem/cautem-driver/driver"
)

func TestCreateBuildsAndPersistsSandboxArtifacts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test formatter requires a POSIX shell")
	}
	root := t.TempDir()
	staging := filepath.Join(root, "uploads")
	requestDir := filepath.Join(staging, "request-1")
	if err := os.MkdirAll(requestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(requestDir, "rootfs.tar")
	archive, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(archive)
	if err := tw.WriteHeader(&tar.Header{Name: "etc/os-release", Mode: 0o644, Size: 5}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("test\n")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	formatter := filepath.Join(root, "formatter")
	if err := os.WriteFile(formatter, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	guestAgent := filepath.Join(root, "guest-agent")
	if err := os.WriteFile(guestAgent, testGuestELF(), 0o700); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(root, "state")
	d := NewWithHostConfig(HostConfig{
		StateDir: stateDir, RootfsTarDir: staging, RootfsTarMaxBytes: 1 << 20,
		FormatterPath: formatter, OverlaySizeBytes: 64 << 20, GuestAgentPath: guestAgent,
	})
	handle, err := d.Create(context.Background(), driver.Spec{
		Name: "sandbox-one", Image: "fixture:latest",
		DriverConfigJSON: `{"rootfs_tar_path":"` + archivePath + `"}`,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !validSandboxID(string(handle.ID)) || handle.Name != "sandbox-one" || handle.Image != "fixture:latest" {
		t.Fatalf("Create() handle = %+v", handle)
	}
	state, err := openStateStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := state.load(string(handle.ID))
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Rootfs == "" {
		t.Fatal("persisted state has no rootfs image")
	}
	if persisted.RootfsSourceType != "tar" || !strings.HasPrefix(persisted.RootfsSourceDigest, "sha256:") || persisted.Platform != "linux/"+runtime.GOARCH {
		t.Fatalf("persisted rootfs provenance = type %q digest %q platform %q", persisted.RootfsSourceType, persisted.RootfsSourceDigest, persisted.Platform)
	}
	for _, path := range []string{persisted.Rootfs, filepath.Join(stateDir, "sandboxes", persisted.ID, "overlay.ext4")} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			t.Fatalf("expected regular non-empty artifact at %q, stat=%v err=%v", path, info, err)
		}
	}
	rows, err := d.List(context.Background())
	if err != nil || len(rows) != 1 || rows[0].ID != handle.ID || rows[0].Status != "created" {
		t.Fatalf("List() = (%+v, %v), want one created sandbox", rows, err)
	}
	byName, err := d.Inspect(context.Background(), handle.Name)
	if err != nil || byName.ID != handle.ID {
		t.Fatalf("Inspect(name) = (%+v, %v)", byName, err)
	}
	byID, err := d.Inspect(context.Background(), string(handle.ID))
	if err != nil || byID.Name != handle.Name {
		t.Fatalf("Inspect(id) = (%+v, %v)", byID, err)
	}
	if err := d.Delete(context.Background(), handle.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "sandboxes", string(handle.ID))); !os.IsNotExist(err) {
		t.Fatalf("sandbox assets remain after delete, stat error = %v", err)
	}
	if err := d.Delete(context.Background(), handle.ID); err != nil {
		t.Fatalf("idempotent Delete() error = %v", err)
	}
}

func testGuestELF() []byte {
	header := make([]byte, 64)
	copy(header[:4], []byte{0x7f, 'E', 'L', 'F'})
	header[4], header[5], header[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(header[16:18], 3)
	machine := uint16(62)
	if runtime.GOARCH == "arm64" {
		machine = 183
	}
	binary.LittleEndian.PutUint16(header[18:20], machine)
	binary.LittleEndian.PutUint32(header[20:24], 1)
	return header
}

func TestCreateRequiresImageOrRootfsArchiveAndRejectsInvalidSpec(t *testing.T) {
	d := NewWithHostConfig(HostConfig{StateDir: filepath.Join(t.TempDir(), "state")})
	if _, err := d.Create(context.Background(), driver.Spec{Name: "missing-rootfs"}); err == nil || !strings.Contains(err.Error(), "image or rootfs_tar_path is required") {
		t.Fatalf("Create() missing rootfs error = %v", err)
	}
	if _, err := d.Create(context.Background(), driver.Spec{Name: "../escape"}); err == nil {
		t.Fatal("Create() accepted path-like sandbox name")
	}
}

func TestDeleteReconcilesDeadWorkerAndExecReportsMissingGuest(t *testing.T) {
	root := t.TempDir()
	store, err := openStateStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.create("running-vm", "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	assets := filepath.Join(store.root, "sandboxes", state.ID)
	if err := os.MkdirAll(assets, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := createControlToken(assets); err != nil {
		t.Fatal(err)
	}
	state.Status = "running"
	if err := store.save(state); err != nil {
		t.Fatal(err)
	}
	d := NewWithHostConfig(HostConfig{StateDir: store.root})
	if _, err := d.Exec(context.Background(), core.ID(state.ID), driver.ExecRequest{Argv: []string{"true"}}); err == nil || !strings.Contains(err.Error(), "connect VM guest control socket") {
		t.Fatalf("Exec() missing worker error = %v", err)
	}
	if err := d.Delete(context.Background(), core.ID(state.ID)); err != nil {
		t.Fatalf("Delete() did not reconcile dead worker: %v", err)
	}
}
