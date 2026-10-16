//go:build darwin || linux

package vm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStateStorePersistsListsAndDeletesSandboxes(t *testing.T) {
	store, err := openStateStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	want, err := store.create("sandbox-one", "image:latest", now)
	if err != nil {
		t.Fatal(err)
	}
	if !validSandboxID(want.ID) || want.Status != "created" || !want.CreatedAt.Equal(now) {
		t.Fatalf("created state=%+v", want)
	}
	got, err := store.load(want.ID)
	if err != nil || got != want {
		t.Fatalf("load state=(%+v, %v), want %+v", got, err, want)
	}
	states, err := store.list()
	if err != nil || len(states) != 1 || states[0] != want {
		t.Fatalf("list states=(%+v, %v), want one state %+v", states, err, want)
	}
	if _, err := store.create("sandbox-one", "image:other", now.Add(time.Second)); err == nil {
		t.Fatal("create duplicate name succeeded")
	}
	if err := store.delete(want.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.delete(want.ID); err != nil {
		t.Fatalf("delete should be idempotent: %v", err)
	}
	states, err = store.list()
	if err != nil || len(states) != 0 {
		t.Fatalf("list after delete=(%+v, %v), want empty", states, err)
	}
}

func TestStateStoreUsesPrivateDirectoryAndFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := openStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.create("sandbox-one", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if directory.Mode().Perm() != 0o700 {
		t.Fatalf("state directory mode=%#o, want 0700", directory.Mode().Perm())
	}
	file, err := os.Stat(filepath.Join(root, state.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if file.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode=%#o, want 0600", file.Mode().Perm())
	}
}

func TestStoredRootfsProvenanceMustBeComplete(t *testing.T) {
	state := sandboxState{
		Version: sandboxStateVersion, ID: "3a967f5c-4ad7-4e36-8cd5-8b9b1b2db00c", Name: "sandbox", Status: "created",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := validateStoredState(state); err != nil {
		t.Fatalf("legacy state without provenance rejected: %v", err)
	}
	state.RootfsSourceType = "oci"
	state.RootfsSourceRef = "registry.example/team/image:stable"
	state.RootfsSourceDigest = "sha256:" + strings.Repeat("a", 64)
	state.RootfsSourceManifestDigest = "sha256:" + strings.Repeat("b", 64)
	state.Platform = "linux/amd64"
	if err := validateStoredState(state); err != nil {
		t.Fatalf("complete OCI provenance rejected: %v", err)
	}
	state.RootfsSourceManifestDigest = "sha256:short"
	if err := validateStoredState(state); err == nil || !strings.Contains(err.Error(), "invalid source manifest digest") {
		t.Fatalf("invalid manifest digest error = %v", err)
	}
	store, err := openStateStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	state.RootfsSourceManifestDigest = "sha256:" + strings.Repeat("b", 64)
	if err := store.save(state); err != nil {
		t.Fatalf("persist OCI provenance: %v", err)
	}
	loaded, err := store.load(state.ID)
	if err != nil || loaded != state {
		t.Fatalf("load OCI provenance = (%+v, %v), want %+v", loaded, err, state)
	}
}

func TestVMGuestControlTokenIsPrivateAndValidated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sandbox")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	token, err := createControlToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 {
		t.Fatalf("control token length=%d, want 64 hex characters", len(token))
	}
	got, err := readControlToken(dir)
	if err != nil || got != token {
		t.Fatalf("read control token=(%q, %v), want generated token", got, err)
	}
	info, err := os.Stat(filepath.Join(dir, "control.token"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("control token file mode=(%v, %v), want 0600", info, err)
	}
	if err := os.Chmod(filepath.Join(dir, "control.token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readControlToken(dir); err == nil {
		t.Fatal("readControlToken accepted a world-readable token")
	}
}

func TestPendingControlTokenRotationIsPrivateAndCanCommitAtomically(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldToken, err := createControlToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := newControlTokenRotation()
	if err != nil {
		t.Fatal(err)
	}
	if rotation.NextToken == oldToken {
		t.Fatal("rotation generated the current token")
	}
	if err := writePendingControlTokenRotation(dir, rotation); err != nil {
		t.Fatal(err)
	}
	got, pending, err := readPendingControlTokenRotation(dir)
	if err != nil || !pending || got != rotation {
		t.Fatalf("pending rotation=(%+v,%t,%v), want %+v,true,nil", got, pending, err, rotation)
	}
	info, err := os.Stat(filepath.Join(dir, pendingControlTokenRotationName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("pending rotation mode=(%v,%v), want 0600", info, err)
	}
	if err := replaceControlToken(dir, rotation.NextToken); err != nil {
		t.Fatal(err)
	}
	if got, err := readControlToken(dir); err != nil || got != rotation.NextToken {
		t.Fatalf("committed token=(%q,%v), want new token", got, err)
	}
	if err := removePendingControlTokenRotation(dir); err != nil {
		t.Fatal(err)
	}
	if _, pending, err := readPendingControlTokenRotation(dir); err != nil || pending {
		t.Fatalf("pending rotation after commit=(%t,%v), want false,nil", pending, err)
	}
}

func TestStateStoreRejectsSymlinkRootAndRecord(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	rootLink := filepath.Join(base, "root-link")
	if err := os.Symlink(target, rootLink); err != nil {
		t.Fatal(err)
	}
	if _, err := openStateStore(rootLink); err == nil {
		t.Fatal("openStateStore accepted symlink root")
	}

	store, err := openStateStore(filepath.Join(base, "store"))
	if err != nil {
		t.Fatal(err)
	}
	id := "01234567-89ab-4def-8123-0123456789ab"
	if err := os.Symlink(filepath.Join(target, "victim"), filepath.Join(store.root, id+".json")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.load(id); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("load symlink record error=%v", err)
	}
}

func TestStateStoreRejectsMalformedRecordAndIDs(t *testing.T) {
	store, err := openStateStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "../escape", "0123456789abcdef", "01234567-89AB-4def-8123-0123456789ab"} {
		if _, err := store.load(id); err == nil {
			t.Errorf("load invalid ID %q succeeded", id)
		}
	}
	id := "01234567-89ab-4def-8123-0123456789ab"
	if err := os.WriteFile(filepath.Join(store.root, id+".json"), []byte(`{"version":1,"id":"`+id+`","name":"broken","status":"unknown","created_at":"2026-10-15T12:00:00Z","updated_at":"2026-10-15T12:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.load(id); err == nil || !strings.Contains(err.Error(), "invalid sandbox status") {
		t.Fatalf("load malformed record error=%v", err)
	}
}
