package mounts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveWorkspaceOK(t *testing.T) {
	dir := t.TempDir()
	got, err := ResolveWorkspace(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %q want canonical path %q", got, want)
	}
}

func TestWorkspaceSourceRejectsReplacementAfterValidation(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	source, err := ResolveWorkspaceSource(workspace, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(workspace, filepath.Join(root, "original-workspace")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := source.VerifyUnchanged(); err == nil || !strings.Contains(err.Error(), "source changed after validation") {
		t.Fatalf("VerifyUnchanged() error = %v, want path replacement refusal", err)
	}
}

func TestWorkspaceSourcePinsCanonicalSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	other := filepath.Join(root, "other")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "project")
	if err := os.Symlink(workspace, link); err != nil {
		t.Fatal(err)
	}
	canonicalWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal(err)
	}
	source, err := ResolveWorkspaceSource(link, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	if source.Path != canonicalWorkspace {
		t.Fatalf("canonical source path = %q, want %q", source.Path, canonicalWorkspace)
	}
	if err := source.VerifyUnchanged(); err != nil {
		t.Fatalf("retargeting the original symlink changed the canonical mount source: %v", err)
	}
}

func TestResolveWorkspaceRejectsSymlinkIntoDeniedDirectory(t *testing.T) {
	root := t.TempDir()
	denied := filepath.Join(root, ".ssh")
	if err := os.Mkdir(denied, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "project")
	if err := os.Symlink(denied, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveWorkspace(link, false); err == nil {
		t.Fatal("workspace symlink into denied directory was accepted")
	}
}

func TestRefuseHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	if _, err := ResolveWorkspace(home, false); err == nil {
		t.Fatal("expected refuse $HOME")
	}
	if _, err := ResolveWorkspace(home, true); err != nil {
		t.Fatalf("iKnow should allow: %v", err)
	}
}

func TestRefuseSSH(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	ssh := filepath.Join(home, ".ssh")
	if _, err := os.Stat(ssh); err != nil {
		t.Skip("no ~/.ssh")
	}
	if _, err := ResolveWorkspace(ssh, false); err == nil {
		t.Fatal("expected refuse ~/.ssh")
	}
}

func TestResolveWorkspaceRequiresHomeForValidation(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	dir := t.TempDir()
	if _, err := ResolveWorkspace(dir, false); err == nil {
		t.Fatal("mount validation must report missing home directory")
	}
	if _, err := ResolveWorkspace(dir, true); err != nil {
		t.Fatalf("explicit override: %v", err)
	}
}
