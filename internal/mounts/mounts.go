// Package mounts validates host bind mounts and guest mount targets.
//
// Host workspace sources use a deny-list (denyBasenames / $HOME) unless --i-know.
// Guest targets use OpenShell-style reserved roots (controlRoots) so users cannot
// overwrite /cautem control state — not a general Linux system-path denylist.
package mounts

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cautem/quarshell-core/defaults"
)

// WorkdirInContainer is where the host workspace is mounted.
const WorkdirInContainer = defaults.GuestWorkspace

// WorkspaceSource records the canonical path and directory identity checked
// before a backend creates a host bind mount.
type WorkspaceSource struct {
	Path     string
	identity os.FileInfo
}

// denyBasenames are never auto-mounted as workspace (secrets / cloud CLIs).
// OpenShell relies more on --upload; cautem still bind-mounts workspace, so this
// host-side check remains as hardening.
var denyBasenames = []string{
	".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config",
	".cursor", ".codex", ".claude",
}

// ResolveWorkspace returns the canonical absolute path and checks the deny-list.
// iKnow skips deny-list (still requires the path to exist as a directory).
func ResolveWorkspace(path string, iKnow bool) (string, error) {
	source, err := ResolveWorkspaceSource(path, iKnow)
	if err != nil {
		return "", err
	}
	return source.Path, nil
}

// ResolveWorkspaceSource resolves the workspace path, checks the deny-list,
// and records the directory identity for revalidation immediately before a
// backend asks its engine to create the bind mount.
func ResolveWorkspaceSource(path string, iKnow bool) (WorkspaceSource, error) {
	if strings.TrimSpace(path) == "" {
		path = "."
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return WorkspaceSource{}, fmt.Errorf("workspace: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return WorkspaceSource{}, fmt.Errorf("workspace: resolve path: %w", err)
	}
	// Stat a directory handle instead of a path lookup. On Windows, os.Stat
	// leaves file identity resolution lazy until os.SameFile; retaining only
	// that FileInfo would let a later path replacement change both identities
	// before the comparison. File.Stat captures the original file ID eagerly.
	dir, err := os.Open(canonical)
	if err != nil {
		return WorkspaceSource{}, fmt.Errorf("workspace: %w", err)
	}
	fi, statErr := dir.Stat()
	closeErr := dir.Close()
	if statErr != nil {
		return WorkspaceSource{}, fmt.Errorf("workspace: stat directory: %w", statErr)
	}
	if closeErr != nil {
		return WorkspaceSource{}, fmt.Errorf("workspace: close directory: %w", closeErr)
	}
	if !fi.IsDir() {
		return WorkspaceSource{}, fmt.Errorf("workspace: not a directory: %s", abs)
	}
	if !iKnow {
		if err := checkDeny(canonical); err != nil {
			return WorkspaceSource{}, err
		}
	}
	return WorkspaceSource{Path: canonical, identity: fi}, nil
}

// VerifyUnchanged rejects a workspace path that no longer resolves to the
// directory admitted during validation. Engines accept host paths rather than
// directory handles, so callers should run this directly before create.
func (source WorkspaceSource) VerifyUnchanged() error {
	if source.Path == "" || source.identity == nil {
		return fmt.Errorf("workspace: source identity is unavailable")
	}
	current, err := os.Stat(source.Path)
	if err != nil {
		return fmt.Errorf("workspace: source changed after validation: %w", err)
	}
	if !current.IsDir() || !os.SameFile(source.identity, current) {
		return fmt.Errorf("workspace: source changed after validation; refusing to mount %s", source.Path)
	}
	return nil
}

func checkDeny(abs string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("workspace: determine home directory for mount validation: %w", err)
	}
	home = filepath.Clean(home)
	abs = filepath.Clean(abs)

	if home != "" && abs == home {
		return fmt.Errorf("workspace: refusing to mount $HOME (%s); use a project dir, --upload, or --i-know", abs)
	}
	base := filepath.Base(abs)
	for _, d := range denyBasenames {
		if strings.EqualFold(base, d) {
			return fmt.Errorf("workspace: refusing to mount %q (%s); pass --i-know to override", d, abs)
		}
	}
	// Also refuse if path is under ~/.ssh etc.
	if home != "" {
		for _, d := range denyBasenames {
			prefix := filepath.Join(home, d)
			if abs == prefix || strings.HasPrefix(abs, prefix+string(os.PathSeparator)) {
				return fmt.Errorf("workspace: refusing path under ~/%s (%s); pass --i-know to override", d, abs)
			}
		}
	}
	return nil
}
