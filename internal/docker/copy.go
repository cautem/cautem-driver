// Package docker implements driver.ComputeDriver via the Docker Engine API.
package docker

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/moby/moby/client"

	"archive/tar"
	"path/filepath"

	core "github.com/cautem/quarshell-core"
)

// CopyTo tars srcHost and extracts at destPath inside the container.
// For a single file, destPath is the full guest path (basename used in the tar).
// For a directory, destPath is the guest parent directory under which src's basename appears.
func (d *Driver) CopyTo(ctx context.Context, id core.ID, srcHost, destPath string) error {
	srcHost = filepath.Clean(srcHost)
	st, err := os.Lstat(srcHost)
	if err != nil {
		return err
	}
	destPath = filepath.ToSlash(filepath.Clean(destPath))
	pr, pw := io.Pipe()
	errCh := make(chan error, 1)
	go func() {
		tw := tar.NewWriter(pw)
		var err error
		if st.IsDir() {
			err = writeTarDir(tw, srcHost, filepath.Base(srcHost))
		} else {
			err = writeTarFile(tw, srcHost, st, filepath.Base(destPath))
		}
		_ = tw.Close()
		_ = pw.CloseWithError(err)
		errCh <- err
	}()
	destDir := destPath
	if !st.IsDir() {
		destDir = filepath.ToSlash(filepath.Dir(destPath))
		if destDir == "." || destDir == "" {
			destDir = "/"
		}
	}
	_, err = d.cli.CopyToContainer(ctx, string(id), client.CopyToContainerOptions{DestinationPath: destDir, Content: pr, AllowOverwriteDirWithFile: true})
	_ = pr.Close()
	if werr := <-errCh; werr != nil && err == nil {
		err = werr
	}
	if err != nil {
		return fmt.Errorf("docker copy to: %w", err)
	}
	return nil
}

func writeTarDir(tw *tar.Writer, src, base string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(filepath.Join(base, rel))
		if rel == "." {
			name = base + "/"
		}
		linkTarget := ""
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}
		hdr, err := tar.FileInfoHeader(info, linkTarget)
		if err != nil {
			return err
		}
		hdr.Name = name
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("docker copy to: unsupported source entry type %s", info.Mode().Type())
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		_ = f.Close()
		return err
	})
}

func writeTarFile(tw *tar.Writer, src string, st os.FileInfo, archiveName string) error {
	linkTarget := ""
	if st.Mode()&os.ModeSymlink != 0 {
		var err error
		linkTarget, err = os.Readlink(src)
		if err != nil {
			return err
		}
	}
	hdr, err := tar.FileInfoHeader(st, linkTarget)
	if err != nil {
		return err
	}
	hdr.Name = archiveName
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("docker copy to: unsupported source entry type %s", st.Mode().Type())
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

// CopyFrom reads a container path as tar and writes into destHost.
// If destHost exists as a directory (or ends with a path separator), entries are
// extracted under it. Otherwise a single regular file is written to destHost.

// CopyFrom reads a container path as tar and writes into destHost.
// If destHost exists as a directory (or ends with a path separator), entries are
// extracted under it. Otherwise a single regular file is written to destHost.
func (d *Driver) CopyFrom(ctx context.Context, id core.ID, srcPath, destHost string) error {
	copied, err := d.cli.CopyFromContainer(ctx, string(id), client.CopyFromContainerOptions{SourcePath: srcPath})
	if err != nil {
		return fmt.Errorf("docker copy from: %w", err)
	}
	rc := copied.Content
	defer rc.Close()

	asDir := strings.HasSuffix(destHost, string(os.PathSeparator)) || strings.HasSuffix(destHost, "/")
	destInfo, destErr := os.Stat(destHost)
	if destErr == nil && destInfo.IsDir() {
		asDir = true
	}
	if copied.Stat.Mode.IsDir() {
		if destErr == nil && !destInfo.IsDir() {
			return fmt.Errorf("docker copy from: cannot extract directory %q over non-directory destination %q", srcPath, destHost)
		}
		asDir = true
	}

	tr := tar.NewReader(rc)
	return extractCopyTar(tr, destHost, asDir, srcPath)
}

func extractCopyTar(tr *tar.Reader, destHost string, asDir bool, srcPath string) error {
	rootPath := filepath.Dir(destHost)
	if asDir {
		rootPath = destHost
	}
	if err := os.MkdirAll(rootPath, 0o755); err != nil {
		return err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	wroteFile := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			if !asDir && !wroteFile {
				return fmt.Errorf("docker copy from: no file at %s", srcPath)
			}
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeDir && (hdr.Name == "." || hdr.Name == "./") {
			continue
		}
		name, err := safeArchiveName(hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if !asDir {
				continue
			}
			if err := rejectExistingSymlink(root, name); err != nil {
				return err
			}
			if err := root.MkdirAll(name, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			target := name
			if !asDir {
				if wroteFile {
					return fmt.Errorf("docker copy from: dest %s is a file but archive has multiple entries", destHost)
				}
				target = filepath.Base(destHost)
				wroteFile = true
			}
			if err := rejectExistingSymlink(root, target); err != nil {
				return err
			}
			if err := root.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if hdr.Mode&0o111 != 0 {
				mode = 0o755
			}
			f, err := root.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr)
			if chmodErr := f.Chmod(mode); err == nil {
				err = chmodErr
			}
			if closeErr := f.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				return err
			}
		case tar.TypeSymlink:
			target := name
			if !asDir {
				if wroteFile {
					return fmt.Errorf("docker copy from: dest %s is a file but archive has multiple entries", destHost)
				}
				target = filepath.Base(destHost)
				wroteFile = true
			}
			if err := rejectExistingSymlink(root, target); err != nil {
				return err
			}
			if err := root.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := root.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		default:
			return fmt.Errorf("docker copy from: unsupported archive entry type %d at %q", hdr.Typeflag, hdr.Name)
		}
	}
}

func safeArchiveName(raw string) (string, error) {
	if raw == "" || filepath.IsAbs(raw) {
		return "", fmt.Errorf("docker copy from: invalid archive path %q", raw)
	}
	for _, part := range strings.Split(raw, string(os.PathSeparator)) {
		if part == ".." {
			return "", fmt.Errorf("docker copy from: archive path escapes destination: %q", raw)
		}
	}
	name := filepath.Clean(raw)
	if name == "." || name == ".." || strings.HasPrefix(name, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("docker copy from: archive path escapes destination: %q", raw)
	}
	return name, nil
}

func rejectExistingSymlink(root *os.Root, name string) error {
	component := ""
	for _, part := range strings.Split(filepath.Clean(name), string(os.PathSeparator)) {
		component = filepath.Join(component, part)
		info, err := root.Lstat(component)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("docker copy from: symlink in destination path %q", component)
		}
	}
	return nil
}

// EnsureSSHDaemon starts cautem-sshd as root on the relay socket
// (idempotent: sshd exits when a live daemon already owns the socket) and
// waits until the socket exists. Returns driver.ErrSSHDisabled for sandboxes
// created without SSH.
