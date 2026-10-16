package docker

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteTarDirPreservesSymlinkEntries(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "target.txt"), []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.txt", filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writeTarDir(writer, root, "upload"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(&archive)
	for {
		header, err := reader.Next()
		if err != nil {
			break
		}
		if header.Name == "upload/link.txt" {
			if header.Typeflag != tar.TypeSymlink || header.Linkname != "target.txt" {
				t.Fatalf("symlink tar header type=%d link=%q", header.Typeflag, header.Linkname)
			}
			return
		}
	}
	t.Fatal("symlink entry missing from tar archive")
}

func TestWriteTarFilePreservesRootSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink("target", link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writeTarFile(writer, link, info, "link"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(&archive)
	header, err := reader.Next()
	if err != nil {
		t.Fatal(err)
	}
	if header.Typeflag != tar.TypeSymlink || header.Linkname != "target" {
		t.Fatalf("root symlink tar header type=%d link=%q", header.Typeflag, header.Linkname)
	}
}
