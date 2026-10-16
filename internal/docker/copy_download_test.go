package docker

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func directoryCopyArchive(t *testing.T) []byte {
	t.Helper()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(&tar.Header{Name: "source/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeader(&tar.Header{Name: "source/file.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "data"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func directoryCopyDriver(t *testing.T) *Driver {
	t.Helper()
	archive := directoryCopyArchive(t)
	stat, err := json.Marshal(map[string]any{"name": "source", "size": 0, "mode": uint32(os.ModeDir | 0o755)})
	if err != nil {
		t.Fatal(err)
	}
	return sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/archive") || r.URL.Query().Get("path") != "/guest/source" {
			t.Errorf("unexpected archive request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString(stat))
		_, _ = w.Write(archive)
	})
}

func symlinkCopyDriver(t *testing.T) *Driver {
	t.Helper()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for _, entry := range []struct{ name, link string }{
		{name: "source/", link: ""},
		{name: "source/file-link", link: "target.txt"},
		{name: "source/dangling-link", link: "missing.txt"},
	} {
		typeflag := byte(tar.TypeSymlink)
		if entry.link == "" {
			typeflag = tar.TypeDir
		}
		if err := writer.WriteHeader(&tar.Header{Name: entry.name, Typeflag: typeflag, Linkname: entry.link, Mode: 0o777}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	stat, err := json.Marshal(map[string]any{"name": "source", "size": 0, "mode": uint32(os.ModeDir | 0o755)})
	if err != nil {
		t.Fatal(err)
	}
	return sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/archive") || r.URL.Query().Get("path") != "/guest/source" {
			t.Errorf("unexpected archive request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString(stat))
		_, _ = w.Write(archive.Bytes())
	})
}

func TestCopyFromPreservesRegularAndDanglingSymlinks(t *testing.T) {
	driver := symlinkCopyDriver(t)
	dest := filepath.Join(t.TempDir(), "downloaded")
	if err := driver.CopyFrom(t.Context(), "container-id", "/guest/source", dest); err != nil {
		t.Fatalf("copy symlink directory: %v", err)
	}
	for name, target := range map[string]string{"file-link": "target.txt", "dangling-link": "missing.txt"} {
		got, err := os.Readlink(filepath.Join(dest, "source", name))
		if err != nil || got != target {
			t.Fatalf("%s link target=%q err=%v", name, got, err)
		}
	}
}

func TestCopyFromDirectoryCreatesNewDirectoryDestination(t *testing.T) {
	driver := directoryCopyDriver(t)
	dest := filepath.Join(t.TempDir(), "downloaded")
	if err := driver.CopyFrom(t.Context(), "container-id", "/guest/source", dest); err != nil {
		t.Fatalf("copy directory to new destination: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dest, "source", "file.txt"))
	if err != nil || string(data) != "data" {
		t.Fatalf("downloaded file=%q err=%v", data, err)
	}
}

func TestCopyFromDirectoryRefusesFileDestinationWithoutClobbering(t *testing.T) {
	driver := directoryCopyDriver(t)
	dest := filepath.Join(t.TempDir(), "existing.txt")
	if err := os.WriteFile(dest, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := driver.CopyFrom(t.Context(), "container-id", "/guest/source", dest); err == nil || !strings.Contains(err.Error(), "cannot extract directory") {
		t.Fatalf("copy directory to file error=%v", err)
	}
	data, err := os.ReadFile(dest)
	if err != nil || string(data) != "keep me" {
		t.Fatalf("existing destination=%q err=%v; directory download must not modify it", data, err)
	}
}
