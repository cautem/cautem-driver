package sidecar

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cautem/cautem-core/defaults"
)

func TestCABundleEnvIncludesGit(t *testing.T) {
	got := CABundleEnv("")
	wantKeys := []string{
		"SSL_CERT_FILE",
		"CURL_CA_BUNDLE",
		"REQUESTS_CA_BUNDLE",
		"NODE_EXTRA_CA_CERTS",
		"GIT_SSL_CAINFO",
	}
	var keys []string
	for _, e := range got {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			t.Fatalf("bad entry %q", e)
		}
		keys = append(keys, k)
		if v != defaults.GuestCAFile {
			t.Fatalf("%s=%q want %q", k, v, defaults.GuestCAFile)
		}
	}
	for _, k := range wantKeys {
		if !slices.Contains(keys, k) {
			t.Fatalf("missing %s in %v", k, keys)
		}
	}
}

func TestNeedsLinuxRebuildMissingSourceTree(t *testing.T) {
	t.Setenv("CAUTEM_REBUILD_CLI", "")
	t.Setenv("CAUTEM_REBUILD_INIT", "")
	dir := t.TempDir()
	binary := filepath.Join(dir, "binary")
	if err := os.WriteFile(binary, []byte("cached"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !needsLinuxRebuild(binary, filepath.Join(dir, "missing")) {
		t.Fatal("missing source tree must invalidate the cache")
	}
}

func TestNeedsLinuxRebuildChangedSource(t *testing.T) {
	t.Setenv("CAUTEM_REBUILD_CLI", "")
	t.Setenv("CAUTEM_REBUILD_INIT", "")
	dir := t.TempDir()
	binary := filepath.Join(dir, "binary")
	if err := os.WriteFile(binary, []byte("cached"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(binary, past, past); err != nil {
		t.Fatal(err)
	}
	if !needsLinuxRebuild(binary, dir) {
		t.Fatal("changed source must invalidate the cache")
	}
}
