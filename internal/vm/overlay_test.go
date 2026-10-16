//go:build darwin || linux

package vm

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPrepareOverlayTemplateFormatsPrivateExt4Cache(t *testing.T) {
	root := t.TempDir()
	count := filepath.Join(root, "count")
	formatter := filepath.Join(root, "mke2fs")
	statMode := `stat -c %a`
	if runtime.GOOS == "darwin" {
		statMode = `stat -f %Lp`
	}
	script := "#!/bin/sh\n" +
		"printf x >> '" + count + "'\n" +
		"expect=0\nfor arg do if [ \"$expect\" = 1 ]; then root=$arg; expect=0; elif [ \"$arg\" = -d ]; then expect=1; fi; done\n" +
		"test -d \"$root/upper\" && test -d \"$root/work\" && test -d \"$root/config\"\n" +
		"test \"$(" + statMode + " \"$root\")\" = 755\n" +
		"test \"$(" + statMode + " \"$root/upper\")\" = 755\n" +
		"test \"$(" + statMode + " \"$root/work\")\" = 700\n"
	if err := os.WriteFile(formatter, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(root, "cache")
	first, err := prepareOverlayTemplate(t.Context(), cache, formatter, 64<<20)
	if err != nil {
		t.Fatalf("prepareOverlayTemplate() error = %v", err)
	}
	second, err := prepareOverlayTemplate(t.Context(), cache, formatter, 64<<20)
	if err != nil {
		t.Fatalf("prepareOverlayTemplate() second error = %v", err)
	}
	if first != second {
		t.Fatalf("template paths differ: %q and %q", first, second)
	}
	info, err := os.Stat(first)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 64<<20 || info.Mode().Perm() != 0o400 {
		t.Fatalf("overlay template size=%d mode=%#o", info.Size(), info.Mode().Perm())
	}
	calls, err := os.ReadFile(count)
	if err != nil || string(calls) != "x" {
		t.Fatalf("formatter calls=%q err=%v, want once", calls, err)
	}
	if _, err := prepareOverlayTemplate(t.Context(), cache, formatter, 32<<20); err == nil || !strings.Contains(err.Error(), "64 MiB minimum") {
		t.Fatalf("undersized overlay error=%v", err)
	}
}

func TestCreateSandboxOverlayMakesPrivateIndependentWritableCopy(t *testing.T) {
	root := t.TempDir()
	template := filepath.Join(root, "template.ext4")
	if err := os.WriteFile(template, []byte("base-image"), 0o400); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "sandbox", "overlay.ext4")
	if err := createSandboxOverlay(template, destination); err != nil {
		t.Fatalf("createSandboxOverlay() error = %v", err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("overlay mode=%#o, want 0600", info.Mode().Perm())
	}
	if err := os.WriteFile(destination, []byte("sandbox-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadFile(template)
	if err != nil || string(base) != "base-image" {
		t.Fatalf("template changed to %q, err=%v", base, err)
	}
	if err := createSandboxOverlay(template, destination); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate overlay creation error=%v", err)
	}
}

func TestCreateSandboxOverlayRejectsSymlinkAndInvalidTemplate(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "regular.ext4")
	if err := os.WriteFile(regular, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "template.ext4")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	if err := createSandboxOverlay(symlink, filepath.Join(root, "overlay.ext4")); err == nil {
		t.Fatal("createSandboxOverlay accepted symlink template")
	}
}

func TestCopySparseFilePreservesContentsAndLength(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "copy")
	content := make([]byte, 2<<20)
	content[17] = 0x4a
	content[len(content)-1] = 0x6b
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copySparseFile(source, destination); err != nil {
		t.Fatalf("copySparseFile() error = %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatal("sparse copy contents differ")
	}
}
