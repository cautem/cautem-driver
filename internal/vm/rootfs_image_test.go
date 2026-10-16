package vm

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareRootfsImageBuildsAndReusesContentAddressedImage(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "rootfs.tar.gz")
	if err := writeRootfsArchive(archivePath, []rootfsTarEntry{
		{name: "etc/hostname", kind: tar.TypeReg, body: "sandbox"},
		{name: "bin", kind: tar.TypeDir, mode: 0o755},
	}); err != nil {
		t.Fatal(err)
	}
	countPath := filepath.Join(root, "formatter-count")
	formatter := filepath.Join(root, "mke2fs")
	script := "#!/bin/sh\nprintf x >> '" + countPath + "'\nfor last do :; done\nprintf ext4 >> \"$last\"\n"
	if err := os.WriteFile(formatter, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(root, "cache")
	first, err := prepareRootfsImage(context.Background(), archivePath, cacheDir, formatter, 4096)
	if err != nil {
		t.Fatalf("prepareRootfsImage() error = %v", err)
	}
	second, err := prepareRootfsImage(context.Background(), archivePath, cacheDir, formatter, 4096)
	if err != nil {
		t.Fatalf("prepareRootfsImage() second call error = %v", err)
	}
	if first != second || !strings.HasSuffix(first, ".ext4") {
		t.Fatalf("image paths = %q and %q", first, second)
	}
	imageInfo, err := os.Stat(first)
	if err != nil || imageInfo.Mode().Perm() != 0o400 {
		t.Fatalf("cached image mode = %v, err=%v; want 0400", imageInfo, err)
	}
	count, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(count) != "x" {
		t.Fatalf("formatter invocation count = %q, want one invocation", count)
	}
	if image, err := os.ReadFile(first); err != nil || !strings.HasSuffix(string(image), "ext4") {
		t.Fatalf("cached image tail = %q, err=%v", image, err)
	}
}

func TestPrepareRootfsImageRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "rootfs.tar")
	if err := writeRootfsArchive(archivePath, []rootfsTarEntry{
		{name: "escape", kind: tar.TypeSymlink, link: "../../outside"},
		{name: "escape/payload", kind: tar.TypeReg, body: "owned"},
	}); err != nil {
		t.Fatal(err)
	}
	formatter := filepath.Join(root, "unused-formatter")
	if _, err := prepareRootfsImage(context.Background(), archivePath, filepath.Join(root, "cache"), formatter, 4096); err == nil {
		t.Fatal("prepareRootfsImage accepted symlink escape archive")
	}
	if _, err := os.Stat(filepath.Join(root, "outside", "payload")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("archive wrote outside extraction root: stat error=%v", err)
	}
}

func TestPrepareRootfsImageHonorsCancellationAndFormatterFailure(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "rootfs.tar")
	if err := writeRootfsArchive(archivePath, []rootfsTarEntry{{name: "file", kind: tar.TypeReg, body: "content"}}); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := prepareRootfsImage(canceled, archivePath, filepath.Join(root, "canceled-cache"), "", 4096); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled build error = %v", err)
	}
	formatter := filepath.Join(root, "failing-mke2fs")
	if err := os.WriteFile(formatter, []byte("#!/bin/sh\necho formatter-failed >&2\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareRootfsImage(context.Background(), archivePath, filepath.Join(root, "failed-cache"), formatter, 4096); err == nil || !strings.Contains(err.Error(), "formatter-failed") {
		t.Fatalf("formatter failure = %v", err)
	}
}

func TestPrepareRootfsImageLiveE2FS(t *testing.T) {
	if os.Getenv("CAUTEM_VM_ACCEPTANCE") != "1" {
		t.Skip("set CAUTEM_VM_ACCEPTANCE=1 to run live ext4 acceptance")
	}
	formatter := os.Getenv("CAUTEM_VM_TEST_E2FS_FORMATTER")
	if formatter == "" {
		var err error
		formatter, err = resolveExt4Formatter()
		if err != nil {
			t.Skip(err.Error())
		}
	}
	if _, err := exec.LookPath(formatter); err != nil {
		if _, statErr := os.Stat(formatter); statErr != nil {
			t.Fatalf("live formatter %q is unavailable: %v", formatter, err)
		}
	}
	root := t.TempDir()
	archivePath := filepath.Join(root, "rootfs.tar.gz")
	if err := writeRootfsArchive(archivePath, []rootfsTarEntry{
		{name: "etc", kind: tar.TypeDir, mode: 0o755},
		{name: "etc/os-release", kind: tar.TypeReg, body: "ID=cautem-test\n"},
		{name: "bin", kind: tar.TypeDir, mode: 0o755},
	}); err != nil {
		t.Fatal(err)
	}
	guestAgent := os.Getenv("CAUTEM_VM_TEST_GUEST_AGENT")
	imagePath, err := prepareRootfsImageWithGuest(context.Background(), archivePath, filepath.Join(root, "cache"), formatter, 4096, guestAgent)
	if err != nil {
		t.Fatalf("live ext4 image build: %v", err)
	}
	info, err := os.Stat(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() < int64(rootfsImageMinBytes) || info.Mode().Perm() != 0o400 {
		t.Fatalf("ext4 image metadata = size %d mode %#o", info.Size(), info.Mode().Perm())
	}
	if guestAgent != "" {
		verifier := os.Getenv("CAUTEM_VM_TEST_E2FS_VERIFY")
		if verifier != "" {
			output, err := exec.Command(verifier, imagePath).CombinedOutput()
			if err != nil {
				t.Fatalf("verify injected guest runtime: %v: %s", err, output)
			}
		}
	}
	overlayTemplate, err := prepareOverlayTemplate(context.Background(), filepath.Join(root, "cache"), formatter, 64<<20)
	if err != nil {
		t.Fatalf("live overlay template build: %v", err)
	}
	overlay := filepath.Join(root, "sandbox", "overlay.ext4")
	if err := createSandboxOverlay(overlayTemplate, overlay); err != nil {
		t.Fatalf("live sandbox overlay clone: %v", err)
	}
	overlayInfo, err := os.Stat(overlay)
	if err != nil || overlayInfo.Size() != 64<<20 || overlayInfo.Mode().Perm() != 0o600 {
		t.Fatalf("sandbox overlay metadata = %v, err=%v", overlayInfo, err)
	}
}

func TestBoundedReaderRejectsExpandedArchiveOverLimit(t *testing.T) {
	reader := &boundedReader{reader: strings.NewReader("123456"), limit: 5}
	data, err := io.ReadAll(reader)
	if err == nil || !reader.exceeded || string(data) != "12345" {
		t.Fatalf("read=(%q, %v), exceeded=%t", data, err, reader.exceeded)
	}
}

type rootfsTarEntry struct {
	name string
	kind byte
	mode int64
	link string
	body string
}

func writeRootfsArchive(path string, entries []rootfsTarEntry) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	var writer io.WriteCloser = file
	if strings.HasSuffix(path, ".gz") {
		compressed := gzip.NewWriter(file)
		writer = compressed
	}
	tarWriter := tar.NewWriter(writer)
	for _, entry := range entries {
		mode := entry.mode
		if mode == 0 {
			mode = 0o644
		}
		header := &tar.Header{Name: entry.name, Typeflag: entry.kind, Mode: mode, Linkname: entry.link, Size: int64(len(entry.body))}
		if err := tarWriter.WriteHeader(header); err != nil {
			_ = writer.Close()
			return err
		}
		if _, err := io.WriteString(tarWriter, entry.body); err != nil {
			_ = writer.Close()
			return err
		}
	}
	if err := tarWriter.Close(); err != nil {
		_ = writer.Close()
		return err
	}
	return writer.Close()
}
