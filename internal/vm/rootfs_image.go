package vm

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/moby/go-archive"
)

const (
	rootfsImageMinBytes        = uint64(512 << 20)
	rootfsImageMinHeadroom     = uint64(256 << 20)
	rootfsExpandedMaxBytes     = int64(32 << 30)
	rootfsImageSizeGranularity = uint64(1 << 20)
	rootfsImageFormatVersion   = "quarshell-rootfs-ext4-v3"
)

// prepareRootfsImage unpacks a staged archive into a private temporary tree,
// formats it as ext4, then atomically publishes it under a content-addressed
// name. formatterPath is injectable for unit tests; an empty value resolves
// mke2fs or mkfs.ext4 from PATH.
func prepareRootfsImage(ctx context.Context, archivePath, cacheDir, formatterPath string, maxArchiveBytes int64) (string, error) {
	return prepareRootfsImageWithGuest(ctx, archivePath, cacheDir, formatterPath, maxArchiveBytes, "")
}

func prepareRootfsImageWithGuest(ctx context.Context, archivePath, cacheDir, formatterPath string, maxArchiveBytes int64, guestAgentPath string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	archiveFile, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("open rootfs archive %q: %w", archivePath, err)
	}
	defer archiveFile.Close()
	return prepareRootfsImageFileWithGuest(ctx, archiveFile, archivePath, cacheDir, formatterPath, maxArchiveBytes, guestAgentPath)
}

// prepareRootfsImageFileWithGuest consumes the already-open archive descriptor
// supplied by rootfs staging validation. It deliberately does not reopen the
// path, so an attacker cannot replace the validated archive between checks.
func prepareRootfsImageFileWithGuest(ctx context.Context, archiveFile *os.File, archivePath, cacheDir, formatterPath string, maxArchiveBytes int64, guestAgentPath string) (string, error) {
	prepared, err := prepareRootfsImageFileWithGuestLease(ctx, archiveFile, archivePath, cacheDir, formatterPath, maxArchiveBytes, guestAgentPath, defaultRootfsImageCacheMaxBytes)
	if err != nil {
		return "", err
	}
	if err := prepared.Lease.Release(); err != nil {
		return "", fmt.Errorf("release rootfs image cache lease: %w", err)
	}
	return prepared.Path, nil
}

func prepareRootfsImageFileWithGuestLease(ctx context.Context, archiveFile *os.File, archivePath, cacheDir, formatterPath string, maxArchiveBytes int64, guestAgentPath string, cacheMaxBytes int64) (preparedRootfsImage, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if maxArchiveBytes <= 0 {
		maxArchiveBytes = defaultRootfsTarMaxBytes
	}
	if archiveFile == nil {
		return preparedRootfsImage{}, fmt.Errorf("rootfs archive file is required")
	}
	if err := ctx.Err(); err != nil {
		return preparedRootfsImage{}, err
	}
	archiveInfo, err := archiveFile.Stat()
	if err != nil || !archiveInfo.Mode().IsRegular() {
		if err == nil {
			err = fmt.Errorf("not a regular file")
		}
		return preparedRootfsImage{}, fmt.Errorf("inspect rootfs archive %q: %w", archivePath, err)
	}
	if archiveInfo.Size() > maxArchiveBytes {
		return preparedRootfsImage{}, fmt.Errorf("rootfs archive %q is %d bytes, exceeding the %d byte limit", archivePath, archiveInfo.Size(), maxArchiveBytes)
	}
	if _, err := archiveFile.Seek(0, io.SeekStart); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("rewind rootfs archive %q before hashing: %w", archivePath, err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, &contextReader{ctx: ctx, reader: archiveFile}); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("hash rootfs archive %q: %w", archivePath, err)
	}
	if _, err := archiveFile.Seek(0, io.SeekStart); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("rewind rootfs archive %q: %w", archivePath, err)
	}
	guestDigest, err := validateGuestAgent(guestAgentPath)
	if err != nil {
		return preparedRootfsImage{}, err
	}
	return prepareRootfsImageFromSource(ctx, cacheDir, formatterPath, guestAgentPath, string(hasher.Sum(nil)), guestDigest, cacheMaxBytes, func(rootfsDir string) error {
		return unpackRootfsArchive(ctx, archiveFile, archivePath, rootfsDir)
	})
}

func prepareRootfsImageFromSource(ctx context.Context, cacheDir, formatterPath, guestAgentPath, sourceIdentity string, guestDigest []byte, cacheMaxBytes int64, populate func(string) error) (preparedRootfsImage, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return preparedRootfsImage{}, err
	}
	keyInput := append([]byte(rootfsImageFormatVersion+"\x00"), sourceIdentity...)
	keyInput = append(keyInput, 0)
	keyInput = append(keyInput, guestDigest...)
	key := sha256.Sum256(keyInput)
	digest := hex.EncodeToString(key[:])
	if err := ensureRootfsImageCacheDirectories(cacheDir); err != nil {
		return preparedRootfsImage{}, err
	}
	imagePath := filepath.Join(cacheDir, digest+".ext4")
	if lease, cached, err := acquireCachedRootfsImage(cacheDir, imagePath, cacheMaxBytes); err != nil {
		return preparedRootfsImage{}, err
	} else if cached {
		return preparedRootfsImage{Path: imagePath, Lease: lease}, nil
	}
	if formatterPath == "" {
		resolvedFormatter, err := resolveExt4Formatter()
		if err != nil {
			return preparedRootfsImage{}, err
		}
		formatterPath = resolvedFormatter
	}
	staging, err := os.MkdirTemp(cacheDir, ".rootfs-build-*")
	if err != nil {
		return preparedRootfsImage{}, fmt.Errorf("create rootfs build staging directory: %w", err)
	}
	buildLock, err := os.OpenFile(filepath.Join(staging, ".build.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		_ = os.RemoveAll(staging)
		return preparedRootfsImage{}, fmt.Errorf("create rootfs build lock: %w", err)
	}
	locked, err := tryLockImageCacheLease(buildLock)
	if err != nil || !locked {
		_ = buildLock.Close()
		_ = os.RemoveAll(staging)
		if err == nil {
			err = fmt.Errorf("new rootfs build lock is already held")
		}
		return preparedRootfsImage{}, fmt.Errorf("lock rootfs build staging directory: %w", err)
	}
	defer func() {
		_ = unlockImageCacheLease(buildLock)
		_ = buildLock.Close()
		_ = os.RemoveAll(staging)
	}()
	if err := os.Chmod(staging, 0o700); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("secure rootfs build staging directory: %w", err)
	}
	rootfsDir := filepath.Join(staging, "rootfs")
	if err := os.Mkdir(rootfsDir, 0o700); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("create unpacked rootfs directory: %w", err)
	}
	if populate == nil {
		return preparedRootfsImage{}, fmt.Errorf("rootfs source importer is required")
	}
	if err := populate(rootfsDir); err != nil {
		return preparedRootfsImage{}, err
	}
	if guestAgentPath != "" {
		if err := installGuestRuntime(rootfsDir, guestAgentPath); err != nil {
			return preparedRootfsImage{}, err
		}
	}
	// The host staging directory starts private (0700), but that mode becomes
	// the root directory mode in the guest ext4 image. Sandboxed users must be
	// able to traverse the guest root after the overlay is mounted.
	if err := os.Chmod(rootfsDir, 0o755); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("set guest rootfs directory permissions: %w", err)
	}
	imageSize, err := rootfsImageSize(rootfsDir)
	if err != nil {
		return preparedRootfsImage{}, err
	}
	stagingImage := filepath.Join(staging, "rootfs.ext4")
	image, err := os.OpenFile(stagingImage, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return preparedRootfsImage{}, fmt.Errorf("create staged rootfs image: %w", err)
	}
	if err := image.Truncate(int64(imageSize)); err != nil {
		_ = image.Close()
		return preparedRootfsImage{}, fmt.Errorf("size staged rootfs image: %w", err)
	}
	if err := image.Close(); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("close staged rootfs image: %w", err)
	}
	if err := formatExt4Image(ctx, formatterPath, rootfsDir, stagingImage); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("format ext4 rootfs: %w", err)
	}
	if err := os.Chmod(stagingImage, 0o400); err != nil {
		return preparedRootfsImage{}, fmt.Errorf("make rootfs base image read-only: %w", err)
	}
	lease, err := publishRootfsImage(cacheDir, stagingImage, imagePath, int64(imageSize), cacheMaxBytes)
	if err != nil {
		return preparedRootfsImage{}, err
	}
	return preparedRootfsImage{Path: imagePath, Lease: lease}, nil
}

func unpackRootfsArchive(ctx context.Context, archiveFile *os.File, archivePath, rootfsDir string) error {
	var decompressed io.Reader
	var compressed io.Closer
	buffered := bufio.NewReader(&contextReader{ctx: ctx, reader: archiveFile})
	magic, peekErr := buffered.Peek(2)
	if peekErr != nil && !errors.Is(peekErr, io.EOF) {
		return fmt.Errorf("read rootfs archive header: %w", peekErr)
	}
	decompressed = buffered
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gzipReader, err := gzip.NewReader(buffered)
		if err != nil {
			return fmt.Errorf("open gzip rootfs archive: %w", err)
		}
		decompressed = gzipReader
		compressed = gzipReader
	}
	bounded := &boundedReader{reader: decompressed, limit: rootfsExpandedMaxBytes}
	unpackErr := archive.UntarUncompressed(bounded, rootfsDir, &archive.TarOptions{
		NoLchown:             true,
		NoOverwriteDirNonDir: true,
	})
	if unpackErr == nil {
		if _, drainErr := io.Copy(io.Discard, bounded); drainErr != nil {
			unpackErr = fmt.Errorf("verify expanded rootfs archive stream: %w", drainErr)
		}
	}
	var closeErr error
	if compressed != nil {
		closeErr = compressed.Close()
	}
	if unpackErr != nil {
		return fmt.Errorf("safely unpack rootfs archive %q: %w", archivePath, unpackErr)
	}
	if closeErr != nil {
		return fmt.Errorf("finish rootfs archive decompression: %w", closeErr)
	}
	if bounded.exceeded {
		return fmt.Errorf("expanded rootfs archive exceeds %d byte limit", rootfsExpandedMaxBytes)
	}
	return nil
}

func validateGuestAgent(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect VM guest agent %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 || info.Size() <= 0 || info.Size() > 128<<20 {
		return nil, fmt.Errorf("VM guest agent %q must be a non-empty executable regular file no larger than 128 MiB", path)
	}
	file, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("VM guest agent %q is not an ELF executable: %w", path, err)
	}
	if file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		_ = file.Close()
		return nil, fmt.Errorf("VM guest agent %q is not an executable ELF image", path)
	}
	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			_ = file.Close()
			return nil, fmt.Errorf("VM guest agent %q must be statically linked", path)
		}
	}
	if file.Machine != hostGuestELFMachine() {
		_ = file.Close()
		return nil, fmt.Errorf("VM guest agent %q has an architecture incompatible with host %s/%s", path, runtime.GOOS, runtime.GOARCH)
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	hasher := sha256.New()
	input, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(hasher, input); err != nil {
		_ = input.Close()
		return nil, fmt.Errorf("hash VM guest agent: %w", err)
	}
	if err := input.Close(); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func hostGuestELFMachine() elf.Machine {
	switch runtime.GOARCH {
	case "amd64":
		return elf.EM_X86_64
	case "arm64":
		return elf.EM_AARCH64
	default:
		return elf.EM_NONE
	}
}

func installGuestRuntime(rootfsDir, guestAgentPath string) error {
	for _, mountpoint := range []string{"proc", "sys", "dev", "run", "tmp", "overlay", "lower", "newroot"} {
		if err := os.MkdirAll(filepath.Join(rootfsDir, mountpoint), 0o755); err != nil {
			return fmt.Errorf("create guest mountpoint %q: %w", mountpoint, err)
		}
	}
	destination := filepath.Join(rootfsDir, "opt", "cautem", "bin", "guest-agent")
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("create guest agent directory: %w", err)
	}
	if err := copyRegularFile(guestAgentPath, destination, 0o755); err != nil {
		return fmt.Errorf("install guest agent: %w", err)
	}
	initPath := filepath.Join(rootfsDir, "opt", "cautem", "vm-init")
	if err := os.WriteFile(initPath, []byte(guestInitScript), 0o755); err != nil {
		return fmt.Errorf("install guest VM init: %w", err)
	}
	return nil
}

func copyRegularFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	return os.Chmod(destination, mode)
}

const guestInitScript = `#!/bin/sh
set -eu
mkdir -p /proc /sys /dev /run /tmp /overlay /lower /newroot
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true
mount -t tmpfs tmpfs /tmp 2>/dev/null || true
mount -o remount,ro / 2>/dev/null || true
mkdir -p /overlay /lower /newroot
mount -t ext4 -o rw /dev/vdb /overlay
mkdir -p /overlay/upper /overlay/work
mount --bind / /lower
mount -o remount,bind,ro /lower 2>/dev/null || true
mount -t overlay overlay -o lowerdir=/lower,upperdir=/overlay/upper,workdir=/overlay/work /newroot
for path in proc sys dev run tmp; do
  mkdir -p "/newroot/$path"
  mount --rbind "/$path" "/newroot/$path"
done
mkdir -p /newroot/workspace
guest_uid=1000
guest_gid=1000
if [ -r /newroot/etc/passwd ]; then
  while IFS=: read -r name password uid gid rest; do
    if [ "$name" = sandbox ]; then guest_uid=${uid:-1000}; guest_gid=${gid:-$guest_uid}; break; fi
  done < /newroot/etc/passwd
fi
chown "$guest_uid:$guest_gid" /newroot/workspace 2>/dev/null || true
export CAUTEM_VM_UID="$guest_uid" CAUTEM_VM_GID="$guest_gid"
exec chroot /newroot /opt/cautem/bin/guest-agent
`

type boundedReader struct {
	reader   io.Reader
	limit    int64
	read     int64
	exceeded bool
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func (r *boundedReader) Read(buffer []byte) (int, error) {
	if r.read >= r.limit {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n > 0 {
			r.exceeded = true
			return 0, fmt.Errorf("expanded rootfs archive exceeds %d byte limit", r.limit)
		}
		return 0, err
	}
	remaining := r.limit - r.read
	if int64(len(buffer)) > remaining {
		buffer = buffer[:remaining]
	}
	n, err := r.reader.Read(buffer)
	r.read += int64(n)
	return n, err
}

func ensurePrivateDirectory(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("VM rootfs image cache directory is unset")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve VM rootfs image cache directory: %w", err)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return fmt.Errorf("create VM rootfs image cache %q: %w", absolute, err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return fmt.Errorf("inspect VM rootfs image cache %q: %w", absolute, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("VM rootfs image cache %q must be a real directory", absolute)
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return fmt.Errorf("secure VM rootfs image cache %q: %w", absolute, err)
	}
	return nil
}

func resolveExt4Formatter() (string, error) {
	for _, name := range []string{"mke2fs", "mkfs.ext4"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("ext4 formatter unavailable: install e2fsprogs (mke2fs or mkfs.ext4)")
}

func rootfsImageSize(rootfs string) (uint64, error) {
	var used uint64 = 4096
	err := filepath.WalkDir(rootfs, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			if info.Size() > 0 {
				used += uint64(info.Size())
			}
		} else if info.IsDir() {
			used += 4096
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("measure unpacked rootfs: %w", err)
	}
	headroom := used / 4
	if headroom < rootfsImageMinHeadroom {
		headroom = rootfsImageMinHeadroom
	}
	size := used + headroom
	if size < rootfsImageMinBytes {
		size = rootfsImageMinBytes
	}
	return (size + rootfsImageSizeGranularity - 1) / rootfsImageSizeGranularity * rootfsImageSizeGranularity, nil
}
