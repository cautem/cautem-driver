package vm

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/klauspost/compress/zstd"
	"github.com/moby/go-archive"
)

const (
	rootfsRegistryMaxCompressedBytes = int64(16 << 30)
	rootfsRegistryMaxLayers          = 256
)

var errOCIManifestNotFound = errors.New("selected OCI manifest not found in index")

type resolvedOCIImage struct {
	Image                  v1.Image
	ImageConfig            v1.Config
	RequestedReference     string
	SourceManifestDigest   string
	PlatformManifestDigest string
	Platform               v1.Platform
}

func vmOCIPlatform() (v1.Platform, error) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return v1.Platform{}, fmt.Errorf("VM OCI images are unsupported on host architecture %q", runtime.GOARCH)
	}
	return v1.Platform{OS: "linux", Architecture: runtime.GOARCH}, nil
}

func parseOCIImageReference(imageRef string) (name.Reference, error) {
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" {
		return nil, fmt.Errorf("OCI image reference is required")
	}
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("invalid OCI image reference %q: %w", imageRef, err)
	}
	return ref, nil
}

func resolveOCIImageWithOptions(ctx context.Context, imageRef string, platform v1.Platform, nameOptions []name.Option, remoteOptions []remote.Option) (resolvedOCIImage, error) {
	if ctx == nil {
		return resolvedOCIImage{}, fmt.Errorf("OCI image resolution context is nil")
	}
	if err := ctx.Err(); err != nil {
		return resolvedOCIImage{}, err
	}
	if platform.OS != "linux" || platform.Architecture == "" {
		return resolvedOCIImage{}, fmt.Errorf("VM OCI platform must specify linux and an architecture")
	}
	var ref name.Reference
	var err error
	if len(nameOptions) == 0 {
		ref, err = parseOCIImageReference(imageRef)
	} else {
		ref, err = name.ParseReference(strings.TrimSpace(imageRef), nameOptions...)
	}
	if err != nil {
		return resolvedOCIImage{}, fmt.Errorf("parse OCI image reference %q: %w", imageRef, err)
	}
	if len(remoteOptions) == 0 {
		remoteOptions = []remote.Option{
			remote.WithContext(ctx),
			remote.WithAuthFromKeychain(authn.DefaultKeychain),
			remote.WithPlatform(platform),
		}
	}
	descriptor, err := remote.Get(ref, remoteOptions...)
	if err != nil {
		return resolvedOCIImage{}, fmt.Errorf("resolve OCI image %q: %w", imageRef, err)
	}
	image, err := descriptor.Image()
	if err != nil {
		return resolvedOCIImage{}, fmt.Errorf("select OCI image platform %s for %q: %w", platform.String(), imageRef, err)
	}
	config, err := image.ConfigFile()
	if err != nil {
		return resolvedOCIImage{}, fmt.Errorf("read OCI image config %q: %w", imageRef, err)
	}
	if config.OS != platform.OS || config.Architecture != platform.Architecture {
		return resolvedOCIImage{}, fmt.Errorf("OCI image %q config platform is %s/%s; requested %s", imageRef, config.OS, config.Architecture, platform.String())
	}
	manifestDigest, err := selectedOCIManifestDigest(descriptor, image, platform)
	if err != nil {
		return resolvedOCIImage{}, fmt.Errorf("identify selected OCI manifest %q: %w", imageRef, err)
	}
	return resolvedOCIImage{
		Image:                  image,
		ImageConfig:            config.Config,
		RequestedReference:     imageRef,
		SourceManifestDigest:   descriptor.Digest.String(),
		PlatformManifestDigest: manifestDigest,
		Platform:               platform,
	}, nil
}

// resolveOCIImageAtDigestWithOptions retrieves the selected platform image by
// its immutable manifest digest. Recovery does not follow a moved tag.
func resolveOCIImageAtDigestWithOptions(ctx context.Context, imageRef, manifestDigest string, platform v1.Platform, nameOptions []name.Option, remoteOptions []remote.Option) (resolvedOCIImage, error) {
	var ref name.Reference
	var err error
	if len(nameOptions) == 0 {
		ref, err = parseOCIImageReference(imageRef)
	} else {
		ref, err = name.ParseReference(strings.TrimSpace(imageRef), nameOptions...)
	}
	if err != nil {
		return resolvedOCIImage{}, err
	}
	pinned := ref.Context().Digest(manifestDigest)
	resolved, err := resolveOCIImageWithOptions(ctx, pinned.String(), platform, nameOptions, remoteOptions)
	if err != nil {
		return resolvedOCIImage{}, err
	}
	if resolved.PlatformManifestDigest != manifestDigest {
		return resolvedOCIImage{}, fmt.Errorf("OCI image %q resolved to platform manifest %s; durable state requires %s", imageRef, resolved.PlatformManifestDigest, manifestDigest)
	}
	resolved.RequestedReference = imageRef
	return resolved, nil
}

func selectedOCIManifestDigest(descriptor *remote.Descriptor, image v1.Image, platform v1.Platform) (string, error) {
	if descriptor == nil || image == nil {
		return "", fmt.Errorf("OCI manifest descriptor and image are required")
	}
	switch descriptor.MediaType {
	case types.OCIImageIndex, types.DockerManifestList:
		selectedManifest, err := image.RawManifest()
		if err != nil {
			return "", err
		}
		index, err := descriptor.ImageIndex()
		if err != nil {
			return "", err
		}
		return findOCIManifestDigest(index, selectedManifest, platform)
	default:
		return descriptor.Digest.String(), nil
	}
}

func findOCIManifestDigest(index v1.ImageIndex, selectedManifest []byte, platform v1.Platform) (string, error) {
	manifest, err := index.IndexManifest()
	if err != nil {
		return "", err
	}
	for _, child := range manifest.Manifests {
		if child.Platform != nil && !child.Platform.Satisfies(platform) {
			continue
		}
		switch child.MediaType {
		case types.OCIImageIndex, types.DockerManifestList:
			nested, err := index.ImageIndex(child.Digest)
			if err != nil {
				return "", err
			}
			digest, err := findOCIManifestDigest(nested, selectedManifest, platform)
			if err == nil {
				return digest, nil
			}
			if !errors.Is(err, errOCIManifestNotFound) {
				return "", err
			}
		case types.OCIManifestSchema1, types.DockerManifestSchema2:
			if child.Platform == nil {
				continue
			}
			candidate, err := index.Image(child.Digest)
			if err != nil {
				return "", err
			}
			candidateManifest, err := candidate.RawManifest()
			if err != nil {
				return "", err
			}
			if bytes.Equal(candidateManifest, selectedManifest) {
				return child.Digest.String(), nil
			}
		}
	}
	return "", fmt.Errorf("selected manifest for %s is not present in the registry index: %w", platform.String(), errOCIManifestNotFound)
}

func (resolved resolvedOCIImage) cacheIdentity() string {
	return "oci:" + resolved.SourceManifestDigest + ":" + resolved.PlatformManifestDigest + ":" + resolved.Platform.String()
}

func prepareOCIImageRootfsWithNameOptions(ctx context.Context, imageRef, cacheDir, formatterPath, guestAgentPath string, cacheMaxBytes int64, nameOptions []name.Option) (preparedRootfsImage, resolvedOCIImage, error) {
	platform, err := vmOCIPlatform()
	if err != nil {
		return preparedRootfsImage{}, resolvedOCIImage{}, err
	}
	resolved, err := resolveOCIImageWithOptions(ctx, imageRef, platform, nameOptions, nil)
	if err != nil {
		return preparedRootfsImage{}, resolvedOCIImage{}, err
	}
	guestDigest, err := validateGuestAgent(guestAgentPath)
	if err != nil {
		return preparedRootfsImage{}, resolvedOCIImage{}, err
	}
	prepared, err := prepareRootfsImageFromSource(ctx, cacheDir, formatterPath, guestAgentPath, resolved.cacheIdentity(), guestDigest, cacheMaxBytes, func(rootfsDir string) error {
		return populateRootfsFromOCI(ctx, resolved.Image, resolved.RequestedReference, resolved.Platform, rootfsDir)
	})
	if err != nil {
		return preparedRootfsImage{}, resolvedOCIImage{}, err
	}
	return prepared, resolved, nil
}

func populateRootfsFromOCI(ctx context.Context, image v1.Image, imageRef string, platform v1.Platform, rootfsDir string) error {
	manifest, err := image.Manifest()
	if err != nil {
		return fmt.Errorf("read OCI manifest for %q: %w", imageRef, err)
	}
	if len(manifest.Layers) > rootfsRegistryMaxLayers {
		return fmt.Errorf("OCI image %q has %d layers, exceeding the %d layer limit", imageRef, len(manifest.Layers), rootfsRegistryMaxLayers)
	}
	layers, err := image.Layers()
	if err != nil {
		return fmt.Errorf("read OCI layers for %q: %w", imageRef, err)
	}
	if len(layers) != len(manifest.Layers) {
		return fmt.Errorf("OCI image %q has inconsistent manifest and layer counts", imageRef)
	}
	var compressedTotal int64
	for _, descriptor := range manifest.Layers {
		if descriptor.Size < 0 || descriptor.Size > rootfsRegistryMaxCompressedBytes-compressedTotal {
			return fmt.Errorf("OCI image %q compressed layers exceed the %d byte limit", imageRef, rootfsRegistryMaxCompressedBytes)
		}
		compressedTotal += descriptor.Size
		if err := validateOCILayerMediaType(string(descriptor.MediaType)); err != nil {
			return fmt.Errorf("OCI image %q: %w", imageRef, err)
		}
	}

	stagingDir, err := os.MkdirTemp(filepath.Dir(rootfsDir), ".oci-layer-staging-*")
	if err != nil {
		return fmt.Errorf("create OCI layer staging directory: %w", err)
	}
	defer os.RemoveAll(stagingDir)
	if err := os.Chmod(stagingDir, 0o700); err != nil {
		return fmt.Errorf("secure OCI layer staging directory: %w", err)
	}
	var expandedTotal int64
	for index, descriptor := range manifest.Layers {
		if err := ctx.Err(); err != nil {
			return err
		}
		blobPath := filepath.Join(stagingDir, fmt.Sprintf("layer-%03d.blob", index))
		if err := downloadOCICompressedLayer(ctx, layers[index], descriptor, blobPath); err != nil {
			return fmt.Errorf("download OCI layer %d (%s) for %q: %w", index, descriptor.Digest, imageRef, err)
		}
		layerDir := filepath.Join(stagingDir, fmt.Sprintf("layer-%03d", index))
		layerExpanded, err := extractOCICompressedLayer(ctx, blobPath, string(descriptor.MediaType), layerDir, rootfsExpandedMaxBytes-expandedTotal)
		if err != nil {
			return fmt.Errorf("extract OCI layer %d (%s) for %q: %w", index, descriptor.Digest, imageRef, err)
		}
		expandedTotal += layerExpanded
		if err := applyOCILayer(layerDir, rootfsDir); err != nil {
			return fmt.Errorf("apply OCI layer %d for %q on %s: %w", index, imageRef, platform.String(), err)
		}
		if err := os.Remove(blobPath); err != nil {
			return fmt.Errorf("remove downloaded OCI layer blob: %w", err)
		}
		if err := os.RemoveAll(layerDir); err != nil {
			return fmt.Errorf("remove extracted OCI layer: %w", err)
		}
	}
	return nil
}

func downloadOCICompressedLayer(ctx context.Context, layer v1.Layer, descriptor v1.Descriptor, destination string) error {
	if descriptor.Size < 0 || descriptor.Size > rootfsRegistryMaxCompressedBytes {
		return fmt.Errorf("invalid compressed layer size %d", descriptor.Size)
	}
	reader, err := layer.Compressed()
	if err != nil {
		return err
	}
	defer reader.Close()
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	hasher, err := v1.Hasher(descriptor.Digest.Algorithm)
	if err != nil {
		return fmt.Errorf("unsupported layer digest algorithm %q: %w", descriptor.Digest.Algorithm, err)
	}
	bounded := &contextReader{ctx: ctx, reader: io.LimitReader(reader, descriptor.Size+1)}
	written, err := io.Copy(io.MultiWriter(file, hasher), bounded)
	if err != nil {
		return fmt.Errorf("read compressed layer: %w", err)
	}
	if written != descriptor.Size {
		return fmt.Errorf("compressed layer size is %d bytes; manifest declares %d", written, descriptor.Size)
	}
	digest := v1.Hash{Algorithm: descriptor.Digest.Algorithm, Hex: hex.EncodeToString(hasher.Sum(nil))}
	if digest != descriptor.Digest {
		return fmt.Errorf("compressed layer digest %s does not match manifest digest %s", digest, descriptor.Digest)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync compressed layer: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close compressed layer: %w", err)
	}
	closed = true
	return nil
}

func validateOCILayerMediaType(mediaType string) error {
	switch {
	case mediaType == "application/vnd.oci.image.layer.v1.tar",
		mediaType == "application/vnd.oci.image.layer.nondistributable.v1.tar",
		mediaType == "application/vnd.docker.image.rootfs.diff.tar":
		return nil
	case strings.HasSuffix(mediaType, "+gzip"), strings.HasSuffix(mediaType, ".gzip"):
		return nil
	case strings.HasSuffix(mediaType, "+zstd"):
		return nil
	default:
		return fmt.Errorf("unsupported OCI layer media type %q", mediaType)
	}
}

func extractOCICompressedLayer(ctx context.Context, blobPath, mediaType, layerDir string, maxExpanded int64) (int64, error) {
	if maxExpanded <= 0 {
		return 0, fmt.Errorf("expanded OCI rootfs exceeds %d byte limit", rootfsExpandedMaxBytes)
	}
	file, err := os.Open(blobPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	if err := os.Mkdir(layerDir, 0o700); err != nil {
		return 0, err
	}
	var input io.Reader = &contextReader{ctx: ctx, reader: file}
	var closer io.Closer
	switch {
	case strings.HasSuffix(mediaType, "+gzip"), strings.HasSuffix(mediaType, ".gzip"):
		gzipReader, err := gzip.NewReader(input)
		if err != nil {
			return 0, fmt.Errorf("open gzip layer: %w", err)
		}
		input, closer = gzipReader, gzipReader
	case strings.HasSuffix(mediaType, "+zstd"):
		zstdReader, err := zstd.NewReader(input)
		if err != nil {
			return 0, fmt.Errorf("open zstd layer: %w", err)
		}
		input, closer = zstdReader, zstdReader.IOReadCloser()
	}
	if closer != nil {
		defer closer.Close()
	}
	bounded := &boundedReader{reader: input, limit: maxExpanded}
	if err := archive.UntarUncompressed(bounded, layerDir, &archive.TarOptions{
		NoLchown:             true,
		NoOverwriteDirNonDir: true,
	}); err != nil {
		return 0, err
	}
	if _, err := io.Copy(io.Discard, bounded); err != nil {
		return 0, fmt.Errorf("finish decompressed OCI layer: %w", err)
	}
	if bounded.exceeded {
		return 0, fmt.Errorf("expanded OCI layer exceeds remaining %d byte limit", maxExpanded)
	}
	return bounded.read, nil
}

func applyOCILayer(layerDir, rootfsDir string) error {
	source, err := os.OpenRoot(layerDir)
	if err != nil {
		return fmt.Errorf("open extracted layer root: %w", err)
	}
	defer source.Close()
	destination, err := os.OpenRoot(rootfsDir)
	if err != nil {
		return fmt.Errorf("open merged rootfs: %w", err)
	}
	defer destination.Close()
	var entries []string
	err = filepath.WalkDir(layerDir, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filePath == layerDir {
			return nil
		}
		relative, err := filepath.Rel(layerDir, filePath)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "." || path.IsAbs(relative) || strings.HasPrefix(relative, "../") || strings.Contains(relative, "/../") {
			return fmt.Errorf("layer path %q escapes extraction root", relative)
		}
		entries = append(entries, relative)
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk extracted OCI layer: %w", err)
	}
	sort.Strings(entries)
	for _, entry := range entries {
		base := path.Base(entry)
		if base == ".wh..wh..opq" {
			if err := clearOCIPath(destination, path.Dir(entry)); err != nil {
				return fmt.Errorf("apply opaque whiteout %q: %w", entry, err)
			}
			continue
		}
		if strings.HasPrefix(base, ".wh.") {
			name := strings.TrimPrefix(base, ".wh.")
			if name == "" || name == "." || name == ".." {
				return fmt.Errorf("invalid OCI whiteout entry %q", entry)
			}
			target := path.Join(path.Dir(entry), name)
			if err := removeOCIPath(destination, target); err != nil {
				return fmt.Errorf("apply whiteout %q: %w", entry, err)
			}
		}
	}
	for _, entry := range entries {
		base := path.Base(entry)
		if strings.HasPrefix(base, ".wh.") {
			continue
		}
		info, err := source.Lstat(filepath.FromSlash(entry))
		if err != nil {
			return fmt.Errorf("inspect layer entry %q: %w", entry, err)
		}
		if info.IsDir() {
			if err := ensureOCIDirectory(destination, entry); err != nil {
				return fmt.Errorf("create layer directory %q: %w", entry, err)
			}
			if err := copyOCIDirectoryXattrs(source, destination, entry); err != nil {
				return fmt.Errorf("copy layer directory attributes %q: %w", entry, err)
			}
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if err := ensureOCIParent(destination, entry); err != nil {
				return err
			}
			if err := removeOCIPath(destination, entry); err != nil {
				return err
			}
			target, err := source.Readlink(filepath.FromSlash(entry))
			if err != nil {
				return fmt.Errorf("read layer symlink %q: %w", entry, err)
			}
			if err := destination.Symlink(target, filepath.FromSlash(entry)); err != nil {
				return fmt.Errorf("create layer symlink %q: %w", entry, err)
			}
			continue
		}
		if !info.Mode().IsRegular() {
			if strings.HasPrefix(entry, "dev/") {
				continue
			}
			return fmt.Errorf("unsupported special file %q with mode %s", entry, info.Mode())
		}
		if err := copyOCIRegularFile(source, destination, entry, info.Mode().Perm(), info.ModTime()); err != nil {
			return fmt.Errorf("copy layer file %q: %w", entry, err)
		}
	}
	for index := len(entries) - 1; index >= 0; index-- {
		entry := entries[index]
		info, err := source.Lstat(filepath.FromSlash(entry))
		if err != nil || !info.IsDir() {
			continue
		}
		if err := destination.Chmod(filepath.FromSlash(entry), info.Mode().Perm()); err != nil {
			return fmt.Errorf("set layer directory mode %q: %w", entry, err)
		}
		if err := destination.Chtimes(filepath.FromSlash(entry), info.ModTime(), info.ModTime()); err != nil {
			return fmt.Errorf("set layer directory time %q: %w", entry, err)
		}
	}
	return nil
}

func ensureOCIDirectory(root *os.Root, name string) error {
	if err := ensureOCIParent(root, name); err != nil {
		return err
	}
	name = filepath.FromSlash(name)
	info, err := root.Lstat(name)
	if err == nil && info.IsDir() {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := root.RemoveAll(name); err != nil {
		return err
	}
	return root.MkdirAll(name, 0o755)
}

func ensureOCIParent(root *os.Root, name string) error {
	parent := filepath.ToSlash(path.Dir(name))
	if parent == "." || parent == "" {
		return nil
	}
	current := ""
	for _, component := range strings.Split(parent, "/") {
		if component == "" || component == "." {
			continue
		}
		current = path.Join(current, component)
		info, err := root.Lstat(filepath.FromSlash(current))
		if errors.Is(err, os.ErrNotExist) {
			if err := root.Mkdir(filepath.FromSlash(current), 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if info.IsDir() {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			opened, err := root.OpenRoot(filepath.FromSlash(current))
			if err == nil {
				_ = opened.Close()
				continue
			}
			targetInfo, targetErr := root.Stat(filepath.FromSlash(current))
			if targetErr != nil {
				return fmt.Errorf("resolve layer parent symlink %q within rootfs: %w", current, targetErr)
			}
			if targetInfo.IsDir() {
				return fmt.Errorf("open layer parent symlink %q within rootfs: %w", current, err)
			}
		}
		if err := root.RemoveAll(filepath.FromSlash(current)); err != nil {
			return err
		}
		if err := root.Mkdir(filepath.FromSlash(current), 0o755); err != nil {
			return err
		}
	}
	return nil
}

func removeOCIPath(root *os.Root, name string) error {
	if name == "." || name == "" || path.IsAbs(name) || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
		return fmt.Errorf("invalid rootfs path %q", name)
	}
	err := root.RemoveAll(filepath.FromSlash(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func clearOCIPath(root *os.Root, name string) error {
	directoryPath := filepath.FromSlash(name)
	if name == "." {
		directoryPath = "."
	}
	info, err := root.Lstat(directoryPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("opaque whiteout parent %q is not a directory", name)
	}
	directory, err := root.OpenRoot(directoryPath)
	if err != nil {
		return err
	}
	defer directory.Close()
	file, err := directory.Open(".")
	if err != nil {
		return err
	}
	children, err := file.ReadDir(-1)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	for _, child := range children {
		if err := directory.RemoveAll(child.Name()); err != nil {
			return err
		}
	}
	return nil
}

func copyOCIRegularFile(source, destination *os.Root, name string, mode os.FileMode, modified time.Time) error {
	if err := ensureOCIParent(destination, name); err != nil {
		return err
	}
	if err := removeOCIPath(destination, name); err != nil {
		return err
	}
	input, err := source.Open(filepath.FromSlash(name))
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := destination.OpenFile(filepath.FromSlash(name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode.Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return err
	}
	if err := copyOCIXattrs(input, output); err != nil {
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
	if err := destination.Chmod(filepath.FromSlash(name), mode.Perm()); err != nil {
		return err
	}
	return destination.Chtimes(filepath.FromSlash(name), modified, modified)
}

func copyOCIDirectoryXattrs(source, destination *os.Root, name string) error {
	input, err := source.Open(filepath.FromSlash(name))
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := destination.Open(filepath.FromSlash(name))
	if err != nil {
		return err
	}
	defer output.Close()
	return copyOCIXattrs(input, output)
}

func digestSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
