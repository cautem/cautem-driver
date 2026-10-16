// Package vm contains the OpenShell-style libkrun MicroVM driver.
package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cautem/cautem-core"
	"github.com/cautem/quarshell-driver/driver"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Driver configures and preflights libkrun-backed microVM sandboxes.
type Driver struct {
	host             HostConfig
	mu               sync.Mutex
	rotationMu       sync.Mutex
	launchSpecs      map[string]vmLaunchSpec
	launchSpecInputs map[string]vmLaunchSpec
	workers          map[string]*exec.Cmd
	// ociNameOptions permits in-package acceptance tests to use a local HTTP
	// registry. Production drivers leave it empty and retain secure defaults.
	ociNameOptions []name.Option
}

// New returns the MicroVM driver using the process host configuration.
func New() *Driver { return NewWithHostConfig(DefaultHostConfig()) }

// NewWithHostConfig returns a MicroVM driver with explicit runtime paths.
func NewWithHostConfig(config HostConfig) *Driver {
	return &Driver{
		host: normalizeHostConfig(config), launchSpecs: make(map[string]vmLaunchSpec),
		launchSpecInputs: make(map[string]vmLaunchSpec), workers: make(map[string]*exec.Cmd),
	}
}

func (d *Driver) Create(ctx context.Context, spec driver.Spec) (driver.Handle, error) {
	if ctx == nil {
		return driver.Handle{}, fmt.Errorf("vm driver: Create context is nil")
	}
	if d == nil {
		return driver.Handle{}, fmt.Errorf("vm driver: driver is nil")
	}
	if err := ctx.Err(); err != nil {
		return driver.Handle{}, err
	}
	if err := validateSandboxName(spec.Name); err != nil {
		return driver.Handle{}, err
	}
	config, err := ParseSandboxDriverConfig(spec.DriverConfigJSON)
	if err != nil {
		return driver.Handle{}, err
	}
	if err := d.ValidateSpec(spec); err != nil {
		return driver.Handle{}, err
	}
	var archiveFile *os.File
	archivePath := ""
	if config.RootfsTarPath != "" {
		archiveFile, archivePath, err = openRootfsTar(config.RootfsTarPath, d.host.RootfsTarDir, d.host.RootfsTarMaxBytes)
		if err != nil {
			return driver.Handle{}, fmt.Errorf("vm driver rootfs: %w", err)
		}
		defer archiveFile.Close()
	}
	if d.host.GuestAgentPath == "" {
		return driver.Handle{}, fmt.Errorf("vm driver: set CAUTEM_VM_GUEST_AGENT to the matching static Linux guest agent binary")
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return driver.Handle{}, err
	}
	cacheDir := filepath.Join(store.root, "images")
	assetsDir := filepath.Join(store.root, "sandboxes")
	if err := ensurePrivateDirectory(assetsDir); err != nil {
		return driver.Handle{}, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return driver.Handle{}, err
	}
	states, err := store.list()
	if err != nil {
		return driver.Handle{}, err
	}
	for _, state := range states {
		if state.Name == spec.Name {
			return driver.Handle{}, fmt.Errorf("vm driver: sandbox %q already exists", spec.Name)
		}
	}
	var rootfsImage string
	var rootfsSourceType, rootfsSourceRef, rootfsSourceDigest, rootfsSourceManifestDigest, imagePlatform string
	var imageConfig *v1.Config
	if archiveFile != nil {
		prepared, prepareErr := prepareRootfsImageFileWithGuestLease(ctx, archiveFile, archivePath, cacheDir, d.host.FormatterPath, d.host.RootfsTarMaxBytes, d.host.GuestAgentPath, d.host.RootfsImageCacheMaxBytes)
		err = prepareErr
		if err != nil {
			return driver.Handle{}, fmt.Errorf("vm driver prepare rootfs: %w", err)
		}
		rootfsImage = prepared.Path
		defer prepared.Lease.Release()
		rootfsSourceType = "tar"
		rootfsSourceRef = "uploaded-tar"
		rootfsSourceDigest, err = digestOpenFile(archiveFile)
		if err != nil {
			return driver.Handle{}, fmt.Errorf("vm driver identify uploaded rootfs: %w", err)
		}
		imagePlatform = "linux/" + runtime.GOARCH
	} else {
		var source resolvedOCIImage
		prepared, preparedSource, prepareErr := prepareOCIImageRootfsWithNameOptions(ctx, spec.Image, cacheDir, d.host.FormatterPath, d.host.GuestAgentPath, d.host.RootfsImageCacheMaxBytes, d.ociNameOptions)
		err = prepareErr
		if err != nil {
			return driver.Handle{}, fmt.Errorf("vm driver pull and prepare OCI rootfs: %w", err)
		}
		rootfsImage = prepared.Path
		source = preparedSource
		imageConfig = &source.ImageConfig
		defer prepared.Lease.Release()
		rootfsSourceType = "oci"
		rootfsSourceRef = source.RequestedReference
		rootfsSourceDigest = source.PlatformManifestDigest
		rootfsSourceManifestDigest = source.SourceManifestDigest
		imagePlatform = source.Platform.String()
	}
	launchSpec := cloneVMLaunchSpec(spec)
	if imageConfig != nil {
		launchSpec, err = applyOCIImageConfig(launchSpec, *imageConfig)
		if err != nil {
			return driver.Handle{}, fmt.Errorf("vm driver apply OCI image config: %w", err)
		}
	} else if len(launchSpec.Command) == 0 {
		launchSpec.Command = defaultVMCommand()
	}
	template, err := prepareOverlayTemplate(ctx, filepath.Join(store.root, "templates"), d.host.FormatterPath, d.host.OverlaySizeBytes)
	if err != nil {
		return driver.Handle{}, fmt.Errorf("vm driver prepare overlay template: %w", err)
	}
	id, err := newSandboxID()
	if err != nil {
		return driver.Handle{}, fmt.Errorf("vm driver: allocate sandbox ID: %w", err)
	}
	sandboxDir := filepath.Join(assetsDir, id)
	if err := os.Mkdir(sandboxDir, 0o700); err != nil {
		return driver.Handle{}, fmt.Errorf("create VM sandbox asset directory: %w", err)
	}
	if _, err := createControlToken(sandboxDir); err != nil {
		_ = os.RemoveAll(sandboxDir)
		return driver.Handle{}, err
	}
	overlayPath := filepath.Join(sandboxDir, "overlay.ext4")
	if err := createSandboxOverlay(template, overlayPath); err != nil {
		_ = os.RemoveAll(sandboxDir)
		return driver.Handle{}, fmt.Errorf("create VM sandbox overlay: %w", err)
	}
	now := time.Now().UTC()
	state := sandboxState{
		Version: sandboxStateVersion, ID: id, Name: spec.Name, Image: spec.Image,
		Rootfs: rootfsImage, RootfsSourceType: rootfsSourceType, RootfsSourceRef: rootfsSourceRef,
		RootfsSourceDigest: rootfsSourceDigest, RootfsSourceManifestDigest: rootfsSourceManifestDigest, Platform: imagePlatform,
		VCPUs:     specVCPUs(spec.CPU, d.host.VCPUs),
		MemoryMiB: specMemoryMiB(spec.MemoryBytes, d.host.MemoryMiB),
		Status:    "created", CreatedAt: now, UpdatedAt: now,
	}
	if err := store.save(state); err != nil {
		_ = os.RemoveAll(sandboxDir)
		return driver.Handle{}, fmt.Errorf("persist VM sandbox state: %w", err)
	}
	d.launchSpecs[id] = launchSpec
	d.launchSpecInputs[id] = cloneVMLaunchSpec(spec)
	return driver.Handle{ID: core.ID(state.ID), Name: state.Name, Image: state.Image}, nil
}

func digestOpenFile(file *os.File) (string, error) {
	if file == nil {
		return "", fmt.Errorf("rootfs source file is nil")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func cloneVMLaunchSpec(spec driver.Spec) vmLaunchSpec {
	cloned := driver.Spec{
		Command:                  append([]string(nil), spec.Command...),
		MainProcessRestartPolicy: spec.MainProcessRestartPolicy,
		Env:                      append([]string(nil), spec.Env...),
		ProxyBin:                 spec.ProxyBin,
		PolicyPath:               spec.PolicyPath,
		ProxyPort:                spec.ProxyPort,
		ProxyEnv:                 append([]string(nil), spec.ProxyEnv...),
		DriverConfigJSON:         spec.DriverConfigJSON,
		InitBin:                  spec.InitBin,
		SupervisorBin:            spec.SupervisorBin,
		EnableSSH:                spec.EnableSSH,
		SSHBin:                   spec.SSHBin,
	}
	return vmLaunchSpec{Spec: cloned, WorkDir: "/workspace"}
}

// RootfsTarStaging exposes the private staging root consumed by the Gateway's
// single-use rootfs archive upload flow.
func (d *Driver) RootfsTarStaging(ctx context.Context) (string, uint64, error) {
	if d == nil {
		return "", 0, fmt.Errorf("vm driver: driver is nil")
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
	}
	root := strings.TrimSpace(d.host.RootfsTarDir)
	if root == "" {
		return "", 0, fmt.Errorf("vm driver rootfs staging directory is unset")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", 0, fmt.Errorf("resolve vm rootfs staging directory: %w", err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", 0, fmt.Errorf("create vm rootfs staging directory %q: %w", root, err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", 0, fmt.Errorf("inspect vm rootfs staging directory %q: %w", root, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", 0, fmt.Errorf("vm rootfs staging path %q must be a real directory", root)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return "", 0, fmt.Errorf("secure vm rootfs staging directory %q: %w", root, err)
	}
	return root, uint64(d.host.RootfsTarMaxBytes), nil
}

func (d *Driver) Delete(ctx context.Context, id core.ID) error {
	if d == nil {
		return fmt.Errorf("vm driver: driver is nil")
	}
	if ctx == nil {
		return fmt.Errorf("vm driver: Delete context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return err
	}
	state, err := store.load(string(id))
	if err != nil {
		if os.IsNotExist(err) && validSandboxID(string(id)) {
			return nil
		}
		return err
	}
	state = d.refreshState(store, state)
	if state.Status == "running" {
		if err := d.stopLocked(ctx, store, state); err != nil {
			return fmt.Errorf("stop VM sandbox before delete: %w", err)
		}
	}
	workerSocketPath, guestSocketPath, _ := workerSocketPaths(store.root, state.ID)
	for _, socketPath := range []string{
		workerSocketPath, guestSocketPath, networkBrokerSocketPath(workerSocketPath, state.ID),
		sshRelaySocketPath(workerSocketPath, state.ID), supervisorControlSocketPath(workerSocketPath, state.ID),
	} {
		if err := removeStaleUnixSocket(socketPath); err != nil {
			return fmt.Errorf("remove stale VM socket: %w", err)
		}
	}
	assets := filepath.Join(store.root, "sandboxes", state.ID)
	if err := removePrivateTree(assets); err != nil {
		return fmt.Errorf("remove VM sandbox assets: %w", err)
	}
	if err := store.delete(state.ID); err != nil {
		return err
	}
	delete(d.launchSpecs, state.ID)
	delete(d.launchSpecInputs, state.ID)
	return nil
}
func (d *Driver) List(ctx context.Context) ([]driver.Info, error) {
	if d == nil || ctx == nil {
		return nil, fmt.Errorf("vm driver: List requires a driver and context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return nil, err
	}
	states, err := store.list()
	if err != nil {
		return nil, err
	}
	infos := make([]driver.Info, 0, len(states))
	for _, state := range states {
		state = d.refreshState(store, state)
		infos = append(infos, stateInfo(state))
	}
	return infos, nil
}
func (d *Driver) Inspect(ctx context.Context, nameOrID string) (driver.Info, error) {
	if d == nil || ctx == nil {
		return driver.Info{}, fmt.Errorf("vm driver: Inspect requires a driver and context")
	}
	if err := ctx.Err(); err != nil {
		return driver.Info{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return driver.Info{}, err
	}
	state, err := store.find(strings.TrimSpace(nameOrID))
	if err != nil {
		return driver.Info{}, err
	}
	state = d.refreshState(store, state)
	return stateInfo(state), nil
}
func stateInfo(state sandboxState) driver.Info {
	return driver.Info{ID: core.ID(state.ID), Name: state.Name, Image: state.Image, Status: state.Status}
}

func removePrivateTree(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("VM sandbox asset path must be absolute")
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("VM sandbox assets %q must be a real directory", path)
	}
	return os.RemoveAll(path)
}

var _ driver.ComputeDriver = (*Driver)(nil)
var _ driver.RootfsTarStager = (*Driver)(nil)
var _ driver.SpecValidator = (*Driver)(nil)
var _ driver.GatewayRuntimeValidator = (*Driver)(nil)
var _ driver.LaunchSpecRestorer = (*Driver)(nil)
