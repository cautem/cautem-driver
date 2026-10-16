package vm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	core "github.com/cautem/cautem-core"
	"github.com/cautem/cautem-driver/driver"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const (
	defaultVMStartupTimeout = 2 * time.Minute
	workerStopTimeout       = 10 * time.Second
)

func (d *Driver) Start(ctx context.Context, id core.ID) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("vm driver: Start requires a driver and context")
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
		return err
	}
	if recovered, err := d.recoverWorker(ctx, store, state); err != nil {
		return err
	} else if recovered {
		_, guestSocket, _ := workerSocketPaths(store.root, state.ID)
		return d.rotateGuestControlToken(ctx, state.ID, guestSocket)
	}
	if state.Status == "running" {
		_, guestSocket, _ := workerSocketPaths(store.root, state.ID)
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, pingErr := d.exchangeControl(pingCtx, state.ID, guestSocket, controlRequest{Operation: "ping"})
		cancel()
		if pingErr == nil {
			return d.rotateGuestControlToken(ctx, state.ID, guestSocket)
		}
		state.Status = "stopped"
		state.UpdatedAt = time.Now().UTC()
		if err := store.save(state); err != nil {
			return fmt.Errorf("repair stale VM state: %w", err)
		}
	}
	if state.Status != "created" && state.Status != "stopped" {
		return fmt.Errorf("vm driver: sandbox %q cannot start from status %q", state.Name, state.Status)
	}
	launchSpec, configured := d.launchSpecs[state.ID]
	if !configured || len(launchSpec.Command) == 0 {
		return fmt.Errorf("vm driver: sandbox %q workload spec is unavailable; restore it from the durable control-plane spec before starting", state.Name)
	}
	if _, err := probeHost(runtime.GOOS, runtime.GOARCH, d.host); err != nil {
		return fmt.Errorf("vm driver host preflight: %w", err)
	}
	return d.startLocked(ctx, store, state, launchSpec)
}

func (d *Driver) startLocked(ctx context.Context, store *stateStore, state sandboxState, launchSpec vmLaunchSpec) (startErr error) {
	spec := launchSpec.Spec
	driverConfig, err := ParseSandboxDriverConfig(spec.DriverConfigJSON)
	if err != nil {
		return err
	}
	worker, err := workerPath(d.host.WorkerPath)
	if err != nil {
		return err
	}
	overlayPath := filepath.Join(store.root, "sandboxes", state.ID, "overlay.ext4")
	if err := validateSandboxArtifacts(store.root, state, overlayPath); err != nil {
		return err
	}
	workerControlPath, guestSocket, consolePath := workerSocketPaths(store.root, state.ID)
	brokerSocket := networkBrokerSocketPath(workerControlPath, state.ID)
	sshSocket := sshRelaySocketPath(workerControlPath, state.ID)
	supervisorSocket := supervisorControlSocketPath(workerControlPath, state.ID)
	if err := validateWorkerSocket(workerControlPath); err != nil {
		return err
	}
	for _, socket := range []string{workerControlPath, guestSocket, brokerSocket, sshSocket, supervisorSocket} {
		if err := removeStaleUnixSocket(socket); err != nil {
			return err
		}
	}
	controlToken, err := readControlToken(filepath.Join(store.root, "sandboxes", state.ID))
	if err != nil {
		return err
	}
	console, err := os.OpenFile(consolePath+".worker", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open VM console log: %w", err)
	}
	if err := console.Chmod(0o600); err != nil {
		_ = console.Close()
		return fmt.Errorf("secure VM console log: %w", err)
	}
	launch := KrunLaunchConfig{
		RootDisk: state.Rootfs, OverlayDisk: overlayPath,
		VCPUs: state.VCPUs, MemoryMiB: state.MemoryMiB, WorkDir: "/",
		ExecPath: "/bin/sh", Args: []string{"/opt/cautem/vm-init"},
		Env:         []string{"CAUTEM_VM_CONTROL_TOKEN=" + controlToken},
		ConsolePath: consolePath, VsockPort: guestControlPort, VsockSocket: guestSocket,
	}
	var brokerConfig *networkBrokerConfig
	if spec.ProxyBin != "" {
		proxyPort := vmGuestProxyPort(spec.ProxyPort)
		launch.Env = append(launch.Env,
			"CAUTEM_VM_NETWORK_BROKER_PORT="+strconv.Itoa(int(networkBrokerVsockPort)),
			"CAUTEM_VM_NETWORK_PROXY_PORT="+strconv.Itoa(proxyPort),
		)
		launch.VsockPorts = append(launch.VsockPorts, KrunVsockPort{Port: networkBrokerVsockPort, Socket: brokerSocket, Listen: false})
		proxyEnv := append([]string(nil), spec.ProxyEnv...)
		if driverConfig.GRPCEndpoint != "" {
			proxyEnv = append(proxyEnv, "CAUTEM_GATEWAY_GRPC_ENDPOINT="+driverConfig.GRPCEndpoint)
		}
		if driverConfig.GuestTLSCA != "" {
			proxyEnv = append(proxyEnv,
				"CAUTEM_GUEST_TLS_CA="+driverConfig.GuestTLSCA,
				"CAUTEM_GUEST_TLS_CERT="+driverConfig.GuestTLSCert,
				"CAUTEM_GUEST_TLS_KEY="+driverConfig.GuestTLSKey,
			)
		}
		brokerConfig = &networkBrokerConfig{
			Binary: spec.ProxyBin, Policy: spec.PolicyPath,
			Socket: brokerSocket, LogDir: filepath.Join(store.root, "sandboxes", state.ID),
			ProxyEnv: proxyEnv,
		}
		if spec.SupervisorBin != "" {
			launch.Env = append(launch.Env,
				"CAUTEM_VM_SUPERVISOR_ENABLED=1",
				"CAUTEM_VM_SUPERVISOR_CONTROL_PORT="+strconv.Itoa(int(supervisorControlPort)),
			)
			launch.VsockPorts = append(launch.VsockPorts, KrunVsockPort{Port: supervisorControlPort, Socket: supervisorSocket, Listen: false})
			brokerConfig.ControlSocket = supervisorSocket
		}
		if spec.EnableSSH {
			launch.Env = append(launch.Env, "CAUTEM_VM_SSH_RELAY_PORT="+strconv.Itoa(int(sshRelayVsockPort)))
			launch.VsockPorts = append(launch.VsockPorts, KrunVsockPort{Port: sshRelayVsockPort, Socket: sshSocket, Listen: true})
			brokerConfig.SSHSocket = sshSocket
		}
	}
	isolationFunc := d.host.workerIsolation
	if isolationFunc == nil {
		isolationFunc = workerIsolationForChild
	}
	isolation, err := isolationFunc()
	if err != nil {
		_ = console.Close()
		return fmt.Errorf("prepare VM worker isolation: %w", err)
	}
	config, err := workerConfigJSON(workerConfig{RuntimeDir: d.host.RuntimeDir, ControlSocket: workerControlPath, Isolation: isolation, NetworkBroker: brokerConfig, Launch: launch})
	if err != nil {
		_ = console.Close()
		return err
	}
	command := exec.Command(worker)
	command.Stdin = bytes.NewReader(config)
	command.Stdout = console
	command.Stderr = console
	command.Env = workerEnvironment(d.host.RuntimeDir)
	processAttributes := d.host.workerProcessAttributes
	if processAttributes == nil {
		processAttributes = workerProcessAttributes
	}
	command.SysProcAttr = processAttributes()
	if err := command.Start(); err != nil {
		_ = console.Close()
		return fmt.Errorf("start libkrun worker: %w", err)
	}
	_ = console.Close()
	d.workers[state.ID] = command
	done := make(chan error, 1)
	go func() {
		done <- command.Wait()
		close(done)
	}()
	started := false
	defer func() {
		if started {
			go d.watchWorker(state.ID, store.root, done)
			return
		}
		if startErr != nil {
			forceStopWorker(workerControlPath)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				_ = command.Process.Kill()
				<-done
			}
			delete(d.workers, state.ID)
		}
	}()

	startupCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		startupCtx, cancel = context.WithTimeout(ctx, defaultVMStartupTimeout)
		defer cancel()
	}
	if err := waitForWorkerOrExit(startupCtx, workerControlPath, done); err != nil {
		return err
	}
	if err := d.waitForGuestOrExit(startupCtx, state.ID, guestSocket, done); err != nil {
		return err
	}
	if spec.SupervisorBin != "" || spec.EnableSSH {
		if err := d.installGuestRuntimeAssets(startupCtx, state.ID, guestSocket, spec); err != nil {
			return err
		}
	}
	if spec.EnableSSH {
		if _, err := d.exchangeControl(startupCtx, state.ID, guestSocket, controlRequest{Operation: "start-ssh"}); err != nil {
			return fmt.Errorf("start guest SSH relay: %w", err)
		}
	}
	if _, err := d.exchangeControl(startupCtx, state.ID, guestSocket, controlRequest{
		Operation: "start-workload", Argv: launchSpec.Command,
		Env: launchSpec.Env, RestartPolicy: launchSpec.MainProcessRestartPolicy,
		WorkDir: launchSpec.WorkDir, User: launchSpec.User,
	}); err != nil {
		return fmt.Errorf("start guest workload: %w", err)
	}
	if err := d.rotateGuestControlToken(startupCtx, state.ID, guestSocket); err != nil {
		return fmt.Errorf("rotate guest control token after startup: %w", err)
	}
	state.Status = "running"
	state.UpdatedAt = time.Now().UTC()
	if err := store.save(state); err != nil {
		return fmt.Errorf("persist running VM state: %w", err)
	}
	started = true
	return nil
}

func (d *Driver) installGuestRuntimeAssets(ctx context.Context, id, guestSocket string, spec driver.Spec) error {
	assets := make([]struct {
		host  string
		guest string
	}, 0, 4)
	if spec.SupervisorBin != "" {
		assets = append(assets, struct{ host, guest string }{spec.SupervisorBin, guestSupervisorBinary})
	}
	if spec.InitBin != "" {
		assets = append(assets, struct{ host, guest string }{spec.InitBin, guestInitBinary})
	}
	if spec.PolicyPath != "" && (spec.SupervisorBin != "" || spec.EnableSSH) {
		assets = append(assets, struct{ host, guest string }{spec.PolicyPath, guestPolicyFile})
	}
	if spec.EnableSSH {
		assets = append(assets, struct{ host, guest string }{spec.SSHBin, guestSSHBinary})
	}
	for _, asset := range assets {
		path, err := filepath.Abs(asset.host)
		if err != nil || filepath.Clean(path) != path {
			return fmt.Errorf("resolve guest runtime asset %q: invalid path", asset.host)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("guest runtime asset %q must be a regular file", asset.host)
		}
		if info.Size() <= 0 || info.Size() > controlFrameMax/2 {
			return fmt.Errorf("guest runtime asset %q exceeds the VM control transfer limit", asset.host)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read guest runtime asset %q: %w", asset.host, err)
		}
		mode := uint32(0o600)
		if info.Mode().Perm()&0o111 != 0 {
			mode = 0o755
		}
		if _, err := d.exchangeControl(ctx, id, guestSocket, controlRequest{
			Operation: "copy-to", Path: asset.guest, Data: data, Mode: mode,
		}); err != nil {
			return fmt.Errorf("install guest runtime asset %q: %w", asset.guest, err)
		}
	}
	return nil
}

// RestoreLaunchSpec installs a durable control-plane workload spec after the
// Gateway process or compute driver has restarted. Runtime env/argv remain
// process-local and are never written to VM state.
func (d *Driver) RestoreLaunchSpec(ctx context.Context, id core.ID, spec driver.Spec) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("vm driver: RestoreLaunchSpec requires a driver and context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateMainProcessRestartPolicy(spec); err != nil {
		return err
	}
	if err := validateNetworkBrokerSpec(spec); err != nil {
		return err
	}
	if _, err := ParseSandboxDriverConfig(spec.DriverConfigJSON); err != nil {
		return err
	}
	if err := validateGuestRuntimeAssets(spec); err != nil {
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
		return err
	}
	if spec.Name != "" && spec.Name != state.Name {
		return fmt.Errorf("vm driver: restored workload name does not match sandbox state")
	}
	requestedSpec := cloneVMLaunchSpec(spec)
	if state.Status == "running" {
		if previous, configured := d.launchSpecInputs[state.ID]; configured && reflect.DeepEqual(previous, requestedSpec) {
			return nil
		}
		if _, configured := d.launchSpecs[state.ID]; configured {
			return fmt.Errorf("vm driver: cannot replace workload spec for running sandbox %q", state.Name)
		}
	}
	launchSpec := cloneVMLaunchSpec(spec)
	if state.RootfsSourceType == "oci" {
		platform, err := v1.ParsePlatform(state.Platform)
		if err != nil {
			return fmt.Errorf("vm driver: restore OCI workload platform: %w", err)
		}
		if platform == nil {
			return fmt.Errorf("vm driver: restore OCI workload platform is empty")
		}
		resolved, err := resolveOCIImageAtDigestWithOptions(ctx, state.RootfsSourceRef, state.RootfsSourceDigest, *platform, d.ociNameOptions, nil)
		if err != nil {
			return fmt.Errorf("vm driver: restore OCI image config by pinned manifest digest: %w", err)
		}
		launchSpec, err = applyOCIImageConfig(launchSpec, resolved.ImageConfig)
		if err != nil {
			return fmt.Errorf("vm driver: restore OCI image config: %w", err)
		}
	} else if len(launchSpec.Command) == 0 {
		launchSpec.Command = defaultVMCommand()
	}
	d.launchSpecs[state.ID] = launchSpec
	d.launchSpecInputs[state.ID] = requestedSpec
	return nil
}

func validateSandboxArtifacts(root string, state sandboxState, overlayPath string) error {
	imageDir := filepath.Join(root, "images")
	imageRelative, err := filepath.Rel(imageDir, state.Rootfs)
	if err != nil || filepath.IsAbs(imageRelative) || imageRelative == "." || strings.Contains(filepath.ToSlash(imageRelative), "/") || strings.HasPrefix(imageRelative, "..") || filepath.Ext(imageRelative) != ".ext4" {
		return fmt.Errorf("VM state rootfs path is outside the private image cache")
	}
	rootfsInfo, err := os.Lstat(state.Rootfs)
	if err != nil {
		return fmt.Errorf("inspect VM rootfs image: %w", err)
	}
	if !rootfsInfo.Mode().IsRegular() || rootfsInfo.Size() == 0 || rootfsInfo.Mode().Perm()&0o222 != 0 {
		return fmt.Errorf("VM rootfs image must be a non-empty immutable regular file")
	}
	overlayInfo, err := os.Lstat(overlayPath)
	if err != nil {
		return fmt.Errorf("inspect VM overlay image: %w", err)
	}
	if !overlayInfo.Mode().IsRegular() || overlayInfo.Size() == 0 || overlayInfo.Mode().Perm() != 0o600 {
		return fmt.Errorf("VM overlay image must be a private mode 0600 regular file")
	}
	return nil
}

func waitForWorkerOrExit(ctx context.Context, socket string, done <-chan error) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		response, err := workerControl(ctx, socket, "status")
		if err == nil && response.Ready {
			return nil
		}
		select {
		case workerErr := <-done:
			if workerErr == nil {
				workerErr = fmt.Errorf("worker exited without an error")
			}
			return fmt.Errorf("libkrun worker exited before ready: %w", workerErr)
		case <-ctx.Done():
			return fmt.Errorf("wait for libkrun worker: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (d *Driver) waitForGuestOrExit(ctx context.Context, id, socket string, done <-chan error) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, err := d.exchangeControl(ctx, id, socket, controlRequest{Operation: "ping"})
		if err == nil {
			return nil
		}
		select {
		case workerErr := <-done:
			if workerErr == nil {
				workerErr = fmt.Errorf("worker exited without an error")
			}
			return fmt.Errorf("libkrun worker exited before guest agent was ready: %w", workerErr)
		case <-ctx.Done():
			return fmt.Errorf("wait for guest control agent: %w (last error: %v)", ctx.Err(), err)
		case <-ticker.C:
		}
	}
}

func (d *Driver) recoverWorker(ctx context.Context, store *stateStore, state sandboxState) (bool, error) {
	workerSocketPath, guestSocket, _ := workerSocketPaths(store.root, state.ID)
	probeCtx, cancel := context.WithTimeout(ctx, time.Second)
	status, err := workerControl(probeCtx, workerSocketPath, "status")
	cancel()
	if err != nil {
		return false, nil
	}
	startupCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var timeout context.CancelFunc
		startupCtx, timeout = context.WithTimeout(ctx, defaultVMStartupTimeout)
		defer timeout()
	}
	if err := d.waitForExistingGuest(startupCtx, state.ID, guestSocket); err != nil {
		return false, fmt.Errorf("recover VM worker (ready=%t): %w", status.Ready, err)
	}
	if state.Status != "running" {
		state.Status = "running"
		state.UpdatedAt = time.Now().UTC()
		if err := store.save(state); err != nil {
			return false, fmt.Errorf("persist recovered VM state: %w", err)
		}
	}
	return true, nil
}

func (d *Driver) waitForExistingGuest(ctx context.Context, id, socket string) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := d.exchangeControl(ctx, id, socket, controlRequest{Operation: "ping"}); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (d *Driver) watchWorker(id, root string, done <-chan error) {
	<-done
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.workers, id)
	store, err := openStateStore(root)
	if err != nil {
		return
	}
	state, err := store.load(id)
	if err != nil || state.Status != "running" {
		return
	}
	state.Status = "stopped"
	state.UpdatedAt = time.Now().UTC()
	_ = store.save(state)
}

func (d *Driver) Stop(ctx context.Context, id core.ID) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("vm driver: Stop requires a driver and context")
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
		return err
	}
	return d.stopLocked(ctx, store, state)
}

func (d *Driver) stopLocked(ctx context.Context, store *stateStore, state sandboxState) error {
	if state.Status != "running" {
		if state.Status == "created" {
			state.Status = "stopped"
			state.UpdatedAt = time.Now().UTC()
			return store.save(state)
		}
		return nil
	}
	workerControlPath, guestSocket, _ := workerSocketPaths(store.root, state.ID)
	shutdownCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		shutdownCtx, cancel = context.WithTimeout(ctx, workerStopTimeout)
		defer cancel()
	}
	if _, err := d.exchangeControl(shutdownCtx, state.ID, guestSocket, controlRequest{Operation: "stop-workload"}); err != nil {
		return fmt.Errorf("stop guest workload: %w", err)
	}
	if _, err := d.exchangeControl(shutdownCtx, state.ID, guestSocket, controlRequest{Operation: "shutdown"}); err != nil {
		return fmt.Errorf("request guest shutdown: %w", err)
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := workerControl(shutdownCtx, workerControlPath, "status"); err != nil {
			state.Status = "stopped"
			state.UpdatedAt = time.Now().UTC()
			if err := store.save(state); err != nil {
				return fmt.Errorf("persist stopped VM state: %w", err)
			}
			return nil
		}
		select {
		case <-shutdownCtx.Done():
			return fmt.Errorf("wait for guest shutdown: %w", shutdownCtx.Err())
		case <-ticker.C:
		}
	}
}

func forceStopWorker(socket string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _ = workerControl(ctx, socket, "stop")
}

func (d *Driver) Exec(ctx context.Context, id core.ID, request driver.ExecRequest) (driver.ExecResult, error) {
	if d == nil || ctx == nil {
		return driver.ExecResult{}, fmt.Errorf("vm driver: Exec requires a driver and context")
	}
	if len(request.Argv) == 0 {
		return driver.ExecResult{}, fmt.Errorf("vm exec: argv is empty")
	}
	if request.TTY {
		return d.execWithTerminal(ctx, id, request)
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return driver.ExecResult{}, err
	}
	state, err := store.load(string(id))
	if err != nil {
		return driver.ExecResult{}, err
	}
	if state.Status != "running" {
		return driver.ExecResult{}, fmt.Errorf("vm exec: sandbox %q is %s", state.Name, state.Status)
	}
	_, guestSocket, _ := workerSocketPaths(store.root, state.ID)
	d.mu.Lock()
	launchSpec := d.launchSpecs[state.ID]
	d.mu.Unlock()
	workdir := strings.TrimSpace(request.WorkDir)
	if workdir == "" {
		workdir = launchSpec.WorkDir
	}
	if workdir == "" {
		workdir = "/workspace"
	}
	env, err := mergeLaunchEnvironment(launchSpec.Env, request.Env)
	if err != nil {
		return driver.ExecResult{}, err
	}
	response, err := d.exchangeControl(ctx, state.ID, guestSocket, controlRequest{
		Operation: "exec", Argv: request.Argv, Env: env, WorkDir: workdir,
		User: launchSpec.User, Stdin: request.Stdin, NoLoginShell: request.NoLoginShell,
	})
	if err != nil {
		return driver.ExecResult{}, err
	}
	return driver.ExecResult{ExitCode: response.ExitCode, Stdout: response.Stdout, Stderr: response.Stderr, OutputTruncated: response.OutputTruncated}, nil
}

func (d *Driver) Logs(ctx context.Context, id core.ID, follow bool, writer io.Writer) error {
	if d == nil || ctx == nil || writer == nil {
		return fmt.Errorf("vm driver: Logs requires a driver, context, and writer")
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return err
	}
	if _, err := store.load(string(id)); err != nil {
		return err
	}
	_, _, consolePath := workerSocketPaths(store.root, string(id))
	file, err := os.Open(consolePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open VM console log: %w", err)
	}
	defer file.Close()
	if err := streamFile(ctx, file, follow, writer); err != nil {
		return err
	}
	workerLog, err := os.Open(consolePath + ".worker")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open VM worker log: %w", err)
	}
	defer workerLog.Close()
	return streamFile(ctx, workerLog, follow, writer)
}

func streamFile(ctx context.Context, file *os.File, follow bool, writer io.Writer) error {
	buffer := make([]byte, 32*1024)
	for {
		count, readErr := file.Read(buffer)
		if count > 0 {
			if _, err := writer.Write(buffer[:count]); err != nil {
				return err
			}
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if errors.Is(readErr, io.EOF) {
			if !follow {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
}

func (d *Driver) CopyTo(ctx context.Context, id core.ID, source, destination string) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("vm driver: CopyTo requires a driver and context")
	}
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > controlFrameMax/2 {
		return fmt.Errorf("vm copy-to source must be a regular file no larger than %d bytes", controlFrameMax/2)
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return d.copyControl(ctx, id, controlRequest{Operation: "copy-to", Path: destination, Data: data, Mode: uint32(info.Mode().Perm())})
}

func (d *Driver) CopyFrom(ctx context.Context, id core.ID, source, destination string) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("vm driver: CopyFrom requires a driver and context")
	}
	response, err := d.copyControlRequest(ctx, id, controlRequest{Operation: "copy-from", Path: source})
	if err != nil {
		return err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".cautem-copy-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(response.Data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, destination)
}

func (d *Driver) copyControl(ctx context.Context, id core.ID, request controlRequest) error {
	_, err := d.copyControlRequest(ctx, id, request)
	return err
}

func (d *Driver) copyControlRequest(ctx context.Context, id core.ID, request controlRequest) (controlResponse, error) {
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return controlResponse{}, err
	}
	state, err := store.load(string(id))
	if err != nil {
		return controlResponse{}, err
	}
	if state.Status != "running" {
		return controlResponse{}, fmt.Errorf("vm copy: sandbox %q is %s", state.Name, state.Status)
	}
	_, socket, _ := workerSocketPaths(store.root, state.ID)
	return d.exchangeControl(ctx, state.ID, socket, request)
}

func (d *Driver) exchangeControl(ctx context.Context, id, socket string, request controlRequest) (controlResponse, error) {
	if d == nil || ctx == nil {
		return controlResponse{}, fmt.Errorf("VM control exchange requires a driver and context")
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return controlResponse{}, err
	}
	sandboxDir := filepath.Join(store.root, "sandboxes", id)
	d.rotationMu.Lock()
	if err := d.completePendingControlTokenRotation(ctx, sandboxDir, socket); err != nil {
		d.rotationMu.Unlock()
		return controlResponse{}, err
	}
	token, err := readControlToken(sandboxDir)
	d.rotationMu.Unlock()
	if err != nil {
		return controlResponse{}, err
	}
	request.AuthToken = token
	response, err := exchangeControl(ctx, socket, request)
	if !isGuestControlUnauthorized(err) || ctx.Err() != nil {
		return response, err
	}
	d.rotationMu.Lock()
	defer d.rotationMu.Unlock()
	if err := d.completePendingControlTokenRotation(ctx, sandboxDir, socket); err != nil {
		return controlResponse{}, err
	}
	token, err = readControlToken(sandboxDir)
	if err != nil {
		return controlResponse{}, err
	}
	request.AuthToken = token
	return exchangeControl(ctx, socket, request)
}

func isGuestControlUnauthorized(err error) bool {
	return err != nil && strings.HasSuffix(err.Error(), "unauthorized guest control request")
}

func (d *Driver) rotateGuestControlToken(ctx context.Context, id, socket string) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("VM control token rotation requires a driver and context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return err
	}
	sandboxDir := filepath.Join(store.root, "sandboxes", id)
	d.rotationMu.Lock()
	defer d.rotationMu.Unlock()
	if err := d.completePendingControlTokenRotation(ctx, sandboxDir, socket); err != nil {
		return err
	}
	rotation, err := newControlTokenRotation()
	if err != nil {
		return err
	}
	if err := writePendingControlTokenRotation(sandboxDir, rotation); err != nil {
		return err
	}
	return d.completePendingControlTokenRotation(ctx, sandboxDir, socket)
}

func (d *Driver) completePendingControlTokenRotation(ctx context.Context, sandboxDir, socket string) error {
	rotation, pending, err := readPendingControlTokenRotation(sandboxDir)
	if err != nil || !pending {
		return err
	}
	current, err := readControlToken(sandboxDir)
	if err != nil {
		return err
	}
	if current == rotation.NextToken {
		return removePendingControlTokenRotation(sandboxDir)
	}
	_, err = exchangeControl(ctx, socket, controlRequest{
		Operation: "rotate-token", AuthToken: current,
		NextAuthToken: rotation.NextToken, RotationID: rotation.RotationID,
	})
	if err != nil {
		return fmt.Errorf("request guest control token rotation: %w", err)
	}
	if err := replaceControlToken(sandboxDir, rotation.NextToken); err != nil {
		return err
	}
	return removePendingControlTokenRotation(sandboxDir)
}

func (d *Driver) EnsureSSHDaemon(ctx context.Context, id core.ID) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("vm driver: EnsureSSHDaemon requires a driver and context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := d.Inspect(ctx, string(id)); err != nil {
		return err
	}
	d.mu.Lock()
	launchSpec, ok := d.launchSpecs[string(id)]
	d.mu.Unlock()
	if !ok || !launchSpec.EnableSSH {
		return driver.ErrSSHDisabled
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return err
	}
	state, err := store.load(string(id))
	if err != nil {
		return err
	}
	if state.Status != "running" {
		return fmt.Errorf("vm driver: sandbox %q is %s", state.Name, state.Status)
	}
	_, guestSocket, _ := workerSocketPaths(store.root, state.ID)
	_, err = d.exchangeControl(ctx, state.ID, guestSocket, controlRequest{Operation: "start-ssh"})
	if err != nil {
		return fmt.Errorf("start guest SSH relay: %w", err)
	}
	return nil
}

// WaitProxyReady implements driver.ProxyReadiness for the worker-owned
// per-VM policy proxy. Worker startup already waits for /healthz; this method
// lets Gateway use the same readiness contract as container sidecars.
func (d *Driver) WaitProxyReady(ctx context.Context, sandboxName string) error {
	if d == nil || ctx == nil {
		return fmt.Errorf("vm driver: WaitProxyReady requires a driver and context")
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		return err
	}
	states, err := store.list()
	if err != nil {
		return err
	}
	var state sandboxState
	for _, candidate := range states {
		if candidate.Name == sandboxName {
			state = candidate
			break
		}
	}
	if state.ID == "" {
		return fmt.Errorf("vm driver: sandbox %q not found while checking policy proxy", sandboxName)
	}
	d.mu.Lock()
	launchSpec, configured := d.launchSpecs[state.ID]
	d.mu.Unlock()
	if !configured || launchSpec.ProxyBin == "" {
		return fmt.Errorf("vm driver: sandbox %q has no policy proxy", sandboxName)
	}
	workerSocketPath, _, _ := workerSocketPaths(store.root, state.ID)
	socket := networkBrokerSocketPath(workerSocketPath, state.ID)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := checkNetworkBrokerHealth(ctx, socket); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for VM policy proxy: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (d *Driver) refreshState(store *stateStore, state sandboxState) sandboxState {
	if state.Status != "running" {
		return state
	}
	workerSocketPath, _, _ := workerSocketPaths(store.root, state.ID)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if response, err := workerControl(ctx, workerSocketPath, "status"); err == nil && response.Ready {
		return state
	}
	state.Status = "stopped"
	state.UpdatedAt = time.Now().UTC()
	_ = store.save(state)
	return state
}

func specVCPUs(cpu float64, defaultValue uint8) uint8 {
	if cpu <= 0 {
		return defaultValue
	}
	if cpu > 255 {
		return 255
	}
	value := uint8(cpu)
	if float64(value) < cpu {
		value++
	}
	return value
}

func specMemoryMiB(bytes int64, defaultValue uint32) uint32 {
	if bytes <= 0 {
		return defaultValue
	}
	const mebibyte = int64(1 << 20)
	value := bytes / mebibyte
	if bytes%mebibyte != 0 {
		value++
	}
	if value > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(value)
}
