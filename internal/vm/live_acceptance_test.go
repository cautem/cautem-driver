//go:build darwin || linux

package vm

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	core "github.com/cautem/quarshell-core"
	"github.com/cautem/quarshell-driver/driver"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/crypto/ssh"
)

// TestLiveMicroVMLifecycle exercises the full host-to-guest path. It is opt-in
// because it needs a native libkrun runtime and an ext4/overlayfs-capable guest.
func TestLiveMicroVMLifecycle(t *testing.T) {
	if os.Getenv("CAUTEM_VM_ACCEPTANCE") != "1" {
		t.Skip("set CAUTEM_VM_ACCEPTANCE=1 and configure the MicroVM runtime to run live acceptance")
	}
	rootfsTar := strings.TrimSpace(os.Getenv("CAUTEM_VM_TEST_ROOTFS_TAR"))
	if rootfsTar == "" {
		t.Fatal("CAUTEM_VM_TEST_ROOTFS_TAR is required for live MicroVM acceptance")
	}
	guestAgent := strings.TrimSpace(os.Getenv("CAUTEM_VM_TEST_GUEST_AGENT"))
	if guestAgent == "" {
		t.Fatal("CAUTEM_VM_TEST_GUEST_AGENT is required for live MicroVM acceptance")
	}
	initBin := requireLiveAsset(t, "CAUTEM_VM_TEST_INIT_BIN")
	supervisorBin := requireLiveAsset(t, "CAUTEM_VM_TEST_SUPERVISOR_BIN")
	sshBin := requireLiveAsset(t, "CAUTEM_VM_TEST_SSH_BIN")
	securityProbe := requireLiveAsset(t, "CAUTEM_VM_TEST_SECURITY_PROBE")
	runtimeDir := strings.TrimSpace(os.Getenv("CAUTEM_VM_RUNTIME_DIR"))
	if runtimeDir == "" {
		t.Fatal("CAUTEM_VM_RUNTIME_DIR is required for live MicroVM acceptance")
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("live MicroVM acceptance is unsupported on %s", runtime.GOOS)
	}

	formatter := strings.TrimSpace(os.Getenv("CAUTEM_VM_TEST_E2FS_FORMATTER"))
	if formatter == "" {
		var err error
		formatter, err = resolveExt4Formatter()
		if err != nil {
			t.Fatal(err)
		}
	}
	stateDir := filepath.Join(t.TempDir(), "state")
	host := HostConfig{
		RuntimeDir: runtimeDir, StateDir: stateDir, RootfsTarDir: filepath.Dir(filepath.Dir(rootfsTar)),
		KVMDevice:     strings.TrimSpace(os.Getenv("CAUTEM_KVM_DEVICE")),
		FormatterPath: formatter, OverlaySizeBytes: 64 << 20,
		GuestAgentPath: guestAgent, WorkerPath: strings.TrimSpace(os.Getenv("CAUTEM_VM_WORKER")),
		VCPUs: 2, MemoryMiB: 1024,
	}
	host = normalizeHostConfig(host)
	if _, err := ProbeHost(host); err != nil {
		t.Fatalf("probe live MicroVM host: %v", err)
	}
	driverConfig, err := json.Marshal(SandboxDriverConfig{RootfsTarPath: rootfsTar})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	proxyBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve live policy proxy fixture: %v", err)
	}
	policyDir := filepath.Join(t.TempDir(), "policy")
	if err := os.Mkdir(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(policyDir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("# cautem-policy-revision: 1\nversion: 1\nnetwork_policies: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	controlEventsPath := filepath.Join(policyDir, "supervisor-events.log")
	brokerPIDPath := filepath.Join(policyDir, "broker.pid")
	policyAckPath := filepath.Join(policyDir, "policy-ack")
	brokerSpec := driver.Spec{
		ProxyBin: proxyBinary, PolicyPath: policyPath,
		ProxyEnv: []string{
			"CAUTEM_VM_TEST_POLICY_PROXY_HELPER=1",
			"CAUTEM_VM_TEST_BROKER_PID_FILE=" + brokerPIDPath,
			"CAUTEM_VM_TEST_POLICY_ACK_FILE=" + policyAckPath,
			"CAUTEM_VM_TEST_CONTROL_EVENTS=" + controlEventsPath,
		},
		InitBin: initBin, SupervisorBin: supervisorBin, EnableSSH: true, SSHBin: sshBin,
	}
	first := NewWithHostConfig(host)
	handle, err := first.Create(ctx, driver.Spec{
		Name: "live-microvm-acceptance", Image: "alpine:3.22",
		DriverConfigJSON:         string(driverConfig),
		Command:                  []string{"/bin/sh", "-c", "if [ ! -e /workspace/.restart-once ]; then touch /workspace/.restart-once; exit 7; fi; while :; do sleep 1; done"},
		MainProcessRestartPolicy: "on-failure",
		ProxyBin:                 brokerSpec.ProxyBin, PolicyPath: brokerSpec.PolicyPath, ProxyEnv: brokerSpec.ProxyEnv,
		InitBin: brokerSpec.InitBin, SupervisorBin: brokerSpec.SupervisorBin,
		EnableSSH: brokerSpec.EnableSSH, SSHBin: brokerSpec.SSHBin,
	})
	if err != nil {
		t.Fatalf("create live MicroVM: %v", err)
	}
	defer func() { _ = NewWithHostConfig(host).Delete(context.Background(), handle.ID) }()
	if err := first.Start(ctx, handle.ID); err != nil {
		var logs bytes.Buffer
		_ = first.Logs(context.Background(), handle.ID, false, &logs)
		store, _ := openStateStore(host.StateDir)
		_, _, consolePath := workerSocketPaths(store.root, string(handle.ID))
		workerLog, _ := os.ReadFile(consolePath + ".worker")
		t.Fatalf("start live MicroVM: %v; console: %s; worker: %s", err, logs.String(), workerLog)
	}
	assertLiveGuestResources(t, ctx, first, handle.ID, host.VCPUs, host.MemoryMiB)
	assertLiveHostLoopbackIsolation(t, ctx, first, handle.ID, "tcp4", "127.0.0.1")
	assertLiveHostLoopbackIsolation(t, ctx, first, handle.ID, "tcp6", "::1")
	assertLiveGuestNetworkBoundaries(t, ctx, first, handle.ID, securityProbe)
	assertLiveNetworkBroker(t, ctx, first, handle.ID, "policy-probe.invalid")
	assertLivePolicyRevisionUpdate(t, ctx, first, handle.ID, policyPath, policyAckPath)
	assertLiveGuestExec(t, ctx, first, handle.ID)
	assertLiveGuestCopy(t, ctx, first, handle.ID)
	assertLiveSupervisorReady(t, ctx, controlEventsPath)
	assertLiveSupervisorRestarted(t, ctx, controlEventsPath)
	if err := first.EnsureSSHDaemon(ctx, handle.ID); err != nil {
		t.Fatalf("ensure live guest SSH daemon: %v", err)
	}
	assertLiveSSHRelay(t, ctx, first, handle.ID)
	if err := first.WaitProxyReady(ctx, handle.Name); err != nil {
		t.Fatalf("wait for live VM policy proxy readiness: %v", err)
	}
	if info, err := first.Inspect(ctx, handle.Name); err != nil || info.Status != "running" {
		t.Fatalf("inspect live MicroVM: info=%+v err=%v", info, err)
	}
	if infos, err := first.List(ctx); err != nil || len(infos) != 1 || infos[0].ID != handle.ID {
		t.Fatalf("list live MicroVM: infos=%+v err=%v", infos, err)
	}
	if err := first.Logs(ctx, handle.ID, false, &bytes.Buffer{}); err != nil {
		t.Fatalf("read live MicroVM logs: %v", err)
	}

	// Recover the running worker through a fresh driver instance, as happens
	// after a Gateway/compute process restart.
	recovered := NewWithHostConfig(host)
	if err := recovered.RestoreLaunchSpec(ctx, handle.ID, driver.Spec{
		Name: handle.Name, Command: []string{"/bin/sh", "-c", "while :; do sleep 1; done"},
		MainProcessRestartPolicy: "on-failure", ProxyBin: brokerSpec.ProxyBin, PolicyPath: brokerSpec.PolicyPath,
		ProxyEnv: brokerSpec.ProxyEnv, InitBin: brokerSpec.InitBin, SupervisorBin: brokerSpec.SupervisorBin,
		EnableSSH: brokerSpec.EnableSSH, SSHBin: brokerSpec.SSHBin,
	}); err != nil {
		t.Fatalf("restore workload spec for live worker adoption: %v", err)
	}
	if err := recovered.Start(ctx, handle.ID); err != nil {
		t.Fatalf("recover live MicroVM worker: %v", err)
	}
	assertLiveGuestExec(t, ctx, recovered, handle.ID)
	assertLiveGuestCopy(t, ctx, recovered, handle.ID)
	assertLiveSSHRelay(t, ctx, recovered, handle.ID)
	if err := recovered.Stop(ctx, handle.ID); err != nil {
		t.Fatalf("stop live MicroVM: %v", err)
	}
	if err := os.Remove(controlEventsPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("reset supervisor acceptance events before restart: %v", err)
	}
	if err := recovered.RestoreLaunchSpec(ctx, handle.ID, driver.Spec{
		Name: handle.Name, Command: []string{"/bin/sh", "-c", "while :; do sleep 1; done"}, MainProcessRestartPolicy: "on-failure",
		ProxyBin: brokerSpec.ProxyBin, PolicyPath: brokerSpec.PolicyPath, ProxyEnv: brokerSpec.ProxyEnv,
		InitBin: brokerSpec.InitBin, SupervisorBin: brokerSpec.SupervisorBin,
		EnableSSH: brokerSpec.EnableSSH, SSHBin: brokerSpec.SSHBin,
	}); err != nil {
		t.Fatalf("restore stopped workload spec: %v", err)
	}
	if err := recovered.Start(ctx, handle.ID); err != nil {
		var logs bytes.Buffer
		_ = recovered.Logs(context.Background(), handle.ID, false, &logs)
		store, _ := openStateStore(host.StateDir)
		_, _, consolePath := workerSocketPaths(store.root, string(handle.ID))
		workerLog, _ := os.ReadFile(consolePath + ".worker")
		t.Fatalf("restart live MicroVM: %v; console: %s; worker: %s", err, logs.String(), workerLog)
	}
	assertLiveNetworkBroker(t, ctx, recovered, handle.ID, "blocked-probe.invalid")
	assertLiveGuestExec(t, ctx, recovered, handle.ID)
	assertLiveGuestCopy(t, ctx, recovered, handle.ID)
	assertLiveSupervisorReady(t, ctx, controlEventsPath)
	assertLiveSSHRelay(t, ctx, recovered, handle.ID)

	// Kill only the broker while the guest is live. The worker watcher must
	// terminate the VM process group and persist stopped state before recovery.
	brokerPID := liveTestBrokerPID(t, brokerPIDPath)
	brokerProcess, err := os.FindProcess(brokerPID)
	if err != nil {
		t.Fatalf("find live policy broker process %d: %v", brokerPID, err)
	}
	if err := brokerProcess.Kill(); err != nil {
		t.Fatalf("kill live policy broker process %d: %v", brokerPID, err)
	}
	waitForLiveVMStoppedState(t, ctx, host.StateDir, string(handle.ID))
	t.Logf("live broker loss stopped worker group and persisted stopped state (broker pid %d)", brokerPID)

	active := NewWithHostConfig(host)
	if err := active.RestoreLaunchSpec(ctx, handle.ID, driver.Spec{
		Name: handle.Name, Command: []string{"/bin/sh", "-c", "while :; do sleep 1; done"}, MainProcessRestartPolicy: "on-failure",
		ProxyBin: brokerSpec.ProxyBin, PolicyPath: brokerSpec.PolicyPath, ProxyEnv: brokerSpec.ProxyEnv,
		InitBin: initBin, SupervisorBin: supervisorBin, EnableSSH: true, SSHBin: sshBin,
	}); err != nil {
		t.Fatalf("restore workload after live broker loss: %v", err)
	}
	if err := os.Remove(brokerPIDPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("remove stale broker PID before live broker recovery: %v", err)
	}
	if err := active.Start(ctx, handle.ID); err != nil {
		t.Fatalf("restart MicroVM after live broker loss: %v", err)
	}
	_ = liveTestBrokerPID(t, brokerPIDPath)
	assertLiveNetworkBroker(t, ctx, active, handle.ID, "blocked-probe.invalid")
	assertLiveGuestExec(t, ctx, active, handle.ID)

	// Simulate a host worker crash, including its broker/relay child processes.
	// The next driver instance must discard stale sockets and relaunch from the
	// durable rootfs/overlay state after the control plane restores its spec.
	active.mu.Lock()
	worker := active.workers[string(handle.ID)]
	active.mu.Unlock()
	if worker == nil || worker.Process == nil {
		t.Fatal("running MicroVM has no worker process to crash for recovery acceptance")
	}
	if err := killVMWorkerProcessGroupForAcceptance(worker.Process.Pid); err != nil {
		t.Fatalf("kill live VM worker process group: %v", err)
	}
	waitForLiveVMStoppedState(t, ctx, host.StateDir, string(handle.ID))

	afterCrash := NewWithHostConfig(host)
	if err := afterCrash.RestoreLaunchSpec(ctx, handle.ID, driver.Spec{
		Name: handle.Name, Command: []string{"/bin/sh", "-c", "while :; do sleep 1; done"}, MainProcessRestartPolicy: "on-failure",
		ProxyBin: brokerSpec.ProxyBin, PolicyPath: brokerSpec.PolicyPath, ProxyEnv: brokerSpec.ProxyEnv,
		InitBin: initBin, SupervisorBin: supervisorBin, EnableSSH: true, SSHBin: sshBin,
	}); err != nil {
		t.Fatalf("restore workload after worker crash: %v", err)
	}
	if err := afterCrash.Start(ctx, handle.ID); err != nil {
		t.Fatalf("restart MicroVM after worker crash: %v", err)
	}
	assertLiveGuestExec(t, ctx, afterCrash, handle.ID)
	assertLiveGuestCopy(t, ctx, afterCrash, handle.ID)
	assertLiveNetworkBroker(t, ctx, afterCrash, handle.ID, "blocked-probe.invalid")
	assertLiveSSHRelay(t, ctx, afterCrash, handle.ID)
	if err := afterCrash.Delete(ctx, handle.ID); err != nil {
		t.Fatalf("delete live MicroVM: %v", err)
	}
	assertLiveOCIImageRuntime(t, ctx, host, rootfsTar)
}

func assertLiveOCIImageRuntime(t *testing.T, ctx context.Context, host HostConfig, rootfsTar string) {
	t.Helper()
	registry := newTestOCIRegistry(t)
	const registryUsername = "live-acceptance"
	const registryPassword = "test-only-registry-secret"
	registry.requireBasicAuth(registryUsername, registryPassword)
	dockerConfigDir := filepath.Join(t.TempDir(), "docker-config")
	if err := os.Mkdir(dockerConfigDir, 0o700); err != nil {
		t.Fatalf("create isolated Docker credential config: %v", err)
	}
	registryHost := strings.TrimPrefix(registry.server.URL, "http://")
	helperMarker := configureTestDockerCredentialHelper(t, registryHost, registryUsername, registryPassword)
	dockerConfig, err := json.Marshal(map[string]any{
		"credHelpers": map[string]string{registryHost: "test"},
	})
	if err != nil {
		t.Fatalf("marshal isolated Docker credential config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dockerConfigDir, "config.json"), dockerConfig, 0o600); err != nil {
		t.Fatalf("write isolated Docker credential config: %v", err)
	}
	t.Setenv("DOCKER_CONFIG", dockerConfigDir)
	platform, err := vmOCIPlatform()
	if err != nil {
		t.Fatal(err)
	}
	baseLayer := testOCILayerFromArchive(t, rootfsTar)
	appLayer := testOCILayer(t, []rootfsTarEntry{
		{name: "opt", kind: tar.TypeDir, mode: 0o755},
		{name: "opt/app", kind: tar.TypeDir, mode: 0o755},
	})
	workload := "printf '%s|%s|%s' \"$(pwd)\" \"$(id -u)\" \"$OCI_LIVE_EXPECTED\" > /tmp/oci-live-config; while :; do sleep 1; done"
	registry.publishImageIndexWithConfig(t, []testOCILayerBlob{baseLayer, appLayer}, platform, v1.Config{
		Entrypoint: []string{"/bin/sh", "-c"}, Cmd: []string{workload},
		Env: []string{"OCI_LIVE_EXPECTED=from-pinned-image"}, WorkingDir: "/opt/app", User: "1000:1000",
	})
	imageRef := registryHost + "/agent:latest"
	sandbox := NewWithHostConfig(host)
	sandbox.ociNameOptions = []name.Option{name.Insecure}
	handle, err := sandbox.Create(ctx, driver.Spec{Name: "live-oci-image-acceptance", Image: imageRef})
	if err != nil {
		t.Fatalf("create live OCI-backed MicroVM: %v", err)
	}
	helperCalls, err := os.ReadFile(helperMarker)
	if err != nil || !strings.Contains(string(helperCalls), registryHost) {
		t.Fatalf("live OCI credential helper was not called for %q: calls=%q err=%v", registryHost, helperCalls, err)
	}
	store, err := openStateStore(host.StateDir)
	if err != nil {
		t.Fatalf("open live OCI state: %v", err)
	}
	state, err := store.load(string(handle.ID))
	if err != nil || state.RootfsSourceType != "oci" || state.RootfsSourceDigest == "" {
		t.Fatalf("live OCI source identity = %+v err=%v", state, err)
	}
	durableState, err := json.Marshal(state)
	if err != nil || bytes.Contains(durableState, []byte(registryPassword)) || bytes.Contains(durableState, []byte("from-pinned-image")) {
		t.Fatalf("live OCI durable state contains registry credentials or image environment: state=%s err=%v", durableState, err)
	}
	t.Log("live OCI private registry authentication succeeded through a Docker credential helper; credentials and image env are absent from durable state")
	t.Logf("live OCI rootfs imported for %s from platform manifest %s", state.Platform, state.RootfsSourceDigest)
	defer func() { _ = NewWithHostConfig(host).Delete(context.Background(), handle.ID) }()
	if err := sandbox.Start(ctx, handle.ID); err != nil {
		t.Fatalf("start live OCI-backed MicroVM: %v", err)
	}
	assertLiveOCIWorkloadConfig(t, ctx, sandbox, handle.ID, "from-pinned-image")
	if err := sandbox.Stop(ctx, handle.ID); err != nil {
		t.Fatalf("stop live OCI-backed MicroVM: %v", err)
	}
	registry.publishImageIndexWithConfig(t, []testOCILayerBlob{baseLayer, appLayer}, platform, v1.Config{
		Entrypoint: []string{"/bin/sh", "-c"}, Cmd: []string{workload},
		Env: []string{"OCI_LIVE_EXPECTED=from-moved-tag"}, WorkingDir: "/opt/app", User: "1000:1000",
	})
	if err := sandbox.RestoreLaunchSpec(ctx, handle.ID, driver.Spec{Name: handle.Name}); err != nil {
		t.Fatalf("restore live OCI workload from pinned manifest digest: %v", err)
	}
	if err := sandbox.Start(ctx, handle.ID); err != nil {
		t.Fatalf("restart live OCI-backed MicroVM after tag move: %v", err)
	}
	assertLiveOCIWorkloadConfig(t, ctx, sandbox, handle.ID, "from-pinned-image")
	t.Logf("live OCI recovery used pinned manifest %s after the image tag moved", state.RootfsSourceDigest)
	if err := sandbox.Delete(ctx, handle.ID); err != nil {
		t.Fatalf("delete live OCI-backed MicroVM: %v", err)
	}
}

func assertLiveOCIWorkloadConfig(t *testing.T, ctx context.Context, sandbox *Driver, id core.ID, expectedEnv string) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		result, err := sandbox.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/cat", "/tmp/oci-live-config"}, NoLoginShell: true})
		if err == nil && result.ExitCode == 0 {
			want := "/opt/app|1000|" + expectedEnv
			if got := string(result.Stdout); got != want {
				t.Fatalf("live OCI workload config = %q, want %q", got, want)
			}
			terminal, err := sandbox.Exec(ctx, id, driver.ExecRequest{
				Argv:         []string{"/bin/sh", "-c", `printf '%s|%s' "$PWD" "$OCI_LIVE_EXPECTED"`},
				NoLoginShell: true, TTY: true,
			})
			if err != nil || terminal.ExitCode != 0 || string(terminal.Stdout) != "/opt/app|"+expectedEnv {
				t.Fatalf("live OCI TTY exec config = exit %d stdout %q err=%v", terminal.ExitCode, terminal.Stdout, err)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for live OCI workload config: %v", ctx.Err())
		case <-deadline.C:
			t.Fatalf("live OCI workload did not publish config marker: result=%+v err=%v", result, err)
		case <-ticker.C:
		}
	}
}

func assertLiveHostLoopbackIsolation(t *testing.T, ctx context.Context, d *Driver, id core.ID, network, host string) {
	t.Helper()
	listener, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("listen on host %s loopback for isolation check: %v", network, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan struct{}, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		accepted <- struct{}{}
		const body = "host-loopback-reached\n"
		_, _ = fmt.Fprintf(connection, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	}()
	endpoint := "http://" + net.JoinHostPort(host, fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port))
	result, err := d.Exec(ctx, id, driver.ExecRequest{
		Argv: []string{"/bin/sh", "-c", `wget -T 3 -q -O - "$1"`, "vm-loopback-isolation", endpoint},
		Env:  []string{"NO_PROXY=*", "no_proxy=*"},
	})
	if err != nil {
		t.Fatalf("probe host %s loopback from guest: %v", network, err)
	}
	if result.ExitCode == 0 || strings.Contains(string(result.Stdout), "host-loopback-reached") {
		t.Fatalf("guest reached host %s loopback: exit=%d stdout=%q stderr=%q", network, result.ExitCode, result.Stdout, result.Stderr)
	}
	select {
	case <-accepted:
		t.Fatalf("guest connected to host %s loopback listener", network)
	default:
	}
}

func assertLiveGuestNetworkBoundaries(t *testing.T, ctx context.Context, d *Driver, id core.ID, probePath string) {
	t.Helper()
	const guestProbePath = "/workspace/.quarshell-vm-security-probe"
	if err := d.CopyTo(ctx, id, probePath, guestProbePath); err != nil {
		t.Fatalf("copy guest network security probe: %v", err)
	}
	if _, err := d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/chmod", "0700", guestProbePath}}); err != nil {
		t.Fatalf("make guest network security probe executable: %v", err)
	}

	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := d.Exec(probeCtx, id, driver.ExecRequest{Argv: []string{guestProbePath, "raw"}})
	if err != nil {
		t.Fatalf("run live raw-socket egress probe: %v", err)
	}
	if raw.ExitCode != 0 || !strings.Contains(string(raw.Stdout), "raw-egress-denied:") {
		t.Fatalf("live raw-socket egress probe = exit %d stdout %q stderr %q", raw.ExitCode, raw.Stdout, raw.Stderr)
	}
	t.Logf("live raw ICMP probe denied egress: %s", strings.TrimSpace(string(raw.Stdout)))

	vsock, err := d.Exec(probeCtx, id, driver.ExecRequest{Argv: []string{guestProbePath, "vsock", "5504"}})
	if err != nil {
		t.Fatalf("run live unmapped-vsock probe: %v", err)
	}
	if vsock.ExitCode != 0 || !strings.Contains(string(vsock.Stdout), "unmapped-vsock-denied: port=5504") {
		t.Fatalf("live unmapped-vsock probe = exit %d stdout %q stderr %q", vsock.ExitCode, vsock.Stdout, vsock.Stderr)
	}
	t.Logf("live guest-to-host vsock probe denied unmapped port: %s", strings.TrimSpace(string(vsock.Stdout)))
}

func assertLiveGuestResources(t *testing.T, ctx context.Context, d *Driver, id core.ID, wantCPUs uint8, wantMemoryMiB uint32) {
	t.Helper()
	result, err := d.Exec(ctx, id, driver.ExecRequest{Argv: []string{
		"/bin/sh", "-c",
		`awk '/^processor[[:space:]]*:/ {cpus++} END {printf "%d ", cpus+0}' /proc/cpuinfo; awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo`,
	}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("read live guest CPU/memory limits: result=%+v err=%v", result, err)
	}
	values := strings.Fields(string(result.Stdout))
	if len(values) != 2 {
		t.Fatalf("live guest resource probe output = %q, want CPU count and memory KiB", result.Stdout)
	}
	cpus, cpuErr := strconv.ParseUint(values[0], 10, 8)
	memoryKiB, memoryErr := strconv.ParseUint(values[1], 10, 32)
	if cpuErr != nil || memoryErr != nil {
		t.Fatalf("parse live guest resource probe output %q: cpu error=%v memory error=%v", result.Stdout, cpuErr, memoryErr)
	}
	wantMinMemoryKiB := uint64(wantMemoryMiB) * 1024 * 3 / 4
	wantMaxMemoryKiB := uint64(wantMemoryMiB) * 1024
	if uint8(cpus) != wantCPUs || memoryKiB < wantMinMemoryKiB || memoryKiB > wantMaxMemoryKiB {
		t.Fatalf("live guest resources = %d vCPU, %d MiB visible memory; want %d vCPU and between %d and %d MiB", cpus, memoryKiB/1024, wantCPUs, wantMinMemoryKiB/1024, wantMaxMemoryKiB/1024)
	}
	t.Logf("guest sees %d vCPU and %d MiB memory (configured %d MiB)", cpus, memoryKiB/1024, wantMemoryMiB)
}

func waitForLiveVMStoppedState(t *testing.T, ctx context.Context, stateDir, id string) {
	t.Helper()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		store, err := openStateStore(stateDir)
		if err != nil {
			t.Fatalf("open state while waiting for crashed worker: %v", err)
		}
		state, err := store.load(id)
		if err != nil {
			t.Fatalf("read state while waiting for crashed worker: %v", err)
		}
		if state.Status == "stopped" {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("worker crash did not update durable state: status=%q: %v", state.Status, ctx.Err())
		case <-ticker.C:
		}
	}
}

func liveTestBrokerPID(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read live policy broker PID: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 || pid == os.Getpid() {
		t.Fatalf("invalid live policy broker PID %q: %v", data, err)
	}
	return pid
}

func assertLiveSupervisorRestarted(t *testing.T, ctx context.Context, eventPath string) {
	t.Helper()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()
	for {
		data, err := os.ReadFile(eventPath)
		if err == nil && strings.Count(string(data), "begin\n") >= 2 {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("live supervisor did not restart on failure: events=%q: %v", data, ctx.Err())
		case <-timeout.C:
			t.Fatalf("live supervisor did not start a second process instance: events=%q", data)
		case <-ticker.C:
		}
	}
}

func requireLiveAsset(t *testing.T, variable string) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv(variable))
	if path == "" {
		t.Fatalf("%s is required for live MicroVM supervisor/SSH acceptance", variable)
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("%s must name an executable regular file: %q", variable, path)
	}
	return path
}

func assertLiveSupervisorReady(t *testing.T, ctx context.Context, eventPath string) {
	t.Helper()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()
	for {
		data, err := os.ReadFile(eventPath)
		if err == nil && strings.Contains(string(data), "begin") && strings.Contains(string(data), "process_event") {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("live supervisor did not complete its begin handshake: events=%q: %v", data, ctx.Err())
		case <-timeout.C:
			t.Fatalf("live supervisor did not complete its begin handshake: events=%q", data)
		case <-ticker.C:
		}
	}
}

func assertLiveSSHRelay(t *testing.T, ctx context.Context, d *Driver, id core.ID) {
	t.Helper()
	store, err := openStateStore(d.host.StateDir)
	if err != nil {
		t.Fatalf("open VM state for SSH acceptance: %v", err)
	}
	workerSocket, _, _ := workerSocketPaths(store.root, string(id))
	path := sshRelaySocketPath(workerSocket, string(id))
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", path)
	if err != nil {
		t.Fatalf("connect to live VM SSH relay socket: %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
	clientConfig := &ssh.ClientConfig{
		User: "acceptance", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second,
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, "vm-acceptance", clientConfig)
	if err != nil {
		t.Fatalf("complete SSH handshake through live vsock relay: %v", err)
	}
	client := ssh.NewClient(clientConnection, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("open SSH session through live vsock relay: %v", err)
	}
	defer session.Close()
	output, err := session.Output("printf 'ssh-live-ok\\n'")
	if err != nil || !strings.Contains(string(output), "ssh-live-ok") {
		t.Fatalf("run command through live SSH relay: output=%q err=%v", output, err)
	}
}

func assertLiveNetworkBroker(t *testing.T, ctx context.Context, sandbox *Driver, id core.ID, host string) {
	t.Helper()
	result, err := sandbox.Exec(ctx, id, driver.ExecRequest{
		Argv: []string{"/bin/sh", "-c", "wget -q -O - http://" + host + " 2>&1"},
		Env:  []string{"HTTP_PROXY=http://127.0.0.1:1", "NO_PROXY=*"},
	})
	if err != nil {
		t.Fatalf("request through live VM policy broker: %v", err)
	}
	response := string(result.Stdout) + string(result.Stderr)
	if result.ExitCode == 0 || !strings.Contains(response, "403") {
		t.Fatalf("live VM policy broker did not deny %s: exit=%d stdout=%q stderr=%q", host, result.ExitCode, result.Stdout, result.Stderr)
	}
}

func assertLivePolicyRevisionUpdate(t *testing.T, ctx context.Context, sandbox *Driver, id core.ID, policyPath, ackPath string) {
	t.Helper()
	policyDocument := []byte("# cautem-policy-revision: 2\nversion: 1\nnetwork_policies:\n  live-acceptance:\n    endpoints:\n      - host: policy-probe.invalid\n        port: 80\n")
	updatedPath := policyPath + ".next"
	if err := os.WriteFile(updatedPath, policyDocument, 0o600); err != nil {
		t.Fatalf("write next live policy revision: %v", err)
	}
	if err := os.Rename(updatedPath, policyPath); err != nil {
		t.Fatalf("atomically publish live policy revision: %v", err)
	}
	waitForLivePolicyAck(t, ctx, ackPath, 2)
	t.Log("live policy broker acknowledged revision 2")

	allowed, err := sandbox.Exec(ctx, id, driver.ExecRequest{Argv: []string{
		"/bin/sh", "-c", `wget -T 3 -q -O - "$1" 2>&1`, "vm-policy-allow-probe", "http://policy-probe.invalid",
	}})
	if err != nil {
		t.Fatalf("request through newly allowed live policy endpoint: %v", err)
	}
	allowedOutput := string(allowed.Stdout) + string(allowed.Stderr)
	if allowed.ExitCode == 0 || strings.Contains(allowedOutput, "403") {
		t.Fatalf("revision 2 did not allow policy-probe.invalid past policy evaluation: exit=%d stdout=%q stderr=%q", allowed.ExitCode, allowed.Stdout, allowed.Stderr)
	}
	t.Logf("revision 2 allow decision passed policy evaluation: %s", strings.TrimSpace(allowedOutput))
	assertLiveNetworkBroker(t, ctx, sandbox, id, "blocked-probe.invalid")
}

func waitForLivePolicyAck(t *testing.T, ctx context.Context, ackPath string, wantRevision int) {
	t.Helper()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(ackPath)
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) >= 2 {
				revision, parseErr := strconv.Atoi(fields[0])
				if parseErr == nil && revision == wantRevision {
					if fields[1] != "loaded" {
						t.Fatalf("live policy revision %d was not loaded: %q", wantRevision, data)
					}
					return
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("live policy broker did not acknowledge revision %d: last ack=%q: %v", wantRevision, data, ctx.Err())
		case <-ticker.C:
		}
	}
}

func assertLiveGuestCopy(t *testing.T, ctx context.Context, d *Driver, id core.ID) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "upload.txt")
	if err := os.WriteFile(source, []byte("microvm-copy-roundtrip"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := d.CopyTo(ctx, id, source, "/workspace/upload.txt"); err != nil {
		t.Fatalf("copy file into live guest: %v", err)
	}
	destination := filepath.Join(root, "download.txt")
	if err := d.CopyFrom(ctx, id, "/workspace/upload.txt", destination); err != nil {
		t.Fatalf("copy file from live guest: %v", err)
	}
	data, err := os.ReadFile(destination)
	if err != nil || string(data) != "microvm-copy-roundtrip" {
		t.Fatalf("live guest copy roundtrip = %q err=%v", data, err)
	}
}

func assertLiveGuestExec(t *testing.T, ctx context.Context, d *Driver, id core.ID) {
	t.Helper()
	profile := filepath.Join(t.TempDir(), "profile")
	if err := os.WriteFile(profile, []byte("export QUARSHELL_VM_LOGIN_PROFILE=loaded\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.CopyTo(ctx, id, profile, "/workspace/.profile"); err != nil {
		t.Fatalf("install live guest login profile: %v", err)
	}
	result, err := d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", `printf '%s' "${QUARSHELL_VM_LOGIN_PROFILE-unset}"`}})
	if err != nil {
		t.Fatalf("execute in live guest: %v", err)
	}
	if result.ExitCode != 0 || string(result.Stdout) != "loaded" {
		t.Fatalf("live guest exec result = exit %d stdout %q stderr %q", result.ExitCode, result.Stdout, result.Stderr)
	}
	result, err = d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", `printf '%s' "${QUARSHELL_VM_LOGIN_PROFILE-unset}"`}, NoLoginShell: true})
	if err != nil || result.ExitCode != 0 || string(result.Stdout) != "unset" {
		t.Fatalf("live guest no-login-shell result = exit %d stdout %q stderr %q err=%v", result.ExitCode, result.Stdout, result.Stderr, err)
	}
	result, err = d.Exec(ctx, id, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", "printf 'guest-live-ok\\n'"}})
	if err != nil || result.ExitCode != 0 || !bytes.Contains(result.Stdout, []byte("guest-live-ok")) {
		t.Fatalf("live guest command result = exit %d stdout %q stderr %q err=%v", result.ExitCode, result.Stdout, result.Stderr, err)
	}
	assertLiveExecTerminal(t, ctx, d, id)
}

func assertLiveExecTerminal(t *testing.T, ctx context.Context, d *Driver, id core.ID) {
	t.Helper()
	session, err := d.OpenExecTerminal(ctx, id, driver.ExecTerminalRequest{
		Argv:         []string{"/bin/sh", "-c", "stty size; IFS= read -r line; stty size"},
		NoLoginShell: true, Columns: 80, Rows: 24,
	})
	if err != nil {
		t.Fatalf("open live guest exec terminal: %v", err)
	}
	defer session.Close()
	terminalOutput := bufio.NewReader(session)
	var initialOutput strings.Builder
	for !strings.Contains(initialOutput.String(), "24 80") {
		line, err := terminalOutput.ReadString('\n')
		initialOutput.WriteString(line)
		if err != nil {
			t.Fatalf("read live guest initial terminal size from %q: %v", initialOutput.String(), err)
		}
		if initialOutput.Len() > 4096 {
			t.Fatalf("live guest did not report initial terminal dimensions: %q", initialOutput.String())
		}
	}
	if err := session.Resize(ctx, 101, 41); err != nil {
		t.Fatalf("resize live guest exec terminal: %v", err)
	}
	if _, err := io.WriteString(session, "resize-check\n"); err != nil {
		t.Fatalf("write live guest exec terminal input: %v", err)
	}
	output, err := io.ReadAll(terminalOutput)
	if err != nil {
		t.Fatalf("read live guest exec terminal output: %v", err)
	}
	if exitCode, err := session.Wait(ctx); err != nil || exitCode != 0 {
		t.Fatalf("wait for live guest exec terminal: exit %d err=%v", exitCode, err)
	}
	if !bytes.Contains(output, []byte("41 101")) {
		t.Fatalf("live guest terminal did not apply initial and resized dimensions: %q", output)
	}

	result, err := d.Exec(ctx, id, driver.ExecRequest{
		Argv:         []string{"/bin/sh", "-c", "if [ -t 0 ] && [ -t 1 ]; then printf 'tty-exec-ok'; else exit 33; fi"},
		NoLoginShell: true, TTY: true,
	})
	if err != nil || result.ExitCode != 0 || !bytes.Contains(result.Stdout, []byte("tty-exec-ok")) {
		t.Fatalf("live guest TTY exec result = exit %d stdout %q err=%v", result.ExitCode, result.Stdout, err)
	}
	assertLivePTYInterrupt(t, ctx, d, id)
}

func assertLivePTYInterrupt(t *testing.T, ctx context.Context, d *Driver, id core.ID) {
	t.Helper()
	session, err := d.OpenExecTerminal(ctx, id, driver.ExecTerminalRequest{
		Argv:         []string{"/bin/sh", "-c", "trap 'printf interrupted; exit 42' INT; printf 'ready\\n'; while :; do sleep 1; done"},
		NoLoginShell: true, Columns: 80, Rows: 24,
	})
	if err != nil {
		t.Fatalf("open live guest interrupt terminal: %v", err)
	}
	defer session.Close()
	terminalOutput := bufio.NewReader(session)
	var readyOutput strings.Builder
	for !strings.Contains(readyOutput.String(), "ready") {
		line, err := terminalOutput.ReadString('\n')
		readyOutput.WriteString(line)
		if err != nil {
			t.Fatalf("read live guest interrupt readiness from %q: %v", readyOutput.String(), err)
		}
		if readyOutput.Len() > 4096 {
			t.Fatalf("live guest interrupt command did not become ready: %q", readyOutput.String())
		}
	}
	if _, err := session.Write([]byte{3}); err != nil {
		t.Fatalf("send live guest terminal interrupt: %v", err)
	}
	output, err := io.ReadAll(terminalOutput)
	if err != nil {
		t.Fatalf("read live guest output after terminal interrupt: %v", err)
	}
	exitCode, err := session.Wait(ctx)
	if err != nil || exitCode != 42 || !bytes.Contains(output, []byte("interrupted")) {
		t.Fatalf("live guest terminal interrupt = exit %d output %q err=%v; want trap exit 42", exitCode, output, err)
	}
}
