//go:build darwin || linux

package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	core "github.com/cautem/cautem-core"
	"github.com/cautem/cautem-driver/driver"
)

func TestVMStartExecCopyLogsStopDeleteLifecycle(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "vm-life-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	stateRoot := filepath.Join(root, "state")
	store, err := openStateStore(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.create("lifecycle", "fixture:latest", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	imageDir := filepath.Join(stateRoot, "images")
	if err := os.MkdirAll(imageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	state.Rootfs = filepath.Join(imageDir, "fixture.ext4")
	if err := os.WriteFile(state.Rootfs, []byte("fake immutable image"), 0o400); err != nil {
		t.Fatal(err)
	}
	assetDir := filepath.Join(stateRoot, "sandboxes", state.ID)
	if err := os.MkdirAll(assetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := createControlToken(assetDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(assetDir, "overlay.ext4"), []byte("fake overlay"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.save(state); err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(root, "libkrun")
	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	libName, fwName, err := libKrunLibraryNames(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{libName, fwName} {
		if err := os.WriteFile(filepath.Join(runtimeDir, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kvmDevice := "/dev/kvm"
	if runtime.GOOS == "linux" {
		// The lifecycle is driven by a fake worker, so a writable fixture is
		// sufficient for the host preflight without requiring KVM hardware.
		kvmDevice = filepath.Join(root, "kvm-fixture")
		if err := os.WriteFile(kvmDevice, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	workerPath := filepath.Join(root, "fake-worker")
	workerScript := "#!/bin/sh\nCAUTEM_TEST_VM_WORKER=1 exec " + shellQuote(executable) + " -test.run='^TestFakeVMWorker$'\n"
	if err := os.WriteFile(workerPath, []byte(workerScript), 0o700); err != nil {
		t.Fatal(err)
	}
	d := NewWithHostConfig(HostConfig{
		StateDir: stateRoot, RuntimeDir: runtimeDir, WorkerPath: workerPath, KVMDevice: kvmDevice,
		kvmDeviceCheck: func(path string) error {
			if path != kvmDevice {
				return fmt.Errorf("unexpected KVM device path %q", path)
			}
			return nil // The fake worker exercises lifecycle protocol, not KVM hardware.
		},
		workerIsolation: func() (workerIsolationConfig, error) {
			return workerIsolationConfig{NoHostMounts: true}, nil
		},
		workerProcessAttributes: func() *syscall.SysProcAttr {
			return &syscall.SysProcAttr{Setsid: true}
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.Start(ctx, core.ID(state.ID)); err == nil || !strings.Contains(err.Error(), "workload spec is unavailable") {
		t.Fatalf("Start() without restored workload error = %v, want fail-closed workload error", err)
	}
	if err := d.RestoreLaunchSpec(ctx, core.ID(state.ID), driver.Spec{Name: state.Name, Command: []string{"true"}, MainProcessRestartPolicy: "always"}); err == nil || !strings.Contains(err.Error(), "restart policy requires supervisor_bin") {
		t.Fatalf("RestoreLaunchSpec() accepted restart without supervisor: %v", err)
	}
	launchSpec := driver.Spec{Name: state.Name, Command: []string{"/bin/sh", "-c", "sleep infinity"}, Env: []string{"TOKEN=not-persisted"}}
	if err := d.RestoreLaunchSpec(ctx, core.ID(state.ID), launchSpec); err != nil {
		t.Fatalf("RestoreLaunchSpec() error = %v", err)
	}
	launchSpec.Command[0] = "mutated"
	if got := d.launchSpecs[state.ID].Command[0]; got != "/bin/sh" {
		t.Fatalf("RestoreLaunchSpec() retained caller-owned command slice: %q", got)
	}
	if err := d.RestoreLaunchSpec(ctx, core.ID(state.ID), driver.Spec{Name: "other", Command: []string{"true"}}); err == nil {
		t.Fatal("RestoreLaunchSpec() accepted a mismatched sandbox name")
	}
	if err := d.Start(ctx, core.ID(state.ID)); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := d.RestoreLaunchSpec(ctx, core.ID(state.ID), driver.Spec{Name: state.Name, Command: []string{"true"}}); err == nil {
		t.Fatal("RestoreLaunchSpec() replaced a running sandbox workload")
	}
	recovered := NewWithHostConfig(d.host)
	if err := recovered.RestoreLaunchSpec(ctx, core.ID(state.ID), driver.Spec{
		Name: state.Name, Command: []string{"/bin/sh", "-c", "sleep infinity"}, Env: []string{"TOKEN=not-persisted"},
	}); err != nil {
		t.Fatalf("RestoreLaunchSpec() could not hydrate a running sandbox after driver restart: %v", err)
	}
	if got := recovered.launchSpecs[state.ID].Command[0]; got != "/bin/sh" {
		t.Fatalf("restored running workload command = %q", got)
	}
	info, err := d.Inspect(ctx, state.ID)
	if err != nil || info.Status != "running" {
		var workerLogs strings.Builder
		_ = d.Logs(ctx, core.ID(state.ID), false, &workerLogs)
		_, _, consolePath := workerSocketPaths(store.root, state.ID)
		workerLog, _ := os.ReadFile(consolePath + ".worker")
		t.Fatalf("Inspect after Start = (%+v, %v); logs: %s; worker: %s", info, err, workerLogs.String(), workerLog)
	}
	result, err := d.Exec(ctx, core.ID(state.ID), driver.ExecRequest{Argv: []string{"echo", "test"}, Stdin: []byte("fixture-input")})
	if err != nil || result.ExitCode != 0 || string(result.Stdout) != "fixture-exec" {
		t.Fatalf("Exec() = (%+v, %v)", result, err)
	}
	source := filepath.Join(root, "source.txt")
	if err := os.WriteFile(source, []byte("upload"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := d.CopyTo(ctx, core.ID(state.ID), source, "/workspace/source.txt"); err != nil {
		t.Fatalf("CopyTo() error = %v", err)
	}
	destination := filepath.Join(root, "download.txt")
	if err := d.CopyFrom(ctx, core.ID(state.ID), "/workspace/result.txt", destination); err != nil {
		t.Fatalf("CopyFrom() error = %v", err)
	}
	if payload, err := os.ReadFile(destination); err != nil || string(payload) != "fixture-download" {
		t.Fatalf("CopyFrom() payload = (%q, %v)", payload, err)
	}
	_, _, consolePath := workerSocketPaths(stateRoot, state.ID)
	if err := os.WriteFile(consolePath, []byte("console-output"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	if err := d.Logs(ctx, core.ID(state.ID), false, &logs); err != nil || !strings.Contains(logs.String(), "console-output") {
		t.Fatalf("Logs() = (%q, %v)", logs.String(), err)
	}
	if err := d.Stop(ctx, core.ID(state.ID)); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	info, err = d.Inspect(ctx, state.ID)
	if err != nil || info.Status != "stopped" {
		t.Fatalf("Inspect after Stop = (%+v, %v)", info, err)
	}
	if err := d.Delete(ctx, core.ID(state.ID)); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestFakeVMWorker(t *testing.T) {
	if os.Getenv("CAUTEM_TEST_VM_WORKER") != "1" {
		return
	}
	var config workerConfig
	if err := json.NewDecoder(os.Stdin).Decode(&config); err != nil {
		t.Fatalf("read worker configuration: %v", err)
	}
	var expectedToken string
	for _, value := range config.Launch.Env {
		if strings.HasPrefix(value, "CAUTEM_VM_CONTROL_TOKEN=") {
			expectedToken = strings.TrimPrefix(value, "CAUTEM_VM_CONTROL_TOKEN=")
		}
	}
	if len(expectedToken) != 64 {
		t.Fatal("worker launch is missing per-sandbox guest control token")
	}
	var tokenMu sync.Mutex
	workerListener, ready, _, err := startWorkerControl(config.ControlSocket)
	if err != nil {
		t.Fatalf("start fake worker control: %v", err)
	}
	defer func() {
		_ = workerListener.Close()
		_ = os.Remove(config.ControlSocket)
	}()
	guestListener, err := net.Listen("unix", config.Launch.VsockSocket)
	if err != nil {
		t.Fatalf("listen fake guest control: %v", err)
	}
	defer func() {
		_ = guestListener.Close()
		_ = os.Remove(config.Launch.VsockSocket)
	}()
	close(ready)
	shutdown := make(chan struct{})
	go func() {
		for {
			connection, err := guestListener.Accept()
			if err != nil {
				return
			}
			go func(connection net.Conn) {
				defer connection.Close()
				frame, err := readFrame(connection)
				if err != nil {
					return
				}
				var request controlRequest
				if err := json.Unmarshal(frame, &request); err != nil {
					return
				}
				response := controlResponse{Version: 1}
				tokenMu.Lock()
				currentToken := expectedToken
				if request.Operation == "rotate-token" {
					if request.AuthToken != currentToken || len(request.NextAuthToken) != 64 || request.RotationID == "" {
						response.Error = "host sent invalid guest control token rotation"
					} else {
						expectedToken = request.NextAuthToken
					}
				} else if request.AuthToken != currentToken {
					response.Error = "host sent invalid guest control token"
				}
				tokenMu.Unlock()
				switch request.Operation {
				case "exec":
					response.Stdout = []byte("fixture-exec")
				case "copy-from":
					response.Data = []byte("fixture-download")
				case "shutdown":
					defer func() { close(shutdown) }()
				}
				encoded, _ := json.Marshal(response)
				_ = writeFrame(connection, encoded)
			}(connection)
		}
	}()
	<-shutdown
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
