package podman_test

import (
	"context"
	"os"
	osexec "os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cautem/cautem-driver/driver"
	podman "github.com/cautem/cautem-driver/internal/podman"
	"github.com/cautem/cautem-driver/tests/internal/testenv"
	"github.com/moby/moby/client"
)

func TestPodmanDriverLifecycleAgainstTestcontainersEngine(t *testing.T) {
	ctx := testenv.RequireContainers(t)
	_, endpoint, workspace := testenv.RunPodmanDaemon(ctx, t)
	t.Setenv("DOCKER_HOST", endpoint)

	engine, err := podman.NewWithConfig(podman.Config{
		ImagePullPolicy:         "missing",
		NetworkName:             "cautem-testcontainers",
		HealthCheckIntervalSecs: 0,
		UsernsMode:              "host",
	})
	if err != nil {
		t.Fatalf("create Podman driver: %v", err)
	}
	defer engine.Close()

	handle, err := engine.Create(ctx, driver.Spec{
		Name:             "testcontainers-podman-lifecycle",
		Image:            "docker.io/library/alpine:3.22",
		Workspace:        workspace,
		Command:          []string{"sh", "-c", "echo ready; sleep 60"},
		NoHarden:         true,
		CPU:              0.25,
		MemoryBytes:      128 * 1024 * 1024,
		PidsLimit:        64,
		DriverConfigJSON: `{"mounts":[{"type":"volume","source":"cautem-testcontainers-podman-data","target":"/persist","read_only":false},{"type":"volume","source":"cautem-testcontainers-podman-readonly","target":"/readonly","read_only":true},{"type":"tmpfs","target":"/scratch","size_bytes":4096,"read_only":false}]}`,
	})
	if err != nil {
		t.Fatalf("create sandbox through Podman driver: %v", err)
	}
	info, err := engine.Inspect(ctx, string(handle.ID))
	if err != nil {
		t.Fatalf("inspect Podman sandbox: %v", err)
	}
	if info.ID == "" || info.Name == "" {
		t.Fatalf("Podman inspect returned incomplete info: %+v", info)
	}
	defer func() { _ = engine.Delete(context.Background(), handle.ID) }()
	if err := engine.Start(ctx, handle.ID); err != nil {
		t.Fatalf("start sandbox: %v", err)
	}
	result, err := engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{"sh", "-c", "test \"$(id -u)\" = 0 && printf volume > /persist/marker && test -w /scratch && ! touch /readonly/marker"}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("exec in Podman sandbox: result=%+v err=%v", result, err)
	}
	if err := engine.Stop(ctx, handle.ID); err != nil {
		t.Fatalf("stop sandbox: %v", err)
	}
	if err := engine.Start(ctx, handle.ID); err != nil {
		t.Fatalf("restart sandbox: %v", err)
	}
	result, err = engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{"sh", "-c", "test \"$(cat /persist/marker)\" = volume"}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("named volume did not persist across restart: result=%+v err=%v", result, err)
	}
	if err := engine.Delete(ctx, handle.ID); err != nil {
		t.Fatalf("delete sandbox: %v", err)
	}
}

func TestPodmanDriverRecoversAfterServiceRestart(t *testing.T) {
	ctx := testenv.RequireContainers(t)
	daemon, endpoint, workspace := testenv.RunPodmanDaemon(ctx, t)
	t.Setenv("DOCKER_HOST", endpoint)

	api, err := client.New(client.WithHost(endpoint), client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("create Podman API client: %v", err)
	}
	defer api.Close()
	engine, err := podman.NewWithConfig(podman.Config{
		ImagePullPolicy:         "missing",
		NetworkName:             "cautem-testcontainers-recovery",
		HealthCheckIntervalSecs: 0,
		UsernsMode:              "host",
	})
	if err != nil {
		t.Fatalf("create Podman driver: %v", err)
	}
	defer engine.Close()

	handle, err := engine.Create(ctx, driver.Spec{
		Name:      "testcontainers-podman-recovery",
		Image:     "docker.io/library/alpine:3.22",
		Workspace: workspace,
		Command:   []string{"sh", "-c", "sleep 120"},
		NoHarden:  true,
	})
	if err != nil {
		t.Fatalf("create recovery sandbox: %v", err)
	}
	defer func() { _ = engine.Delete(context.Background(), handle.ID) }()
	if err := engine.Start(ctx, handle.ID); err != nil {
		t.Fatalf("start recovery sandbox: %v", err)
	}
	result, err := engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{"sh", "-c", "printf podman-recovery > /workspace/recovery-marker"}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("write recovery marker: result=%+v err=%v", result, err)
	}

	if _, _, err := daemon.Exec(ctx, []string{"sh", "-c", "kill \"$(cat /tmp/podman-service.pid)\""}); err != nil {
		t.Fatalf("stop Podman API service: %v", err)
	}
	outageCtx, outageCancel := context.WithTimeout(context.Background(), 5*time.Second)
	var outageErr error
	for outageCtx.Err() == nil {
		_, outageErr = api.Info(outageCtx, client.InfoOptions{})
		if outageErr != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	outageCancel()
	if outageErr == nil {
		t.Fatal("Podman API remained reachable after service stop")
	}

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer readyCancel()
	var infoErr error
	for readyCtx.Err() == nil {
		_, infoErr = api.Info(readyCtx, client.InfoOptions{})
		if infoErr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if infoErr != nil {
		t.Fatalf("Podman API did not recover after service restart: %v", infoErr)
	}
	result, err = engine.Exec(readyCtx, handle.ID, driver.ExecRequest{Argv: []string{"sh", "-c", "test \"$(cat /workspace/recovery-marker)\" = podman-recovery"}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("recovery sandbox state was not restored: result=%+v err=%v", result, err)
	}
}

func TestPodmanRootlessServiceRecovery(t *testing.T) {
	if os.Getenv("CAUTEM_PODMAN_ROOTLESS") != "1" {
		t.Skip("rootless Podman service lane is not enabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	workspace := strings.TrimSpace(os.Getenv("CAUTEM_PODMAN_WORKSPACE"))
	image := strings.TrimSpace(os.Getenv("CAUTEM_E2E_SANDBOX_IMAGE"))
	if workspace == "" || image == "" {
		t.Fatal("CAUTEM_PODMAN_WORKSPACE and CAUTEM_E2E_SANDBOX_IMAGE are required")
	}

	api, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatalf("create rootless Podman API client: %v", err)
	}
	defer api.Close()
	engine, err := podman.NewWithConfig(podman.Config{
		ImagePullPolicy:         "missing",
		NetworkName:             "cautem-rootless-recovery",
		HealthCheckIntervalSecs: 0,
		UsernsMode:              "host",
	})
	if err != nil {
		t.Fatalf("create rootless Podman driver: %v", err)
	}
	defer engine.Close()
	handle, err := engine.Create(ctx, driver.Spec{
		Name: "rootless-podman-service-recovery", Image: image, Workspace: workspace,
		Command: []string{"sh", "-c", "sleep 120"}, NoHarden: true,
	})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "host-gateway isolation requires podman 6.0") {
			t.Skip("host-gateway isolation requires Podman 6.0 or newer")
		}
		t.Fatalf("create rootless recovery sandbox: %v", err)
	}
	defer func() { _ = engine.Delete(context.Background(), handle.ID) }()
	if err := engine.Start(ctx, handle.ID); err != nil {
		t.Fatalf("start rootless recovery sandbox: %v", err)
	}
	result, err := engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{"sh", "-c", "printf rootless-recovery > /workspace/recovery-marker"}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("write rootless recovery marker: result=%+v err=%v", result, err)
	}

	if err := osexec.CommandContext(ctx, "sh", "-lc", "kill \"$(cat /tmp/podman-rootless-service.pid)\"").Run(); err != nil {
		t.Fatalf("stop rootless Podman service: %v", err)
	}
	outageCtx, outageCancel := context.WithTimeout(ctx, 5*time.Second)
	var outageErr error
	for outageCtx.Err() == nil {
		_, outageErr = api.Info(outageCtx, client.InfoOptions{})
		if outageErr != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	outageCancel()
	if outageErr == nil {
		t.Fatal("rootless Podman API remained reachable after service stop")
	}

	readyCtx, readyCancel := context.WithTimeout(ctx, 30*time.Second)
	defer readyCancel()
	var infoErr error
	for readyCtx.Err() == nil {
		_, infoErr = api.Info(readyCtx, client.InfoOptions{})
		if infoErr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if infoErr != nil {
		t.Fatalf("rootless Podman API did not recover: %v", infoErr)
	}
	result, err = engine.Exec(readyCtx, handle.ID, driver.ExecRequest{Argv: []string{"sh", "-c", "test \"$(cat /workspace/recovery-marker)\" = rootless-recovery"}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("rootless recovery sandbox state was not restored: result=%+v err=%v", result, err)
	}
}

// TestPodmanUsernsMatrixE2E exercises user namespace modes independently of
// the proxy/network capability lane. Podman 5 cannot provide the blackhole
// route required by proxy-backed sandboxes, but that limitation must not hide
// the identity contract we can verify on the same daemon.
func TestPodmanUsernsMatrixE2E(t *testing.T) {
	if os.Getenv("CAUTEM_PODMAN_USERNS_E2E") != "1" {
		t.Skip("set CAUTEM_PODMAN_USERNS_E2E=1 to run the Podman userns matrix")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	workspace := strings.TrimSpace(os.Getenv("CAUTEM_PODMAN_WORKSPACE"))
	image := strings.TrimSpace(os.Getenv("CAUTEM_E2E_SANDBOX_IMAGE"))
	if workspace == "" || image == "" {
		t.Fatal("CAUTEM_PODMAN_WORKSPACE and CAUTEM_E2E_SANDBOX_IMAGE are required")
	}
	rootless := os.Getenv("CAUTEM_PODMAN_ROOTLESS") == "1"
	for _, mode := range []string{"private", "auto", "host", "keep-id", "no-map"} {
		t.Run(mode, func(t *testing.T) {
			if rootless && mode == "private" {
				// Rootless Podman owns the subordinate range and rejects explicit
				// host mappings; auto is the equivalent runtime-owned case.
				t.Skip("rootless Podman does not accept explicit private ID maps")
			}
			cfg := podman.Config{ImagePullPolicy: "missing", UsernsMode: mode}
			if mode == "private" {
				cfg.UIDMap = []podman.IDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}
				cfg.GIDMap = []podman.IDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}
			}
			engine, err := podman.NewWithConfig(cfg)
			if err != nil {
				t.Fatalf("create %s Podman driver: %v", mode, err)
			}
			defer engine.Close()
			name := "podman-userns-" + strings.ReplaceAll(mode, "-", "")
			handle, err := engine.Create(ctx, driver.Spec{
				Name: name, Image: image, Workspace: workspace,
				Command: []string{"sh", "-c", "sleep 120"}, NoHarden: true,
			})
			if err != nil {
				if mode == "no-map" && strings.Contains(strings.ToLower(err.Error()), "nomap is only supported in rootless mode") {
					t.Skip("nomap is only supported in rootless mode")
				}
				t.Fatalf("create %s userns sandbox: %v", mode, err)
			}
			defer func() { _ = engine.Delete(context.Background(), handle.ID) }()
			if err := engine.Start(ctx, handle.ID); err != nil {
				if mode == "keep-id" && strings.Contains(strings.ToLower(err.Error()), "mqueue") {
					t.Skip("nested crun does not provide the mqueue capability required by keep-id")
				}
				t.Fatalf("start %s userns sandbox: %v", mode, err)
			}
			result, err := engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{"sh", "-c", "set -eu; grep -Eq '[0-9]' /proc/self/uid_map; grep -Eq '[0-9]' /proc/self/gid_map; id -u; cat /proc/self/uid_map; cat /proc/self/gid_map"}})
			if err != nil || result.ExitCode != 0 {
				t.Fatalf("%s userns identity probe: result=%+v err=%v", mode, result, err)
			}
		})
	}
}
