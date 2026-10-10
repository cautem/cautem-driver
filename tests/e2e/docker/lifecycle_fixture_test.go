package docker_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/cautem/cautem-driver/driver"
	docker "github.com/cautem/cautem-driver/internal/docker"
	"github.com/cautem/cautem-driver/tests/internal/testenv"
	"github.com/moby/moby/client"
)

func TestDockerDriverLifecycleAgainstTestcontainersEngine(t *testing.T) {
	ctx := testenv.RequireContainers(t)
	_, endpoint := testenv.RunDockerDaemon(ctx, t)

	engineClient, err := client.New(client.WithHost(endpoint), client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("create Docker Engine client: %v", err)
	}
	defer engineClient.Close()

	engine := docker.NewFromClientWithRuntimeConfig(engineClient, docker.RuntimeConfig{
		ImagePullPolicy: "missing",
		NetworkName:     "cautem-testcontainers",
	})
	defer engine.Close()

	name := "testcontainers-lifecycle"
	handle, err := engine.Create(ctx, driver.Spec{
		Name:             name,
		Image:            "docker.io/library/alpine:3.22",
		Workspace:        "/tmp",
		Command:          []string{"sh", "-c", "echo ready; sleep 60"},
		NoHarden:         true,
		CPU:              0.25,
		MemoryBytes:      128 * 1024 * 1024,
		PidsLimit:        64,
		DriverConfigJSON: `{"mounts":[{"type":"volume","source":"cautem-testcontainers-docker-data","target":"/persist","read_only":false},{"type":"volume","source":"cautem-testcontainers-docker-readonly","target":"/readonly","read_only":true},{"type":"tmpfs","target":"/scratch","size_bytes":4096,"read_only":false}]}`,
	})
	if err != nil {
		t.Fatalf("create sandbox through Docker driver: %v", err)
	}
	inspect, err := engineClient.ContainerInspect(ctx, string(handle.ID), client.ContainerInspectOptions{})
	if err != nil {
		t.Fatalf("inspect Docker sandbox: %v", err)
	}
	if inspect.Container.HostConfig == nil {
		t.Fatal("Docker sandbox has no host config")
	}
	resources := inspect.Container.HostConfig.Resources
	if resources.NanoCPUs != 250_000_000 || resources.Memory != 128*1024*1024 || resources.PidsLimit == nil || *resources.PidsLimit != 64 {
		t.Fatalf("Docker resource limits=%+v", resources)
	}
	if !containsString(inspect.Container.HostConfig.SecurityOpt, "no-new-privileges:true") || !containsString(inspect.Container.HostConfig.CapDrop, "CAP_NET_RAW") {
		t.Fatalf("Docker security settings missing: security=%v cap_drop=%v", inspect.Container.HostConfig.SecurityOpt, inspect.Container.HostConfig.CapDrop)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = engine.Delete(cleanupCtx, handle.ID)
	}()

	if err := engine.Start(ctx, handle.ID); err != nil {
		t.Fatalf("start sandbox: %v", err)
	}
	result, err := engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{"sh", "-c", "printf persisted > /workspace/testcontainers-marker && printf volume > /persist/marker && test -w /scratch && ! touch /readonly/marker"}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("exec marker: result=%+v err=%v", result, err)
	}
	if err := engine.Stop(ctx, handle.ID); err != nil {
		t.Fatalf("stop sandbox: %v", err)
	}
	if err := engine.Start(ctx, handle.ID); err != nil {
		t.Fatalf("restart sandbox: %v", err)
	}
	result, err = engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{"sh", "-c", "test \"$(cat /workspace/testcontainers-marker)\" = persisted && test \"$(cat /persist/marker)\" = volume"}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("workspace did not persist across restart: result=%+v err=%v", result, err)
	}
	if err := engine.Delete(ctx, handle.ID); err != nil {
		t.Fatalf("delete sandbox: %v", err)
	}
	if _, err := engineClient.ContainerInspect(ctx, string(handle.ID), client.ContainerInspectOptions{}); err == nil {
		t.Fatal("sandbox still exists after driver delete")
	}
}

func TestDockerDriverRecoversAfterDaemonRestart(t *testing.T) {
	ctx := testenv.RequireContainers(t)
	daemon, endpoint := testenv.RunDockerDaemon(ctx, t)

	engineClient, err := client.New(client.WithHost(endpoint), client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("create Docker Engine client: %v", err)
	}
	defer engineClient.Close()

	engine := docker.NewFromClientWithRuntimeConfig(engineClient, docker.RuntimeConfig{
		ImagePullPolicy: "missing",
		NetworkName:     "cautem-testcontainers-recovery",
	})
	defer engine.Close()

	handle, err := engine.Create(ctx, driver.Spec{
		Name:      "testcontainers-daemon-recovery",
		Image:     "docker.io/library/alpine:3.22",
		Workspace: "/tmp",
		Command:   []string{"sh", "-c", "sleep 120"},
		NoHarden:  true,
	})
	if err != nil {
		t.Fatalf("create recovery sandbox: %v", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = engine.Delete(cleanupCtx, handle.ID)
	}()

	if err := engine.Start(ctx, handle.ID); err != nil {
		t.Fatalf("start recovery sandbox: %v", err)
	}
	result, err := engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{"sh", "-c", "printf daemon-recovery > /workspace/recovery-marker"}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("write recovery marker: result=%+v err=%v", result, err)
	}

	if _, _, err := daemon.Exec(ctx, []string{"sh", "-c", "kill $(pidof dockerd)"}); err != nil {
		t.Fatalf("stop Docker daemon process: %v", err)
	}

	outageCtx, outageCancel := context.WithTimeout(context.Background(), 5*time.Second)
	var outageErr error
	for outageCtx.Err() == nil {
		_, outageErr = engineClient.Info(outageCtx, client.InfoOptions{})
		if outageErr != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	outageCancel()
	if outageErr == nil {
		t.Fatal("Docker Engine remained reachable after daemon stop")
	}

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer readyCancel()
	var infoErr error
	for readyCtx.Err() == nil {
		_, infoErr = engineClient.Info(readyCtx, client.InfoOptions{})
		if infoErr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if infoErr != nil {
		logs, _ := daemon.Logs(context.Background())
		var logText []byte
		if logs != nil {
			logText, _ = io.ReadAll(logs)
			_ = logs.Close()
		}
		t.Fatalf("Docker Engine did not recover after daemon restart: %v; daemon logs=%q", infoErr, logText)
	}

	if err := engine.Start(readyCtx, handle.ID); err != nil {
		t.Fatalf("restart recovery sandbox after daemon outage: %v", err)
	}
	result, err = engine.Exec(readyCtx, handle.ID, driver.ExecRequest{Argv: []string{"sh", "-c", "test \"$(cat /workspace/recovery-marker)\" = daemon-recovery"}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("recovery sandbox state was not restored: result=%+v err=%v", result, err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
