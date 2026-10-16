package docker_test

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	core "github.com/cautem/cautem-core"
	"github.com/cautem/cautem-core/resourceadmission"
	"github.com/cautem/quarshell-driver/driver"
	docker "github.com/cautem/quarshell-driver/internal/docker"
	"github.com/cautem/quarshell-driver/tests/internal/testenv"
	"github.com/moby/moby/api/types/container"
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
		ImagePullPolicy:   "missing",
		NetworkName:       "cautem-testcontainers",
		AllowDriverConfig: true,
		ResourceAdmission: &resourceadmission.Config{Enabled: false},
	})
	defer engine.Close()
	for _, volume := range []string{"cautem-testcontainers-docker-data", "cautem-testcontainers-docker-readonly"} {
		if _, err := engineClient.VolumeCreate(ctx, client.VolumeCreateOptions{Name: volume}); err != nil {
			t.Fatalf("create caller volume fixture %q: %v", volume, err)
		}
		defer func() {
			_, _ = engineClient.VolumeRemove(context.Background(), volume, client.VolumeRemoveOptions{Force: true})
		}()
	}

	name := "testcontainers-lifecycle"
	handle, err := engine.Create(ctx, driver.Spec{
		Name:             name,
		Image:            testenv.AlpineImage,
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
	uploadSource := filepath.Join(t.TempDir(), "upload-fixture")
	if err := os.Mkdir(uploadSource, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uploadSource, "marker"), []byte("uploaded"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("marker", filepath.Join(uploadSource, "link")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if err := os.Symlink("missing", filepath.Join(uploadSource, "dangling")); err != nil {
		t.Skipf("dangling symlink creation unavailable: %v", err)
	}
	if err := engine.CopyTo(ctx, handle.ID, uploadSource, "/workspace"); err != nil {
		t.Fatalf("copy upload fixture into Docker sandbox: %v", err)
	}
	uploadTarget := "/workspace/" + filepath.Base(uploadSource)
	result, err := engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{"sh", "-c", "printf persisted > /workspace/testcontainers-marker && printf volume > /persist/marker && test -w /scratch && ! touch /readonly/marker"}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("exec marker: result=%+v err=%v", result, err)
	}
	result, err = engine.Exec(ctx, handle.ID, driver.ExecRequest{
		Argv:        []string{"sh", "-c", "cat > /workspace/stdin-fixture"},
		StdinReader: strings.NewReader("stdin-streamed-without-tty\n"),
	})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("exec piped stdin: result=%+v err=%v", result, err)
	}
	result, err = engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{"sh", "-c", "test \"$(cat /workspace/stdin-fixture)\" = stdin-streamed-without-tty"}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("piped stdin was not delivered to the process: result=%+v err=%v", result, err)
	}
	result, err = engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{"sh", "-c", "test \"$(cat " + uploadTarget + "/marker)\" = uploaded && test -L " + uploadTarget + "/link && test \"$(readlink " + uploadTarget + "/link)\" = marker && test -L " + uploadTarget + "/dangling"}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("uploaded files or symlinks were not preserved: result=%+v err=%v", result, err)
	}
	downloadTarget := filepath.Join(t.TempDir(), "downloaded-upload")
	if err := engine.CopyFrom(ctx, handle.ID, uploadTarget, downloadTarget); err != nil {
		t.Fatalf("copy uploaded directory back from Docker sandbox: %v", err)
	}
	downloadedUpload := filepath.Join(downloadTarget, filepath.Base(uploadSource))
	if got, err := os.ReadFile(filepath.Join(downloadedUpload, "marker")); err != nil || string(got) != "uploaded" {
		t.Fatalf("downloaded file=%q err=%v", got, err)
	}
	if got, err := os.Readlink(filepath.Join(downloadedUpload, "link")); err != nil || got != "marker" {
		t.Fatalf("downloaded symlink=%q err=%v", got, err)
	}
	if got, err := os.Readlink(filepath.Join(downloadedUpload, "dangling")); err != nil || got != "missing" {
		t.Fatalf("downloaded dangling symlink=%q err=%v", got, err)
	}
	fileInfo, err := os.Stat(filepath.Join(downloadedUpload, "marker"))
	if err != nil {
		t.Fatalf("stat downloaded file: %v", err)
	}
	if fileInfo.Mode().Perm() != 0o644 {
		t.Fatalf("downloaded file mode=%v", fileInfo.Mode().Perm())
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

func TestDockerDriverBuildsImageFromDockerfileContext(t *testing.T) {
	ctx := testenv.RequireContainers(t)
	_, endpoint := testenv.RunDockerDaemon(ctx, t)

	engineClient, err := client.New(client.WithHost(endpoint), client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("create Docker Engine client: %v", err)
	}
	defer engineClient.Close()
	engine := docker.NewFromClient(engineClient)
	defer engine.Close()

	tag := fmt.Sprintf("cautem-e2e-build:%d", time.Now().UnixNano())
	defer func() {
		_, _ = engineClient.ImageRemove(context.Background(), tag, client.ImageRemoveOptions{Force: true, PruneChildren: true})
	}()
	var contextTar bytes.Buffer
	tarWriter := tar.NewWriter(&contextTar)
	files := map[string]string{
		"Dockerfile": "FROM " + testenv.AlpineImage + "\nCOPY marker /marker\n",
		"marker":     "built-from-source\n",
	}
	for name, body := range files {
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tarWriter, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	var buildOutput bytes.Buffer
	if err := engine.BuildImage(ctx, driver.ImageBuildRequest{Context: bytes.NewReader(contextTar.Bytes()), Dockerfile: "Dockerfile", Tag: tag, Output: &buildOutput}); err != nil {
		t.Fatalf("build local image: %v\n%s", err, buildOutput.String())
	}
	if _, err := engineClient.ImageInspect(ctx, tag); err != nil {
		t.Fatalf("inspect built image: %v", err)
	}
	created, err := engineClient.ContainerCreate(ctx, client.ContainerCreateOptions{Config: &container.Config{Image: tag, Cmd: []string{"sh", "-c", "test \"$(cat /marker)\" = built-from-source"}}})
	if err != nil {
		t.Fatalf("create container from built image: %v", err)
	}
	defer func() {
		_, _ = engineClient.ContainerRemove(context.Background(), created.ID, client.ContainerRemoveOptions{Force: true})
	}()
	if _, err := engineClient.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatalf("start built image container: %v", err)
	}
	waitResult := engineClient.ContainerWait(ctx, created.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case response := <-waitResult.Result:
		if response.StatusCode != 0 {
			t.Fatalf("built image command exit=%d", response.StatusCode)
		}
	case err := <-waitResult.Error:
		t.Fatalf("wait for built image container: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
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
		Image:     testenv.AlpineImage,
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

func TestDockerMainProcessRestartPolicyLifecycle(t *testing.T) {
	ctx := testenv.RequireContainers(t)
	daemon, endpoint := testenv.RunDockerDaemon(ctx, t)
	supervisorBin, initBin := testenv.InstallSupervisorHelpers(ctx, t, daemon)
	policyPath := testenv.InstallSupervisorTestPolicy(ctx, t, daemon)
	image := testenv.BuildSandboxImage(ctx, t, daemon, []string{"docker", "-H", "tcp://127.0.0.1:2375"})
	engineClient, err := client.New(client.WithHost(endpoint), client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("create Docker Engine client: %v", err)
	}
	defer engineClient.Close()
	engine := docker.NewFromClientWithRuntimeConfig(engineClient, docker.RuntimeConfig{ImagePullPolicy: "missing", NetworkName: "cautem-restart-policy"})
	defer engine.Close()
	var handles []driver.Handle
	defer func() {
		for _, handle := range handles {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			_ = engine.Delete(cleanupCtx, handle.ID)
			cancel()
		}
	}()

	create := func(name, policy string, command []string) driver.Handle {
		t.Helper()
		handle, err := engine.Create(ctx, driver.Spec{
			Name: name, Image: image, Workspace: "/tmp", Command: command,
			InitBin: initBin, SupervisorBin: supervisorBin,
			PolicyPath: policyPath, MainProcessRestartPolicy: policy,
		})
		if err != nil {
			t.Fatalf("create %s sandbox: %v", policy, err)
		}
		handles = append(handles, handle)
		return handle
	}
	waitForExit := func(id core.ID, want int) {
		t.Helper()
		code, err := engine.WaitMainProcess(ctx, id)
		if err != nil || code != want {
			logs, _ := engineClient.ContainerLogs(ctx, string(id), client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
			var output []byte
			if logs != nil {
				output, _ = io.ReadAll(logs)
				_ = logs.Close()
			}
			t.Fatalf("container %s exit=%d err=%v, want %d; raw logs=%q", id, code, err, want, output)
		}
	}
	readAttempts := func(handle driver.Handle) int {
		t.Helper()
		logs, err := engineClient.ContainerLogs(ctx, string(handle.ID), client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
		if err != nil {
			t.Fatalf("read restart lifecycle logs: %v", err)
		}
		defer logs.Close()
		data, err := io.ReadAll(logs)
		if err != nil {
			t.Fatalf("read restart lifecycle logs: %v", err)
		}
		return strings.Count(string(data), "CAUTEM_RESTART_ATTEMPT")
	}

	never := create("restart-never", "never", []string{"sh", "-c", "echo CAUTEM_RESTART_ATTEMPT; exit 9"})
	if err := engine.Start(ctx, never.ID); err != nil {
		t.Fatalf("start never-policy sandbox: %v", err)
	}
	waitForExit(never.ID, 9)
	if got := readAttempts(never); got != 1 {
		t.Fatalf("never policy attempts=%d, want 1", got)
	}

	onFailure := create("restart-on-failure", "on-failure", []string{"sh", "-c", "echo CAUTEM_RESTART_ATTEMPT; exit 9"})
	if err := engine.Start(ctx, onFailure.ID); err != nil {
		t.Fatalf("start on-failure sandbox: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && readAttempts(onFailure) < 3 {
		time.Sleep(25 * time.Millisecond)
	}
	if got := readAttempts(onFailure); got < 3 {
		t.Fatalf("on-failure policy attempts=%d, want at least 3 before shutdown", got)
	}
	if err := engine.Stop(ctx, onFailure.ID); err != nil {
		t.Fatalf("stop on-failure retry loop: %v", err)
	}
	waitForExit(onFailure.ID, 9)

	always := create("restart-always", "always", []string{"sh", "-c", "echo CAUTEM_RESTART_ATTEMPT; trap 'exit 0' TERM; sleep 60"})
	if err := engine.Start(ctx, always.ID); err != nil {
		t.Fatalf("start always-policy sandbox: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := engine.Stop(ctx, always.ID); err != nil {
		t.Fatalf("stop always-policy sandbox: %v", err)
	}
	waitForExit(always.ID, 0)
	if got := readAttempts(always); got != 1 {
		t.Fatalf("always policy restarted after external stop: attempts=%d, want 1", got)
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
