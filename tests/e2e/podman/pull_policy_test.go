package podman_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/cautem/quarshell-driver/driver"
	podman "github.com/cautem/quarshell-driver/internal/podman"
	"github.com/cautem/quarshell-driver/tests/internal/testenv"
	"github.com/moby/moby/client"
)

func TestPodmanPullPolicyNeverFailsClosedBeforeNetworkCreate(t *testing.T) {
	ctx := testenv.RequireContainers(t)
	_, endpoint, workspace := testenv.RunPodmanDaemon(ctx, t)
	t.Setenv("DOCKER_HOST", endpoint)
	cli, err := client.New(client.WithHost(endpoint), client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	engine, err := podman.NewWithConfig(podman.Config{ImagePullPolicy: "never", UsernsMode: "host", NetworkName: "cautem-pull-policy"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	_, err = engine.Create(ctx, driver.Spec{Name: "never-missing", Image: "example.invalid/cautem/missing:never", Workspace: workspace, NoHarden: true})
	if err == nil || !strings.Contains(err.Error(), "image_pull_policy is never") {
		t.Fatalf("never policy error=%v", err)
	}
	if _, err := cli.NetworkInspect(ctx, "cautem-pull-policy-never-missing", client.NetworkInspectOptions{}); err == nil {
		t.Fatal("never policy created a network before rejecting missing image")
	}
}

func TestPodmanPullPolicySupportsDigestPinnedImage(t *testing.T) {
	setupCtx := testenv.RequireContainers(t)
	daemon, endpoint, workspace := testenv.RunPodmanDaemon(setupCtx, t)
	t.Setenv("DOCKER_HOST", endpoint)
	cli, err := client.New(client.WithHost(endpoint), client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	pullCtx, cancelPull := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancelPull()
	pull, err := cli.ImagePull(pullCtx, testenv.AlpineImage, client.ImagePullOptions{})
	if err != nil {
		logs, _ := daemon.Logs(context.Background())
		var logText []byte
		if logs != nil {
			logText, _ = io.ReadAll(logs)
			_ = logs.Close()
		}
		t.Fatalf("pull digest fixture image: %v; Podman service logs=%q", err, logText)
	}
	_, _ = io.Copy(io.Discard, pull)
	_ = pull.Close()
	image, err := cli.ImageInspect(pullCtx, testenv.AlpineImage)
	if err != nil || len(image.RepoDigests) == 0 {
		t.Fatalf("inspect pulled image digests=%v err=%v", image.RepoDigests, err)
	}
	engine, err := podman.NewWithConfig(podman.Config{ImagePullPolicy: "missing", UsernsMode: "host", NetworkName: "cautem-digest"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	handle, err := engine.Create(pullCtx, driver.Spec{Name: "digest-pinned", Image: image.RepoDigests[0], Workspace: workspace, Command: []string{"sleep", "30"}, NoHarden: true})
	if err != nil {
		t.Fatalf("create digest-pinned sandbox: %v", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = engine.Delete(cleanupCtx, handle.ID)
	}()
	inspect, err := cli.ContainerInspect(pullCtx, string(handle.ID), client.ContainerInspectOptions{})
	if err != nil || inspect.Container.Image != image.ID {
		t.Fatalf("container image=%q inspect image=%q err=%v", inspect.Container.Image, image.ID, err)
	}
}
