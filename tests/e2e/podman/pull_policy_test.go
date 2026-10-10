package podman_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/cautem/cautem-driver/driver"
	podman "github.com/cautem/cautem-driver/internal/podman"
	"github.com/cautem/cautem-driver/tests/internal/testenv"
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
	ctx := testenv.RequireContainers(t)
	_, endpoint, workspace := testenv.RunPodmanDaemon(ctx, t)
	t.Setenv("DOCKER_HOST", endpoint)
	cli, err := client.New(client.WithHost(endpoint), client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	pull, err := cli.ImagePull(ctx, "docker.io/library/alpine:3.22", client.ImagePullOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, pull)
	_ = pull.Close()
	image, err := cli.ImageInspect(ctx, "docker.io/library/alpine:3.22")
	if err != nil || len(image.RepoDigests) == 0 {
		t.Fatalf("inspect pulled image digests=%v err=%v", image.RepoDigests, err)
	}
	engine, err := podman.NewWithConfig(podman.Config{ImagePullPolicy: "missing", UsernsMode: "host", NetworkName: "cautem-digest"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	handle, err := engine.Create(ctx, driver.Spec{Name: "digest-pinned", Image: image.RepoDigests[0], Workspace: workspace, Command: []string{"sleep", "30"}, NoHarden: true})
	if err != nil {
		t.Fatalf("create digest-pinned sandbox: %v", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = engine.Delete(cleanupCtx, handle.ID)
	}()
	inspect, err := cli.ContainerInspect(ctx, string(handle.ID), client.ContainerInspectOptions{})
	if err != nil || inspect.Container.Image != image.ID {
		t.Fatalf("container image=%q inspect image=%q err=%v", inspect.Container.Image, image.ID, err)
	}
}
