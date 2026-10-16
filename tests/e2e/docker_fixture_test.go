package e2e

import (
	"context"
	"io"
	"testing"

	"github.com/cautem/quarshell-driver/tests/internal/testenv"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func TestDockerDriverFixtureExposesIsolatedEngine(t *testing.T) {
	ctx := testenv.RequireContainers(t)
	_, endpoint := testenv.RunDockerDaemon(ctx, t)

	engine, err := client.New(client.WithHost(endpoint), client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("create Docker Engine client: %v", err)
	}
	defer engine.Close()

	if _, err := engine.Info(ctx, client.InfoOptions{}); err != nil {
		t.Fatalf("Docker-in-Docker Engine info: %v", err)
	}
	pull, err := engine.ImagePull(ctx, testenv.AlpineImage, client.ImagePullOptions{})
	if err != nil {
		t.Fatalf("pull fixture image: %v", err)
	}
	defer pull.Close()
	if _, err := io.Copy(io.Discard, pull); err != nil {
		t.Fatalf("read fixture image pull: %v", err)
	}

	created, err := engine.ContainerCreate(ctx, client.ContainerCreateOptions{Config: &container.Config{Image: testenv.AlpineImage, Cmd: []string{"/bin/true"}}})
	if err != nil {
		t.Fatalf("create fixture container: %v", err)
	}
	defer func() {
		_, _ = engine.ContainerRemove(context.Background(), created.ID, client.ContainerRemoveOptions{Force: true})
	}()
	if _, err := engine.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatalf("start fixture container: %v", err)
	}
}
