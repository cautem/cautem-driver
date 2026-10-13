package testenv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const containerTimeout = 2 * time.Minute

// AlpineImage uses the Docker Official Images mirror on Public ECR. Its tag
// manifest is byte-for-byte identical to docker.io/library/alpine:3.22, while
// avoiding Docker Hub pull throttling in nested test daemons.
const AlpineImage = "public.ecr.aws/docker/library/alpine:3.22"

// RequireContainers makes container-backed suites opt-in and gives every
// container a bounded lifetime. The normal module test command remains usable
// without Docker or Podman.
func RequireContainers(t *testing.T) context.Context {
	t.Helper()
	if testing.Short() || getenv("CAUTEM_TESTCONTAINERS") != "1" {
		t.Skip("set CAUTEM_TESTCONTAINERS=1 to run container-backed tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), containerTimeout)
	t.Cleanup(cancel)
	return ctx
}

func RunAlpine(ctx context.Context, t *testing.T) testcontainers.Container {
	t.Helper()
	container, err := testcontainers.Run(ctx, AlpineImage,
		testcontainers.WithCmd("sh", "-c", "echo cautem-testcontainers-ready"),
		testcontainers.WithWaitStrategy(wait.ForLog("cautem-testcontainers-ready")),
	)
	if err != nil {
		t.Fatalf("start test container: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := container.Terminate(cleanupCtx); err != nil {
			t.Errorf("terminate test container: %v", err)
		}
	})
	return container
}

// RunDockerDaemon starts an isolated, unencrypted Docker Engine for tests
// that need to exercise the driver's Engine API without borrowing the host
// daemon. The returned endpoint is reachable from the test process.
func RunDockerDaemon(ctx context.Context, t *testing.T) (testcontainers.Container, string) {
	t.Helper()
	container, err := testcontainers.Run(ctx, "docker.io/library/docker:28.0.4-dind",
		testcontainers.WithExposedPorts("2375/tcp"),
		// docker:dind declares /var/lib/docker as an anonymous volume. That
		// volume is unnecessary with the vfs storage driver and accumulates on
		// Docker Desktop across repeated suites, eventually making container
		// create calls stall. Keep disposable daemon storage in tmpfs instead.
		testcontainers.WithTmpfs(map[string]string{"/var/lib/docker": "rw,exec,size=4g"}),
		testcontainers.WithHostConfigModifier(func(config *container.HostConfig) {
			config.Privileged = true
			config.CgroupnsMode = container.CgroupnsModeHost
		}),
		testcontainers.WithEnv(map[string]string{"DOCKER_TLS_CERTDIR": ""}),
		// Keep the endpoint stable while allowing recovery tests to kill and
		// restart dockerd inside this container. Restarting the outer container
		// breaks Docker Desktop's random host-port forwarding.
		testcontainers.WithCmd("sh", "-c", "while true; do dockerd --host=tcp://0.0.0.0:2375 --storage-driver=vfs; sleep 1; done"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("2375/tcp")),
	)
	if err != nil {
		t.Fatalf("start Docker-in-Docker fixture: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := container.Terminate(cleanupCtx); err != nil {
			t.Errorf("terminate Docker-in-Docker fixture: %v", err)
		}
	})
	port, err := container.MappedPort(ctx, "2375/tcp")
	if err != nil {
		t.Fatalf("map Docker Engine port: %v", err)
	}
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("resolve Docker Engine host: %v", err)
	}
	return container, fmt.Sprintf("tcp://%s:%s", host, port.Port())
}

// RunPodmanDaemon starts a rootful Podman Docker-compatible API service in an
// isolated privileged container. It is intentionally separate from the Docker
// fixture because Podman has different storage and user-namespace semantics.
func RunPodmanDaemon(ctx context.Context, t *testing.T) (testcontainers.Container, string, string) {
	t.Helper()
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve Podman fixture workspace: %v", err)
	}
	image := strings.TrimSpace(os.Getenv("CAUTEM_TEST_PODMAN_IMAGE"))
	if image == "" {
		image = "quay.io/podman/stable:v5.8.7"
	}
	container, err := testcontainers.Run(ctx, image,
		testcontainers.WithExposedPorts("18500/tcp"),
		testcontainers.WithEnv(map[string]string{"STORAGE_DRIVER": "vfs"}),
		testcontainers.WithHostConfigModifier(func(config *container.HostConfig) {
			config.Privileged = true
		}),
		// Keep the API endpoint stable while allowing recovery tests to kill
		// and restart only the Podman service inside the fixture.
		testcontainers.WithCmd("sh", "-lc", "printf 'root:100000:65536\\n' > /etc/subuid; printf 'root:100000:65536\\n' > /etc/subgid; while true; do podman system service --time=0 tcp:0.0.0.0:18500 & pid=$!; echo $pid >/tmp/podman-service.pid; wait $pid; sleep 2; done"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("18500/tcp")),
	)
	if err != nil {
		t.Fatalf("start Podman fixture: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := container.Terminate(cleanupCtx); err != nil {
			t.Errorf("terminate Podman fixture: %v", err)
		}
	})
	// Podman resolves bind sources in its own container namespace. Create the
	// same canonical path there; the fixture workspace data is only consumed by
	// nested sandbox containers, so it does not need a host bind mount.
	if _, _, err := container.Exec(ctx, []string{"mkdir", "-p", "--", workspace}); err != nil {
		t.Fatalf("create Podman fixture workspace: %v", err)
	}
	port, err := container.MappedPort(ctx, "18500/tcp")
	if err != nil {
		t.Fatalf("map Podman API port: %v", err)
	}
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("resolve Podman API host: %v", err)
	}
	return container, fmt.Sprintf("tcp://%s:%s", host, port.Port()), workspace
}

var getenv = func(key string) string { return lookupEnv(key) }
