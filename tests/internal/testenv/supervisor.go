package testenv

import (
	"context"
	containerexec "github.com/testcontainers/testcontainers-go/exec"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// InstallSupervisorHelpers places Linux helper binaries in the namespace of
// an isolated nested engine. The driver bind-mounts these same paths into its
// sandbox, so the files must exist both on the test host (for validation) and
// inside the Docker/Podman daemon container (for bind-mount resolution).
func InstallSupervisorHelpers(ctx context.Context, t *testing.T, daemon interface {
	CopyFileToContainer(context.Context, string, string, int64) error
}) (supervisorPath, initPath string) {
	t.Helper()
	helperDir := strings.TrimSpace(os.Getenv("CAUTEM_TEST_RUNTIME_HELPER_DIR"))
	if helperDir == "" {
		t.Skip("set CAUTEM_TEST_RUNTIME_HELPER_DIR to Linux cautem helper binaries for restart-policy acceptance")
	}
	for _, name := range []string{"cautem-supervisor", "cautem-init"} {
		source := filepath.Join(helperDir, name)
		info, err := os.Stat(source)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("runtime helper %q is missing or not executable: %v", source, err)
		}
		if err := daemon.CopyFileToContainer(ctx, source, source, 0o755); err != nil {
			t.Fatalf("copy runtime helper into engine fixture: %v", err)
		}
	}
	return filepath.Join(helperDir, "cautem-supervisor"), filepath.Join(helperDir, "cautem-init")
}

func InstallSupervisorTestPolicy(ctx context.Context, t *testing.T, daemon interface {
	CopyFileToContainer(context.Context, string, string, int64) error
}) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "restart-policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatalf("write supervisor acceptance policy: %v", err)
	}
	if err := daemon.CopyFileToContainer(ctx, path, path, 0o600); err != nil {
		t.Fatalf("copy supervisor acceptance policy into engine fixture: %v", err)
	}
	return path
}

func BuildSandboxImage(ctx context.Context, t *testing.T, daemon interface {
	CopyFileToContainer(context.Context, string, string, int64) error
	Exec(context.Context, []string, ...containerexec.ProcessOption) (int, io.Reader, error)
}, builder []string) string {
	t.Helper()
	const image = "cautem-restart-acceptance:latest"
	contextDir := "/tmp/cautem-restart-image"
	if _, _, err := daemon.Exec(ctx, []string{"mkdir", "-p", contextDir}); err != nil {
		t.Fatalf("create sandbox image build context: %v", err)
	}
	dockerfile := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte("FROM public.ecr.aws/docker/library/alpine:3.22\nRUN adduser -D sandbox\n"), 0o600); err != nil {
		t.Fatalf("write sandbox image Dockerfile: %v", err)
	}
	if err := daemon.CopyFileToContainer(ctx, dockerfile, filepath.Join(contextDir, "Dockerfile"), 0o600); err != nil {
		t.Fatalf("copy sandbox image Dockerfile: %v", err)
	}
	command := slices.Concat(builder, []string{"build", "-t", image, contextDir})
	code, output, err := daemon.Exec(ctx, command)
	if output != nil {
		data, _ := io.ReadAll(output)
		if err != nil || code != 0 {
			t.Fatalf("build sandbox acceptance image: exit=%d err=%v output=%s", code, err, data)
		}
	}
	if err != nil || code != 0 {
		t.Fatalf("build sandbox acceptance image: exit=%d err=%v", code, err)
	}
	return image
}
