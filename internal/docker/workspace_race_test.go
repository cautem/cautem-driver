package docker

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cautem/cautem-driver/driver"
	"github.com/moby/moby/client"
)

func TestCreateRejectsWorkspaceReplacementDuringPreparation(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	var containerCreateCalled bool
	var networkCleanupCalled bool
	var replacementErr error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/containers/json"):
			_, _ = io.WriteString(w, `[]`)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/json"):
			_, _ = io.WriteString(w, `{"Id":"sha256:workspace-race-fixture","Config":{}}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/networks/race-fixture"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"not found"}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/networks/create"):
			// Model another process replacing the validated directory during
			// backend preparation, before the workload ContainerCreate request.
			if err := os.Rename(workspace, filepath.Join(root, "original-workspace")); err != nil {
				replacementErr = err
			} else {
				replacementErr = os.Mkdir(workspace, 0o700)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"Id":"race-fixture-network"}`)
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/networks/race-fixture"):
			networkCleanupCalled = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/containers/create"):
			containerCreateCalled = true
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"Id":"unexpected-workload"}`)
		default:
			t.Errorf("unexpected Engine request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cli, err := client.New(client.WithHost("tcp://"+strings.TrimPrefix(server.URL, "http://")), client.WithAPIVersion("1.41"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()
	d := NewFromClientWithRuntimeConfig(cli, RuntimeConfig{
		ImagePullPolicy: "missing",
		NetworkName:     "race",
	})

	_, err = d.Create(context.Background(), driver.Spec{
		Name:      "fixture",
		Image:     "alpine:3.22",
		Workspace: workspace,
		Command:   []string{"sleep", "infinity"},
		NoHarden:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "workspace: source changed after validation") {
		t.Fatalf("Create() error = %v, want workspace replacement refusal", err)
	}
	if replacementErr != nil {
		t.Fatalf("replace workspace during preparation: %v", replacementErr)
	}
	if containerCreateCalled {
		t.Fatal("Engine received ContainerCreate after the workspace path was replaced")
	}
	if !networkCleanupCalled {
		t.Fatal("network created during failed preparation was not cleaned up")
	}
}
