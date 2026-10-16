package docker

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cautem/quarshell-driver/driver"
	"github.com/moby/moby/client"
)

func TestBuildImageStreamsTarAndPassesEngineOptions(t *testing.T) {
	var archive []byte
	d := imageBuildFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/build") {
			t.Errorf("unexpected Engine request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("dockerfile"); got != "docker/Dockerfile.dev" {
			t.Errorf("dockerfile query=%q", got)
		}
		if got := r.URL.Query().Get("t"); got != "cautem-local/build:test" {
			t.Errorf("tag query=%q", got)
		}
		if got := r.URL.Query().Get("rm"); got != "" {
			t.Errorf("rm query=%q, want API default true", got)
		}
		if got := r.URL.Query().Get("forcerm"); got != "1" {
			t.Errorf("forcerm query=%q", got)
		}
		archive, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{\"stream\":\"built\\n\"}\n")
	})
	var output bytes.Buffer
	err := d.BuildImage(context.Background(), driver.ImageBuildRequest{
		Context: strings.NewReader("archive-bytes"), Dockerfile: "docker/Dockerfile.dev", Tag: "cautem-local/build:test", Output: &output,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(archive) != "archive-bytes" || output.String() != "built\n" {
		t.Fatalf("request archive=%q output=%q", archive, output.String())
	}
}

func TestBuildImageReturnsEngineBuildError(t *testing.T) {
	d := imageBuildFixtureDriver(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{\"errorDetail\":{\"message\":\"Dockerfile failed\"},\"error\":\"Dockerfile failed\"}\n")
	})
	err := d.BuildImage(context.Background(), driver.ImageBuildRequest{Context: strings.NewReader("tar"), Tag: "bad"})
	if err == nil || !strings.Contains(err.Error(), "Dockerfile failed") {
		t.Fatalf("BuildImage() error=%v, want Engine build error", err)
	}
}

func imageBuildFixtureDriver(t *testing.T, handler http.HandlerFunc) *Driver {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	cli, err := client.New(client.WithHost("tcp://"+strings.TrimPrefix(server.URL, "http://")), client.WithAPIVersion("1.41"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return NewFromClient(cli)
}
