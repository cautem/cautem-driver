package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	core "github.com/cautem/quarshell-core"
	"github.com/cautem/quarshell-core/resourceadmission"
	"github.com/cautem/quarshell-driver/driver"
	"github.com/moby/moby/client"
)

func sdkFixtureDriver(t *testing.T, handler http.HandlerFunc) *Driver {
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

func TestDefaultSandboxImageUsesCautemBaseWhenNotCached(t *testing.T) {
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/images/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"not found"}`)
			return
		}
		t.Errorf("unexpected engine request: %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusNotFound)
	})

	if got := d.defaultSandboxImage(context.Background(), "", false); got != localSandboxImage {
		t.Fatalf("default sandbox image = %q, want %q", got, localSandboxImage)
	}
}

func TestDefaultSandboxImageSelectsGUIWithGPU(t *testing.T) {
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected engine request: %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusNotFound)
	})

	if got := d.defaultSandboxImage(context.Background(), "novnc", true); got != guiGPUSandboxImage {
		t.Fatalf("GPU display image = %q, want %q", got, guiGPUSandboxImage)
	}
	if !imageHasGUI(guiGPUSandboxImage) {
		t.Fatalf("GPU display image %q was not recognized as GUI", guiGPUSandboxImage)
	}
}

func TestImageHasGUIRecognizesPublishedGUIImages(t *testing.T) {
	for _, image := range []string{
		"cautem-sandbox:gui",
		"cautem-sandbox:gui-gpu",
		"ghcr.io/cautem/cautem/sandboxes/gui:latest",
		"ghcr.io/cautem/cautem/sandboxes/gui-gpu:latest",
	} {
		if !imageHasGUI(image) {
			t.Errorf("imageHasGUI(%q) = false", image)
		}
	}
	if imageHasGUI("ghcr.io/cautem/cautem/sandboxes/gpu:latest") {
		t.Fatal("compute-only GPU image was recognized as GUI")
	}
}

func TestSplitSDKLogsAndArchiveEngineContract(t *testing.T) {
	const content = "archive data"
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Name: "file.txt", Mode: 0o600, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(tw, content)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1.41/containers/container-id/json":
			_, _ = io.WriteString(w, `{"Config":{"Labels":{}},"Name":""}`)
		case strings.HasSuffix(r.URL.Path, "/logs"):
			if r.URL.Query().Get("stdout") != "1" || r.URL.Query().Get("stderr") != "1" {
				t.Errorf("log selectors=%s", r.URL.RawQuery)
			}
			var header [8]byte
			for _, frame := range []struct {
				stream byte
				text   string
			}{{1, "stdout\n"}, {2, "stderr\n"}} {
				header[0] = frame.stream
				binary.BigEndian.PutUint32(header[4:], uint32(len(frame.text)))
				_, _ = w.Write(header[:])
				_, _ = io.WriteString(w, frame.text)
			}
		case strings.HasSuffix(r.URL.Path, "/archive") && r.Method == http.MethodPut:
			if r.URL.Query().Get("path") != "/guest" {
				t.Errorf("archive destination=%q", r.URL.Query().Get("path"))
			}
			reader := tar.NewReader(r.Body)
			header, err := reader.Next()
			if err != nil || header.Name != "file.txt" {
				t.Errorf("copy-to tar header=%+v err=%v", header, err)
				return
			}
			data, err := io.ReadAll(reader)
			if err != nil || string(data) != content {
				t.Errorf("copy-to data=%q err=%v", data, err)
			}
		case strings.HasSuffix(r.URL.Path, "/archive") && r.Method == http.MethodGet:
			if r.URL.Query().Get("path") != "/guest/file.txt" {
				t.Errorf("archive source=%q", r.URL.Query().Get("path"))
			}
			w.Header().Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString([]byte(`{"name":"file.txt","size":12,"mode":384}`)))
			_, _ = w.Write(archive.Bytes())
		default:
			t.Errorf("unexpected engine request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	var logs bytes.Buffer
	if err := d.Logs(context.Background(), "container-id", false, &logs); err != nil || logs.String() != "stdout\nstderr\n" {
		t.Fatalf("logs=%q err=%v", logs.String(), err)
	}
	source := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(source, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.CopyTo(context.Background(), "container-id", source, "/guest/file.txt"); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "copied.txt")
	if err := d.CopyFrom(context.Background(), "container-id", "/guest/file.txt", destination); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(destination)
	if err != nil || string(data) != content {
		t.Fatalf("copy-from data=%q err=%v", data, err)
	}
}

func TestLogsWithOptionsAppliesTailSinceAndProxySource(t *testing.T) {
	var logRequests int
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.41/containers/container-id/json":
			_, _ = io.WriteString(w, `{"Config":{"Labels":{"cautem.name":"demo"}},"Name":"/cautem-demo"}`)
		case "/v1.41/containers/cautem-proxy-demo/json":
			_, _ = io.WriteString(w, `{"Config":{"Labels":{}},"Name":"/cautem-proxy-demo"}`)
		case "/v1.41/containers/cautem-proxy-demo/logs":
			logRequests++
			if r.URL.Query().Get("tail") != "37" || r.URL.Query().Get("since") != "1792022400" || r.URL.Query().Get("follow") != "1" {
				t.Errorf("log query=%s", r.URL.RawQuery)
			}
			if r.URL.Query().Get("stdout") != "1" || r.URL.Query().Get("stderr") != "1" {
				t.Errorf("log stream selectors=%s", r.URL.RawQuery)
			}
			var header [8]byte
			frame := "event\n"
			header[0] = 1
			binary.BigEndian.PutUint32(header[4:], uint32(len(frame)))
			_, _ = w.Write(header[:])
			_, _ = io.WriteString(w, frame)
		default:
			t.Errorf("unexpected engine request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	var output strings.Builder
	err := d.LogsWithOptions(context.Background(), core.ID("container-id"), driver.LogOptions{
		Follow: true, Tail: 37, TailSet: true, Since: "2026-10-15T00:00:00Z", Source: "proxy",
	}, &output)
	if err != nil {
		t.Fatal(err)
	}
	if logRequests != 1 || output.String() != "event\n" {
		t.Fatalf("log requests=%d output=%q", logRequests, output.String())
	}
}

func TestEnsureNetworkRejectsExistingNonInternalProxyNetwork(t *testing.T) {
	var createRequests int
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/networks/proxy-sandbox-risk") && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"Id":"existing-network","Internal":false,"Labels":{"cautem.sandbox":"1","cautem.name":"risk"}}`)
		case strings.HasSuffix(r.URL.Path, "/networks/create"):
			createRequests++
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"Id":"created-network"}`)
		default:
			t.Errorf("unexpected engine request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	created, err := d.ensureNetwork(context.Background(), "proxy-sandbox-risk", "risk", true)
	if err == nil || !strings.Contains(err.Error(), "not internal") {
		t.Fatalf("non-internal existing network error=%v; want fail-closed refusal", err)
	}
	if created {
		t.Fatal("existing non-internal network reported as created")
	}
	if createRequests != 0 {
		t.Fatalf("unexpected replacement network create requests=%d", createRequests)
	}
}

func TestEnsureNetworkReusesInternalProxyNetwork(t *testing.T) {
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/networks/proxy-sandbox-safe") || r.Method != http.MethodGet {
			t.Errorf("unexpected engine request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"Id":"internal-network","Internal":true,"EnableIPv6":true,"Labels":{"cautem.sandbox":"1","cautem.name":"safe"},"Options":{"com.docker.network.bridge.gateway_mode_ipv4":"isolated","com.docker.network.bridge.gateway_mode_ipv6":"isolated"}}`)
	})
	d.runtimeConfig.BackendID = "docker"
	created, err := d.ensureNetwork(context.Background(), "proxy-sandbox-safe", "safe", true)
	if err != nil {
		t.Fatalf("reuse internal network: %v", err)
	}
	if created {
		t.Fatal("existing internal network reported as newly created")
	}
}

func TestEnsureNetworkRejectsOwnedInternalNetworkWithoutIPv6(t *testing.T) {
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/networks/proxy-sandbox-no-ipv6") || r.Method != http.MethodGet {
			t.Errorf("unexpected engine request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"Id":"owned-network","Name":"proxy-sandbox-no-ipv6","Internal":true,"Labels":{"cautem.sandbox":"1","cautem.name":"no-ipv6","cautem.role":"network"},"Options":{"com.docker.network.bridge.gateway_mode_ipv4":"isolated","com.docker.network.bridge.gateway_mode_ipv6":"isolated"}}`)
	})
	d.runtimeConfig.BackendID = "docker"
	if _, err := d.ensureNetwork(context.Background(), "proxy-sandbox-no-ipv6", "no-ipv6", true); err == nil || !strings.Contains(err.Error(), "does not enable IPv6") {
		t.Fatalf("reuse of IPv6-disabled internal network error = %v, want fail-closed IPv6 error", err)
	}
}

func TestEnsureNetworkCreatesDualStackIsolatedProxyNetwork(t *testing.T) {
	var createRequests int
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/networks/proxy-sandbox-dual-stack") && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"not found"}`)
		case strings.HasSuffix(r.URL.Path, "/networks/create") && r.Method == http.MethodPost:
			createRequests++
			var request struct {
				Driver     string            `json:"Driver"`
				Internal   bool              `json:"Internal"`
				EnableIPv6 *bool             `json:"EnableIPv6"`
				Options    map[string]string `json:"Options"`
				Labels     map[string]string `json:"Labels"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode network create request: %v", err)
			}
			if request.Driver != "bridge" || !request.Internal {
				t.Fatalf("proxy network driver/internal = %q/%t", request.Driver, request.Internal)
			}
			if request.EnableIPv6 == nil || !*request.EnableIPv6 {
				t.Errorf("proxy network EnableIPv6 = %v, want true", request.EnableIPv6)
			}
			for _, family := range []string{"ipv4", "ipv6"} {
				key := "com.docker.network.bridge.gateway_mode_" + family
				if request.Options[key] != "isolated" {
					t.Errorf("proxy network option %s = %q, want isolated", key, request.Options[key])
				}
			}
			if request.Labels[labelSandbox] != "1" || request.Labels[labelName] != "dual-stack" || request.Labels[labelRole] != roleNetwork {
				t.Errorf("proxy network ownership labels = %v", request.Labels)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"Id":"created-network"}`)
		default:
			t.Errorf("unexpected engine request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	d.runtimeConfig.BackendID = "docker"

	created, err := d.ensureNetwork(context.Background(), "proxy-sandbox-dual-stack", "dual-stack", true)
	if err != nil {
		t.Fatal(err)
	}
	if !created || createRequests != 1 {
		t.Fatalf("network created=%t create requests=%d", created, createRequests)
	}
}

func TestCreateProxySidecarMountsUpstreamCredentialsOutsideSandbox(t *testing.T) {
	authPath := filepath.Join(t.TempDir(), "auth")
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	binPath := filepath.Join(t.TempDir(), "cautem")
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	for path, data := range map[string]string{
		authPath:   "robot:s3cret",
		caPath:     "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
		binPath:    "proxy",
		policyPath: "version: 1\n",
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(binPath, 0o755); err != nil {
		t.Fatal(err)
	}

	var created struct {
		Env        []string
		Image      string
		HostConfig struct {
			Binds []string `json:"Binds"`
		} `json:"HostConfig"`
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/containers/cautem-proxy-fixture"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1.41/containers/create":
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				t.Errorf("decode proxy create: %v", err)
			}
			_, _ = io.WriteString(w, `{"Id":"proxy-id"}`)
			cancel()
		default:
			t.Errorf("unexpected proxy request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	cli, err := client.New(client.WithHost("tcp://"+strings.TrimPrefix(server.URL, "http://")), client.WithAPIVersion("1.41"))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	d := NewFromClientWithRuntimeConfig(cli, RuntimeConfig{
		UpstreamProxyURL:               "https://proxy.example.test:8443",
		UpstreamProxyNoProxy:           "localhost,.svc.cluster.local",
		UpstreamProxyAuthFile:          authPath,
		UpstreamProxyCABundle:          caPath,
		UpstreamProxyConnectByHostname: true,
	})
	err = d.createProxySidecar(ctx, "fixture", "cautem-net-fixture", "proxy:latest", binPath, policyPath, 3128, "", "", "", nil, 0)
	if err == nil {
		t.Fatal("proxy create unexpectedly reached readiness with canceled context")
	}

	if created.Image != "proxy:latest" {
		t.Fatalf("proxy image=%q", created.Image)
	}
	for _, want := range []string{
		"CAUTEM_PROXY_AUTH_FILE=/run/cautem/upstream-proxy/auth",
		"CAUTEM_PROXY_CA_BUNDLE=/run/cautem/upstream-proxy/ca.pem",
		"CAUTEM_PROXY_CONNECT_BY_HOSTNAME=true",
		"NO_PROXY=localhost,.svc.cluster.local",
	} {
		if !containsEnvValue(created.Env, strings.SplitN(want, "=", 2)[0], strings.SplitN(want, "=", 2)[1]) {
			t.Errorf("proxy env missing %q: %v", want, created.Env)
		}
	}
	for _, forbidden := range []string{"robot:s3cret", authPath, caPath} {
		if strings.Contains(strings.Join(created.Env, "\n"), forbidden) {
			t.Errorf("proxy secret/path leaked into env: %q", forbidden)
		}
	}
	joinedBinds := strings.Join(created.HostConfig.Binds, "\n")
	for _, want := range []string{authPath + ":/run/cautem/upstream-proxy/auth:ro", caPath + ":/run/cautem/upstream-proxy/ca.pem:ro"} {
		if !strings.Contains(joinedBinds, want) {
			t.Errorf("proxy bind missing %q: %v", want, created.HostConfig.Binds)
		}
	}
}

func TestExecFailsClosedWhenContainerInspectFails(t *testing.T) {
	var execCreateRequests int
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/containers/container-id/json") && r.Method == http.MethodGet {
			http.Error(w, "temporary inspect failure", http.StatusServiceUnavailable)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/containers/container-id/exec") && r.Method == http.MethodPost {
			execCreateRequests++
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"Id":"unexpected-exec"}`)
			return
		}
		t.Errorf("unexpected engine request: %s %s", r.Method, r.URL)
		http.NotFound(w, r)
	})
	if _, err := d.Exec(context.Background(), core.ID("container-id"), driver.ExecRequest{Argv: []string{"id"}}); err == nil {
		t.Fatal("exec unexpectedly succeeded after container inspect failed")
	}
	if execCreateRequests != 0 {
		t.Fatalf("ExecCreate called %d times after failed inspect", execCreateRequests)
	}
}

func TestSplitSDKCreateAndInspectEngineContract(t *testing.T) {
	var created map[string]json.RawMessage
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1.41/containers/json" && r.Method == http.MethodGet:
			_, _ = io.WriteString(w, `[]`)
		case strings.Contains(r.URL.Path, "/images/"):
			_, _ = io.WriteString(w, `{"Id":"sha256:immutable-image-id","Config":{"User":"app:staff"}}`)
		case r.URL.Path == "/v1.41/volumes/cache" && r.Method == http.MethodGet:
			_, _ = io.WriteString(w, `{"Name":"cache","Driver":"local","Labels":{},"Options":{}}`)
		case strings.Contains(r.URL.Path, "/networks/"):
			_, _ = io.WriteString(w, `{"Id":"network-id","Labels":{"cautem.sandbox":"1","cautem.name":"sdk-fixture"}}`)
		case r.URL.Path == "/v1.41/containers/create":
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				t.Error(err)
			}
			if r.URL.Query().Get("name") != "cautem-sdk-fixture" {
				t.Errorf("container name=%q", r.URL.Query().Get("name"))
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"Id":"container-id"}`)
		case r.URL.Path == "/v1.41/containers/container-id/json":
			_, _ = io.WriteString(w, `{"Id":"container-id","Name":"/cautem-sdk-fixture","Config":{"Image":"busybox:latest","Labels":{"cautem.sandbox":"1","cautem.name":"sdk-fixture","cautem.network":"cautem-net-sdk-fixture"}},"State":{"Status":"running"},"NetworkSettings":{"Networks":{"cautem-net-sdk-fixture":{"IPAddress":"172.18.0.2"}}}}`)
		default:
			t.Errorf("unexpected engine request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	d.runtimeConfig.HealthCheckIntervalSecs = 30
	d.runtimeConfig.AppArmorProfile = AppArmorUnconfined
	d.runtimeConfig.AllowDriverConfig = true
	d.runtimeConfig.ResourceAdmission = &resourceadmission.Config{Enabled: false}
	d.runtimeConfig.UsernsMode = "private"
	d.runtimeConfig.SandboxNamespace = "openshell-test"
	d.runtimeConfig.DefaultCPU = 1.5
	d.runtimeConfig.DefaultMemoryBytes = 1024 * 1024 * 1024
	d.enableBindMounts = true
	bindSource := t.TempDir()
	ctx := context.Background()
	driverConfigJSON := fmt.Sprintf(`{"cdi_devices":["nvidia.com/gpu=7"],"mounts":[{"type":"volume","source":"cache","target":"/cache"},{"type":"tmpfs","target":"/scratch","size_bytes":4096},{"type":"bind","source":%q,"target":"/host-data","read_only":true,"selinux_label":"shared"}]}`, bindSource)
	handle, err := d.Create(ctx, driver.Spec{Name: "sdk-fixture", Image: "cautem-sandbox:local", Workspace: t.TempDir(), Env: []string{"OPENSHELL_OCI_IMAGE_USER=spoofed", "OPENSHELL_SANDBOX_UID=0", "PATH=/usr/bin"}, Labels: map[string]string{"openshell.ai/sandbox-namespace": "spoofed"}, PublishPorts: []driver.PortPublish{{Host: 18080, Guest: 8080}}, DriverConfigJSON: driverConfigJSON})
	if err != nil {
		t.Fatal(err)
	}
	if handle.ID != core.ID("container-id") {
		t.Fatalf("created handle=%+v", handle)
	}
	var host struct {
		PortBindings   map[string][]struct{ HostIP, HostPort string }
		Binds          []string
		SecurityOpt    []string
		UsernsMode     string
		NanoCPUs       int64
		Memory         int64
		CapDrop        []string
		DeviceRequests []struct {
			Driver    string
			DeviceIDs []string
		}
		Mounts []struct {
			Type         string
			Source       string
			Target       string
			ReadOnly     bool
			TmpfsOptions *struct{ SizeBytes int64 }
		}
	}
	if err := json.Unmarshal(created["HostConfig"], &host); err != nil {
		t.Fatal(err)
	}
	var config struct {
		Image       string
		Env         []string
		User        string
		Labels      map[string]string
		Healthcheck struct {
			Test     []string
			Interval time.Duration
			Timeout  time.Duration
			Retries  int
		}
	}
	configJSON, err := json.Marshal(created)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(configJSON, &config); err != nil {
		t.Fatal(err)
	}
	if config.Image != "sha256:immutable-image-id" {
		t.Fatalf("created image=%q, want inspected immutable ID", config.Image)
	}
	if config.User != "0" {
		t.Fatalf("supervisor user=%q, want root for hardening setup", config.User)
	}
	if config.Labels["openshell.ai/sandbox-namespace"] != "openshell-test" {
		t.Fatalf("sandbox namespace label=%q", config.Labels["openshell.ai/sandbox-namespace"])
	}
	if config.Healthcheck.Interval != 30*time.Second || config.Healthcheck.Timeout != 2*time.Second || config.Healthcheck.Retries != 10 || len(config.Healthcheck.Test) != 2 || host.UsernsMode != "private" {
		t.Fatalf("Podman-compatible health/userns config not applied: health=%+v userns=%q", config.Healthcheck, host.UsernsMode)
	}
	if host.NanoCPUs != 1_500_000_000 || host.Memory != 1024*1024*1024 {
		t.Fatalf("CPU/memory resource defaults not applied: %+v", host)
	}
	if !containsEnvValue(config.Env, "OPENSHELL_OCI_IMAGE_USER", "app:staff") || containsEnvKey(config.Env, "OPENSHELL_SANDBOX_UID") {
		t.Fatalf("container identity environment=%v; want trusted OCI USER and no injected sandbox IDs", config.Env)
	}
	bindings := host.PortBindings["8080/tcp"]
	if len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" || bindings[0].HostPort != "18080" || !slices.Equal(host.SecurityOpt, []string{"no-new-privileges:true", "apparmor=unconfined"}) || len(host.CapDrop) != 1 || host.CapDrop[0] != "CAP_NET_RAW" {
		t.Fatalf("container security/loopback publish contract changed: %+v", host)
	}
	if len(host.DeviceRequests) != 1 || host.DeviceRequests[0].Driver != "cdi" || len(host.DeviceRequests[0].DeviceIDs) != 1 || host.DeviceRequests[0].DeviceIDs[0] != "nvidia.com/gpu=7" {
		t.Fatalf("OpenShell cdi_devices were not applied to container create: %+v", host.DeviceRequests)
	}
	if len(host.Mounts) != 2 || host.Mounts[0].Type != "volume" || host.Mounts[0].Source != "cache" || host.Mounts[0].Target != "/cache" || !host.Mounts[0].ReadOnly || host.Mounts[1].Type != "tmpfs" || host.Mounts[1].Target != "/scratch" || host.Mounts[1].TmpfsOptions == nil || host.Mounts[1].TmpfsOptions.SizeBytes != 4096 {
		t.Fatalf("OpenShell mounts were not applied to container create: %+v", host.Mounts)
	}
	if len(host.Binds) != 2 || host.Binds[1] != bindSource+":/host-data:ro,z" {
		t.Fatalf("read-only bind mount/SELinux policy not applied: %v", host.Binds)
	}
	info, err := d.Inspect(ctx, "container-id")
	if err != nil || info.Status != "running" || info.Name != "sdk-fixture" {
		t.Fatalf("inspect=%+v err=%v", info, err)
	}
	ip, err := d.ContainerIP(ctx, "container-id", "")
	if err != nil || ip != "172.18.0.2" {
		t.Fatalf("container IP=%q err=%v", ip, err)
	}
}

func TestContainerIPDoesNotFallBackToAnotherNetwork(t *testing.T) {
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.41/containers/container-id/json" {
			t.Errorf("unexpected engine request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.18.0.2"}}}}`)
	})
	if ip, err := d.ContainerIP(context.Background(), "container-id", "cautem-net-fixture"); err == nil || ip != "" {
		t.Fatalf("container IP=%q err=%v; must fail closed when requested network has no IP", ip, err)
	}
}

func TestStaticPodmanProxyIPUsesReservedAddressAfterGateway(t *testing.T) {
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.41/networks/cautem-net-fixture" {
			t.Errorf("unexpected engine request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"Id":"network-id","Name":"cautem-net-fixture","IPAM":{"Driver":"bridge","Config":[{"Subnet":"172.27.1.0/24","Gateway":"172.27.1.1"}]}}`)
	})
	ip, err := d.staticPodmanProxyIP(context.Background(), "cautem-net-fixture")
	if err != nil || ip.String() != "172.27.1.2" {
		t.Fatalf("static Podman proxy IP=%q err=%v; want first host address after gateway", ip, err)
	}
	proxyIP, sandboxIP, err := d.staticPodmanNetworkIPs(context.Background(), "cautem-net-fixture")
	if err != nil || proxyIP.String() != "172.27.1.2" || sandboxIP.String() != "172.27.1.3" {
		t.Fatalf("static Podman network IPs=(%q, %q) err=%v; want proxy .2 and sandbox .3", proxyIP, sandboxIP, err)
	}
}

func TestCreateRunsGoSupervisorAroundHardenedInit(t *testing.T) {
	var created map[string]json.RawMessage
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1.41/containers/json" && r.Method == http.MethodGet:
			_, _ = io.WriteString(w, `[]`)
		case strings.Contains(r.URL.Path, "/images/"):
			_, _ = io.WriteString(w, `{"Id":"sha256:immutable-image-id","Config":{"User":"sandbox"}}`)
		case strings.Contains(r.URL.Path, "/networks/"):
			_, _ = io.WriteString(w, `{"Id":"network-id","Labels":{"cautem.sandbox":"1","cautem.name":"go-supervisor"}}`)
		case r.URL.Path == "/v1.41/containers/create":
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				t.Error(err)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"Id":"container-id"}`)
		default:
			t.Errorf("unexpected engine request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	makeExecutable := func(name string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte("fixture"), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policy, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := d.Create(context.Background(), driver.Spec{
		Name: "go-supervisor", Image: "sandbox:local", Workspace: t.TempDir(),
		Command: []string{"sleep", "infinity"}, InitBin: makeExecutable("cautem-init"), PolicyPath: policy,
		SupervisorBin: makeExecutable("cautem-supervisor"), MainProcessRestartPolicy: "always", TTY: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Entrypoint []string
		Cmd        []string
		User       string
		Env        []string
		TTY        bool `json:"Tty"`
		OpenStdin  bool
	}
	var host struct{ Binds []string }
	if err := json.Unmarshal(created["HostConfig"], &host); err != nil {
		t.Fatal(err)
	}
	createdJSON, err := json.Marshal(created)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(createdJSON, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Entrypoint) != 1 || config.Entrypoint[0] != "/cautem/cautem-supervisor" || config.User != "0" {
		t.Fatalf("container entrypoint/user=%v/%q, want Go supervisor PID 1 as root", config.Entrypoint, config.User)
	}
	if !config.TTY || !config.OpenStdin {
		t.Fatalf("TTY sandbox config tty/openStdin=%v/%v, want both enabled", config.TTY, config.OpenStdin)
	}
	wantArgs := []string{"--", "/cautem/cautem-init", "--policy", "/cautem/policy.yaml", "--", "sleep", "infinity"}
	if !slices.Equal(config.Cmd, wantArgs) {
		t.Fatalf("Go supervisor command=%q, want %q", config.Cmd, wantArgs)
	}
	if !containsEnvValue(config.Env, driver.MainProcessRestartPolicyEnv, "always") {
		t.Fatalf("container env does not carry the selected main process restart policy: %v", config.Env)
	}
	for _, want := range []string{"/cautem/cautem-supervisor:ro", "/cautem/cautem-init:ro", "/cautem/policy.yaml:ro"} {
		found := false
		for _, bind := range host.Binds {
			if strings.HasSuffix(bind, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("required supervisor mount %q missing in %v", want, host.Binds)
		}
	}
}

func containsEnvValue(env []string, key, want string) bool {
	for _, entry := range env {
		k, v, ok := strings.Cut(entry, "=")
		if ok && k == key && v == want {
			return true
		}
	}
	return false
}

func containsEnvKey(env []string, key string) bool {
	for _, entry := range env {
		k, _, ok := strings.Cut(entry, "=")
		if ok && k == key {
			return true
		}
	}
	return false
}

func TestSplitSDKExecEngineContract(t *testing.T) {
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.41/containers/container-id/json":
			_, _ = io.WriteString(w, `{"Config":{"Env":["PATH=/usr/bin"],"Labels":{}}}`)
		case "/v1.41/containers/container-id/exec":
			var payload struct {
				Cmd                        []string
				TTY                        bool `json:"Tty"`
				AttachStdout, AttachStderr bool
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			if len(payload.Cmd) != 2 || payload.Cmd[0] != "echo" || payload.Cmd[1] != "hello" || payload.TTY || !payload.AttachStdout || !payload.AttachStderr {
				t.Errorf("exec payload=%+v", payload)
			}
			_, _ = io.WriteString(w, `{"Id":"exec-id"}`)
		case "/v1.41/exec/exec-id/start":
			connection, buffer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = buffer.WriteString("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
			var header [8]byte
			for _, frame := range []struct {
				stream byte
				text   string
			}{{1, "stdout\n"}, {2, "stderr\n"}} {
				header[0] = frame.stream
				binary.BigEndian.PutUint32(header[4:], uint32(len(frame.text)))
				_, _ = buffer.Write(header[:])
				_, _ = buffer.WriteString(frame.text)
			}
			_ = buffer.Flush()
			// Finish the response stream with a TCP half-close, then drain the
			// client's close. Closing the socket immediately after Flush can
			// reset the connection on Windows while the Docker client is still
			// consuming the final multiplexed frame.
			if halfCloser, ok := connection.(interface{ CloseWrite() error }); ok {
				_ = halfCloser.CloseWrite()
				_, _ = io.Copy(io.Discard, buffer)
			}
			_ = connection.Close()
		case "/v1.41/exec/exec-id/json":
			_, _ = io.WriteString(w, `{"ExitCode":0,"Running":false}`)
		default:
			t.Errorf("unexpected engine request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		_ = stdoutRead.Close()
		_ = stdoutWrite.Close()
		t.Fatal(err)
	}
	previousStdout, previousStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutWrite, stderrWrite
	result, err := d.Exec(context.Background(), core.ID("container-id"), driver.ExecRequest{Argv: []string{"echo", "hello"}})
	os.Stdout, os.Stderr = previousStdout, previousStderr
	_ = stdoutWrite.Close()
	_ = stderrWrite.Close()
	stdout, stdoutErr := io.ReadAll(stdoutRead)
	stderr, stderrErr := io.ReadAll(stderrRead)
	_ = stdoutRead.Close()
	_ = stderrRead.Close()
	if stdoutErr != nil || stderrErr != nil || string(stdout) != "stdout\n" || string(stderr) != "stderr\n" {
		t.Fatalf("exec output stdout=%q (%v), stderr=%q (%v)", stdout, stdoutErr, stderr, stderrErr)
	}
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("exec result=%+v err=%v", result, err)
	}
}

func TestSplitSDKExecStreamsPipedStdinWithoutTTY(t *testing.T) {
	const input = "line from a pipe\n"
	d := sdkFixtureDriver(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.41/containers/container-id/json":
			_, _ = io.WriteString(w, `{"Config":{"Env":[],"Labels":{}}}`)
		case "/v1.41/containers/container-id/exec":
			var payload struct {
				AttachStdin bool `json:"AttachStdin"`
				TTY         bool `json:"Tty"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			if !payload.AttachStdin || payload.TTY {
				t.Errorf("exec stdin/tty flags = %+v; want stdin attached without TTY", payload)
			}
			_, _ = io.WriteString(w, `{"Id":"exec-id"}`)
		case "/v1.41/exec/exec-id/start":
			connection, buffer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = buffer.WriteString("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
			if err := buffer.Flush(); err != nil {
				t.Error(err)
				_ = connection.Close()
				return
			}
			var startOptions struct {
				Detach bool `json:"Detach"`
				TTY    bool `json:"Tty"`
			}
			decoder := json.NewDecoder(buffer)
			if err := decoder.Decode(&startOptions); err != nil {
				t.Error(err)
			}
			if startOptions.Detach || startOptions.TTY {
				t.Errorf("exec start options=%+v; want attached non-TTY stdin", startOptions)
			}
			piped, err := io.ReadAll(io.MultiReader(decoder.Buffered(), buffer))
			if err != nil || string(piped) != input {
				t.Errorf("stdin stream=%q err=%v; want %q", piped, err, input)
			}
			var header [8]byte
			header[0] = 1
			binary.BigEndian.PutUint32(header[4:], uint32(len("received\n")))
			_, _ = buffer.Write(header[:])
			_, _ = io.WriteString(buffer, "received\n")
			_ = buffer.Flush()
			if halfCloser, ok := connection.(interface{ CloseWrite() error }); ok {
				_ = halfCloser.CloseWrite()
				_, _ = io.Copy(io.Discard, buffer)
			}
			_ = connection.Close()
		case "/v1.41/exec/exec-id/json":
			_, _ = io.WriteString(w, `{"ExitCode":0,"Running":false}`)
		default:
			t.Errorf("unexpected engine request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	result, err := d.Exec(context.Background(), core.ID("container-id"), driver.ExecRequest{
		Argv:        []string{"cat"},
		StdinReader: strings.NewReader(input),
	})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("exec result=%+v err=%v", result, err)
	}
}
