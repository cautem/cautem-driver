package docker_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cautem/cautem-core"
	"github.com/cautem/cautem-driver/driver"
	docker "github.com/cautem/cautem-driver/internal/docker"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// TestDockerEngineE2E exercises the Docker driver lifecycle against the
// disposable Docker-in-Docker daemon started by tools/e2e/docker.sh.
func TestDockerEngineE2E(t *testing.T) {
	if os.Getenv("CAUTEM_DOCKER_E2E") != "1" {
		t.Skip("set CAUTEM_DOCKER_E2E=1 to run against a disposable Docker daemon")
	}
	workspace := strings.TrimSpace(os.Getenv("CAUTEM_DOCKER_WORKSPACE"))
	if workspace == "" {
		t.Fatal("CAUTEM_DOCKER_WORKSPACE must name a directory visible to the Docker daemon")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	image := strings.TrimSpace(os.Getenv("CAUTEM_E2E_SANDBOX_IMAGE"))
	if image == "" {
		image = "localhost/cautem-connect-e2e:latest"
	}
	helperDir := strings.TrimSpace(os.Getenv("CAUTEM_HELPERS_DIR"))
	proxyBin := filepath.Join(helperDir, "cautem")
	proxyImage := strings.TrimSpace(os.Getenv("CAUTEM_PROXY_IMAGE"))
	policyPath := filepath.Join(workspace, "docker-driver-deny-policy.yaml")
	if helperDir == "" || proxyImage == "" {
		t.Fatal("CAUTEM_HELPERS_DIR and CAUTEM_PROXY_IMAGE are required for policy E2E")
	}
	if err := os.WriteFile(policyPath, []byte("version: 1\nnetwork_policies: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bindSource := filepath.Join(workspace, "docker-driver-config-bind")
	if err := os.MkdirAll(bindSource, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bindSource, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bindSource, "marker"), []byte("bind-ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	cli, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal(err)
	}
	engine := docker.NewFromClientWithRuntimeConfig(cli, docker.RuntimeConfig{
		ImagePullPolicy:  "missing",
		NetworkName:      "cautem-docker-driver-e2e",
		EnableBindMounts: true,
	})
	defer engine.Close()
	partialName := "docker-partial-failure"
	if _, err := engine.Create(ctx, driver.Spec{
		Name: partialName, Image: image, Workspace: workspace,
		ProxyBin: filepath.Join(workspace, "missing-proxy-binary"), ProxyImage: proxyImage, PolicyPath: policyPath,
	}); err == nil {
		t.Fatal("partial create with missing proxy binary unexpectedly succeeded")
	}
	if _, err := cli.NetworkInspect(ctx, "cautem-docker-driver-e2e-"+partialName, client.NetworkInspectOptions{}); err == nil {
		t.Fatal("partial proxy create left its isolated network behind")
	}
	if _, err := cli.VolumeInspect(ctx, "cautem-ca-"+partialName, client.VolumeInspectOptions{}); err == nil {
		t.Fatal("partial proxy create left its CA volume behind")
	}
	policyNetwork := fmt.Sprintf("cautem-docker-policy-e2e-%d", time.Now().UnixNano())
	if _, err := cli.NetworkCreate(ctx, policyNetwork, client.NetworkCreateOptions{Driver: "bridge", Internal: true, Labels: map[string]string{"cautem": "policy-e2e"}}); err != nil {
		t.Fatalf("create proxy-isolated network: %v", err)
	}
	defer func() { _, _ = cli.NetworkRemove(context.Background(), policyNetwork, client.NetworkRemoveOptions{}) }()
	policyNetworkInfo, err := cli.NetworkInspect(ctx, policyNetwork, client.NetworkInspectOptions{})
	if err != nil || !policyNetworkInfo.Network.Internal {
		t.Fatalf("proxy policy network inspect internal=%t err=%v; want internal network", policyNetworkInfo.Network.Internal, err)
	}

	runID := time.Now().UnixNano()
	name := fmt.Sprintf("docker-e2e-%d", runID)
	volumeName := fmt.Sprintf("cautem-docker-e2e-cache-%d", runID)
	handle, err := engine.Create(ctx, driver.Spec{
		Name: name, Image: image, Workspace: workspace,
		Command:  []string{"/bin/sh", "-c", "echo cautem-docker-e2e-ready; sleep 300"},
		NoHarden: true, PersistVolume: true, CPU: 0.5, MemoryBytes: 256 << 20, PidsLimit: 128,
		ProxyBin: proxyBin, ProxyImage: proxyImage, PolicyPath: policyPath,
		DriverConfigJSON: fmt.Sprintf(`{"mounts":[{"type":"bind","source":%s,"target":"/openshell-bind","read_only":true},{"type":"volume","source":%s,"target":"/openshell-volume","read_only":false},{"type":"tmpfs","target":"/openshell-tmpfs","read_only":false,"size_bytes":4096,"mode":448}]}`, strconv.Quote(bindSource), strconv.Quote(volumeName)),
	})
	if err != nil {
		t.Fatalf("create sandbox through Docker Engine API: %v", err)
	}
	deleted := false
	defer func() {
		if deleted {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := engine.Delete(cleanupCtx, handle.ID); err != nil {
			t.Errorf("delete sandbox: %v", err)
		}
		_, _ = cli.VolumeRemove(cleanupCtx, volumeName, client.VolumeRemoveOptions{Force: true})
	}()
	imageInfo, err := cli.ImageInspect(ctx, image)
	if err != nil {
		t.Fatalf("inspect pinned image: %v", err)
	}
	if err := engine.Start(ctx, handle.ID); err != nil {
		t.Fatalf("start sandbox: %v", err)
	}
	probeTarget, closeProbeTarget := startPolicyProbeTarget(t, ctx, cli, image)
	defer closeProbeTarget()
	targetHost, targetPort, err := net.SplitHostPort(probeTarget)
	if err != nil {
		t.Fatal(err)
	}
	upstreamProxyID, upstreamProxyAddr := startUpstreamProxy(t, ctx, cli, image)
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		_, _ = cli.ContainerRemove(cleanupCtx, upstreamProxyID, client.ContainerRemoveOptions{Force: true})
	}()
	upstreamAuth := filepath.Join(workspace, "docker-upstream-proxy-auth")
	if err := os.WriteFile(upstreamAuth, []byte("robot:s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	upstreamPolicy := filepath.Join(workspace, "docker-upstream-proxy-policy.yaml")
	if err := os.WriteFile(upstreamPolicy, []byte(fmt.Sprintf("version: 1\nnetwork_policies:\n  upstream:\n    endpoints:\n      - host: %s\n        port: %s\n", targetHost, targetPort)), 0o644); err != nil {
		t.Fatal(err)
	}
	upstreamEngine := docker.NewFromClientWithRuntimeConfig(cli, docker.RuntimeConfig{
		ImagePullPolicy:                "missing",
		NetworkName:                    "cautem-docker-upstream-e2e",
		EnableBindMounts:               true,
		UpstreamProxyURL:               "http://" + upstreamProxyAddr,
		UpstreamProxyAuthFile:          upstreamAuth,
		UpstreamProxyAuthAllowInsecure: true,
	})
	upstreamName := fmt.Sprintf("docker-upstream-%d", time.Now().UnixNano())
	upstreamHandle, err := upstreamEngine.Create(ctx, driver.Spec{
		Name: upstreamName, Image: image, Workspace: workspace, Command: []string{"sleep", "300"},
		NoHarden: true, ProxyBin: proxyBin, ProxyImage: proxyImage, PolicyPath: upstreamPolicy,
	})
	if err != nil {
		t.Fatalf("create upstream-proxy sandbox: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = upstreamEngine.Delete(cleanupCtx, upstreamHandle.ID)
	}()
	if err := upstreamEngine.Start(ctx, upstreamHandle.ID); err != nil {
		t.Fatalf("start upstream-proxy sandbox: %v", err)
	}
	upstreamProxyInfo, err := cli.ContainerInspect(ctx, "cautem-proxy-"+upstreamName, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(upstreamProxyInfo.Container.Config.Env, "CAUTEM_PROXY_AUTH_FILE=/run/cautem/upstream-proxy/auth") || !slices.Contains(upstreamProxyInfo.Container.HostConfig.Binds, upstreamAuth+":/run/cautem/upstream-proxy/auth:ro") {
		t.Fatalf("upstream proxy auth wiring missing: env=%v binds=%v", upstreamProxyInfo.Container.Config.Env, upstreamProxyInfo.Container.HostConfig.Binds)
	}
	result, err := upstreamEngine.Exec(ctx, core.ID(upstreamProxyInfo.Container.ID), driver.ExecRequest{Argv: []string{"/usr/local/bin/cautem-tcp-echo", "probe-connect-status", probeTarget, "200"}})
	if err != nil || result.ExitCode != 0 {
		logs, _ := cli.ContainerLogs(ctx, upstreamProxyID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: "20"})
		var logBuf bytes.Buffer
		if logs != nil {
			_, _ = io.Copy(&logBuf, logs)
			_ = logs.Close()
		}
		t.Fatalf("authenticated upstream proxy CONNECT result=%+v err=%v logs=%q", result, err, logBuf.String())
	}
	proxyNetwork, err := cli.NetworkInspect(ctx, "cautem-docker-driver-e2e-"+name, client.NetworkInspectOptions{})
	if err != nil || !proxyNetwork.Network.Internal || proxyNetwork.Network.Options["com.docker.network.bridge.gateway_mode_ipv4"] != "isolated" || proxyNetwork.Network.Options["com.docker.network.bridge.gateway_mode_ipv6"] != "isolated" {
		t.Fatalf("actual Docker sandbox network internal=%v options=%v err=%v; want isolated internal gateway", proxyNetwork.Network.Internal, proxyNetwork.Network.Options, err)
	}
	if len(proxyNetwork.Network.IPAM.Config) == 0 || !proxyNetwork.Network.IPAM.Config[0].Subnet.IsValid() {
		t.Fatal("isolated network does not report an IPv4 subnet for the direct host reachability probe")
	}
	// Isolated mode deliberately has no assigned gateway address; probe the
	// conventional first subnet address where a bridge gateway would normally sit.
	hostGatewayTarget, closeHostGateway := startHostGatewayProbeTarget(t, ctx, cli, image, proxyNetwork.Network.IPAM.Config[0].Subnet.Addr().Next().String())
	defer closeHostGateway()
	proxyInfo, err := cli.ContainerInspect(ctx, "cautem-proxy-"+name, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatalf("inspect Docker policy proxy sidecar: %v", err)
	}
	for _, probe := range [][]string{{"probe-tcp", probeTarget}, {"probe-udp", strings.TrimSuffix(probeTarget, ":17777") + ":17778"}} {
		result, err := engine.Exec(ctx, core.ID(proxyInfo.Container.ID), driver.ExecRequest{Argv: append([]string{"/usr/local/bin/cautem-tcp-echo"}, probe...)})
		if err != nil || result.ExitCode != 2 {
			t.Fatalf("policy sidecar could not reach control listener via bridge: probe=%v exit=%d err=%v", probe, result.ExitCode, err)
		}
	}
	for _, probe := range [][]string{
		{"probe-connect", probeTarget},
		{"probe-tcp", probeTarget},
		{"probe-udp", strings.TrimSuffix(probeTarget, ":17777") + ":17778"},
	} {
		result, err := engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: append([]string{"/usr/local/bin/cautem-tcp-echo"}, probe...)})
		if err != nil || result.ExitCode != 0 {
			t.Fatalf("network policy probe %v exit=%d err=%v; want denied", probe, result.ExitCode, err)
		}
	}
	if result, err := engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{"/usr/local/bin/cautem-tcp-echo", "probe-tcp", hostGatewayTarget}}); err != nil || result.ExitCode != 0 {
		t.Fatalf("sandbox reached host gateway directly at %s: result=%+v err=%v", hostGatewayTarget, result, err)
	}
	info, err := engine.Inspect(ctx, string(handle.ID))
	if err != nil {
		t.Fatalf("inspect sandbox: %v", err)
	}
	if !strings.Contains(strings.ToLower(info.Status), "running") && !strings.Contains(strings.ToLower(info.Status), "up") {
		t.Fatalf("sandbox status = %q, want running", info.Status)
	}
	inspected, err := cli.ContainerInspect(ctx, string(handle.ID), client.ContainerInspectOptions{})
	if err != nil {
		t.Fatalf("inspect Docker template effects: %v", err)
	}
	host := inspected.Container.HostConfig
	if host == nil || len(host.Mounts) != 2 || !strings.Contains(strings.Join(host.Binds, "\n"), ":/openshell-bind:ro") || !slices.Contains(host.SecurityOpt, "no-new-privileges:true") || !slices.Contains(host.CapDrop, "CAP_NET_RAW") {
		t.Fatalf("Docker template mount/security effects missing: %+v", inspected.Container.HostConfig)
	}
	if host.NanoCPUs != 500_000_000 || host.Memory != 256<<20 || host.PidsLimit == nil || *host.PidsLimit != 128 {
		t.Fatalf("Docker resource limits did not reach Engine create: nano_cpus=%d memory=%d pids=%v", host.NanoCPUs, host.Memory, host.PidsLimit)
	}
	if inspected.Container.Image != imageInfo.ID {
		t.Fatalf("container image ID=%q, inspected image ID=%q; create must pin immutable image identity", inspected.Container.Image, imageInfo.ID)
	}
	command := `set -eu
test "$(id -u)" = 1000
grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status
test "$(cat /openshell-bind/marker)" = bind-ok
if touch /openshell-bind/write-denied 2>/dev/null; then exit 41; fi
printf persisted > /cautem/data/persisted
printf volume > /openshell-volume/persisted
test "$(stat -c %a /openshell-tmpfs)" = 700
cap=$(awk '/^CapBnd:/ {print $2}' /proc/self/status)
[ $((0x$cap & 0x2000)) -eq 0 ]`
	result, err = engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", command}})
	if err != nil {
		t.Fatalf("exec in sandbox: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exec exit code = %d, want 0", result.ExitCode)
	}
	if err := engine.Stop(ctx, handle.ID); err != nil {
		t.Fatalf("stop sandbox: %v", err)
	}
	if err := engine.Start(ctx, handle.ID); err != nil {
		t.Fatalf("restart sandbox: %v", err)
	}
	result, err = engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", `set -eu; test "$(cat /cautem/data/persisted)" = persisted; test "$(cat /openshell-volume/persisted)" = volume; test "$(stat -c %a /openshell-tmpfs)" = 700`}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("stop/start persistence and tmpfs reset: result=%+v err=%v", result, err)
	}
	var logs bytes.Buffer
	if err := engine.Logs(ctx, handle.ID, false, &logs); err != nil || !strings.Contains(logs.String(), "cautem-docker-e2e-ready") {
		t.Fatalf("sandbox logs=%q err=%v, expected readiness marker", logs.String(), err)
	}
	if err := engine.Stop(ctx, handle.ID); err != nil {
		t.Fatalf("stop restarted sandbox: %v", err)
	}
	if err := engine.Delete(ctx, handle.ID); err != nil {
		t.Fatalf("delete sandbox: %v", err)
	}
	deleted = true
	if _, err := cli.ContainerInspect(ctx, string(handle.ID), client.ContainerInspectOptions{}); err == nil {
		t.Fatalf("container %s still exists after delete", handle.ID)
	}
	if _, err := cli.VolumeRemove(ctx, volumeName, client.VolumeRemoveOptions{Force: true}); err != nil {
		t.Errorf("remove E2E named volume: %v", err)
	}
}

func startHostGatewayProbeTarget(t *testing.T, ctx context.Context, engine *client.Client, image, gateway string) (string, func()) {
	t.Helper()
	created, err := engine.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name:       "cautem-docker-host-gateway-probe-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		Config:     &container.Config{Image: image, User: "0", Entrypoint: []string{"/bin/sh"}, Cmd: []string{"-c", "/usr/local/bin/cautem-tcp-echo serve-tcp 0.0.0.0:17779 & wait"}},
		HostConfig: &container.HostConfig{NetworkMode: "host"},
	})
	if err != nil {
		t.Fatalf("create host-network policy probe: %v", err)
	}
	cleanup := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = engine.ContainerKill(cleanupCtx, created.ID, client.ContainerKillOptions{Signal: "KILL"})
		_, _ = engine.ContainerRemove(cleanupCtx, created.ID, client.ContainerRemoveOptions{Force: true})
	}
	if _, err := engine.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		cleanup()
		t.Fatalf("start host-network policy probe: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if policyProbeContainerExit(ctx, engine, created.ID, "probe-tcp", "127.0.0.1:17779") == 2 {
			return net.JoinHostPort(gateway, "17779"), cleanup
		}
		time.Sleep(50 * time.Millisecond)
	}
	cleanup()
	t.Fatal("host-network policy-probe listener did not become reachable")
	return "", func() {}
}

func startUpstreamProxy(t *testing.T, ctx context.Context, engine *client.Client, image string) (string, string) {
	t.Helper()
	created, err := engine.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: "cautem-docker-upstream-proxy-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		Config: &container.Config{
			Image: image, Entrypoint: []string{"/usr/local/bin/cautem-tcp-echo"},
			Cmd: []string{"serve-proxy", "0.0.0.0:17880", "robot", "s3cret"},
		},
		HostConfig: &container.HostConfig{NetworkMode: "bridge"},
	})
	if err != nil {
		t.Fatalf("create upstream proxy: %v", err)
	}
	if _, err := engine.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		_, _ = engine.ContainerRemove(context.Background(), created.ID, client.ContainerRemoveOptions{Force: true})
		t.Fatalf("start upstream proxy: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		inspect, inspectErr := engine.ContainerInspect(ctx, created.ID, client.ContainerInspectOptions{})
		if inspectErr == nil && inspect.Container.NetworkSettings != nil {
			for _, network := range inspect.Container.NetworkSettings.Networks {
				if network.IPAddress.IsValid() {
					return created.ID, net.JoinHostPort(network.IPAddress.String(), "17880")
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, _ = engine.ContainerRemove(context.Background(), created.ID, client.ContainerRemoveOptions{Force: true})
	t.Fatal("upstream proxy did not receive a bridge IP")
	return "", ""
}

func startPolicyProbeTarget(t *testing.T, ctx context.Context, engine *client.Client, image string) (string, func()) {
	t.Helper()
	created, err := engine.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: "cautem-docker-policy-probe-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		Config: &container.Config{
			Image: image, User: "0", Entrypoint: []string{"/bin/sh"},
			Cmd: []string{"-c", "/usr/local/bin/cautem-tcp-echo serve-tcp 0.0.0.0:17777 & /usr/local/bin/cautem-tcp-echo serve-udp 0.0.0.0:17778 & wait"},
		},
		HostConfig: &container.HostConfig{NetworkMode: "bridge"},
	})
	if err != nil {
		t.Fatalf("create reachable policy-probe target on bridge: %v", err)
	}
	cleanup := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = engine.ContainerKill(cleanupCtx, created.ID, client.ContainerKillOptions{Signal: "KILL"})
		_, _ = engine.ContainerRemove(cleanupCtx, created.ID, client.ContainerRemoveOptions{Force: true})
	}
	if _, err := engine.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		cleanup()
		t.Fatalf("start reachable policy-probe target: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var address string
	for time.Now().Before(deadline) {
		inspect, inspectErr := engine.ContainerInspect(ctx, created.ID, client.ContainerInspectOptions{})
		if inspectErr == nil && inspect.Container.NetworkSettings != nil {
			for _, network := range inspect.Container.NetworkSettings.Networks {
				if network.IPAddress.IsValid() {
					address = net.JoinHostPort(network.IPAddress.String(), "17777")
					break
				}
			}
		}
		if address != "" {
			if policyProbeContainerExit(ctx, engine, created.ID, "probe-tcp", "127.0.0.1:17777") == 2 &&
				policyProbeContainerExit(ctx, engine, created.ID, "probe-udp", "127.0.0.1:17778") == 2 {
				return address, cleanup
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	cleanup()
	t.Fatal("policy-probe TCP and UDP listeners did not become reachable")
	return "", func() {}
}

func policyProbeContainerExit(ctx context.Context, engine *client.Client, containerID, mode, target string) int {
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	created, err := engine.ExecCreate(checkCtx, containerID, client.ExecCreateOptions{
		TTY: true, AttachStdout: true, AttachStderr: true,
		Cmd: []string{"/usr/local/bin/cautem-tcp-echo", mode, target},
	})
	if err != nil {
		return -1
	}
	attach, err := engine.ExecAttach(checkCtx, created.ID, client.ExecAttachOptions{TTY: true})
	if err != nil {
		return -1
	}
	_, _ = io.Copy(io.Discard, attach.Reader)
	attach.Close()
	result, err := engine.ExecInspect(checkCtx, created.ID, client.ExecInspectOptions{})
	if err != nil {
		return -1
	}
	return result.ExitCode
}
