package docker_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cautem/cautem-driver/driver"
	docker "github.com/cautem/cautem-driver/internal/docker"
	"github.com/moby/moby/client"
)

// TestDockerDesktopWorkspaceBindE2E checks the host-path translation and
// workspace persistence used by Docker Desktop on macOS. The test runner and
// daemon must see the same absolute workspace path through Docker Desktop's
// host file sharing.
func TestDockerDesktopWorkspaceBindE2E(t *testing.T) {
	if os.Getenv("CAUTEM_DOCKER_DESKTOP_E2E") != "1" {
		t.Skip("set CAUTEM_DOCKER_DESKTOP_E2E=1 to run against Docker Desktop")
	}
	workspace := strings.TrimSpace(os.Getenv("CAUTEM_DOCKER_WORKSPACE"))
	image := strings.TrimSpace(os.Getenv("CAUTEM_E2E_SANDBOX_IMAGE"))
	if workspace == "" || image == "" {
		t.Fatal("CAUTEM_DOCKER_WORKSPACE and CAUTEM_E2E_SANDBOX_IMAGE are required")
	}
	if err := os.MkdirAll(workspace, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(workspace, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "host-marker"), []byte("from-macos-host"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cli, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal(err)
	}
	engine := docker.NewFromClientWithRuntimeConfig(cli, docker.RuntimeConfig{
		ImagePullPolicy: "missing",
		NetworkName:     "cautem-docker-desktop-e2e",
	})
	defer engine.Close()

	name := "docker-desktop-workspace-e2e-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	handle, err := engine.Create(ctx, driver.Spec{
		Name: name, Image: image, Workspace: workspace,
		Command:  []string{"/bin/sh", "-c", "sleep 300"},
		NoHarden: true, PersistVolume: true,
	})
	if err != nil {
		t.Fatalf("create sandbox with macOS workspace bind: %v", err)
	}
	deleted := false
	defer func() {
		if !deleted {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			if err := engine.Delete(cleanupCtx, handle.ID); err != nil {
				t.Errorf("delete sandbox: %v", err)
			}
		}
	}()
	if err := engine.Start(ctx, handle.ID); err != nil {
		t.Fatalf("start sandbox: %v", err)
	}
	result, err := engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", `test "$(cat /workspace/host-marker)" = from-macos-host && printf from-sandbox > /workspace/sandbox-marker`}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("read/write through Docker Desktop workspace bind: result=%+v err=%v", result, err)
	}
	if err := engine.Stop(ctx, handle.ID); err != nil {
		t.Fatalf("stop sandbox: %v", err)
	}
	if err := engine.Start(ctx, handle.ID); err != nil {
		t.Fatalf("restart sandbox: %v", err)
	}
	result, err = engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{"/bin/sh", "-c", `test "$(cat /workspace/sandbox-marker)" = from-sandbox`}})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("workspace content did not survive stop/start: result=%+v err=%v", result, err)
	}
	data, err := os.ReadFile(filepath.Join(workspace, "sandbox-marker"))
	if err != nil || string(data) != "from-sandbox" {
		t.Fatalf("Docker Desktop host did not observe sandbox workspace write: data=%q err=%v", data, err)
	}
	if err := engine.Delete(ctx, handle.ID); err != nil {
		t.Fatalf("delete sandbox: %v", err)
	}
	deleted = true
}

// TestDockerDesktopHostGatewayIsolationE2E proves that an ordinary sandbox
// can reach the macOS host service through Docker Desktop, then verifies that
// the proxy-isolated sandbox cannot use the same route to bypass its broker.
func TestDockerDesktopHostGatewayIsolationE2E(t *testing.T) {
	if os.Getenv("CAUTEM_DOCKER_DESKTOP_HOST_BOUNDARY_E2E") != "1" {
		t.Skip("set CAUTEM_DOCKER_DESKTOP_HOST_BOUNDARY_E2E=1 to run the host-boundary lane")
	}
	workspace := strings.TrimSpace(os.Getenv("CAUTEM_DOCKER_WORKSPACE"))
	image := strings.TrimSpace(os.Getenv("CAUTEM_E2E_SANDBOX_IMAGE"))
	helperDir := strings.TrimSpace(os.Getenv("CAUTEM_HELPERS_DIR"))
	proxyImage := strings.TrimSpace(os.Getenv("CAUTEM_PROXY_IMAGE"))
	if workspace == "" || image == "" || helperDir == "" || proxyImage == "" {
		t.Fatal("CAUTEM_DOCKER_WORKSPACE, CAUTEM_E2E_SANDBOX_IMAGE, CAUTEM_HELPERS_DIR and CAUTEM_PROXY_IMAGE are required")
	}
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(workspace, "docker-desktop-host-boundary-policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\nnetwork_policies: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ipv4Listener, ipv4Accepted := startDockerDesktopProbeListener(t, "tcp4", "0.0.0.0:0")
	ipv6Address := dockerDesktopHostIPv6Address(t)
	ipv6Listener, ipv6Accepted := startDockerDesktopProbeListener(t, "tcp6", net.JoinHostPort(ipv6Address.String(), "0"))
	ipv4Target := net.JoinHostPort("host.docker.internal", strconv.Itoa(ipv4Listener.Addr().(*net.TCPAddr).Port))
	ipv6Target := net.JoinHostPort(ipv6Address.String(), strconv.Itoa(ipv6Listener.Addr().(*net.TCPAddr).Port))

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cli, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal(err)
	}
	runID := strconv.FormatInt(time.Now().UnixNano(), 36)
	networkPrefix := "cautem-docker-desktop-host-boundary"
	engine := docker.NewFromClientWithRuntimeConfig(cli, docker.RuntimeConfig{
		ImagePullPolicy: "missing",
		NetworkName:     networkPrefix,
	})
	defer engine.Close()
	probe := func(name string, spec driver.Spec, targets []string, wantExit int) {
		t.Helper()
		handle, err := engine.Create(ctx, spec)
		if err != nil {
			t.Fatalf("create sandbox %s: %v", name, err)
		}
		defer func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			if err := engine.Delete(cleanupCtx, handle.ID); err != nil {
				t.Errorf("delete sandbox %s: %v", name, err)
			}
		}()
		if err := engine.Start(ctx, handle.ID); err != nil {
			t.Fatalf("start sandbox %s: %v", name, err)
		}
		for _, target := range targets {
			result, err := engine.Exec(ctx, handle.ID, driver.ExecRequest{Argv: []string{
				"/usr/local/bin/cautem-tcp-echo", "probe-tcp", target,
			}})
			if err != nil || result.ExitCode != wantExit {
				t.Fatalf("sandbox %s host-route probe %s result=%+v err=%v; want exit %d", name, target, result, err, wantExit)
			}
		}
	}

	base := driver.Spec{
		Name: "desktop-host-open-" + runID, Image: image, Workspace: workspace,
		Command: []string{"/bin/sh", "-c", "sleep 300"}, NoHarden: true,
	}
	publicNetwork := networkPrefix + "-" + base.Name
	ipv6Enabled := true
	if _, err := cli.NetworkCreate(ctx, publicNetwork, client.NetworkCreateOptions{
		Driver: "bridge", EnableIPv6: &ipv6Enabled,
		Labels: map[string]string{"cautem.sandbox": "1", "cautem.name": base.Name, "cautem.role": "network"},
	}); err != nil {
		t.Fatalf("create dual-stack control network: %v", err)
	}
	defer func() { _, _ = cli.NetworkRemove(context.Background(), publicNetwork, client.NetworkRemoveOptions{}) }()
	publicInfo, err := cli.NetworkInspect(ctx, publicNetwork, client.NetworkInspectOptions{})
	if err != nil || !publicInfo.Network.EnableIPv6 {
		t.Fatalf("control network IPv6 enabled=%t err=%v", publicInfo.Network.EnableIPv6, err)
	}
	probe(base.Name, base, []string{ipv4Target, ipv6Target}, 2)
	waitForDockerDesktopProbeAccepted(t, ipv4Accepted, 1, "IPv4")
	waitForDockerDesktopProbeAccepted(t, ipv6Accepted, 1, "IPv6")
	ipv4ConnectionsBeforeIsolation := ipv4Accepted.Load()
	ipv6ConnectionsBeforeIsolation := ipv6Accepted.Load()

	isolated := driver.Spec{
		Name: "desktop-host-blocked-" + runID, Image: image, Workspace: workspace,
		Command: []string{"/bin/sh", "-c", "sleep 300"}, NoHarden: true,
		ProxyBin: filepath.Join(helperDir, "cautem"), ProxyImage: proxyImage, PolicyPath: policyPath,
	}
	probe(isolated.Name, isolated, []string{ipv4Target, ipv6Target}, 0)
	if ipv4Accepted.Load() != ipv4ConnectionsBeforeIsolation || ipv6Accepted.Load() != ipv6ConnectionsBeforeIsolation {
		t.Fatalf("isolated sandbox reached the macOS host listener: IPv4 before=%d after=%d; IPv6 before=%d after=%d",
			ipv4ConnectionsBeforeIsolation, ipv4Accepted.Load(), ipv6ConnectionsBeforeIsolation, ipv6Accepted.Load())
	}
	fmt.Fprintf(os.Stderr, "Docker Desktop host IPv4 and IPv6 routes accepted by the dual-stack control sandbox and blocked by the isolated sandbox (IPv4 %s, IPv6 %s)\n", ipv4Target, ipv6Target)
}

func startDockerDesktopProbeListener(t *testing.T, network, address string) (net.Listener, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatalf("listen on macOS host %s %s: %v", network, address, err)
	}
	accepted := new(atomic.Int32)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return listener, accepted
}

func dockerDesktopHostIPv6Address(t *testing.T) netip.Addr {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list macOS host interfaces: %v", err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr()
			if ip.Is6() && ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
				return ip
			}
		}
	}
	t.Fatal("macOS host has no non-link-local IPv6 address for the dual-stack acceptance target")
	return netip.Addr{}
}

func waitForDockerDesktopProbeAccepted(t *testing.T, accepted *atomic.Int32, want int32, family string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for accepted.Load() < want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := accepted.Load(); got < want {
		t.Fatalf("ordinary dual-stack Docker Desktop sandbox reported an %s host connection, but the macOS listener accepted %d; want at least %d", family, got, want)
	}
}
