// Package docker implements driver.ComputeDriver via the Docker Engine API.
package docker

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"path/filepath"

	core "github.com/cautem/cautem-core"
	"github.com/cautem/cautem-core/defaults"
	"github.com/cautem/quarshell-driver/driver"
)

func (d *Driver) createProxySidecar(ctx context.Context, name, netName, img, binPath, policyPath string, port int, caVol, sshVol, tcpDialSocket string, proxyEnv []string, pidsLimit int64) error {
	proxyPort, err := network.ParsePort(fmt.Sprintf("%d/tcp", port))
	if err != nil {
		return fmt.Errorf("docker proxy port: %w", err)
	}
	if _, err := os.Stat(binPath); err != nil {
		return fmt.Errorf("docker proxy bin: %w", err)
	}
	if policyPath == "" {
		return fmt.Errorf("docker proxy: policy path required")
	}
	if _, err := os.Stat(policyPath); err != nil {
		return fmt.Errorf("docker proxy policy: %w", err)
	}
	ctrName := "cautem-proxy-" + name

	binds := []string{
		binPath + ":/cautem/cautem:ro",
		policyPath + ":/cautem/policy.yaml:ro",
	}
	for _, entry := range []struct{ source, target string }{
		{d.runtimeConfig.UpstreamProxyAuthFile, "/run/cautem/upstream-proxy/auth"},
		{d.runtimeConfig.UpstreamProxyCABundle, "/run/cautem/upstream-proxy/ca.pem"},
		{d.runtimeConfig.EgressCABundle, "/run/cautem/egress-ca/ca.pem"},
	} {
		if entry.source == "" {
			continue
		}
		f, err := os.Open(entry.source)
		if err != nil {
			return fmt.Errorf("docker upstream proxy file is unavailable")
		}
		info, statErr := f.Stat()
		closeErr := f.Close()
		if statErr != nil || closeErr != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("docker upstream proxy path must be a readable regular file")
		}
		binds = append(binds, entry.source+":"+entry.target+":ro")
	}
	if d.runtimeConfig.GuestTLSCA != "" {
		for _, path := range []string{d.runtimeConfig.GuestTLSCA, d.runtimeConfig.GuestTLSCert, d.runtimeConfig.GuestTLSKey} {
			f, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("docker guest TLS file is unavailable")
			}
			info, statErr := f.Stat()
			closeErr := f.Close()
			if statErr != nil || closeErr != nil || !info.Mode().IsRegular() {
				return fmt.Errorf("docker guest TLS path must be a readable regular file")
			}
		}
		binds = append(binds,
			d.runtimeConfig.GuestTLSCA+":/run/cautem/gateway-tls/ca.pem:ro",
			d.runtimeConfig.GuestTLSCert+":/run/cautem/gateway-tls/cert.pem:ro",
			d.runtimeConfig.GuestTLSKey+":/run/cautem/gateway-tls/key.pem:ro",
		)
	}
	cmd := []string{
		"proxy",
		"--listen", fmt.Sprintf("0.0.0.0:%d", port),
		"--policy", "/cautem/policy.yaml",
	}
	if caVol != "" {
		binds = append(binds, caVol+":/cautem/ca:rw")
		cmd = append(cmd, "--ca-out", "/cautem/ca/ca.pem")
	}
	env := append([]string{}, proxyEnv...)
	env = mergeEnv(env, d.upstreamProxyEnv())
	env = mergeEnv(env, d.egressTrustEnv())
	if d.runtimeConfig.GuestTLSCA != "" {
		env = mergeEnv(env, []string{
			"CAUTEM_GUEST_TLS_CA=/run/cautem/gateway-tls/ca.pem",
			"CAUTEM_GUEST_TLS_CERT=/run/cautem/gateway-tls/cert.pem",
			"CAUTEM_GUEST_TLS_KEY=/run/cautem/gateway-tls/key.pem",
		})
	}
	if d.runtimeConfig.ProviderSPIFFEWorkloadAPISocket != "" {
		env = mergeEnv(env, []string{"CAUTEM_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET=" + d.runtimeConfig.ProviderSPIFFEWorkloadAPISocket})
	}
	if d.runtimeConfig.GatewayGRPCEndpoint != "" {
		env = mergeEnv(env, []string{"CAUTEM_GATEWAY_GRPC_ENDPOINT=" + d.runtimeConfig.GatewayGRPCEndpoint})
	}
	if d.runtimeConfig.GatewayGRPCPort > 0 {
		env = mergeEnv(env, []string{fmt.Sprintf("CAUTEM_GATEWAY_GRPC_PORT=%d", d.runtimeConfig.GatewayGRPCPort)})
	}
	if socketPath, err := providerWorkloadSocket(env); err != nil {
		return fmt.Errorf("docker proxy SPIFFE socket: %w", err)
	} else if socketPath != "" {
		binds = append(binds, socketPath+":"+socketPath)
	}
	if sshVol != "" {
		// Supervisor relay: the sidecar dials sshd on the shared root-only socket.
		sshSocket := strings.TrimSpace(d.runtimeConfig.SandboxSSHSocketPath)
		if sshSocket == "" {
			sshSocket = defaults.GuestSSHSocket
		}
		sshDir := filepath.Dir(sshSocket)
		binds = append(binds, sshVol+":"+sshDir+":rw")
		env = mergeEnv(env, []string{"CAUTEM_SSH_SOCKET=" + sshSocket, "CAUTEM_SANDBOX=" + name})
		if strings.TrimSpace(d.runtimeConfig.GatewayGRPCEndpoint) != "" {
			controlSocket := filepath.Join(sshDir, driver.SupervisorControlSocketName)
			env = mergeEnv(env, []string{"CAUTEM_SUPERVISOR_CONTROL_SOCKET=" + controlSocket})
		}
		if tcpDialSocket != "" {
			env = mergeEnv(env, []string{"CAUTEM_TCP_DIAL_SOCKET=" + tcpDialSocket})
		}
	}

	absPolicy := policyPath
	if a, err := filepath.Abs(policyPath); err == nil {
		absPolicy = a
	}
	cfg := &container.Config{
		Image: img,
		// Agent images (cursor/claude) set ENTRYPOINT=/usr/local/bin/cautem-init — that must
		// NOT wrap the sidecar. Entrypoint is the mounted linux CLI; Cmd is proxy args.
		Entrypoint: []string{"/cautem/cautem"},
		Cmd:        cmd,
		Env:        env,
		Labels: map[string]string{
			labelSandbox: "1",
			labelName:    name,
			labelNetwork: netName,
			labelRole:    roleProxy,
			labelPolicy:  absPolicy,
		},
		ExposedPorts: network.PortSet{
			proxyPort: {},
		},
	}
	// OpenShell-style: host.cautem.internal → host-gateway so the sidecar can
	// ResolveSecrets from cautem-gateway on the host (no runtime hostname fallback).
	host := &container.HostConfig{
		Binds:       binds,
		NetworkMode: container.NetworkMode(netName),
		ExtraHosts:  d.hostGatewayExtraHosts(),
		LogConfig:   sandboxLogConfig(d.runtimeConfig.LogDriver),
		Resources: container.Resources{
			PidsLimit: resolvePidsLimit(d.configuredPidsLimit(pidsLimit)),
		},
	}
	proxyEndpoint := &network.EndpointSettings{Aliases: []string{"cautem-proxy", ctrName}}
	if d.runtimeConfig.BackendID == "podman" {
		proxyIP, sandboxIP, err := d.staticPodmanNetworkIPs(ctx, netName)
		if err != nil {
			return fmt.Errorf("docker proxy %s: reserve Podman isolated-network addresses: %w", ctrName, err)
		}
		proxyEndpoint.IPAMConfig = &network.EndpointIPAMConfig{IPv4Address: proxyIP}
		host.ExtraHosts = append(host.ExtraHosts, "cautem-"+name+":"+sandboxIP.String())
	}
	networking := &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{netName: proxyEndpoint}}
	resp, err := d.cli.ContainerCreate(ctx, client.ContainerCreateOptions{Config: cfg, HostConfig: host, NetworkingConfig: networking, Name: ctrName})
	if err != nil {
		return fmt.Errorf("docker create proxy %s: %w", ctrName, err)
	}
	// Dual-home onto the default bridge so the proxy can reach the internet
	// while the sandbox stays on an internal network only.
	if _, err := d.cli.NetworkConnect(ctx, "bridge", client.NetworkConnectOptions{Container: resp.ID}); err != nil {
		_, _ = d.cli.ContainerRemove(ctx, resp.ID, client.ContainerRemoveOptions{Force: true})
		return fmt.Errorf("docker proxy bridge connect: %w", err)
	}
	if _, err := d.cli.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		_, _ = d.cli.ContainerRemove(ctx, resp.ID, client.ContainerRemoveOptions{Force: true})
		return fmt.Errorf("docker start proxy: %w", err)
	}
	if caVol != "" {
		if err := d.waitProxyCA(ctx, resp.ID, readinessTimeout); err != nil {
			_, _ = d.cli.ContainerRemove(ctx, resp.ID, client.ContainerRemoveOptions{Force: true})
			return err
		}
	}
	if err := d.waitProxyListening(ctx, resp.ID, port, readinessTimeout); err != nil {
		_, _ = d.cli.ContainerRemove(ctx, resp.ID, client.ContainerRemoveOptions{Force: true})
		return err
	}
	return nil
}

func (d *Driver) staticPodmanProxyIP(ctx context.Context, netName string) (netip.Addr, error) {
	proxyIP, _, err := d.staticPodmanNetworkIPs(ctx, netName)
	return proxyIP, err
}

func (d *Driver) staticPodmanNetworkIPs(ctx context.Context, netName string) (netip.Addr, netip.Addr, error) {
	if d == nil || d.cli == nil || strings.TrimSpace(netName) == "" {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("podman network client or name is unavailable")
	}
	inspected, err := d.cli.NetworkInspect(ctx, netName, client.NetworkInspectOptions{})
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("inspect isolated network: %w", err)
	}
	for _, config := range inspected.Network.IPAM.Config {
		if !config.Subnet.IsValid() || !config.Subnet.Addr().Is4() || config.Subnet.Bits() > 30 || !config.Gateway.Is4() || !config.Subnet.Contains(config.Gateway) {
			continue
		}
		proxyIP := config.Gateway.Next()
		sandboxIP := proxyIP.Next()
		if usablePodmanNetworkIP(config.Subnet, config.Gateway, proxyIP) && usablePodmanNetworkIP(config.Subnet, config.Gateway, sandboxIP) {
			return proxyIP, sandboxIP, nil
		}
	}
	return netip.Addr{}, netip.Addr{}, fmt.Errorf("isolated network %q has no room for reserved proxy and sandbox IPv4 addresses", netName)
}

func usablePodmanNetworkIP(subnet netip.Prefix, gateway, candidate netip.Addr) bool {
	if !candidate.Is4() || !subnet.Contains(candidate) || candidate == gateway || candidate == subnet.Masked().Addr() {
		return false
	}
	address := candidate.As4()
	base := subnet.Masked().Addr().As4()
	var hostMask uint32
	for bit := subnet.Bits(); bit < 32; bit++ {
		hostMask = (hostMask << 1) | 1
	}
	broadcast := (uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])) | hostMask
	value := uint32(address[0])<<24 | uint32(address[1])<<16 | uint32(address[2])<<8 | uint32(address[3])
	return value != broadcast
}

func (d *Driver) waitProxyCA(ctx context.Context, proxyID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		res, err := d.Exec(ctx, core.ID(proxyID), driver.ExecRequest{
			Argv: []string{"test", "-s", "/cautem/ca/ca.pem"},
		})
		if err == nil && res.ExitCode == 0 {
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(readinessPollInterval):
		}
	}
	logs, _ := d.cli.ContainerLogs(ctx, proxyID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: "40"})
	var buf strings.Builder
	if logs != nil {
		_, _ = io.Copy(&buf, logs)
		_ = logs.Close()
	}
	detail := strings.TrimSpace(buf.String())
	if detail != "" {
		return fmt.Errorf("docker proxy: timed out waiting for /cautem/ca/ca.pem (last exec: %v)\nproxy logs:\n%s", lastErr, detail)
	}
	return fmt.Errorf("docker proxy: timed out waiting for /cautem/ca/ca.pem (last exec: %v)", lastErr)
}

// waitProxyListening waits until the sidecar accepts TCP on 127.0.0.1:port.

// waitProxyListening waits until the sidecar accepts TCP on 127.0.0.1:port.
func (d *Driver) waitProxyListening(ctx context.Context, proxyID string, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	script := fmt.Sprintf("exec 3<>/dev/tcp/127.0.0.1/%d", port)
	var lastErr error
	for time.Now().Before(deadline) {
		res, err := d.Exec(ctx, core.ID(proxyID), driver.ExecRequest{
			Argv: []string{"bash", "-c", script},
		})
		if err == nil && res.ExitCode == 0 {
			return nil
		}
		lastErr = err
		if res.ExitCode != 0 {
			lastErr = fmt.Errorf("exit %d", res.ExitCode)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(caPollInterval):
		}
	}
	logs, _ := d.cli.ContainerLogs(ctx, proxyID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: "60"})
	var buf strings.Builder
	if logs != nil {
		_, _ = io.Copy(&buf, logs)
		_ = logs.Close()
	}
	detail := strings.TrimSpace(buf.String())
	if detail != "" {
		return fmt.Errorf("docker proxy: timed out waiting for listen :%d (%v)\nproxy logs:\n%s", port, lastErr, detail)
	}
	return fmt.Errorf("docker proxy: timed out waiting for listen :%d (%v)", port, lastErr)
}

func (d *Driver) removeProxySidecar(ctx context.Context, name string) error {
	id, _, found, err := d.inspectProxy(ctx, name)
	if err != nil || !found {
		return err
	}
	_, err = d.cli.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true})
	if isNotFound(err) {
		return nil
	}
	return err
}

func (d *Driver) ensureProxyRunning(ctx context.Context, name string) (string, int, bool, error) {
	id, port, found, err := d.inspectProxy(ctx, name)
	if err != nil || !found {
		return id, port, found, err
	}
	info, err := d.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return "", 0, false, fmt.Errorf("docker start proxy inspect: %w", err)
	}
	if info.Container.State == nil || info.Container.State.Status != "running" {
		if err := d.startContainerIfStopped(ctx, id); err != nil {
			return "", 0, false, fmt.Errorf("docker start proxy: %w", err)
		}
	}
	return id, port, true, nil
}

func (d *Driver) inspectProxy(ctx context.Context, name string) (string, int, bool, error) {
	if strings.TrimSpace(name) == "" {
		return "", 0, false, nil
	}
	info, err := d.cli.ContainerInspect(ctx, "cautem-proxy-"+name, client.ContainerInspectOptions{})
	if isNotFound(err) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	if info.Container.Config == nil || info.Container.Config.Labels[labelSandbox] != "1" ||
		info.Container.Config.Labels[labelName] != name || info.Container.Config.Labels[labelRole] != roleProxy {
		return "", 0, false, fmt.Errorf("container cautem-proxy-%s is not the managed sandbox proxy", name)
	}
	if info.Container.ID == "" {
		return "", 0, false, fmt.Errorf("container cautem-proxy-%s has no ID", name)
	}
	for exposedPort := range info.Container.Config.ExposedPorts {
		if exposedPort.Proto() != "tcp" {
			continue
		}
		port, err := strconv.Atoi(exposedPort.Port())
		if err == nil && port > 0 && port <= 65535 {
			return info.Container.ID, port, true, nil
		}
	}
	return "", 0, false, fmt.Errorf("container cautem-proxy-%s exposes no valid TCP proxy port", name)
}
