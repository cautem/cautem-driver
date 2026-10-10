package docker

import (
	"fmt"
	"github.com/cautem/cautem-core/defaults"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func providerWorkloadSocket(env []string) (string, error) {
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key != "CAUTEM_PROVIDER_SPIFFE_WORKLOAD_API_SOCKET" {
			continue
		}
		value = strings.TrimSpace(strings.TrimPrefix(value, "unix://"))
		if value == "" {
			return "", fmt.Errorf("socket path is empty")
		}
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return "", fmt.Errorf("socket path must be an absolute clean path")
		}
		info, err := os.Stat(value)
		if err != nil {
			return "", fmt.Errorf("socket path is unavailable")
		}
		if info.Mode()&os.ModeSocket == 0 {
			return "", fmt.Errorf("configured path is not a Unix socket")
		}
		return value, nil
	}
	return "", nil
}

func (d *Driver) hostGatewayExtraHosts() []string {
	ip := strings.TrimSpace(d.runtimeConfig.HostGatewayIP)
	if net.ParseIP(ip) == nil {
		return HostGatewayExtraHosts()
	}
	return []string{"host.cautem.internal:" + ip, "host.docker.internal:" + ip}
}

func (d *Driver) configuredPidsLimit(spec int64) int64 {
	if spec != 0 {
		return spec
	}
	if d.runtimeConfig.PidsLimit != 0 {
		return d.runtimeConfig.PidsLimit
	}
	return 0
}

func (d *Driver) stopTimeoutSecs() int {
	if d.runtimeConfig.StopTimeoutSecs > 0 {
		return d.runtimeConfig.StopTimeoutSecs
	}
	return 10
}

func (d *Driver) sandboxSSHSocketPath() string {
	if value := strings.TrimSpace(d.runtimeConfig.SandboxSSHSocketPath); value != "" {
		return value
	}
	return defaults.GuestSSHSocket
}

// upstreamProxyEnv returns only sidecar-scoped proxy settings. Auth and CA
// material are represented by mounted paths, never by sandbox environment
// values or proxy URLs containing credentials.
func (d *Driver) upstreamProxyEnv() []string {
	if d == nil || strings.TrimSpace(d.runtimeConfig.UpstreamProxyURL) == "" {
		return nil
	}
	cfg := d.runtimeConfig
	env := []string{
		"HTTPS_PROXY=" + cfg.UpstreamProxyURL,
		"https_proxy=" + cfg.UpstreamProxyURL,
		"HTTP_PROXY=" + cfg.UpstreamProxyURL,
		"http_proxy=" + cfg.UpstreamProxyURL,
		"NO_PROXY=" + cfg.UpstreamProxyNoProxy,
		"no_proxy=" + cfg.UpstreamProxyNoProxy,
		"CAUTEM_PROXY_CONNECT_BY_HOSTNAME=" + strconv.FormatBool(cfg.UpstreamProxyConnectByHostname),
	}
	if cfg.UpstreamProxyAuthFile != "" {
		env = append(env, "CAUTEM_PROXY_AUTH_FILE=/run/cautem/upstream-proxy/auth")
	}
	if cfg.UpstreamProxyCABundle != "" {
		env = append(env, "CAUTEM_PROXY_CA_BUNDLE=/run/cautem/upstream-proxy/ca.pem")
	}
	return env
}

func (d *Driver) egressTrustEnv() []string {
	if d == nil || strings.TrimSpace(d.runtimeConfig.EgressCABundle) == "" {
		return nil
	}
	return []string{"CAUTEM_EGRESS_CA_BUNDLE=/run/cautem/egress-ca/ca.pem"}
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
