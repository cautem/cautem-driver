package driver

import (
	"context"

	"github.com/docker/go-units"

	"github.com/cautem/cautem-core/defaults"
	"github.com/cautem/cautem-driver/internal/mounts"
	"github.com/cautem/cautem-driver/internal/sidecar"
)

// WorkdirInContainer is where the host workspace is mounted in the guest.
const WorkdirInContainer = mounts.WorkdirInContainer

// SeccompNote summarizes seccomp availability for health output.
func SeccompNote() string {
	return "docker-default + no-new-privileges + CapDrop=NET_RAW (in-process filter later)"
}

// ParseMemoryBytes parses Docker-style memory limits (e.g. 512m, 2g).
func ParseMemoryBytes(s string) (int64, error) {
	return units.RAMInBytes(s)
}

// HostGatewayExtraHosts maps host-gateway aliases into containers.
func HostGatewayExtraHosts() []string {
	return []string{
		defaults.HostInternal + ":host-gateway",
		"host.docker.internal:host-gateway",
	}
}

// ProxyExtraHosts is an alias of HostGatewayExtraHosts for the egress sidecar.
func ProxyExtraHosts() []string { return HostGatewayExtraHosts() }

// ValidateUploadDest rejects uploads into reserved guest control paths.
func ValidateUploadDest(dest string) error { return mounts.ValidateUploadDest(dest) }

// ResolveWorkspace returns an absolute workspace path and checks the deny-list.
func ResolveWorkspace(path string, iKnow bool) (string, error) {
	return mounts.ResolveWorkspace(path, iKnow)
}

// EnsureLinuxCLI builds (if needed) a linux/$GOARCH cautem binary for the proxy sidecar.
func EnsureLinuxCLI(ctx context.Context, moduleDir string) (string, error) {
	return sidecar.EnsureLinuxCLI(ctx, moduleDir)
}

// EnsureLinuxInit builds (if needed) a linux cautem-init for harden.
func EnsureLinuxInit(ctx context.Context, runtimeModuleDir string) (string, error) {
	return sidecar.EnsureLinuxInit(ctx, runtimeModuleDir)
}

// EnsureLinuxSSHD builds (if needed) a linux cautem-sshd.
func EnsureLinuxSSHD(ctx context.Context, runtimeModuleDir string) (string, error) {
	return sidecar.EnsureLinuxSSHD(ctx, runtimeModuleDir)
}

// EnsureLinuxAgent builds (if needed) a linux cautem-agent.
func EnsureLinuxAgent(ctx context.Context, runtimeModuleDir string) (string, error) {
	return sidecar.EnsureLinuxAgent(ctx, runtimeModuleDir)
}

// EnsureLinuxSupervisor builds the Linux workload supervisor.
func EnsureLinuxSupervisor(ctx context.Context, runtimeModuleDir string) (string, error) {
	return sidecar.EnsureLinuxSupervisor(ctx, runtimeModuleDir)
}

// ProxyEnv returns HTTP(S)_PROXY env entries pointing at the sidecar hostname.
func ProxyEnv(proxyHost string, port int) []string { return sidecar.ProxyEnv(proxyHost, port) }

// CABundleEnv points TLS clients at the MITM CA mounted into the sandbox.
func CABundleEnv(caFile string) []string { return sidecar.CABundleEnv(caFile) }
