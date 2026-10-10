// Package driver defines the compute backend interface (Docker, Podman, VM, K8s).
package driver

import (
	"context"
	"errors"
	"io"

	"github.com/cautem/cautem-core"
)

// SupervisorControlSocketName is mounted inside the shared SSH directory so
// sandbox PID 1 can request lifecycle RPCs through the authenticated sidecar.
const SupervisorControlSocketName = "supervisor-control.sock"

// Spec describes a sandbox to create.
type Spec struct {
	Name      string   // human name → container cautem-<name>
	Image     string   // default cautem-sandbox:local (published cautem base)
	Workspace string   // absolute host path → /workspace
	Command   []string // default: sleep infinity
	Env       []string // KEY=VAL (already allowlisted by caller)
	IKnow     bool     // override mount deny-list (logged by caller)

	// Egress sidecar (P3). When ProxyBin is set, network is internal and
	// a dual-homed cautem-proxy-<name> container is started beside the sandbox.
	ProxyBin   string   // linux cautem binary (host path)
	PolicyPath string   // policy YAML mounted read-only into the proxy (+ sandbox)
	ProxyPort  int      // default defaults.ProxyPort
	ProxyEnv   []string // real credential KEY=VAL for placeholder rewrite (proxy only)

	// Harden (P4): linux cautem-init binary mounted at /cautem/cautem-init; execs are wrapped.
	InitBin  string
	NoHarden bool
	// SupervisorBin is the Go workload supervisor used as the container entrypoint.
	// It manages signals and child reaping; InitBin remains the hardened workload wrapper.
	SupervisorBin string

	// Display (P6): noVNC published on host loopback only.
	DisplayMode     string // none | novnc
	DisplayPort     int    // host port; 0 uses defaults.NoVNCPort
	DisplayPassword string // VNC/noVNC password

	// Labels (P8): arbitrary cautem.* / user labels on the container.
	Labels map[string]string

	// ExtraHosts entries "host:ip" (Docker ExtraHosts). host.cautem.internal added by CLI.
	ExtraHosts []string

	// GatewayURL when set, create registers the sandbox with the control plane.
	GatewayURL string

	// PersistVolume mounts named volume cautem-data-<name> at defaults.GuestData (retained across stop/start).
	PersistVolume bool

	// EnableSSH mounts cautem-sshd and shares the root-only relay volume
	// (defaults.GuestSSHSocket and sandbox TCP dial socket) with the proxy
	// sidecar. SSH uses the Unix socket directly; loopback TCP targets are dialed
	// in the sandbox namespace by cautem-supervisor. Nothing is host-published;
	// requires ProxyBin.
	EnableSSH bool
	SSHBin    string // host path to linux cautem-sshd

	// GPU requests NVIDIA CDI devices into the sandbox (Docker DeviceRequests).
	// Default device when CDIDevices empty: nvidia.com/gpu=all (override via CAUTEM_GPU_CDI).
	GPU        bool
	GPUCount   int      // reserved; CDI list takes precedence in MVP
	CDIDevices []string // e.g. nvidia.com/gpu=0

	CPU         float64 // NanoCPUs = CPU * 1e9 when > 0
	MemoryBytes int64   // Docker Memory limit when > 0
	// PidsLimit is Docker PIDs cgroup limit. 0 → driver default (2048 / CAUTEM_SANDBOX_PIDS_LIMIT);
	// -1 → unlimited; >0 → explicit.
	PidsLimit int64
	// ProxyImage overrides the slim egress sidecar base (default debian:bookworm-slim).
	ProxyImage   string
	PublishPorts []PortPublish
	// DriverConfigJSON carries the selected backend's OpenShell-compatible sandbox driver_config.
	DriverConfigJSON string
}

// PortPublish maps a host loopback port to a guest container port.
type PortPublish struct {
	Host  int
	Guest int
}

// Handle is a live sandbox reference.
type Handle struct {
	ID      core.ID
	Name    string
	Network string
	Image   string
}

// Info is a list/status row.
type Info struct {
	ID      core.ID
	Name    string
	Network string
	Image   string
	Status  string
}

// ExecRequest is a one-shot or PTY-backed command.
type ExecRequest struct {
	Argv    []string
	TTY     bool
	Env     []string
	WorkDir string // empty → driver default (/workspace)
}

// ExecResult carries exit status.
type ExecResult struct {
	ExitCode int
}

// ComputeDriver is implemented by docker (default), podman, vm, kubernetes.
type ComputeDriver interface {
	Create(ctx context.Context, spec Spec) (Handle, error)
	Start(ctx context.Context, id core.ID) error
	Stop(ctx context.Context, id core.ID) error
	Exec(ctx context.Context, id core.ID, req ExecRequest) (ExecResult, error)
	Delete(ctx context.Context, id core.ID) error
	List(ctx context.Context) ([]Info, error)
	Inspect(ctx context.Context, nameOrID string) (Info, error)
	// Logs streams container logs to w (follow optional).
	Logs(ctx context.Context, id core.ID, follow bool, w io.Writer) error
	CopyTo(ctx context.Context, id core.ID, srcHost, destPath string) error
	CopyFrom(ctx context.Context, id core.ID, srcPath, destHost string) error
	// EnsureSSHDaemon (re)starts the in-sandbox relay sshd; ErrSSHDisabled when
	// the sandbox was created without SSH.
	EnsureSSHDaemon(ctx context.Context, id core.ID) error
}

// ErrSSHDisabled reports a sandbox created without the SSH relay.
var ErrSSHDisabled = errors.New("sandbox has no SSH relay (created without a proxy sidecar)")
