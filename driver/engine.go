package driver

import (
	"context"
	"io"

	core "github.com/cautem/quarshell-core"
)

// ImageBuildRequest describes a local Engine image build. Context is a tar
// archive rooted at the build context; Dockerfile is relative to that root.
type ImageBuildRequest struct {
	Context    io.Reader
	Dockerfile string
	Tag        string
	Output     io.Writer
}

// ImageBuilder is an optional Engine capability for building a local source
// directory into an image before creating a sandbox.
type ImageBuilder interface {
	BuildImage(context.Context, ImageBuildRequest) error
}

// Probe is a host-side Docker/Podman readiness report for `cautem health`.
type Probe struct {
	OK              bool
	ServerVersion   string
	APIVersion      string
	OperatingSystem string
	Architecture    string
	Context         string
	Isolation       string
	HostGOOS        string
	Capabilities    []string
	SecurityOptions []string
	Rootless        string
	Error           string
}

// Engine extends ComputeDriver with Docker Engine API ops used by the CLI
// (health, policy path, container IP). Implemented by docker and podman backends.
type Engine interface {
	ComputeDriver
	Health(ctx context.Context) Probe
	ImagePresent(ctx context.Context, ref string) bool
	RunProbe(ctx context.Context, initBin string) (string, error)
	PolicyHostPath(ctx context.Context, nameOrID string) (string, error)
	ContainerIP(ctx context.Context, containerID, networkName string) (string, error)
}

// RootfsTarStager is an optional capability exposed by drivers that accept a
// gateway-owned local rootfs tar archive. Docker and Podman intentionally do
// not implement this interface; callers must fail closed when it is absent.
type RootfsTarStager interface {
	RootfsTarStaging(ctx context.Context) (directory string, maxBytes uint64, err error)
}

// SpecValidator is an optional preflight capability for backends that can
// identify unsupported sandbox guarantees before they allocate resources.
// Gateways should call it before persisting lifecycle state or consuming
// one-shot provisioning inputs.
type SpecValidator interface {
	ValidateSpec(spec Spec) error
}

// ContextSpecValidator is the cancellable preflight contract preferred by the
// Backend adapter. It lets drivers perform bounded, read-only engine checks
// before the Gateway persists a sandbox record or consumes one-shot inputs.
type ContextSpecValidator interface {
	ValidateSpecContext(context.Context, Spec) error
}

// GatewayRuntimeValidator is an optional capability for local backends whose
// runtime cannot satisfy the Gateway's mandatory supervisor, workspace, and
// policy lifecycle contract. Gateways should check it before consuming
// one-shot provisioning inputs.
type GatewayRuntimeValidator interface {
	ValidateGatewayRuntime() error
}

// TokenAwareStarter lets a backend replace credentials that are mounted into a
// stopped runtime before it starts again. Gateways should mint a fresh token
// for each restart and call this capability only after the previous runtime
// has been stopped.
type TokenAwareStarter interface {
	StartWithToken(ctx context.Context, id core.ID, token string) error
}

// LaunchSpecRestorer lets a durable control plane restore process-local
// workload argv/environment after its compute driver process has restarted.
// Implementations must not persist the supplied environment in backend state.
type LaunchSpecRestorer interface {
	RestoreLaunchSpec(ctx context.Context, id core.ID, spec Spec) error
}

// SandboxPolicyUpdater lets a compute backend deliver a new policy when its
// runtime does not share the Gateway's local policy file. Implementations must
// return only after the desired policy is durably attached to the sandbox.
type SandboxPolicyUpdater interface {
	UpdateSandboxPolicy(ctx context.Context, id core.ID, policy []byte) error
}

// SandboxRuntimeCredentialRefresher lets a compute backend rotate expiring
// runtime identities without changing the sandbox's effective policy.
type SandboxRuntimeCredentialRefresher interface {
	RefreshSandboxRuntimeCredentials(ctx context.Context, id core.ID) error
}
