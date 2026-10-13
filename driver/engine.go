package driver

import (
	"context"

	core "github.com/cautem/cautem-core"
)

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

// TokenAwareStarter lets a backend replace credentials that are mounted into a
// stopped runtime before it starts again. Gateways should mint a fresh token
// for each restart and call this capability only after the previous runtime
// has been stopped.
type TokenAwareStarter interface {
	StartWithToken(ctx context.Context, id core.ID, token string) error
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
