package driver

import "context"

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
