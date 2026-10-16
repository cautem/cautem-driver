// Package docker implements driver.ComputeDriver via the Docker Engine API.
package docker

import (
	"context"
	"fmt"

	"github.com/moby/moby/client"

	"github.com/cautem/cautem-core/defaults"
	"github.com/cautem/cautem-core/resourceadmission"
	"github.com/cautem/quarshell-driver/driver"
)

const (
	labelSandbox   = "cautem.sandbox"
	labelName      = "cautem.name"
	labelNetwork   = "cautem.network"
	labelRole      = "cautem.role"
	labelInit      = "cautem.init"
	labelVolume    = "cautem.volume"
	labelSSH       = "cautem.ssh"
	labelSSHVol    = "cautem.ssh_volume"
	labelPolicy    = "cautem.policy_path"
	roleSandbox    = "sandbox"
	roleProxy      = "proxy"
	roleNetwork    = "network"
	roleVolumeData = "volume-data"
	roleVolumeCA   = "volume-ca"
	roleVolumeSSH  = "volume-ssh"
)

// Image and guest layout defaults (aliased from cautem-core/defaults).

// Image and guest layout defaults (aliased from cautem-core/defaults).
const (
	defaultImage      = defaults.ImageDebian
	localSandboxImage = defaults.ImageLocal
	guiSandboxImage   = defaults.ImageGUI
	defaultProxy      = defaults.ProxyPort
	defaultNoVNCPort  = defaults.NoVNCPort
	guestDataPath     = defaults.GuestData
	guestHomePath     = defaults.GuestHome
	guestBinPath      = defaults.GuestBin
	guestPath         = defaults.GuestPath
)

// Driver talks to a local Docker Engine / Desktop daemon.

// Driver talks to a local Docker Engine / Desktop daemon.
type Driver struct {
	cli              *client.Client
	enableBindMounts bool
	runtimeConfig    RuntimeConfig
}

// RuntimeConfig contains settings shared by Docker-compatible Engine backends.

// RuntimeConfig contains settings shared by Docker-compatible Engine backends.
type RuntimeConfig struct {
	BackendID         string
	RuntimeContext    string
	EnableBindMounts  bool
	AllowDriverConfig bool
	ResourceAdmission *resourceadmission.Config
	DefaultImage      string
	AppArmorProfile   AppArmorProfile
	// AppArmorSupportValidated is set by backends that verify support through
	// their native API before constructing this Engine adapter.
	AppArmorSupportValidated bool
	// LogDriver overrides the Docker-specific default for compatible engines
	// whose supported log backend differs (for example Podman's k8s-file).
	LogDriver                                string
	NetworkName                              string
	HostGatewayIP                            string
	ImagePullPolicy                          string
	StopTimeoutSecs                          int
	StopTimeoutConfigured                    bool
	PidsLimit                                int64
	ProviderSPIFFEWorkloadAPISocket          string
	GatewayGRPCEndpoint                      string
	GatewayGRPCPort                          int
	SandboxSSHSocketPath                     string
	CleanupManifestDir                       string
	HealthCheckIntervalSecs                  int64
	UsernsMode                               string
	SandboxNamespace                         string
	DefaultCPU                               float64
	DefaultMemoryBytes                       int64
	GuestTLSCA                               string
	GuestTLSCert                             string
	GuestTLSKey                              string
	UpstreamProxyURL                         string
	UpstreamProxyNoProxy                     string
	UpstreamProxyAuthFile                    string
	UpstreamProxyAuthAllowInsecure           bool
	UpstreamProxyAuthAllowInsecureConfigured bool
	UpstreamProxyCABundle                    string
	UpstreamProxyConnectByHostname           bool
	UpstreamProxyConnectByHostnameConfigured bool
	EgressCABundle                           string
	ReconcileDataOwnership                   bool
	// Capabilities describes backend request features, not host hardware
	// inventory. The latter is discovered separately when a GPU is requested.
	Capabilities         []string
	RegistryAuthResolver func(string) (string, error)
	// NativeContainerCreate, when set by a backend adapter, replaces only the
	// primary workload create request. Sidecars remain on the Engine API.
	NativeContainerCreate func(context.Context, client.ContainerCreateOptions) (client.ContainerCreateResult, error)
	// NativeNetworkCreate / Verify use backend APIs for security controls that
	// are not represented by the Docker-compatible network contract.
	NativeNetworkCreate func(context.Context, string, bool, map[string]string) error
	NativeNetworkVerify func(context.Context, string, bool) error
}

func (d *Driver) registryAuth(imageRef string) (string, error) {
	if d != nil && d.runtimeConfig.RegistryAuthResolver != nil {
		return d.runtimeConfig.RegistryAuthResolver(imageRef)
	}
	return dockerRegistryAuth(imageRef)
}

// New returns a Docker compute driver using DOCKER_* env (FromEnv).

// New returns a Docker compute driver using DOCKER_* env (FromEnv).
func New() (*Driver, error) {
	cli, err := client.New(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("docker driver: %w", err)
	}
	return &Driver{cli: cli}, nil
}

// HostGatewayExtraHosts maps OpenShell-style host-gateway aliases into containers.
// Canonical callback is host.cautem.internal (cf. host.openshell.internal). On Linux,
// host.docker.internal is also mapped so Desktop/Linux compose parity holds —
// same pair OpenShell documents under extra_hosts.

// HostGatewayExtraHosts maps OpenShell-style host-gateway aliases into containers.
// Canonical callback is host.cautem.internal (cf. host.openshell.internal). On Linux,
// host.docker.internal is also mapped so Desktop/Linux compose parity holds —
// same pair OpenShell documents under extra_hosts.
func HostGatewayExtraHosts() []string {
	return driver.HostGatewayExtraHosts()
}

// ProxyExtraHosts is an alias of HostGatewayExtraHosts for the egress sidecar.

// ProxyExtraHosts is an alias of HostGatewayExtraHosts for the egress sidecar.
func ProxyExtraHosts() []string {
	return HostGatewayExtraHosts()
}

// NewFromClient wraps an existing client (tests).

// NewFromClient wraps an existing client (tests).
func NewFromClient(cli *client.Client) *Driver {
	return &Driver{cli: cli}
}

// NewFromClientWithConfig wraps an engine client with OpenShell-compatible Docker options.

// NewFromClientWithConfig wraps an engine client with OpenShell-compatible Docker options.
func NewFromClientWithConfig(cli *client.Client, enableBindMounts bool) *Driver {
	return NewFromClientWithRuntimeConfig(cli, RuntimeConfig{EnableBindMounts: enableBindMounts})
}

// NewFromClientWithRuntimeConfig wraps an Engine client with backend settings.

// NewFromClientWithRuntimeConfig wraps an Engine client with backend settings.
func NewFromClientWithRuntimeConfig(cli *client.Client, cfg RuntimeConfig) *Driver {
	if cfg.BackendID == "" {
		cfg.BackendID = "docker"
	}
	return &Driver{cli: cli, enableBindMounts: cfg.EnableBindMounts, runtimeConfig: cfg}
}

// Close releases the underlying HTTP client.

// Close releases the underlying HTTP client.
func (d *Driver) Close() error {
	if d == nil || d.cli == nil {
		return nil
	}
	return d.cli.Close()
}

// Create ensures network + optional proxy sidecar + sandbox container (not started).
