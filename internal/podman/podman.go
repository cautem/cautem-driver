// Package podman discovers a rootless/rootful Podman API socket and speaks
// the Docker-compatible Engine API (same client as internal/docker).
package podman

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	"github.com/moby/moby/client"

	"github.com/cautem/cautem-core/resourceadmission"
	"github.com/cautem/cautem-driver/internal/docker"
)

const (
	defaultPodmanCPU         = 2.0
	defaultPodmanMemoryBytes = 4_294_967_296
)

// New returns a compute driver pointed at Podman.
// Honors DOCKER_HOST / CONTAINER_HOST if already set; otherwise discovers a socket.
func New() (*docker.Driver, error) {
	return NewWithConfig(Config{})
}

// Config contains Podman Engine settings supported by the Docker-compatible
// API implementation. Values are applied to Engine requests by docker.Driver.
type Config struct {
	SocketPath                      string
	DefaultImage                    string
	AllowDriverConfig               bool
	ResourceAdmission               *resourceadmission.Config
	AppArmorProfile                 docker.AppArmorProfile
	NetworkName                     string
	HostGatewayIP                   string
	ImagePullPolicy                 string
	StopTimeoutSecs                 int
	StopTimeoutConfigured           bool
	PidsLimit                       int64
	EnableBindMounts                bool
	ProviderSPIFFEWorkloadAPISocket string
	GatewayGRPCEndpoint             string
	GatewayGRPCPort                 int
	SandboxSSHSocketPath            string
	CleanupManifestDir              string
	HealthCheckIntervalSecs         int64
	UsernsMode                      string
	UIDMap                          []IDMapping
	GIDMap                          []IDMapping
	GuestTLSCA                      string
	GuestTLSCert                    string
	GuestTLSKey                     string
	HTTPSProxy                      string
	NoProxy                         string
	ProxyAuthFile                   string
	ProxyAuthAllowInsecure          *bool
	ProxyConnectByHostname          *bool
	ProxyCABundle                   string
	RegistryAuthFile                string
	EgressCABundle                  string
	ReconcileDataOwnership          bool
}

// NewWithConfig creates a Podman-backed driver and applies compatible runtime settings.
func NewWithConfig(cfg Config) (*docker.Driver, error) {
	var err error
	if err := cfg.AppArmorProfile.Validate(); err != nil {
		return nil, fmt.Errorf("podman: %w", err)
	}
	if cfg.UsernsMode, err = canonicalUsernsMode(cfg.UsernsMode); err != nil {
		return nil, err
	}
	if strings.EqualFold(cfg.UsernsMode, "private") && (len(cfg.UIDMap) == 0 || len(cfg.GIDMap) == 0) {
		return nil, fmt.Errorf("podman: userns=private requires both uidmap and gidmap")
	}
	if len(cfg.UIDMap) > 0 || len(cfg.GIDMap) > 0 {
		if !strings.EqualFold(strings.TrimSpace(cfg.UsernsMode), "private") {
			return nil, fmt.Errorf("podman: uidmap and gidmap require userns=private")
		}
		if len(cfg.UIDMap) == 0 || len(cfg.GIDMap) == 0 {
			return nil, fmt.Errorf("podman: userns=private requires both uidmap and gidmap")
		}
	}
	if err := validateGuestTLSPaths(cfg.GuestTLSCA, cfg.GuestTLSCert, cfg.GuestTLSKey); err != nil {
		return nil, fmt.Errorf("podman: %w", err)
	}
	if err := validateRegistryAuthFile(cfg.RegistryAuthFile); err != nil {
		return nil, fmt.Errorf("podman: %w", err)
	}
	if err := validateEgressCABundle(cfg.EgressCABundle); err != nil {
		return nil, fmt.Errorf("podman: %w", err)
	}
	if err := validateProxyConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.HostGatewayIP != "" {
		if _, err := netip.ParseAddr(cfg.HostGatewayIP); err != nil {
			return nil, fmt.Errorf("podman: invalid host_gateway_ip: %w", err)
		}
	}
	if cfg.SocketPath != "" && (!filepath.IsAbs(cfg.SocketPath) || filepath.Clean(cfg.SocketPath) != cfg.SocketPath) {
		return nil, fmt.Errorf("podman: socket_path must be an absolute clean path")
	}
	if cfg.SandboxSSHSocketPath != "" && (!filepath.IsAbs(cfg.SandboxSSHSocketPath) || filepath.Clean(cfg.SandboxSSHSocketPath) != cfg.SandboxSSHSocketPath || filepath.Dir(cfg.SandboxSSHSocketPath) == "/") {
		return nil, fmt.Errorf("podman: sandbox_ssh_socket_path must be an absolute path below a dedicated directory")
	}
	if cfg.StopTimeoutSecs < 0 || cfg.PidsLimit < 0 {
		return nil, fmt.Errorf("podman: stop_timeout_secs and pids_limit must be non-negative")
	}
	policy, err := docker.NormalizeImagePullPolicy(cfg.ImagePullPolicy)
	if err != nil {
		return nil, fmt.Errorf("podman: %w", err)
	}
	cfg.ImagePullPolicy = policy
	host := ""
	if strings.TrimSpace(cfg.SocketPath) != "" {
		if !socketAlive(cfg.SocketPath) {
			return nil, fmt.Errorf("podman: configured socket_path is unavailable")
		}
		host = "unix://" + cfg.SocketPath
	} else {
		host, err = ResolveHost()
	}
	if err != nil {
		return nil, err
	}
	if cfg.AppArmorProfile.RequiresHostSupport() {
		if err := validatePodmanAppArmorSupport(host, cfg.AppArmorProfile); err != nil {
			return nil, err
		}
	}
	clientOptions := []client.Opt{client.WithHost(host)}
	if strings.TrimSpace(os.Getenv("DOCKER_CERT_PATH")) != "" {
		clientOptions = append(clientOptions, client.WithTLSClientConfigFromEnv())
	}
	cli, err := client.New(clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("podman driver: %w", err)
	}
	policy = cfg.ImagePullPolicy
	if policy == "missing" {
		policy = ""
	}
	runtimeCfg := docker.RuntimeConfig{
		BackendID:         "podman",
		RuntimeContext:    podmanRuntimeContext(host),
		LogDriver:         "k8s-file",
		EnableBindMounts:  cfg.EnableBindMounts,
		AllowDriverConfig: cfg.AllowDriverConfig,
		ResourceAdmission: cfg.ResourceAdmission,
		DefaultImage:      cfg.DefaultImage, NetworkName: cfg.NetworkName,
		AppArmorProfile:          cfg.AppArmorProfile,
		AppArmorSupportValidated: cfg.AppArmorProfile.RequiresHostSupport(),
		HostGatewayIP:            cfg.HostGatewayIP, ImagePullPolicy: policy,
		StopTimeoutSecs: cfg.StopTimeoutSecs, StopTimeoutConfigured: cfg.StopTimeoutConfigured, PidsLimit: cfg.PidsLimit,
		ProviderSPIFFEWorkloadAPISocket: cfg.ProviderSPIFFEWorkloadAPISocket,
		GatewayGRPCEndpoint:             cfg.GatewayGRPCEndpoint, GatewayGRPCPort: cfg.GatewayGRPCPort,
		SandboxSSHSocketPath:           cfg.SandboxSSHSocketPath,
		CleanupManifestDir:             cfg.CleanupManifestDir,
		HealthCheckIntervalSecs:        cfg.HealthCheckIntervalSecs,
		UsernsMode:                     cfg.UsernsMode,
		DefaultCPU:                     defaultPodmanCPU,
		DefaultMemoryBytes:             defaultPodmanMemoryBytes,
		GuestTLSCA:                     cfg.GuestTLSCA,
		GuestTLSCert:                   cfg.GuestTLSCert,
		GuestTLSKey:                    cfg.GuestTLSKey,
		UpstreamProxyURL:               cfg.HTTPSProxy,
		UpstreamProxyNoProxy:           cfg.NoProxy,
		UpstreamProxyAuthFile:          cfg.ProxyAuthFile,
		UpstreamProxyAuthAllowInsecure: cfg.ProxyAuthAllowInsecure != nil && *cfg.ProxyAuthAllowInsecure,
		UpstreamProxyCABundle:          cfg.ProxyCABundle,
		UpstreamProxyConnectByHostname: cfg.ProxyConnectByHostname != nil && *cfg.ProxyConnectByHostname,
		Capabilities:                   []string{"cdi", "libpod-native", "userns"},
		RegistryAuthResolver:           func(ref string) (string, error) { return podmanRegistryAuth(ref, cfg.RegistryAuthFile) },
		EgressCABundle:                 cfg.EgressCABundle,
		ReconcileDataOwnership:         cfg.ReconcileDataOwnership,
	}
	runtimeCfg.NativeNetworkCreate, runtimeCfg.NativeNetworkVerify = nativeNetworkCallbacks(host)
	// Libpod's native create API supports the complete Podman userns mode set.
	// The Docker-compatible API rejects no-map and drops auto ID-map semantics,
	// so all explicitly configured modes must use the native adapter.
	if cfg.UsernsMode != "" {
		runtimeCfg.NativeContainerCreate = nativeCreate(host, cfg.UsernsMode, cfg.UIDMap, cfg.GIDMap)
	}
	return docker.NewFromClientWithRuntimeConfig(cli, runtimeCfg), nil
}

func podmanRuntimeContext(host string) string {
	if strings.HasPrefix(host, "unix://") {
		return "socket " + strings.TrimPrefix(host, "unix://")
	}
	return "remote endpoint"
}

// ResolveHost returns a docker client host URL (unix://… or tcp://…).
func ResolveHost() (string, error) {
	if h := strings.TrimSpace(os.Getenv("DOCKER_HOST")); h != "" {
		return h, nil
	}
	if h := strings.TrimSpace(os.Getenv("CONTAINER_HOST")); h != "" {
		return h, nil
	}
	sock, err := DiscoverSocket()
	if err != nil {
		return "", err
	}
	return "unix://" + sock, nil
}

// DiscoverSocket finds a usable podman.sock.
// Order: CAUTEM_PODMAN_SOCKET, XDG_RUNTIME_DIR, /run/user/$UID/…,
// machine sock under HOME, then `podman info`.
func DiscoverSocket() (string, error) {
	for _, c := range socketCandidates() {
		if socketAlive(c) {
			return c, nil
		}
	}
	if s, ok := socketFromPodmanInfo(); ok {
		return s, nil
	}
	return "", fmt.Errorf("podman: no API socket found (try: systemctl --user enable --now podman.socket, or set CAUTEM_PODMAN_SOCKET / DOCKER_HOST)")
}

func socketCandidates() []string {
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if slices.Contains(out, p) {
			return
		}
		out = append(out, p)
	}
	add(os.Getenv("CAUTEM_PODMAN_SOCKET"))
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		add(filepath.Join(xdg, "podman", "podman.sock"))
	}
	if u, err := user.Current(); err == nil && u.Uid != "" {
		add(filepath.Join("/run/user", u.Uid, "podman", "podman.sock"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		add(filepath.Join(home, ".local/share/containers/podman/machine/podman.sock"))
		add(filepath.Join(home, ".local/share/containers/podman/machine/machine.sock"))
	}
	return out
}

func socketAlive(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		// Some platforms report sockets differently; still try dial.
		if err != nil {
			return false
		}
	}
	c, err := net.DialTimeout("unix", path, daemonProbeTimeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func socketFromPodmanInfo() (string, bool) {
	cmd := exec.Command("podman", "info", "--format", "json")
	cmd.Env = os.Environ()
	b, err := cmd.Output()
	if err != nil {
		return "", false
	}
	var info struct {
		Host struct {
			RemoteSocket struct {
				Path   string `json:"path"`
				Exists bool   `json:"exists"`
			} `json:"remoteSocket"`
		} `json:"host"`
	}
	if err := json.Unmarshal(b, &info); err != nil {
		return "", false
	}
	p := strings.TrimSpace(info.Host.RemoteSocket.Path)
	if p == "" {
		return "", false
	}
	// Strip unix:// prefix if present
	p = strings.TrimPrefix(p, "unix://")
	if socketAlive(p) {
		return p, true
	}
	return "", false
}
