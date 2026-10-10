// Package docker implements driver.ComputeDriver via the Docker Engine API.
package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/go-units"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"golang.org/x/term"

	"archive/tar"
	"path/filepath"

	"github.com/cautem/cautem-core"
	"github.com/cautem/cautem-core/defaults"
	"github.com/cautem/cautem-driver/driver"
	"github.com/cautem/cautem-driver/internal/mounts"
	"github.com/cautem/cautem-driver/internal/sidecar"
)

const (
	labelSandbox = "cautem.sandbox"
	labelName    = "cautem.name"
	labelNetwork = "cautem.network"
	labelRole    = "cautem.role"
	labelInit    = "cautem.init"
	labelVolume  = "cautem.volume"
	labelSSH     = "cautem.ssh"
	labelSSHVol  = "cautem.ssh_volume"
	labelPolicy  = "cautem.policy_path"
	roleSandbox  = "sandbox"
	roleProxy    = "proxy"
)

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
type Driver struct {
	cli              *client.Client
	enableBindMounts bool
	runtimeConfig    RuntimeConfig
}

// RuntimeConfig contains settings shared by Docker-compatible Engine backends.
type RuntimeConfig struct {
	RuntimeContext                  string
	EnableBindMounts                bool
	DefaultImage                    string
	NetworkName                     string
	HostGatewayIP                   string
	ImagePullPolicy                 string
	StopTimeoutSecs                 int
	PidsLimit                       int64
	ProviderSPIFFEWorkloadAPISocket string
	GatewayGRPCEndpoint             string
	GatewayGRPCPort                 int
	SandboxSSHSocketPath            string
	HealthCheckIntervalSecs         int64
	UsernsMode                      string
	SandboxNamespace                string
	DefaultCPU                      float64
	DefaultMemoryBytes              int64
	GuestTLSCA                      string
	GuestTLSCert                    string
	GuestTLSKey                     string
	UpstreamProxyURL                string
	UpstreamProxyNoProxy            string
	UpstreamProxyAuthFile           string
	UpstreamProxyAuthAllowInsecure  bool
	UpstreamProxyCABundle           string
	UpstreamProxyConnectByHostname  bool
	EgressCABundle                  string
	ReconcileDataOwnership          bool
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
func HostGatewayExtraHosts() []string {
	return driver.HostGatewayExtraHosts()
}

// ProxyExtraHosts is an alias of HostGatewayExtraHosts for the egress sidecar.
func ProxyExtraHosts() []string {
	return HostGatewayExtraHosts()
}

// NewFromClient wraps an existing client (tests).
func NewFromClient(cli *client.Client) *Driver {
	return &Driver{cli: cli}
}

// NewFromClientWithConfig wraps an engine client with OpenShell-compatible Docker options.
func NewFromClientWithConfig(cli *client.Client, enableBindMounts bool) *Driver {
	return NewFromClientWithRuntimeConfig(cli, RuntimeConfig{EnableBindMounts: enableBindMounts})
}

// NewFromClientWithRuntimeConfig wraps an Engine client with backend settings.
func NewFromClientWithRuntimeConfig(cli *client.Client, cfg RuntimeConfig) *Driver {
	return &Driver{cli: cli, enableBindMounts: cfg.EnableBindMounts, runtimeConfig: cfg}
}

// Close releases the underlying HTTP client.
func (d *Driver) Close() error {
	if d == nil || d.cli == nil {
		return nil
	}
	return d.cli.Close()
}

// Create ensures network + optional proxy sidecar + sandbox container (not started).
func (d *Driver) Create(ctx context.Context, spec driver.Spec) (driver.Handle, error) {
	if d == nil || d.cli == nil {
		return driver.Handle{}, fmt.Errorf("docker driver: client not initialized")
	}
	if err := ValidateGPURequest(spec); err != nil {
		return driver.Handle{}, fmt.Errorf("docker gpu: %w", err)
	}
	driverCDIDevices, hasDriverCDIDevices, driverMounts, driverBinds, err := parseDockerSandboxDriverConfig(spec.DriverConfigJSON, d.enableBindMounts)
	if err != nil {
		return driver.Handle{}, err
	}
	if hasDriverCDIDevices {
		spec.CDIDevices = driverCDIDevices
	}
	name := sanitizeName(spec.Name)
	if name == "" {
		return driver.Handle{}, fmt.Errorf("docker driver: sandbox name required")
	}
	// Refuse a retry while managed containers with this name still exist. A
	// failed provisioning attempt must not delete a live sandbox's sidecar.
	existing, err := d.cli.ContainerList(ctx, client.ContainerListOptions{
		All: true,
		Filters: client.Filters{}.
			Add("label", labelSandbox+"=1").
			Add("label", labelName+"="+name),
	})
	if err != nil {
		return driver.Handle{}, fmt.Errorf("docker inspect existing sandbox %s: %w", name, err)
	}
	if len(existing.Items) > 0 {
		return driver.Handle{}, fmt.Errorf("docker driver: sandbox %s already has managed container resources; recover or delete it before retrying create", name)
	}
	if spec.ProxyPort > 65535 || spec.DisplayPort > 65535 {
		return driver.Handle{}, fmt.Errorf("docker driver: proxy/display ports must be at most 65535")
	}
	for _, published := range spec.PublishPorts {
		if published.Guest < 1 || published.Guest > 65535 || published.Host < 1 || published.Host > 65535 {
			return driver.Handle{}, fmt.Errorf("docker driver: published ports must be between 1 and 65535")
		}
	}
	img := strings.TrimSpace(spec.Image)
	if img == "" {
		img = strings.TrimSpace(d.runtimeConfig.DefaultImage)
		if img == "" {
			img = d.defaultSandboxImage(ctx, spec.DisplayMode, spec.GPU)
		}
	}
	ws, err := mounts.ResolveWorkspace(spec.Workspace, spec.IKnow)
	if err != nil {
		return driver.Handle{}, err
	}
	netPrefix := strings.TrimSpace(d.runtimeConfig.NetworkName)
	if netPrefix == "" {
		netPrefix = "cautem-net"
	}
	netName := netPrefix + "-" + name
	ctrName := "cautem-" + name
	withProxy := strings.TrimSpace(spec.ProxyBin) != ""
	withSupervisor := strings.TrimSpace(spec.SupervisorBin) != ""
	var caVol string
	if withSupervisor {
		if strings.TrimSpace(spec.InitBin) == "" || spec.PolicyPath == "" {
			return driver.Handle{}, fmt.Errorf("docker supervisor: hardened init and policy are required")
		}
		info, statErr := os.Stat(spec.SupervisorBin)
		if statErr != nil || !supervisorBinaryExecutable(info) {
			return driver.Handle{}, fmt.Errorf("docker supervisor binary is unavailable or not executable")
		}
	}

	var sshVol string
	tcpDialSocket := ""
	if spec.EnableSSH {
		if !withProxy {
			return driver.Handle{}, fmt.Errorf("docker ssh: the supervisor relay runs in the proxy sidecar; sandboxes without a proxy have no SSH/IDE access")
		}
		if strings.TrimSpace(spec.SSHBin) == "" {
			return driver.Handle{}, fmt.Errorf("docker ssh: SSHBin required when EnableSSH")
		}
		if _, err := os.Stat(spec.SSHBin); err != nil {
			return driver.Handle{}, fmt.Errorf("docker ssh bin: %w", err)
		}
		sshVol = "cautem-ssh-" + name
		if withSupervisor {
			tcpDialSocket = filepath.Join(filepath.Dir(d.sandboxSSHSocketPath()), "tcp-forward.sock")
		}
	}

	if err := d.ensureImage(ctx, img); err != nil {
		return driver.Handle{}, err
	}
	imageInfo, err := d.cli.ImageInspect(ctx, img)
	if err != nil {
		return driver.Handle{}, fmt.Errorf("docker inspect sandbox image %s: %w", img, err)
	}
	if strings.TrimSpace(imageInfo.ID) == "" {
		return driver.Handle{}, fmt.Errorf("docker inspect sandbox image %s: daemon returned no immutable image ID", img)
	}
	proxyImg := ""
	if withProxy {
		proxyImg = resolveProxyImage(spec.ProxyImage)
		if proxyImg != img {
			if err := d.ensureImage(ctx, proxyImg); err != nil {
				return driver.Handle{}, err
			}
		}
	}
	networkCreated, err := d.ensureNetwork(ctx, netName, name, withProxy)
	if err != nil {
		return driver.Handle{}, err
	}
	resourcesCommitted := false
	proxyCreated := false
	createdVolumes := make(map[string]bool)
	defer func() {
		if resourcesCommitted {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		if proxyCreated {
			_ = d.removeProxySidecar(cleanupCtx, name)
		}
		for volume := range createdVolumes {
			_, _ = d.cli.VolumeRemove(cleanupCtx, volume, client.VolumeRemoveOptions{Force: true})
		}
		if networkCreated {
			_, _ = d.cli.NetworkRemove(cleanupCtx, netName, client.NetworkRemoveOptions{})
		}
	}()

	// Driver identity metadata is trusted only when derived from the exact
	// inspected image. Callers cannot spoof it through sandbox environment input.
	env := filterIdentityEnv(spec.Env)
	ociImageUser := ""
	if imageInfo.Config != nil {
		ociImageUser = imageInfo.Config.User
	}
	env = mergeEnv(env, []string{"OPENSHELL_OCI_IMAGE_USER=" + ociImageUser})
	if withProxy {
		port := spec.ProxyPort
		if port <= 0 {
			port = defaultProxy
		}
		proxyHost := "cautem-proxy-" + name
		caVol = "cautem-ca-" + name
		created, err := d.ensureVolume(ctx, caVol)
		if err != nil {
			return driver.Handle{}, err
		}
		if created {
			createdVolumes[caVol] = true
		}
		if sshVol != "" {
			created, err := d.ensureVolume(ctx, sshVol)
			if err != nil {
				return driver.Handle{}, err
			}
			if created {
				createdVolumes[sshVol] = true
			}
		}
		if err := d.createProxySidecar(ctx, name, netName, proxyImg, spec.ProxyBin, spec.PolicyPath, port, caVol, sshVol, tcpDialSocket, spec.ProxyEnv, spec.PidsLimit); err != nil {
			return driver.Handle{}, err
		}
		proxyCreated = true
		env = mergeEnv(env, sidecar.ProxyEnv(proxyHost, port))
		env = mergeEnv(env, sidecar.CABundleEnv(defaults.GuestCAFile))
	}

	binds := []string{
		ws + ":" + mounts.WorkdirInContainer + ":rw",
	}
	binds = append(binds, driverBinds...)
	labels := map[string]string{
		labelSandbox: "1",
		labelName:    name,
		labelNetwork: netName,
		labelRole:    roleSandbox,
	}
	if caVol != "" {
		binds = append(binds, caVol+":"+defaults.GuestCADir+":ro")
		labels["cautem.ca_volume"] = caVol
	}
	for k, v := range spec.Labels {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		labels[k] = v
	}
	if namespace := strings.TrimSpace(d.runtimeConfig.SandboxNamespace); namespace != "" {
		labels["openshell.ai/sandbox-namespace"] = namespace
	}
	if spec.PersistVolume {
		volName := "cautem-data-" + name
		if _, err := d.ensureVolume(ctx, volName); err != nil {
			return driver.Handle{}, err
		}
		binds = append(binds, volName+":"+guestDataPath+":rw")
		labels[labelVolume] = volName
		env = mergeEnv(env, []string{
			"CAUTEM_DATA=" + guestDataPath,
			"HOME=" + guestHomePath,
			"PATH=" + guestPath,
		})
		if d.runtimeConfig.ReconcileDataOwnership {
			env = mergeEnv(env, []string{"CAUTEM_RECONCILE_DATA_OWNERSHIP=1"})
		}
	}
	if !spec.NoHarden && strings.TrimSpace(spec.InitBin) != "" {
		if _, err := os.Stat(spec.InitBin); err != nil {
			return driver.Handle{}, fmt.Errorf("docker init bin: %w", err)
		}
		binds = append(binds, spec.InitBin+":/cautem/cautem-init:ro")
		if spec.PolicyPath != "" {
			binds = append(binds, spec.PolicyPath+":/cautem/policy.yaml:ro")
			env = mergeEnv(env, []string{"CAUTEM_POLICY=/cautem/policy.yaml"})
			if abs, err := filepath.Abs(spec.PolicyPath); err == nil {
				labels[labelPolicy] = abs
			} else {
				labels[labelPolicy] = spec.PolicyPath
			}
		}
		labels[labelInit] = "1"
	}
	if withSupervisor {
		binds = append(binds,
			spec.SupervisorBin+":/cautem/cautem-supervisor:ro",
		)
		labels["cautem.supervisor"] = "go"
	}
	if sshVol != "" {
		binds = append(binds,
			spec.SSHBin+":"+defaults.GuestSSHD+":ro",
			sshVol+":"+filepath.Dir(d.sandboxSSHSocketPath())+":rw")
		labels[labelSSH] = "1"
		labels[labelSSHVol] = sshVol
		if tcpDialSocket != "" {
			env = mergeEnv(env, []string{"CAUTEM_RELAY_TARGET_SOCKET=" + tcpDialSocket})
		}
		if withSupervisor && strings.TrimSpace(d.runtimeConfig.GatewayGRPCEndpoint) != "" {
			controlSocket := filepath.Join(filepath.Dir(d.sandboxSSHSocketPath()), driver.SupervisorControlSocketName)
			env = mergeEnv(env, []string{"CAUTEM_SUPERVISOR_CONTROL_SOCKET=" + controlSocket})
		}
	}

	displayMode := strings.ToLower(strings.TrimSpace(spec.DisplayMode))
	withDisplay := displayMode == "novnc"
	if withDisplay {
		if !imageHasGUI(img) {
			return driver.Handle{}, fmt.Errorf("docker display: image %q missing GUI stack; build with: task runtime:image:gui", img)
		}
		pass := strings.TrimSpace(spec.DisplayPassword)
		if pass == "" {
			pass = "cautem"
		}
		hostPort := spec.DisplayPort
		if hostPort <= 0 {
			hostPort = defaultNoVNCPort
		}
		env = mergeEnv(env, []string{
			"DISPLAY_MODE=novnc",
			"DISPLAY=:99",
			"CAUTEM_VNC_PASSWORD=" + pass,
			fmt.Sprintf("CAUTEM_NOVNC_PORT=%d", defaultNoVNCPort),
		})
		labels["cautem.display"] = "novnc"
		labels["cautem.display.port"] = strconv.Itoa(hostPort)
	}

	cmd := spec.Command
	if len(cmd) == 0 {
		switch {
		case withDisplay && usesEmbeddedInit(img):
			cmd = []string{"--", "/usr/local/bin/cautem-gui-boot"}
		case usesEmbeddedInit(img):
			cmd = []string{"--", "sleep", "infinity"}
		case withDisplay:
			cmd = []string{"/usr/local/bin/cautem-gui-boot"}
		default:
			cmd = []string{"sleep", "infinity"}
		}
	}
	workloadCmd := append([]string(nil), cmd...)
	if len(workloadCmd) > 0 && workloadCmd[0] == "--" {
		workloadCmd = workloadCmd[1:]
	}
	cfg := &container.Config{
		Image:      imageInfo.ID,
		Cmd:        cmd,
		Env:        env,
		Labels:     labels,
		WorkingDir: mounts.WorkdirInContainer,
	}
	// The image's OCI USER is retained in OPENSHELL_OCI_IMAGE_USER for the
	// workload identity resolver. The supervisor itself must start as root to
	// establish isolation and perform the checked privilege drop.
	if !spec.NoHarden && (strings.TrimSpace(spec.InitBin) != "" || usesEmbeddedInit(img)) {
		cfg.User = "0"
	}
	// Prefer host-mounted cautem-init over whatever ENTRYPOINT the image baked
	// (legacy osg-init looked for /osg/policy.yaml and dies on rename).
	if !spec.NoHarden && strings.TrimSpace(spec.InitBin) != "" {
		cfg.Entrypoint = []string{"/cautem/cautem-init"}
		if len(spec.Command) == 0 && !usesEmbeddedInit(img) && !withDisplay {
			// Image has no init wrapper — Cmd is the payload after "--".
			cfg.Cmd = append([]string{"--"}, cmd...)
		} else if len(spec.Command) == 0 && !usesEmbeddedInit(img) && withDisplay {
			cfg.Cmd = []string{"--", "/usr/local/bin/cautem-gui-boot"}
		}
	}
	if withSupervisor {
		// The Go PID 1 supervisor owns workload lifecycle and signal handling.
		// The hardened init remains the child entrypoint and applies Landlock
		// plus the checked identity drop before execing the agent command.
		cfg.Entrypoint = []string{"/cautem/cautem-supervisor"}
		cfg.Cmd = append([]string{"--", "/cautem/cautem-init", "--policy", "/cautem/policy.yaml", "--"}, workloadCmd...)
		cfg.User = "0"
	}
	host := &container.HostConfig{
		Binds:       binds,
		Mounts:      driverMounts,
		NetworkMode: container.NetworkMode(netName),
		// Never mount docker.sock into the sandbox.
		// Docker default seccomp stays on (do not set seccomp=unconfined).
		SecurityOpt: []string{"no-new-privileges:true"},
		CapDrop:     []string{"NET_RAW"},
		// Do not give the sandbox a host-gateway alias. Only the proxy sidecar
		// needs that route for gateway-owned control traffic.
		ExtraHosts: append([]string{}, spec.ExtraHosts...),
		LogConfig:  sandboxLogConfig(),
		Resources:  container.Resources{PidsLimit: resolvePidsLimit(d.configuredPidsLimit(spec.PidsLimit))},
	}
	cpu := spec.CPU
	if cpu == 0 {
		cpu = d.runtimeConfig.DefaultCPU
	}
	if cpu > 0 {
		host.NanoCPUs = int64(cpu * 1e9)
	}
	memory := spec.MemoryBytes
	if memory == 0 {
		memory = d.runtimeConfig.DefaultMemoryBytes
	}
	if memory > 0 {
		host.Memory = memory
	}
	if d.runtimeConfig.UsernsMode != "" {
		host.UsernsMode = container.UsernsMode(d.runtimeConfig.UsernsMode)
	}
	if interval := d.runtimeConfig.HealthCheckIntervalSecs; interval > 0 {
		socket := d.sandboxSSHSocketPath()
		cfg.Healthcheck = &container.HealthConfig{
			Test:        []string{"CMD-SHELL", "test -e /var/run/openshell-ssh-ready || test -S " + shellQuote(socket) + " || ss -tlnp | grep -q :22"},
			Interval:    time.Duration(interval) * time.Second,
			Timeout:     2 * time.Second,
			Retries:     10,
			StartPeriod: 5 * time.Second,
		}
	}
	if reqs := DeviceRequestsForGPU(spec); len(reqs) > 0 {
		host.DeviceRequests = reqs
		labels[labelGPU] = "1"
	}
	if cfg.ExposedPorts == nil {
		cfg.ExposedPorts = network.PortSet{}
	}
	if host.PortBindings == nil {
		host.PortBindings = network.PortMap{}
	}
	if withDisplay {
		hostPort := spec.DisplayPort
		if hostPort <= 0 {
			hostPort = defaultNoVNCPort
		}
		p, _ := network.PortFrom(uint16(defaultNoVNCPort), network.TCP)
		cfg.ExposedPorts[p] = struct{}{}
		host.PortBindings[p] = []network.PortBinding{{
			HostIP:   netip.MustParseAddr("127.0.0.1"),
			HostPort: strconv.Itoa(hostPort),
		}}
		// Chromium needs shared memory; default 64MiB is too small in Docker.
		host.ShmSize = 1 << 30 // 1 GiB
	}
	for _, pub := range spec.PublishPorts {
		p, _ := network.PortFrom(uint16(pub.Guest), network.TCP)
		cfg.ExposedPorts[p] = struct{}{}
		host.PortBindings[p] = []network.PortBinding{{
			HostIP:   netip.MustParseAddr("127.0.0.1"),
			HostPort: strconv.Itoa(pub.Host),
		}}
	}
	if spec.CPU > 0 {
		host.NanoCPUs = int64(spec.CPU * 1e9)
	}
	if spec.MemoryBytes > 0 {
		host.Memory = spec.MemoryBytes
	}
	networking := &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{
			netName: {},
		},
	}
	createOpts := client.ContainerCreateOptions{Config: cfg, HostConfig: host, NetworkingConfig: networking, Name: ctrName}
	var resp client.ContainerCreateResult
	if d.runtimeConfig.NativeContainerCreate != nil {
		resp, err = d.runtimeConfig.NativeContainerCreate(ctx, createOpts)
	} else {
		resp, err = d.cli.ContainerCreate(ctx, createOpts)
	}
	if err != nil {
		if len(host.DeviceRequests) > 0 {
			return driver.Handle{}, fmt.Errorf("docker create %s: %w\nhint: enable NVIDIA CDI / Container Toolkit, or unset --gpu (see docs/exp/GPU.md)", ctrName, err)
		}
		return driver.Handle{}, fmt.Errorf("docker create %s: %w", ctrName, err)
	}
	resourcesCommitted = true
	return driver.Handle{
		ID:      core.ID(resp.ID),
		Name:    name,
		Network: netName,
		Image:   img,
	}, nil
}

// Start starts a created container and seeds persist dirs when applicable.
func (d *Driver) Start(ctx context.Context, id core.ID) error {
	if _, err := d.cli.ContainerStart(ctx, string(id), client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("docker start: %w", err)
	}
	if err := d.ensureGuestLayout(ctx, string(id)); err != nil {
		// Non-fatal: PATH is also injected via container/exec env.
		fmt.Fprintf(os.Stderr, "docker: guest layout: %v\n", err)
		d.printContainerDiagnostics(ctx, string(id))
	}
	if err := d.EnsureSSHDaemon(ctx, id); err != nil && !errors.Is(err, driver.ErrSSHDisabled) {
		fmt.Fprintf(os.Stderr, "docker: sshd: %v\n", err)
		d.printContainerDiagnostics(ctx, string(id))
	}
	return nil
}

func (d *Driver) printContainerDiagnostics(ctx context.Context, id string) {
	logs, err := d.cli.ContainerLogs(ctx, id, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: "40"})
	if err != nil || logs == nil {
		return
	}
	defer logs.Close()
	var buf strings.Builder
	if _, err := stdcopy.StdCopy(&buf, &buf, logs); err == nil && strings.TrimSpace(buf.String()) != "" {
		fmt.Fprintf(os.Stderr, "docker: container %s recent logs:\n%s\n", id, strings.TrimSpace(buf.String()))
	}
}

// ensureGuestLayout creates durable home/bin under GuestData for agent installs.
// Uses a raw docker exec (no cautem-init wrap) so layout works before harden paths matter.
func (d *Driver) ensureGuestLayout(ctx context.Context, id string) error {
	info, err := d.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil || info.Container.Config == nil {
		return err
	}
	if info.Container.Config.Labels[labelRole] == roleProxy {
		return nil
	}
	if info.Container.Config.Labels[labelVolume] == "" {
		return nil
	}
	script := "mkdir -p " + guestHomePath + "/.local/bin " + guestBinPath + " /etc/profile.d && " +
		"printf '%s\\n' 'export PATH=\"" + guestHomePath + "/.local/bin:" + guestBinPath + ":$PATH\"' > " + guestHomePath + "/.profile && " +
		"printf '%s\\n' 'export PATH=\"" + guestHomePath + "/.local/bin:" + guestBinPath + ":$PATH\"' > " + guestHomePath + "/.bashrc && " +
		"printf '%s\\n' 'export PATH=\"" + guestHomePath + "/.local/bin:" + guestBinPath + ":$PATH\"' > /etc/profile.d/cautem-path.sh"
	execID, err := d.cli.ExecCreate(ctx, id, client.ExecCreateOptions{
		Cmd:          []string{"/bin/bash", "-c", script},
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   "/",
		Env:          []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
	})
	if err != nil {
		return fmt.Errorf("guest layout exec create: %w", err)
	}
	attach, err := d.cli.ExecAttach(ctx, execID.ID, client.ExecAttachOptions{})
	if err != nil {
		return fmt.Errorf("guest layout exec attach: %w", err)
	}
	defer attach.Close()
	_, _ = io.Copy(io.Discard, attach.Reader)
	insp, err := d.cli.ExecInspect(ctx, execID.ID, client.ExecInspectOptions{})
	if err != nil {
		return err
	}
	if insp.ExitCode != 0 {
		state := "unknown"
		daemonError := ""
		if info, inspectErr := d.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{}); inspectErr == nil && info.Container.State != nil {
			state = string(info.Container.State.Status)
			daemonError = strings.TrimSpace(info.Container.State.Error)
		}
		if daemonError != "" {
			return fmt.Errorf("guest layout exit %d (container state=%s: %s)", insp.ExitCode, state, daemonError)
		}
		return fmt.Errorf("guest layout exit %d (container state=%s)", insp.ExitCode, state)
	}
	return nil
}

// Stop stops a running container.
func (d *Driver) Stop(ctx context.Context, id core.ID) error {
	timeout := d.stopTimeoutSecs()
	if _, err := d.cli.ContainerStop(ctx, string(id), client.ContainerStopOptions{Timeout: &timeout}); err != nil {
		return fmt.Errorf("docker stop: %w", err)
	}
	return nil
}

// Exec runs a command in the container. With TTY, attaches stdin/stdout in raw mode.
// When the sandbox was created with cautem-init, argv is wrapped: cautem-init -- <cmd>.
//
// Docker ExecCreate Env replaces the process environment when non-empty.
// We always merge the container's Config.Env first so HTTP_PROXY / CA / HOME from
// create survive (otherwise `cautem exec` / create `-- agent` cannot reach the sidecar).
func (d *Driver) Exec(ctx context.Context, id core.ID, req driver.ExecRequest) (driver.ExecResult, error) {
	if len(req.Argv) == 0 {
		return driver.ExecResult{}, fmt.Errorf("docker exec: empty argv")
	}
	argv := req.Argv
	workdir := mounts.WorkdirInContainer
	if strings.TrimSpace(req.WorkDir) != "" {
		workdir = strings.TrimSpace(req.WorkDir)
	}
	var containerEnv []string
	info, err := d.cli.ContainerInspect(ctx, string(id), client.ContainerInspectOptions{})
	if err != nil {
		return driver.ExecResult{}, fmt.Errorf("docker exec inspect container: %w", err)
	}
	if info.Container.Config == nil {
		return driver.ExecResult{}, fmt.Errorf("docker exec: container config is unavailable")
	}
	{
		containerEnv = append([]string{}, info.Container.Config.Env...)
		if info.Container.Config.Labels[labelInit] == "1" {
			argv = append([]string{"/cautem/cautem-init", "--"}, req.Argv...)
		}
		// Proxy sidecar has no /workspace mount; exec must not chdir there.
		if info.Container.Config.Labels[labelRole] == roleProxy {
			workdir = "/"
		}
	}
	tty := req.TTY
	inFd := int(os.Stdin.Fd())
	outFd := int(os.Stdout.Fd())
	hostTTY := tty && term.IsTerminal(inFd)

	// Prefer stdout for size (same as docker CLI Out().GetTtySize).
	sizeFd := outFd
	if !term.IsTerminal(sizeFd) {
		sizeFd = inFd
	}

	var consoleSize client.ConsoleSize
	// Container env (proxy, CA, PATH) + caller overrides (credential placeholders).
	env := ensureTTYEnv(mergeEnv(containerEnv, req.Env))
	// Do not inject LINES/COLUMNS: Node TUIs prefer env over ioctl, and a wrong
	// pair permanently squashes the UI. Size comes from ConsoleSize + resize.
	if tty && (hostTTY || term.IsTerminal(sizeFd)) {
		if width, height, err := term.GetSize(sizeFd); err == nil && width > 0 && height > 0 {
			// Docker ConsoleSize is [height, width] (docker CLI fillConsoleSize).
			consoleSize = client.ConsoleSize{Height: uint(height), Width: uint(width)}
		}
	}

	execID, err := d.cli.ExecCreate(ctx, string(id), client.ExecCreateOptions{
		Cmd:          argv,
		Env:          env,
		AttachStdout: true,
		AttachStderr: true,
		AttachStdin:  tty,
		TTY:          tty,
		WorkingDir:   workdir,
		ConsoleSize:  consoleSize,
	})
	if err != nil {
		return driver.ExecResult{}, fmt.Errorf("docker exec create: %w", err)
	}
	attach, err := d.cli.ExecAttach(ctx, execID.ID, client.ExecAttachOptions{
		TTY:         tty,
		ConsoleSize: consoleSize,
	})
	if err != nil {
		return driver.ExecResult{}, fmt.Errorf("docker exec attach: %w", err)
	}
	defer attach.Close()
	setConnNoDelay(attach.Conn)

	if tty {
		if hostTTY {
			old, err := term.MakeRaw(inFd)
			if err != nil {
				return driver.ExecResult{}, fmt.Errorf("docker exec raw terminal: %w", err)
			}
			defer func() { _ = term.Restore(inFd, old) }()
			// Resize before streaming so TUI mouse/scroll sees a real size on first paint.
			resizeExecOnce(ctx, d.cli, execID.ID, sizeFd)
			go resizeExecTTY(ctx, d.cli, execID.ID, sizeFd)
		}
		// When the remote PTY closes (e.g. shell `exit`), stop waiting on stdin —
		// otherwise stdin copy blocks until another keystroke.
		outDone := make(chan struct{})
		go func() {
			defer close(outDone)
			_, _ = io.Copy(os.Stdout, attach.Reader)
		}()
		go func() {
			// Small reads so mouse-wheel CSI sequences are forwarded promptly.
			_, _ = copyStdinTTY(attach.Conn, os.Stdin)
			_ = attach.CloseWrite()
		}()
		<-outDone
		_ = attach.CloseWrite()
	} else {
		_, _ = stdcopy.StdCopy(os.Stdout, os.Stderr, attach.Reader)
	}

	inspect, err := d.cli.ExecInspect(ctx, execID.ID, client.ExecInspectOptions{})
	if err != nil {
		return driver.ExecResult{}, fmt.Errorf("docker exec inspect: %w", err)
	}
	return driver.ExecResult{ExitCode: inspect.ExitCode}, nil
}

// ensureTTYEnv forces a guest TERM that Debian ships terminfo for.
// Host values like xterm-kitty / xterm-ghostty break mouse scroll inside the container.
func ensureTTYEnv(base []string) []string {
	env := append([]string{}, base...)
	termName := strings.TrimSpace(os.Getenv("TERM"))
	switch {
	case termName == "" || termName == "dumb" || termName == "unknown":
		termName = "xterm-256color"
	case strings.Contains(termName, "kitty"),
		strings.Contains(termName, "ghostty"),
		strings.Contains(termName, "alacritty"),
		strings.HasPrefix(termName, "tmux"),
		strings.HasPrefix(termName, "screen"):
		// Keep 256color semantics; container rarely has fancy terminfo entries.
		termName = "xterm-256color"
	}
	env = mergeEnv(env, []string{"TERM=" + termName})
	if os.Getenv("COLORTERM") == "" {
		env = mergeEnv(env, []string{"COLORTERM=truecolor"})
	}
	return env
}

func setConnNoDelay(c net.Conn) {
	type noDelayer interface{ SetNoDelay(bool) error }
	if nd, ok := c.(noDelayer); ok {
		_ = nd.SetNoDelay(true)
	}
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
}

// copyStdinTTY forwards host key/mouse bytes with a small buffer (not io.Copy's 32KiB).
func copyStdinTTY(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 256)
	var n int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			n += int64(nw)
			if ew != nil {
				return n, ew
			}
			if nr != nw {
				return n, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return n, nil
			}
			return n, er
		}
	}
}

func resizeExecOnce(ctx context.Context, cli *client.Client, execID string, inFd int) {
	width, height, err := term.GetSize(inFd)
	if err != nil || width <= 0 || height <= 0 {
		return
	}
	_, _ = cli.ExecResize(ctx, execID, client.ExecResizeOptions{
		Height: uint(height),
		Width:  uint(width),
	})
}

// Delete removes sandbox container, proxy sidecar, cautem network, and data volume.
func (d *Driver) Delete(ctx context.Context, id core.ID) error {
	info, err := d.cli.ContainerInspect(ctx, string(id), client.ContainerInspectOptions{})
	if err != nil {
		return fmt.Errorf("docker delete inspect: %w", err)
	}
	netName := info.Container.Config.Labels[labelNetwork]
	name := info.Container.Config.Labels[labelName]
	volName := info.Container.Config.Labels[labelVolume]
	caVol := info.Container.Config.Labels["cautem.ca_volume"]
	sshVol := info.Container.Config.Labels[labelSSHVol]
	_, _ = d.cli.ContainerRemove(ctx, string(id), client.ContainerRemoveOptions{Force: true})
	if name != "" {
		_ = d.removeProxySidecar(ctx, name)
	}
	if netName != "" {
		_, _ = d.cli.NetworkRemove(ctx, netName, client.NetworkRemoveOptions{})
	}
	if volName != "" {
		_, _ = d.cli.VolumeRemove(ctx, volName, client.VolumeRemoveOptions{Force: true})
	}
	if caVol != "" {
		_, _ = d.cli.VolumeRemove(ctx, caVol, client.VolumeRemoveOptions{Force: true})
	}
	if sshVol != "" {
		_, _ = d.cli.VolumeRemove(ctx, sshVol, client.VolumeRemoveOptions{Force: true})
	}
	return nil
}

// List returns cautem sandbox containers (excludes proxy sidecars).
func (d *Driver) List(ctx context.Context) ([]driver.Info, error) {
	f := client.Filters{}
	f.Add("label", labelSandbox+"=1")
	list, err := d.cli.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: f})
	if err != nil {
		return nil, err
	}
	out := make([]driver.Info, 0, len(list.Items))
	for _, c := range list.Items {
		if c.Labels[labelRole] == roleProxy {
			continue
		}
		name := c.Labels[labelName]
		if name == "" && len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		out = append(out, driver.Info{
			ID:      core.ID(c.ID),
			Name:    name,
			Network: c.Labels[labelNetwork],
			Image:   c.Image,
			Status:  c.Status,
		})
	}
	return out, nil
}

// Inspect resolves by sandbox name or container id/prefix.
func (d *Driver) Inspect(ctx context.Context, nameOrID string) (driver.Info, error) {
	nameOrID = strings.TrimSpace(nameOrID)
	if nameOrID == "" {
		return driver.Info{}, fmt.Errorf("docker inspect: empty name")
	}
	// Try container name cautem-<name>
	candidates := []string{nameOrID, "cautem-" + nameOrID}
	for _, id := range candidates {
		c, err := d.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
		if err != nil {
			continue
		}
		if c.Container.Config.Labels[labelSandbox] != "1" && !strings.HasPrefix(strings.TrimPrefix(c.Container.Name, "/"), "cautem-") {
			continue
		}
		name := c.Container.Config.Labels[labelName]
		if name == "" {
			name = strings.TrimPrefix(c.Container.Name, "/")
			name = strings.TrimPrefix(name, "cautem-")
		}
		return driver.Info{
			ID:      core.ID(c.Container.ID),
			Name:    name,
			Network: c.Container.Config.Labels[labelNetwork],
			Image:   c.Container.Config.Image,
			Status:  string(c.Container.State.Status),
		}, nil
	}
	return driver.Info{}, fmt.Errorf("docker inspect: sandbox %q not found", nameOrID)
}

// ContainerIP returns the sandbox container IP on its cautem network.
func (d *Driver) ContainerIP(ctx context.Context, containerID, networkName string) (string, error) {
	if d == nil || d.cli == nil {
		return "", fmt.Errorf("docker driver: client not initialized")
	}
	c, err := d.cli.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return "", err
	}
	if networkName == "" && c.Container.Config != nil {
		networkName = c.Container.Config.Labels[labelNetwork]
	}
	if networkName != "" && c.Container.NetworkSettings != nil {
		if n, ok := c.Container.NetworkSettings.Networks[networkName]; ok && n.IPAddress.IsValid() {
			return n.IPAddress.String(), nil
		}
	}
	if c.Container.NetworkSettings != nil {
		for _, n := range c.Container.NetworkSettings.Networks {
			if n.IPAddress.IsValid() {
				return n.IPAddress.String(), nil
			}
		}
	}
	return "", fmt.Errorf("docker: no IP for container on network %q", networkName)
}

// ParseMemoryBytes parses Docker-style memory strings (512m, 4g, …).
func ParseMemoryBytes(s string) (int64, error) {
	return units.RAMInBytes(s)
}

// Logs streams stdout/stderr from the sandbox container and, when present, the
// egress proxy sidecar (where OCSF agent-observation events are emitted).
// When follow is true, starts from the last 500 lines per container.
func (d *Driver) Logs(ctx context.Context, id core.ID, follow bool, w io.Writer) error {
	if w == nil {
		w = os.Stdout
	}
	opts := client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     follow,
		Timestamps: false,
	}
	if follow {
		opts.Tail = "500"
	}

	type src struct {
		id     string
		prefix string
	}
	sources := []src{{id: string(id), prefix: "sandbox"}}

	if info, err := d.cli.ContainerInspect(ctx, string(id), client.ContainerInspectOptions{}); err == nil && info.Container.Config != nil {
		name := info.Container.Config.Labels[labelName]
		if name == "" {
			name = strings.TrimPrefix(strings.TrimPrefix(info.Container.Name, "/"), "cautem-")
		}
		if name != "" {
			proxyName := "cautem-proxy-" + name
			if _, err := d.cli.ContainerInspect(ctx, proxyName, client.ContainerInspectOptions{}); err == nil {
				sources = append(sources, src{id: proxyName, prefix: "proxy"})
			}
		}
	}

	if len(sources) == 1 {
		rc, err := d.cli.ContainerLogs(ctx, sources[0].id, opts)
		if err != nil {
			return fmt.Errorf("docker logs: %w", err)
		}
		defer rc.Close()
		_, err = stdcopy.StdCopy(w, w, rc)
		return err
	}

	var mu sync.Mutex
	writeLine := func(prefix, text string) error {
		mu.Lock()
		defer mu.Unlock()
		_, err := fmt.Fprintf(w, "[%s] %s\n", prefix, text)
		return err
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(sources))
	for _, s := range sources {
		rc, err := d.cli.ContainerLogs(ctx, s.id, opts)
		if err != nil {
			if s.prefix == "proxy" {
				continue
			}
			return fmt.Errorf("docker logs %s: %w", s.id, err)
		}
		wg.Add(1)
		go func(prefix string, rc io.ReadCloser) {
			defer wg.Done()
			defer rc.Close()
			pr, pw := io.Pipe()
			go func() {
				_, copyErr := stdcopy.StdCopy(pw, pw, rc)
				_ = pw.CloseWithError(copyErr)
			}()
			sc := bufio.NewScanner(pr)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for sc.Scan() {
				if ctx.Err() != nil {
					errCh <- ctx.Err()
					return
				}
				if err := writeLine(prefix, sc.Text()); err != nil {
					errCh <- err
					return
				}
			}
			if err := sc.Err(); err != nil && ctx.Err() == nil {
				errCh <- err
			}
		}(s.prefix, rc)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		select {
		case err := <-errCh:
			return err
		default:
			return nil
		}
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Driver) ensureVolume(ctx context.Context, name string) (bool, error) {
	_, err := d.cli.VolumeInspect(ctx, name, client.VolumeInspectOptions{})
	if err == nil {
		return false, nil
	}
	_, err = d.cli.VolumeCreate(ctx, client.VolumeCreateOptions{Name: name, Labels: map[string]string{"cautem.volume": "1"}})
	if err != nil {
		return false, fmt.Errorf("docker volume create %s: %w", name, err)
	}
	return true, nil
}

// CopyTo tars srcHost and extracts at destPath inside the container.
// For a single file, destPath is the full guest path (basename used in the tar).
// For a directory, destPath is the guest parent directory under which src's basename appears.
func (d *Driver) CopyTo(ctx context.Context, id core.ID, srcHost, destPath string) error {
	srcHost = filepath.Clean(srcHost)
	st, err := os.Stat(srcHost)
	if err != nil {
		return err
	}
	destPath = filepath.ToSlash(filepath.Clean(destPath))
	pr, pw := io.Pipe()
	errCh := make(chan error, 1)
	go func() {
		tw := tar.NewWriter(pw)
		var err error
		if st.IsDir() {
			err = writeTarDir(tw, srcHost, filepath.Base(srcHost))
		} else {
			err = writeTarFile(tw, srcHost, st, filepath.Base(destPath))
		}
		_ = tw.Close()
		_ = pw.CloseWithError(err)
		errCh <- err
	}()
	destDir := destPath
	if !st.IsDir() {
		destDir = filepath.ToSlash(filepath.Dir(destPath))
		if destDir == "." || destDir == "" {
			destDir = "/"
		}
	}
	_, err = d.cli.CopyToContainer(ctx, string(id), client.CopyToContainerOptions{DestinationPath: destDir, Content: pr, AllowOverwriteDirWithFile: true})
	_ = pr.Close()
	if werr := <-errCh; werr != nil && err == nil {
		err = werr
	}
	if err != nil {
		return fmt.Errorf("docker copy to: %w", err)
	}
	return nil
}

func writeTarDir(tw *tar.Writer, src, base string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(filepath.Join(base, rel))
		if rel == "." {
			name = base + "/"
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = name
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		_ = f.Close()
		return err
	})
}

func writeTarFile(tw *tar.Writer, src string, st os.FileInfo, archiveName string) error {
	hdr, err := tar.FileInfoHeader(st, "")
	if err != nil {
		return err
	}
	hdr.Name = archiveName
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

// CopyFrom reads a container path as tar and writes into destHost.
// If destHost exists as a directory (or ends with a path separator), entries are
// extracted under it. Otherwise a single regular file is written to destHost.
func (d *Driver) CopyFrom(ctx context.Context, id core.ID, srcPath, destHost string) error {
	copied, err := d.cli.CopyFromContainer(ctx, string(id), client.CopyFromContainerOptions{SourcePath: srcPath})
	if err != nil {
		return fmt.Errorf("docker copy from: %w", err)
	}
	rc := copied.Content
	defer rc.Close()

	asDir := strings.HasSuffix(destHost, string(os.PathSeparator)) || strings.HasSuffix(destHost, "/")
	if st, err := os.Stat(destHost); err == nil && st.IsDir() {
		asDir = true
	}

	tr := tar.NewReader(rc)
	return extractCopyTar(tr, destHost, asDir, srcPath)
}

func extractCopyTar(tr *tar.Reader, destHost string, asDir bool, srcPath string) error {
	rootPath := filepath.Dir(destHost)
	if asDir {
		rootPath = destHost
	}
	if err := os.MkdirAll(rootPath, 0o755); err != nil {
		return err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	wroteFile := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			if !asDir && !wroteFile {
				return fmt.Errorf("docker copy from: no regular file at %s", srcPath)
			}
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeDir && (hdr.Name == "." || hdr.Name == "./") {
			continue
		}
		name, err := safeArchiveName(hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if !asDir {
				continue
			}
			if err := rejectExistingSymlink(root, name); err != nil {
				return err
			}
			if err := root.MkdirAll(name, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			target := name
			if !asDir {
				if wroteFile {
					return fmt.Errorf("docker copy from: dest %s is a file but archive has multiple entries", destHost)
				}
				target = filepath.Base(destHost)
				wroteFile = true
			}
			if err := rejectExistingSymlink(root, target); err != nil {
				return err
			}
			if err := root.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if hdr.Mode&0o111 != 0 {
				mode = 0o755
			}
			f, err := root.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr)
			if chmodErr := f.Chmod(mode); err == nil {
				err = chmodErr
			}
			if closeErr := f.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				return err
			}
		}
	}
}

func safeArchiveName(raw string) (string, error) {
	if raw == "" || filepath.IsAbs(raw) {
		return "", fmt.Errorf("docker copy from: invalid archive path %q", raw)
	}
	for _, part := range strings.Split(raw, string(os.PathSeparator)) {
		if part == ".." {
			return "", fmt.Errorf("docker copy from: archive path escapes destination: %q", raw)
		}
	}
	name := filepath.Clean(raw)
	if name == "." || name == ".." || strings.HasPrefix(name, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("docker copy from: archive path escapes destination: %q", raw)
	}
	return name, nil
}

func rejectExistingSymlink(root *os.Root, name string) error {
	component := ""
	for _, part := range strings.Split(filepath.Clean(name), string(os.PathSeparator)) {
		component = filepath.Join(component, part)
		info, err := root.Lstat(component)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("docker copy from: symlink in destination path %q", component)
		}
	}
	return nil
}

// EnsureSSHDaemon starts cautem-sshd as root on the relay socket
// (idempotent: sshd exits when a live daemon already owns the socket) and
// waits until the socket exists. Returns driver.ErrSSHDisabled for sandboxes
// created without SSH.
func (d *Driver) EnsureSSHDaemon(ctx context.Context, id core.ID) error {
	info, err := d.cli.ContainerInspect(ctx, string(id), client.ContainerInspectOptions{})
	if err != nil {
		return err
	}
	if info.Container.Config == nil || info.Container.Config.Labels[labelSSH] != "1" {
		return driver.ErrSSHDisabled
	}
	if info.Container.State == nil || !info.Container.State.Running {
		return fmt.Errorf("sandbox is not running")
	}
	sshSocket := d.sandboxSSHSocketPath()
	script := "exec " + defaults.GuestSSHD + " --socket " + shellQuote(sshSocket) + " >>" + defaults.GuestSSHLog + " 2>&1"
	execID, err := d.cli.ExecCreate(ctx, string(id), client.ExecCreateOptions{
		Cmd:        []string{"/bin/sh", "-c", script},
		User:       "0",
		WorkingDir: "/",
	})
	if err != nil {
		return fmt.Errorf("sshd exec create: %w", err)
	}
	if _, err := d.cli.ExecStart(ctx, execID.ID, client.ExecStartOptions{Detach: true}); err != nil {
		return fmt.Errorf("sshd exec start: %w", err)
	}
	deadline := time.Now().Add(readinessTimeout)
	for time.Now().Before(deadline) {
		if code, err := d.rawExec(ctx, string(id), []string{"test", "-S", sshSocket}); err == nil && code == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(readinessPollInterval):
		}
	}
	return fmt.Errorf("sshd socket %s did not appear (see %s)", sshSocket, defaults.GuestSSHLog)
}

// rawExec runs argv as root without the cautem-init wrapper.
func (d *Driver) rawExec(ctx context.Context, id string, argv []string) (int, error) {
	execID, err := d.cli.ExecCreate(ctx, id, client.ExecCreateOptions{
		Cmd:          argv,
		User:         "0",
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   "/",
	})
	if err != nil {
		return -1, err
	}
	attach, err := d.cli.ExecAttach(ctx, execID.ID, client.ExecAttachOptions{})
	if err != nil {
		return -1, err
	}
	_, _ = io.Copy(io.Discard, attach.Reader)
	attach.Close()
	insp, err := d.cli.ExecInspect(ctx, execID.ID, client.ExecInspectOptions{})
	if err != nil {
		return -1, err
	}
	return insp.ExitCode, nil
}

func (d *Driver) ensureNetwork(ctx context.Context, netName, sandboxName string, internal bool) (bool, error) {
	if internal && d.runtimeConfig.NativeNetworkCreate != nil && d.runtimeConfig.NativeNetworkVerify == nil {
		return false, fmt.Errorf("network %s: native backend cannot verify host-gateway isolation", netName)
	}
	inspected, err := d.cli.NetworkInspect(ctx, netName, client.NetworkInspectOptions{})
	if err == nil {
		if internal && !inspected.Network.Internal {
			return false, fmt.Errorf("docker network %s already exists but is not internal; refusing proxy-isolated sandbox", netName)
		}
		if internal && d.runtimeConfig.NativeNetworkVerify == nil && (inspected.Network.Options["com.docker.network.bridge.gateway_mode_ipv4"] != "isolated" || inspected.Network.Options["com.docker.network.bridge.gateway_mode_ipv6"] != "isolated") {
			return false, fmt.Errorf("docker network %s does not isolate its host gateway; refusing proxy-isolated sandbox", netName)
		}
		if internal && d.runtimeConfig.NativeNetworkVerify != nil {
			if err := d.runtimeConfig.NativeNetworkVerify(ctx, netName, true); err != nil {
				return false, fmt.Errorf("network %s lacks verified host-gateway isolation: %w", netName, err)
			}
		}
		return false, nil
	}
	if d.runtimeConfig.NativeNetworkCreate != nil {
		if err := d.runtimeConfig.NativeNetworkCreate(ctx, netName, internal, map[string]string{labelSandbox: "1", labelName: sandboxName}); err != nil {
			return false, fmt.Errorf("native network create %s: %w", netName, err)
		}
		if internal && d.runtimeConfig.NativeNetworkVerify != nil {
			if err := d.runtimeConfig.NativeNetworkVerify(ctx, netName, true); err != nil {
				_, _ = d.cli.NetworkRemove(ctx, netName, client.NetworkRemoveOptions{})
				return false, fmt.Errorf("network %s lacks verified host-gateway isolation: %w", netName, err)
			}
		}
		return true, nil
	}
	options := map[string]string(nil)
	if internal {
		// Internal=true blocks routed egress but still leaves the bridge gateway
		// reachable from containers. Isolated gateway mode removes the host-side
		// bridge address so sandbox traffic cannot bypass the policy proxy.
		options = map[string]string{
			"com.docker.network.bridge.gateway_mode_ipv4": "isolated",
			"com.docker.network.bridge.gateway_mode_ipv6": "isolated",
		}
	}
	_, err = d.cli.NetworkCreate(ctx, netName, client.NetworkCreateOptions{
		Driver:   "bridge",
		Internal: internal, // fail-closed when proxy sidecar is enabled
		Options:  options,
		Labels: map[string]string{
			labelSandbox: "1",
			labelName:    sandboxName,
		},
	})
	if err != nil {
		return false, fmt.Errorf("docker network create %s: %w", netName, err)
	}
	return true, nil
}

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
		LogConfig:   sandboxLogConfig(),
		Resources: container.Resources{
			PidsLimit: resolvePidsLimit(d.configuredPidsLimit(pidsLimit)),
		},
	}
	networking := &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{
			netName: {Aliases: []string{"cautem-proxy", ctrName}},
		},
	}
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
	ctrName := "cautem-proxy-" + name
	_, _ = d.cli.ContainerRemove(ctx, ctrName, client.ContainerRemoveOptions{Force: true})
	return nil
}

func mergeEnv(base, extra []string) []string {
	keys := map[string]int{}
	out := make([]string, 0, len(base)+len(extra))
	add := func(entry string) {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			return
		}
		if i, exists := keys[key]; exists {
			out[i] = entry
			return
		}
		keys[key] = len(out)
		out = append(out, entry)
	}
	for _, e := range base {
		add(e)
	}
	for _, e := range extra {
		add(e)
	}
	return out
}

func filterIdentityEnv(env []string) []string {
	reserved := map[string]struct{}{
		"OPENSHELL_OCI_IMAGE_USER": {},
		"OPENSHELL_SANDBOX_UID":    {},
		"OPENSHELL_SANDBOX_GID":    {},
	}
	out := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if _, blocked := reserved[key]; blocked {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// ImagePresent reports whether ref exists locally (no pull).
func (d *Driver) ImagePresent(ctx context.Context, ref string) bool {
	if d == nil || d.cli == nil || strings.TrimSpace(ref) == "" {
		return false
	}
	_, err := d.cli.ImageInspect(ctx, ref)
	return err == nil
}

func (d *Driver) ensureImage(ctx context.Context, ref string) error {
	policy := strings.ToLower(strings.TrimSpace(d.runtimeConfig.ImagePullPolicy))
	if policy == "always" || policy == "newer" {
		return d.pullImage(ctx, ref)
	}
	_, err := d.cli.ImageInspect(ctx, ref)
	if err == nil {
		return nil
	}
	if policy == "never" {
		return fmt.Errorf("docker image %s is not available locally and image_pull_policy is never", ref)
	}
	low := strings.ToLower(ref)
	if low == localSandboxImage || low == guiSandboxImage || low == gpuSandboxImage || strings.HasPrefix(low, "cautem-sandbox:") {
		remote, published := defaults.PublishedImage(low)
		var pullErr error
		if published && !strings.EqualFold(os.Getenv(defaults.EnvImagePull), "never") {
			if pullErr = d.pullAs(ctx, remote, ref); pullErr == nil {
				return nil
			}
		}
		hint := "task runtime:image:cli"
		switch {
		case strings.Contains(low, "cursor"):
			hint = "task docker:agent:cursor"
		case strings.Contains(low, "claude"):
			hint = "task docker:agent:claude"
		case strings.Contains(low, "codex"):
			hint = "task docker:agent:codex"
		case low == guiSandboxImage || strings.Contains(low, "gui"):
			hint = "task runtime:image:gui"
		case low == gpuSandboxImage || strings.Contains(low, "gpu"):
			hint = "task runtime:image:gpu"
		}
		if pullErr != nil {
			return fmt.Errorf("docker image %s not found locally and %w; build with: %s", ref, pullErr, hint)
		}
		if published {
			return fmt.Errorf("docker image %s not found locally; build with: %s (or unset %s=never to pull %s)", ref, hint, defaults.EnvImagePull, remote)
		}
		return fmt.Errorf("docker image %s not found locally; build with: %s", ref, hint)
	}
	return d.pullImage(ctx, ref)
}

func (d *Driver) pullImage(ctx context.Context, ref string) error {
	auth, err := d.registryAuth(ref)
	if err != nil {
		return err
	}
	rc, err := d.cli.ImagePull(ctx, ref, client.ImagePullOptions{RegistryAuth: auth})
	if err != nil {
		return fmt.Errorf("docker pull %s: %w", ref, err)
	}
	defer rc.Close()
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return fmt.Errorf("docker pull %s: %w", ref, err)
	}
	return nil
}

// pullAs pulls a published image and tags it with the local name the rest of
// the driver keys on (embedded init, GUI detection).
func (d *Driver) pullAs(ctx context.Context, remote, local string) error {
	fmt.Fprintf(os.Stderr, "docker: pulling %s (for %s)…\n", remote, local)
	auth, err := d.registryAuth(remote)
	if err != nil {
		return err
	}
	rc, err := d.cli.ImagePull(ctx, remote, client.ImagePullOptions{RegistryAuth: auth})
	if err != nil {
		return fmt.Errorf("pull %s failed: %w", remote, err)
	}
	_, _ = io.Copy(io.Discard, rc)
	_ = rc.Close()
	if _, err := d.cli.ImageTag(ctx, client.ImageTagOptions{Source: remote, Target: local}); err != nil {
		return fmt.Errorf("pull %s failed: %w", remote, err)
	}
	return nil
}

func (d *Driver) defaultSandboxImage(ctx context.Context, displayMode string, gpu bool) string {
	if d == nil || d.cli == nil {
		return defaultImage
	}
	if strings.EqualFold(strings.TrimSpace(displayMode), "novnc") {
		if _, err := d.cli.ImageInspect(ctx, guiSandboxImage); err == nil {
			return guiSandboxImage
		}
		return guiSandboxImage // ensureImage will fail with a clear pull error; task runtime:image:gui preferred
	}
	if gpu {
		if _, err := d.cli.ImageInspect(ctx, gpuSandboxImage); err == nil {
			return gpuSandboxImage
		}
		return gpuSandboxImage
	}
	_, err := d.cli.ImageInspect(ctx, localSandboxImage)
	if err == nil {
		return localSandboxImage
	}
	return defaultImage
}

func usesEmbeddedInit(img string) bool {
	img = strings.TrimSpace(strings.ToLower(img))
	return img == localSandboxImage || img == guiSandboxImage || strings.HasPrefix(img, "cautem-sandbox:")
}

func imageHasGUI(img string) bool {
	img = strings.TrimSpace(strings.ToLower(img))
	if img == guiSandboxImage || strings.Contains(img, ":gui") {
		return true
	}
	// Heuristic: inspect for cautem-gui-boot via missing path is hard; require known tags.
	return false
}

// SeccompNote documents the MVP harden posture for health / spike notes.
func SeccompNote() string {
	return "docker-default + no-new-privileges + CapDrop=NET_RAW (in-process filter later)"
}

func sanitizeName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}

// RunProbe runs cautem-init --probe in a one-shot helper container (Landlock ABI).
func (d *Driver) RunProbe(ctx context.Context, initBin string) (string, error) {
	if d == nil || d.cli == nil {
		return "", fmt.Errorf("docker client not initialized")
	}
	if err := d.ensureImage(ctx, defaultImage); err != nil {
		return "", err
	}
	cfg := &container.Config{
		Image:      defaultImage,
		Cmd:        []string{"/cautem/cautem-init", "--probe"},
		WorkingDir: "/",
	}
	host := &container.HostConfig{
		Binds: []string{initBin + ":/cautem/cautem-init:ro"},
		// AutoRemove handled after wait
	}
	resp, err := d.cli.ContainerCreate(ctx, client.ContainerCreateOptions{Config: cfg, HostConfig: host, NetworkingConfig: nil, Name: ""})
	if err != nil {
		return "", fmt.Errorf("probe create: %w", err)
	}
	id := resp.ID
	defer func() { _, _ = d.cli.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true}) }()
	if _, err := d.cli.ContainerStart(ctx, id, client.ContainerStartOptions{}); err != nil {
		return "", fmt.Errorf("probe start: %w", err)
	}
	wait := d.cli.ContainerWait(ctx, id, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case err := <-wait.Error:
		if err != nil {
			return "", err
		}
	case <-wait.Result:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	logs, err := d.cli.ContainerLogs(ctx, id, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return "", err
	}
	defer logs.Close()
	var buf strings.Builder
	_, _ = stdcopy.StdCopy(&buf, &buf, logs)
	out := strings.TrimSpace(buf.String())
	if out == "" {
		return "empty probe output", nil
	}
	// Compact one-line summary if JSON
	if strings.Contains(out, "LandlockABI") {
		return summarizeProbeJSON(out), nil
	}
	return out, nil
}

func summarizeProbeJSON(raw string) string {
	raw = strings.TrimSpace(raw)
	// Prefer a one-line human summary when JSON decode works.
	var m struct {
		LandlockABI   int    `json:"LandlockABI"`
		LandlockError string `json:"LandlockError"`
	}
	if err := json.Unmarshal([]byte(raw), &m); err == nil {
		if m.LandlockABI > 0 {
			return fmt.Sprintf("abi=%d (probe ok)", m.LandlockABI)
		}
		if m.LandlockError != "" {
			return fmt.Sprintf("abi=0 (%s)", m.LandlockError)
		}
		return "abi=0"
	}
	return strings.ReplaceAll(strings.ReplaceAll(raw, "\n", " "), "  ", " ")
}

// Health probes the daemon (Ping + ServerVersion + Info).
func (d *Driver) Health(ctx context.Context) driver.Probe {
	runtimeContext := ""
	if d != nil {
		runtimeContext = d.runtimeConfig.RuntimeContext
	}
	if runtimeContext == "" {
		runtimeContext = dockerContextName()
	}
	p := driver.Probe{
		Context:      runtimeContext,
		HostGOOS:     runtime.GOOS,
		Capabilities: d.capabilities(),
	}
	if d == nil || d.cli == nil {
		p.Error = "docker client not initialized"
		return p
	}
	if _, err := d.cli.Ping(ctx, client.PingOptions{}); err != nil {
		p.Error = err.Error()
		return p
	}
	ver, err := d.cli.ServerVersion(ctx, client.ServerVersionOptions{})
	if err != nil {
		p.Error = err.Error()
		return p
	}
	p.ServerVersion = ver.Version
	p.APIVersion = ver.APIVersion
	p.OperatingSystem = ver.Os
	p.Architecture = ver.Arch

	info, err := d.cli.Info(ctx, client.InfoOptions{})
	if err == nil {
		if info.Info.OperatingSystem != "" {
			p.OperatingSystem = info.Info.OperatingSystem
		}
		if info.Info.Architecture != "" {
			p.Architecture = info.Info.Architecture
		}
		p.Isolation = classifyIsolation(runtime.GOOS, info.Info.OperatingSystem, info.Info.OSType)
		p.SecurityOptions = append([]string(nil), info.Info.SecurityOptions...)
		for _, option := range info.Info.SecurityOptions {
			if strings.Contains(strings.ToLower(option), "rootless") {
				p.Rootless = "yes"
				break
			}
		}
		if p.Rootless == "" {
			p.Rootless = "no or unreported"
		}
	} else {
		p.Isolation = classifyIsolation(runtime.GOOS, p.OperatingSystem, ver.Os)
	}
	p.OK = true
	return p
}

func (d *Driver) capabilities() []string {
	if d != nil && len(d.runtimeConfig.Capabilities) > 0 {
		return append([]string(nil), d.runtimeConfig.Capabilities...)
	}
	return []string{"cdi"}
}

func dockerContextName() string {
	if v := strings.TrimSpace(os.Getenv("DOCKER_CONTEXT")); v != "" {
		return v
	}
	return "default"
}

func classifyIsolation(hostGOOS, _, _ string) string {
	if hostGOOS == "darwin" || hostGOOS == "windows" {
		return "docker-desktop-vm"
	}
	if hostGOOS == "linux" {
		return "native-linux"
	}
	return "unknown"
}
