// Package docker implements driver.ComputeDriver via the Docker Engine API.
package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	enginemount "github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	volumetypes "github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"

	"path/filepath"

	core "github.com/cautem/quarshell-core"
	"github.com/cautem/quarshell-core/defaults"
	"github.com/cautem/quarshell-core/resourceadmission"
	"github.com/cautem/quarshell-driver/driver"
	"github.com/cautem/quarshell-driver/internal/mounts"
	"github.com/cautem/quarshell-driver/internal/sidecar"
)

// Create ensures network + optional proxy sidecar + sandbox container (not started).
func (d *Driver) Create(ctx context.Context, spec driver.Spec) (driver.Handle, error) {
	validated, err := d.validateCreate(ctx, spec)
	if err != nil {
		return driver.Handle{}, err
	}
	driverCDIDevices := validated.cdiDevices
	hasDriverCDIDevices := validated.hasCDIDevices
	driverMounts := validated.mounts
	driverBinds := validated.binds
	resourceIdentities := validated.resourceIdentities
	configUsed := validated.configUsed
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
	workspaceSource, err := mounts.ResolveWorkspaceSource(spec.Workspace, spec.IKnow)
	if err != nil {
		return driver.Handle{}, err
	}
	ws := workspaceSource.Path
	netPrefix := strings.TrimSpace(d.runtimeConfig.NetworkName)
	if netPrefix == "" {
		netPrefix = "cautem-net"
	}
	netName := netPrefix + "-" + name
	ctrName := "cautem-" + name
	withProxy := strings.TrimSpace(spec.ProxyBin) != ""
	withSupervisor := strings.TrimSpace(spec.SupervisorBin) != ""
	restartPolicy, err := driver.NormalizeMainProcessRestartPolicy(spec.MainProcessRestartPolicy)
	if err != nil {
		return driver.Handle{}, fmt.Errorf("docker driver: %w", err)
	}
	if !withSupervisor && restartPolicy != "never" {
		return driver.Handle{}, fmt.Errorf("docker driver: main process restart policy requires cautem-supervisor")
	}
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
	if withSupervisor {
		env = mergeEnv(env, []string{driver.MainProcessRestartPolicyEnv + "=" + restartPolicy})
	}
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
		created, err := d.ensureVolume(ctx, caVol, name, roleVolumeCA)
		if err != nil {
			return driver.Handle{}, err
		}
		if created {
			createdVolumes[caVol] = true
		}
		if sshVol != "" {
			created, err := d.ensureVolume(ctx, sshVol, name, roleVolumeSSH)
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
		if d.runtimeConfig.BackendID == "podman" {
			// Podman 6's fail-closed blackhole route targets the internal
			// network gateway, which also serves container-name DNS. Give the
			// workload the sidecar's reserved address directly so proxy access
			// does not depend on that intentionally unreachable resolver.
			proxyHost, err = d.ContainerIP(ctx, "cautem-proxy-"+name, netName)
			if err != nil {
				return driver.Handle{}, fmt.Errorf("podman proxy sidecar address: %w", err)
			}
		}
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
	if configUsed {
		labels["cautem.internal/driver-config-used"] = "true"
	} else {
		labels["cautem.internal/driver-config-used"] = "false"
	}
	containsUnlabelable := false
	for _, mount := range driverMounts {
		if mount.Type == enginemount.TypeBind || mount.Type == enginemount.TypeImage {
			containsUnlabelable = true
		}
	}
	labels["cautem.internal/driver-config-unlabelable"] = strconv.FormatBool(containsUnlabelable)
	encodedIdentities, err := json.Marshal(resourceIdentities)
	if err != nil || len(encodedIdentities) > 4096 {
		return driver.Handle{}, fmt.Errorf("docker driver: resource admission identity record exceeds label limit")
	}
	labels["cautem.internal/resource-admission-identities"] = string(encodedIdentities)
	if namespace := strings.TrimSpace(d.runtimeConfig.SandboxNamespace); namespace != "" {
		labels["openshell.ai/sandbox-namespace"] = namespace
	}
	if spec.PersistVolume {
		volName := "cautem-data-" + name
		if _, err := d.ensureVolume(ctx, volName, name, roleVolumeData); err != nil {
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
		Tty:        spec.TTY,
		OpenStdin:  spec.TTY,
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
	securityOpts := []string{"no-new-privileges:true"}
	if appArmor, ok := d.runtimeConfig.AppArmorProfile.OCISecurityOption(); ok {
		securityOpts = append(securityOpts, appArmor)
	}
	host := &container.HostConfig{
		Binds:       binds,
		Mounts:      driverMounts,
		NetworkMode: container.NetworkMode(netName),
		// Never mount docker.sock into the sandbox.
		// Docker default seccomp stays on (do not set seccomp=unconfined).
		SecurityOpt: securityOpts,
		CapDrop:     []string{"NET_RAW"},
		// Do not give the sandbox a host-gateway alias. Only the proxy sidecar
		// needs that route for gateway-owned control traffic.
		ExtraHosts: append([]string{}, spec.ExtraHosts...),
		LogConfig:  sandboxLogConfig(d.runtimeConfig.LogDriver),
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
	workloadEndpoint := &network.EndpointSettings{Aliases: []string{ctrName}}
	if d.runtimeConfig.BackendID == "podman" && withProxy {
		_, sandboxIP, err := d.staticPodmanNetworkIPs(ctx, netName)
		if err != nil {
			return driver.Handle{}, fmt.Errorf("docker create %s: reserve Podman isolated-network address: %w", ctrName, err)
		}
		workloadEndpoint.IPAMConfig = &network.EndpointIPAMConfig{IPv4Address: sandboxIP}
	}
	networking := &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{netName: workloadEndpoint}}
	createOpts := client.ContainerCreateOptions{Config: cfg, HostConfig: host, NetworkingConfig: networking, Name: ctrName}
	// The Engine API accepts a path, not an open directory handle. Recheck the
	// canonical directory identity after image/network/sidecar preparation so a
	// path replacement during that work fails closed before the bind is created.
	if err := workspaceSource.VerifyUnchanged(); err != nil {
		return driver.Handle{}, fmt.Errorf("docker driver: %w", err)
	}
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

func (d *Driver) validateExternalDriverMounts(ctx context.Context, spec driver.Spec, requested []enginemount.Mount, policy resourceadmission.Config) (map[string]string, error) {
	identities := make(map[string]string)
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("docker resource admission policy: %w", err)
	}
	workspace := strings.TrimSpace(spec.Labels[driver.WorkspaceLabel])
	for _, mount := range requested {
		switch mount.Type {
		case enginemount.TypeBind, enginemount.TypeImage:
			if err := policy.RejectUnlabelable("host bind or image mount"); err != nil {
				return nil, err
			}
		case enginemount.TypeVolume:
			volume, err := d.cli.VolumeInspect(ctx, mount.Source, client.VolumeInspectOptions{})
			if err != nil {
				return nil, fmt.Errorf("inspect docker volume %q for resource admission: %w", mount.Source, err)
			}
			if err := policy.Admit(workspace, volume.Volume.Labels); err != nil {
				return nil, fmt.Errorf("docker volume %q: %w", mount.Source, err)
			}
			if !d.enableBindMounts && dockerVolumeIsBindBacked(volume.Volume.Driver, volume.Volume.Options) {
				return nil, fmt.Errorf("docker volume %q is backed by a host bind mount and requires enable_bind_mounts = true", mount.Source)
			}
			identities[mount.Source] = dockerVolumeIdentity(volume.Volume)
		}
	}
	return identities, nil
}

func dockerVolumeIsBindBacked(driverName string, options map[string]string) bool {
	if driverName != "local" {
		return false
	}
	for _, option := range strings.Split(options["o"], ",") {
		option = strings.TrimSpace(option)
		if strings.EqualFold(option, "bind") || strings.EqualFold(option, "rbind") {
			return true
		}
	}
	return false
}

func dockerVolumeIdentity(volume volumetypes.Volume) string {
	identity, _ := json.Marshal(struct {
		Name       string            `json:"name"`
		Driver     string            `json:"driver"`
		CreatedAt  string            `json:"created_at"`
		Mountpoint string            `json:"mountpoint"`
		Options    map[string]string `json:"options"`
		Labels     map[string]string `json:"labels"`
	}{
		Name: volume.Name, Driver: volume.Driver, CreatedAt: volume.CreatedAt,
		Mountpoint: volume.Mountpoint, Options: volume.Options, Labels: volume.Labels,
	})
	digest := sha256.Sum256(identity)
	return hex.EncodeToString(digest[:])
}

// Start starts a created workload and its policy proxy, if configured.

func (d *Driver) ensureVolume(ctx context.Context, volumeName, sandboxName, role string) (bool, error) {
	verify := func() error {
		inspected, err := d.cli.VolumeInspect(ctx, volumeName, client.VolumeInspectOptions{})
		if err != nil {
			return err
		}
		labels := inspected.Volume.Labels
		if !volumeOwnershipLabelsValid(volumeName, sandboxName, role, labels) {
			return fmt.Errorf("docker volume %s is not owned by sandbox %s as %s", volumeName, sandboxName, role)
		}
		return nil
	}
	if err := verify(); err == nil {
		return false, nil
	} else if !isNotFound(err) {
		return false, err
	}
	labels := map[string]string{labelSandbox: "1", labelName: sandboxName, labelRole: role, "cautem.volume": "1"}
	if _, err := d.cli.VolumeCreate(ctx, client.VolumeCreateOptions{Name: volumeName, Labels: labels}); err != nil {
		if verifyErr := verify(); verifyErr != nil {
			return false, fmt.Errorf("docker volume create %s: %w", volumeName, err)
		}
		return false, nil
	}
	return true, nil
}

func volumeOwnershipLabelsValid(volumeName, sandboxName, role string, labels map[string]string) bool {
	if labels[labelSandbox] == "1" && labels[labelName] == sandboxName && labels[labelRole] == role && labels["cautem.volume"] == "1" {
		return true
	}
	// Volumes created before per-sandbox ownership labels used this marker and
	// deterministic names. Keep existing sandbox data usable across upgrade;
	// the durable cleanup manifest records the workload-to-volume association.
	return labels["cautem.volume"] == "1" && volumeName == expectedVolumeName(sandboxName, role)
}

func expectedVolumeName(sandboxName, role string) string {
	switch role {
	case roleVolumeData:
		return "cautem-data-" + sandboxName
	case roleVolumeCA:
		return "cautem-ca-" + sandboxName
	case roleVolumeSSH:
		return "cautem-ssh-" + sandboxName
	default:
		return ""
	}
}

// CopyTo tars srcHost and extracts at destPath inside the container.
// For a single file, destPath is the full guest path (basename used in the tar).
// For a directory, destPath is the guest parent directory under which src's basename appears.
