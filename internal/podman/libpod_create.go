package podman

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	enginemount "github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

type nativeIDMap struct {
	ContainerID uint32 `json:"container_id"`
	HostID      uint32 `json:"host_id"`
	Size        uint32 `json:"size"`
}

type nativeIDMappings struct {
	HostUIDMapping bool          `json:"HostUIDMapping"`
	HostGIDMapping bool          `json:"HostGIDMapping"`
	AutoUserNs     bool          `json:"AutoUserNs"`
	UIDMap         []nativeIDMap `json:"UIDMap"`
	GIDMap         []nativeIDMap `json:"GIDMap"`
}

type nativeMount struct {
	Type        string   `json:"type"`
	Source      string   `json:"source,omitempty"`
	Destination string   `json:"destination"`
	Options     []string `json:"options,omitempty"`
}

type nativeVolume struct {
	Name    string   `json:"name"`
	Dest    string   `json:"dest"`
	Options []string `json:"options,omitempty"`
}

type nativeDevice struct {
	Path string `json:"path"`
}

type nativePortMapping struct {
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      uint16 `json:"host_port,omitempty"`
	ContainerPort uint16 `json:"container_port"`
	Protocol      string `json:"protocol,omitempty"`
}

type nativeLogConfiguration struct {
	Driver  string            `json:"driver,omitempty"`
	Path    string            `json:"path,omitempty"`
	Size    int64             `json:"size,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
	Options map[string]string `json:"options,omitempty"`
}

type nativeSpec struct {
	Image            string                  `json:"image"`
	Name             string                  `json:"name,omitempty"`
	Env              map[string]string       `json:"env,omitempty"`
	Labels           map[string]string       `json:"labels,omitempty"`
	Entrypoint       []string                `json:"entrypoint,omitempty"`
	Command          []string                `json:"command,omitempty"`
	User             string                  `json:"user,omitempty"`
	WorkDir          string                  `json:"work_dir,omitempty"`
	Terminal         bool                    `json:"terminal,omitempty"`
	Stdin            bool                    `json:"stdin,omitempty"`
	UserNS           map[string]string       `json:"userns,omitempty"`
	IDMappings       *nativeIDMappings       `json:"idmappings,omitempty"`
	Mounts           []nativeMount           `json:"mounts,omitempty"`
	Volumes          []nativeVolume          `json:"volumes,omitempty"`
	Devices          []nativeDevice          `json:"devices,omitempty"`
	HostAdd          []string                `json:"hostadd,omitempty"`
	CapDrop          []string                `json:"cap_drop,omitempty"`
	CapAdd           []string                `json:"cap_add,omitempty"`
	NoNewPrivileges  bool                    `json:"no_new_privileges,omitempty"`
	ApparmorProfile  string                  `json:"apparmor_profile,omitempty"`
	Network          map[string]string       `json:"netns,omitempty"`
	Networks         map[string]any          `json:"networks,omitempty"`
	Healthcheck      *container.HealthConfig `json:"healthconfig,omitempty"`
	LogConfiguration *nativeLogConfiguration `json:"log_configuration,omitempty"`
	Resources        map[string]any          `json:"resource_limits,omitempty"`
	PortMappings     []nativePortMapping     `json:"portmappings,omitempty"`
	ShmSize          *int64                  `json:"shm_size,omitempty"`
}

func nativeCreate(host, usernsMode string, uidMap, gidMap []IDMapping) func(context.Context, client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
	return func(ctx context.Context, options client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
		spec, err := buildNativeSpec(options, usernsMode, uidMap, gidMap)
		if err != nil {
			return client.ContainerCreateResult{}, err
		}
		endpoint, err := nativeEndpoint(host)
		if err != nil {
			return client.ContainerCreateResult{}, err
		}
		payload, err := json.Marshal(spec)
		if err != nil {
			return client.ContainerCreateResult{}, err
		}
		endpoint.Path += "/v5.0.0/libpod/containers/create"
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
		if err != nil {
			return client.ContainerCreateResult{}, err
		}
		request.Header.Set("Content-Type", "application/json")
		httpClient, err := nativeHTTPClient(host, endpoint)
		if err != nil {
			return client.ContainerCreateResult{}, err
		}
		response, err := httpClient.Do(request)
		if err != nil {
			return client.ContainerCreateResult{}, fmt.Errorf("podman Libpod create: %w", err)
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			var message struct {
				Cause   string `json:"cause"`
				Message string `json:"message"`
			}
			_ = json.NewDecoder(response.Body).Decode(&message)
			if message.Message == "" {
				message.Message = message.Cause
			}
			return client.ContainerCreateResult{}, fmt.Errorf("podman Libpod create returned %s: %s", response.Status, message.Message)
		}
		var result struct {
			ID      string `json:"Id"`
			IDLower string `json:"id"`
		}
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			return client.ContainerCreateResult{}, fmt.Errorf("decode Podman Libpod create response: %w", err)
		}
		if result.ID == "" {
			result.ID = result.IDLower
		}
		if result.ID == "" {
			return client.ContainerCreateResult{}, fmt.Errorf("podman Libpod create returned an empty container ID")
		}
		return client.ContainerCreateResult{ID: result.ID}, nil
	}
}

func nativeEndpoint(host string) (*url.URL, error) {
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("podman Libpod endpoint: %w", err)
	}
	switch u.Scheme {
	case "unix":
		return &url.URL{Scheme: "http", Host: "podman"}, nil
	case "tcp":
		u.Scheme = "http"
		if strings.TrimSpace(os.Getenv("DOCKER_CERT_PATH")) != "" {
			u.Scheme = "https"
		}
		return u, nil
	case "http", "https":
		return u, nil
	default:
		return nil, fmt.Errorf("podman Libpod endpoint does not support scheme %q", u.Scheme)
	}
}

func nativeHTTPClient(host string, endpoint *url.URL) (*http.Client, error) {
	transport := &http.Transport{ResponseHeaderTimeout: 30 * time.Second}
	if endpoint.Host == "podman" {
		u, _ := url.Parse(host)
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", u.Path)
		}
	}
	if endpoint.Scheme == "https" {
		tlsConfig, err := nativeTLSConfigFromEnv()
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConfig
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

func nativeTLSConfigFromEnv() (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	certDir := strings.TrimSpace(os.Getenv("DOCKER_CERT_PATH"))
	if certDir == "" {
		return config, nil
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(certDir, "cert.pem"), filepath.Join(certDir, "key.pem"))
	if err != nil {
		return nil, fmt.Errorf("load Podman client TLS certificate: %w", err)
	}
	config.Certificates = []tls.Certificate{cert}
	caPEM, err := os.ReadFile(filepath.Join(certDir, "ca.pem"))
	if err != nil {
		return nil, fmt.Errorf("read Podman server CA: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("podman server CA contains no certificates")
	}
	config.RootCAs = roots
	config.InsecureSkipVerify = os.Getenv("DOCKER_TLS_VERIFY") == "" //nolint:gosec // Match Moby's DOCKER_TLS_VERIFY behavior.
	return config, nil
}

func buildNativeSpec(options client.ContainerCreateOptions, usernsMode string, uidMap, gidMap []IDMapping) (nativeSpec, error) {
	if options.Config == nil || options.HostConfig == nil {
		return nativeSpec{}, fmt.Errorf("podman Libpod create requires config and host config")
	}
	if usernsMode == "" {
		return nativeSpec{}, fmt.Errorf("podman Libpod create requires an explicit userns mode")
	}
	cfg, host := options.Config, options.HostConfig
	if host.Privileged {
		return nativeSpec{}, fmt.Errorf("podman Libpod ID-map create does not support privileged containers")
	}
	if len(host.Devices) > 0 || len(host.VolumesFrom) > 0 {
		return nativeSpec{}, fmt.Errorf("podman Libpod ID-map create cannot represent requested host device or volumes-from settings")
	}
	var devices []nativeDevice
	for _, request := range host.DeviceRequests {
		if request.Driver != "cdi" {
			return nativeSpec{}, fmt.Errorf("podman Libpod ID-map create supports only CDI device requests, got driver %q", request.Driver)
		}
		if len(request.DeviceIDs) == 0 {
			return nativeSpec{}, fmt.Errorf("podman Libpod ID-map create requires CDI device IDs")
		}
		for _, id := range request.DeviceIDs {
			id = strings.TrimSpace(id)
			if id == "" {
				return nativeSpec{}, fmt.Errorf("podman Libpod ID-map create received an empty CDI device ID")
			}
			devices = append(devices, nativeDevice{Path: id})
		}
	}
	env := make(map[string]string, len(cfg.Env))
	for _, item := range cfg.Env {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			value = ""
		}
		env[key] = value
	}
	noNewPrivileges := false
	appArmorProfile := ""
	for _, option := range host.SecurityOpt {
		if option == "no-new-privileges:true" {
			noNewPrivileges = true
			continue
		}
		if strings.HasPrefix(option, "apparmor=") {
			if appArmorProfile != "" || strings.TrimPrefix(option, "apparmor=") == "" {
				return nativeSpec{}, fmt.Errorf("podman Libpod ID-map create received an invalid or duplicate AppArmor option")
			}
			appArmorProfile = strings.TrimPrefix(option, "apparmor=")
			continue
		}
		return nativeSpec{}, fmt.Errorf("podman Libpod ID-map create cannot translate security option %q", option)
	}
	spec := nativeSpec{Image: cfg.Image, Name: options.Name, Env: env, Labels: cfg.Labels, Entrypoint: cfg.Entrypoint, Command: cfg.Cmd, User: cfg.User, WorkDir: cfg.WorkingDir, Terminal: cfg.Tty, Stdin: cfg.OpenStdin, HostAdd: host.ExtraHosts, CapDrop: host.CapDrop, CapAdd: host.CapAdd, NoNewPrivileges: noNewPrivileges, ApparmorProfile: appArmorProfile, Network: map[string]string{"nsmode": string(host.NetworkMode)}, Healthcheck: cfg.Healthcheck, Devices: devices}
	if host.LogConfig.Type != "" {
		spec.LogConfiguration = &nativeLogConfiguration{Driver: host.LogConfig.Type, Options: host.LogConfig.Config}
	}
	if host.ShmSize > 0 {
		size := host.ShmSize
		spec.ShmSize = &size
	}
	resources := make(map[string]any)
	if host.Memory > 0 {
		resources["memory"] = map[string]any{"limit": host.Memory}
	}
	if pids := valueOrZero(host.PidsLimit); pids > 0 {
		resources["pids"] = map[string]any{"limit": pids}
	}
	if host.NanoCPUs > 0 {
		resources["cpu"] = map[string]any{"quota": host.NanoCPUs / 10000, "period": int64(100000)}
	}
	if len(resources) > 0 {
		spec.Resources = resources
	}
	if options.NetworkingConfig != nil && len(options.NetworkingConfig.EndpointsConfig) > 0 {
		spec.Network = map[string]string{"nsmode": "bridge"}
		spec.Networks = make(map[string]any, len(options.NetworkingConfig.EndpointsConfig))
		for name, endpoint := range options.NetworkingConfig.EndpointsConfig {
			entry := map[string]any{}
			if endpoint != nil && len(endpoint.Aliases) > 0 {
				entry["aliases"] = endpoint.Aliases
			}
			spec.Networks[name] = entry
		}
	}
	for port, bindings := range host.PortBindings {
		for _, binding := range bindings {
			mapping := nativePortMapping{ContainerPort: port.Num(), Protocol: string(port.Proto())}
			if binding.HostIP.IsValid() {
				mapping.HostIP = binding.HostIP.String()
			}
			if binding.HostPort != "" {
				hostPort, err := strconv.ParseUint(binding.HostPort, 10, 16)
				if err != nil {
					return nativeSpec{}, fmt.Errorf("invalid host port %q for %s: %w", binding.HostPort, port, err)
				}
				mapping.HostPort = uint16(hostPort)
			}
			spec.PortMappings = append(spec.PortMappings, mapping)
		}
	}
	mode, value, hasValue := strings.Cut(usernsMode, ":")
	if mode != "private" && mode != "auto" && mode != "host" && mode != "keep-id" && mode != "no-map" {
		return nativeSpec{}, fmt.Errorf("podman Libpod create does not support userns mode %q", mode)
	}
	if mode == "host" || mode == "no-map" {
		if hasValue {
			return nativeSpec{}, fmt.Errorf("userns mode %q does not accept parameters", mode)
		}
	}
	if mode == "auto" && (len(uidMap) != 0 || len(gidMap) != 0) {
		return nativeSpec{}, fmt.Errorf("userns=auto must use Podman automatic ID mappings")
	}
	if mode == "private" {
		if len(uidMap) == 0 || len(gidMap) == 0 || len(uidMap) != len(gidMap) {
			return nativeSpec{}, fmt.Errorf("userns=private requires matching non-empty UID and GID maps")
		}
	} else if len(uidMap) != 0 || len(gidMap) != 0 {
		return nativeSpec{}, fmt.Errorf("explicit UID/GID maps are only valid with userns=private")
	}
	if err := validateIDMap(uidMap, "UID"); err != nil {
		return nativeSpec{}, err
	}
	if err := validateIDMap(gidMap, "GID"); err != nil {
		return nativeSpec{}, err
	}
	spec.UserNS = map[string]string{"nsmode": mode}
	if hasValue {
		spec.UserNS["value"] = value
	}
	if mode == "auto" || mode == "private" {
		spec.IDMappings = &nativeIDMappings{HostUIDMapping: false, HostGIDMapping: false, AutoUserNs: mode == "auto"}
	}
	for _, m := range uidMap {
		spec.IDMappings.UIDMap = append(spec.IDMappings.UIDMap, nativeIDMap(m))
	}
	for _, m := range gidMap {
		spec.IDMappings.GIDMap = append(spec.IDMappings.GIDMap, nativeIDMap(m))
	}
	for _, bind := range host.Binds {
		parts := strings.Split(bind, ":")
		if len(parts) < 2 || len(parts) > 3 {
			return nativeSpec{}, fmt.Errorf("unsupported bind syntax %q", bind)
		}
		opts := []string{}
		if len(parts) == 3 {
			opts = strings.Split(parts[2], ",")
		}
		if filepath.IsAbs(parts[0]) {
			if !slices.Contains(opts, "rbind") {
				opts = append(opts, "rbind")
			}
			spec.Mounts = append(spec.Mounts, nativeMount{Type: "bind", Source: parts[0], Destination: parts[1], Options: opts})
		} else {
			spec.Volumes = append(spec.Volumes, nativeVolume{Name: parts[0], Dest: parts[1], Options: opts})
		}
	}
	for _, m := range host.Mounts {
		if m.Type == enginemount.TypeVolume {
			volume, err := translateNativeVolume(m)
			if err != nil {
				return nativeSpec{}, err
			}
			spec.Volumes = append(spec.Volumes, volume)
			continue
		}
		nativeMount, err := translateNativeMount(m)
		if err != nil {
			return nativeSpec{}, err
		}
		spec.Mounts = append(spec.Mounts, nativeMount)
	}
	tmpfsTargets := make([]string, 0, len(host.Tmpfs))
	for target := range host.Tmpfs {
		tmpfsTargets = append(tmpfsTargets, target)
	}
	sort.Strings(tmpfsTargets)
	for _, target := range tmpfsTargets {
		options := host.Tmpfs[target]
		spec.Mounts = append(spec.Mounts, nativeMount{Type: "tmpfs", Source: "tmpfs", Destination: target, Options: strings.Split(options, ",")})
	}
	return spec, nil
}

func validateIDMap(mappings []IDMapping, kind string) error {
	for _, mapping := range mappings {
		if mapping.Size == 0 {
			return fmt.Errorf("userns private %s map entries must have a positive size", kind)
		}
		if uint64(mapping.ContainerID)+uint64(mapping.Size) > 1<<32 || uint64(mapping.HostID)+uint64(mapping.Size) > 1<<32 {
			return fmt.Errorf("userns private %s map entry exceeds uint32 ID range", kind)
		}
	}
	return nil
}

func translateNativeMount(m enginemount.Mount) (nativeMount, error) {
	translated := nativeMount{Type: string(m.Type), Source: m.Source, Destination: m.Target}
	if m.ReadOnly {
		translated.Options = append(translated.Options, "ro")
	}
	switch m.Type {
	case enginemount.TypeBind:
		if !slices.Contains(translated.Options, "rbind") {
			translated.Options = append(translated.Options, "rbind")
		}
		if m.BindOptions != nil {
			if m.BindOptions.Propagation != "" {
				translated.Options = append(translated.Options, string(m.BindOptions.Propagation))
			}
			if m.BindOptions.NonRecursive {
				translated.Options = append(translated.Options, "bind-nonrecursive")
			}
			if m.BindOptions.CreateMountpoint {
				return nativeMount{}, fmt.Errorf("podman Libpod ID-map create cannot translate bind create_mountpoint")
			}
			if m.BindOptions.ReadOnlyNonRecursive {
				translated.Options = append(translated.Options, "ro")
			}
			if m.BindOptions.ReadOnlyForceRecursive {
				return nativeMount{}, fmt.Errorf("podman Libpod ID-map create cannot guarantee recursive read-only bind")
			}
		}
	case enginemount.TypeVolume:
		return nativeMount{}, fmt.Errorf("internal error: named volume should use Libpod volumes field")
	case enginemount.TypeTmpfs:
		if m.TmpfsOptions != nil {
			if m.TmpfsOptions.SizeBytes > 0 {
				translated.Options = append(translated.Options, "size="+strconv.FormatInt(m.TmpfsOptions.SizeBytes, 10))
			}
			if m.TmpfsOptions.Mode > 0 {
				translated.Options = append(translated.Options, "mode="+strconv.FormatUint(uint64(m.TmpfsOptions.Mode), 8))
			}
			for _, pair := range m.TmpfsOptions.Options {
				if len(pair) == 1 {
					translated.Options = append(translated.Options, pair[0])
				} else if len(pair) == 2 {
					translated.Options = append(translated.Options, pair[0]+"="+pair[1])
				} else {
					return nativeMount{}, fmt.Errorf("invalid tmpfs option pair %v", pair)
				}
			}
		} else {
			translated.Options = append(translated.Options, "rw")
		}
	case enginemount.TypeImage, enginemount.TypeCluster:
		return nativeMount{}, fmt.Errorf("podman Libpod ID-map create cannot translate mount type %q", m.Type)
	default:
		return nativeMount{}, fmt.Errorf("podman Libpod ID-map create does not support mount type %q", m.Type)
	}
	return translated, nil
}

func translateNativeVolume(m enginemount.Mount) (nativeVolume, error) {
	if m.VolumeOptions != nil {
		if m.VolumeOptions.Subpath != "" {
			return nativeVolume{}, fmt.Errorf("podman Libpod ID-map create does not support volume subpath %q", m.VolumeOptions.Subpath)
		}
		if m.VolumeOptions.NoCopy {
			return nativeVolume{}, fmt.Errorf("podman Libpod ID-map create cannot guarantee volume nocopy semantics")
		}
		if len(m.VolumeOptions.Labels) > 0 || m.VolumeOptions.DriverConfig != nil {
			return nativeVolume{}, fmt.Errorf("podman Libpod ID-map create cannot translate volume labels or driver config")
		}
	}
	mode := "rw"
	if m.ReadOnly {
		mode = "ro"
	}
	return nativeVolume{Name: m.Source, Dest: m.Target, Options: []string{mode}}, nil
}

func valueOrZero(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}
