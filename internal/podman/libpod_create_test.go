package podman

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/moby/moby/api/types/container"
	enginemount "github.com/moby/moby/api/types/mount"
	enginenetwork "github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

func TestBuildNativeSpecCarriesExplicitUIDAndGIDMaps(t *testing.T) {
	pids := int64(100)
	options := client.ContainerCreateOptions{
		Name:       "sandbox-a",
		Config:     &container.Config{Image: "sha256:abc", Env: []string{"A=b"}, Cmd: []string{"sleep", "infinity"}, User: "0", WorkingDir: "/workspace", Labels: map[string]string{"a": "b"}},
		HostConfig: &container.HostConfig{NetworkMode: "bridge", SecurityOpt: []string{"no-new-privileges:true"}, CapDrop: []string{"NET_RAW"}, Resources: container.Resources{PidsLimit: &pids}},
	}
	spec, err := buildNativeSpec(options, "private", []IDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}, []IDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}})
	if err != nil {
		t.Fatal(err)
	}
	if spec.UserNS["nsmode"] != "private" || len(spec.IDMappings.UIDMap) != 1 || len(spec.IDMappings.GIDMap) != 1 || spec.IDMappings.UIDMap[0].HostID != 100000 || spec.Name != "sandbox-a" || spec.Env["A"] != "b" || !spec.NoNewPrivileges {
		t.Fatalf("native spec missing expected settings: %+v", spec)
	}
	if pids, ok := spec.Resources["pids"].(map[string]any); !ok || pids["limit"] != int64(100) {
		t.Fatalf("native pids limit not mapped: %+v", spec.Resources)
	}
	body, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	mappings, ok := decoded["idmappings"].(map[string]any)
	if !ok || mappings["HostUIDMapping"] != false || mappings["HostGIDMapping"] != false || mappings["AutoUserNs"] != false {
		t.Fatalf("wrong Libpod ID mapping contract: %s", body)
	}
}

func TestBuildNativeSpecAutoNamespaceRequestsAutomaticMappings(t *testing.T) {
	options := client.ContainerCreateOptions{Config: &container.Config{Image: "alpine"}, HostConfig: &container.HostConfig{}}
	spec, err := buildNativeSpec(options, "auto:size=65536", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if spec.UserNS["nsmode"] != "auto" || spec.UserNS["value"] != "size=65536" || spec.IDMappings == nil || !spec.IDMappings.AutoUserNs || len(spec.IDMappings.UIDMap) != 0 || len(spec.IDMappings.GIDMap) != 0 {
		t.Fatalf("auto user namespace was not expressed as pinned OpenShell expects: %+v", spec)
	}
}

func TestBuildNativeSpecCarriesPodmanLogConfiguration(t *testing.T) {
	options := client.ContainerCreateOptions{
		Config: &container.Config{Image: "alpine"},
		HostConfig: &container.HostConfig{
			LogConfig: container.LogConfig{Type: "k8s-file"},
		},
	}
	spec, err := buildNativeSpec(options, "keep-id", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if spec.LogConfiguration == nil || spec.LogConfiguration.Driver != "k8s-file" {
		t.Fatalf("log configuration=%+v, want k8s-file", spec.LogConfiguration)
	}
	body, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	logConfig, ok := decoded["log_configuration"].(map[string]any)
	if !ok || logConfig["driver"] != "k8s-file" {
		t.Fatalf("serialized native log configuration=%s", body)
	}
}

func TestBuildNativeSpecUserNamespaceModesMatchPinnedLibpodContract(t *testing.T) {
	tests := []struct {
		name             string
		mode             string
		wantMode         string
		wantValue        string
		wantAutoMappings bool
	}{
		{name: "host", mode: "host", wantMode: "host"},
		{name: "keep-id with params", mode: "keep-id:uid=1000,gid=1000", wantMode: "keep-id", wantValue: "uid=1000,gid=1000"},
		{name: "no-map", mode: "no-map", wantMode: "no-map"},
		{name: "auto", mode: "auto", wantMode: "auto", wantAutoMappings: true},
		{name: "auto with params", mode: "auto:size=65536", wantMode: "auto", wantValue: "size=65536", wantAutoMappings: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := client.ContainerCreateOptions{Config: &container.Config{Image: "alpine"}, HostConfig: &container.HostConfig{}}
			spec, err := buildNativeSpec(options, tt.mode, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if spec.UserNS["nsmode"] != tt.wantMode || spec.UserNS["value"] != tt.wantValue {
				t.Fatalf("userns spec=%v; want mode=%q value=%q", spec.UserNS, tt.wantMode, tt.wantValue)
			}
			if tt.wantAutoMappings {
				if spec.IDMappings == nil || !spec.IDMappings.AutoUserNs {
					t.Fatalf("auto userns must request automatic mappings: %+v", spec.IDMappings)
				}
			} else if spec.IDMappings != nil {
				t.Fatalf("%s userns must omit idmappings: %+v", tt.mode, spec.IDMappings)
			}
		})
	}
}

func TestBuildNativeSpecRejectsInvalidExplicitUserNamespaceMaps(t *testing.T) {
	options := client.ContainerCreateOptions{Config: &container.Config{Image: "alpine"}, HostConfig: &container.HostConfig{}}
	validMap := []IDMapping{{ContainerID: 0, HostID: 100000, Size: 1}}
	for _, tt := range []struct {
		name string
		mode string
		uid  []IDMapping
		gid  []IDMapping
	}{
		{name: "private requires both maps", mode: "private", uid: validMap},
		{name: "auto rejects explicit maps", mode: "auto", uid: validMap, gid: validMap},
		{name: "host rejects explicit maps", mode: "host", uid: validMap, gid: validMap},
		{name: "unknown mode", mode: "privileged"},
		{name: "zero sized map", mode: "private", uid: []IDMapping{{Size: 0}}, gid: validMap},
		{name: "overflowing map", mode: "private", uid: []IDMapping{{ContainerID: ^uint32(0), Size: 2}}, gid: validMap},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := buildNativeSpec(options, tt.mode, tt.uid, tt.gid); err == nil {
				t.Fatalf("buildNativeSpec(%q) accepted invalid userns maps", tt.mode)
			}
		})
	}
}

func TestBuildNativeSpecRejectsUntranslatedOptions(t *testing.T) {
	options := client.ContainerCreateOptions{Config: &container.Config{Image: "alpine"}, HostConfig: &container.HostConfig{VolumesFrom: []string{"other"}}}
	if _, err := buildNativeSpec(options, "private", []IDMapping{{Size: 1}}, []IDMapping{{Size: 1}}); err == nil {
		t.Fatal("untranslated volumes-from setting was silently dropped")
	}
	privileged := client.ContainerCreateOptions{Config: &container.Config{Image: "alpine"}, HostConfig: &container.HostConfig{Privileged: true}}
	if _, err := buildNativeSpec(privileged, "private", []IDMapping{{Size: 1}}, []IDMapping{{Size: 1}}); err == nil {
		t.Fatal("privileged container was silently downgraded by native userns create")
	}
}

func TestBuildNativeSpecTranslatesAppArmorOption(t *testing.T) {
	options := client.ContainerCreateOptions{
		Config:     &container.Config{Image: "alpine"},
		HostConfig: &container.HostConfig{SecurityOpt: []string{"no-new-privileges:true", "apparmor=unconfined"}},
	}
	spec, err := buildNativeSpec(options, "private", []IDMapping{{Size: 1}}, []IDMapping{{Size: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if !spec.NoNewPrivileges || spec.ApparmorProfile != "unconfined" {
		t.Fatalf("native AppArmor/no-new-privileges settings=%+v", spec)
	}
	for _, securityOpts := range [][]string{{"apparmor="}, {"apparmor=unconfined", "apparmor=profile"}} {
		invalid := options
		invalid.HostConfig = &container.HostConfig{SecurityOpt: securityOpts}
		if _, err := buildNativeSpec(invalid, "private", []IDMapping{{Size: 1}}, []IDMapping{{Size: 1}}); err == nil {
			t.Errorf("invalid AppArmor options %v were accepted", securityOpts)
		}
	}
}

func TestBuildNativeSpecTranslatesCDIDeviceRequests(t *testing.T) {
	options := client.ContainerCreateOptions{
		Config: &container.Config{Image: "alpine"},
		HostConfig: &container.HostConfig{DeviceRequests: []container.DeviceRequest{{
			Driver: "cdi", DeviceIDs: []string{"nvidia.com/gpu=0", "nvidia.com/gpu=1"},
		}}},
	}
	spec, err := buildNativeSpec(options, "private", []IDMapping{{Size: 1}}, []IDMapping{{Size: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(spec.Devices, []nativeDevice{{Path: "nvidia.com/gpu=0"}, {Path: "nvidia.com/gpu=1"}}) {
		t.Fatalf("CDI devices=%+v", spec.Devices)
	}
}

func TestBuildNativeSpecRejectsNonCDIDeviceRequests(t *testing.T) {
	options := client.ContainerCreateOptions{
		Config:     &container.Config{Image: "alpine"},
		HostConfig: &container.HostConfig{DeviceRequests: []container.DeviceRequest{{Driver: "nvidia", DeviceIDs: []string{"0"}}}},
	}
	if _, err := buildNativeSpec(options, "private", []IDMapping{{Size: 1}}, []IDMapping{{Size: 1}}); err == nil {
		t.Fatal("non-CDI device request accepted")
	}
}

func TestBuildNativeSpecTranslatesLegacyTmpfsAndShm(t *testing.T) {
	shm := int64(1 << 20)
	options := client.ContainerCreateOptions{Config: &container.Config{Image: "alpine"}, HostConfig: &container.HostConfig{Tmpfs: map[string]string{"/tmp": "rw,size=8192"}, ShmSize: shm}}
	spec, err := buildNativeSpec(options, "private", []IDMapping{{Size: 1}}, []IDMapping{{Size: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if spec.ShmSize == nil || *spec.ShmSize != shm {
		t.Fatalf("shm size not transferred: %+v", spec.ShmSize)
	}
	if !slices.ContainsFunc(spec.Mounts, func(m nativeMount) bool {
		return m.Type == "tmpfs" && m.Destination == "/tmp" && slices.Equal(m.Options, []string{"rw", "size=8192"})
	}) {
		t.Fatalf("legacy tmpfs not translated: %+v", spec.Mounts)
	}
}

func TestBuildNativeSpecTranslatesLoopbackPortBinding(t *testing.T) {
	port, _ := enginenetwork.PortFrom(2222, enginenetwork.TCP)
	options := client.ContainerCreateOptions{
		Config:     &container.Config{Image: "alpine"},
		HostConfig: &container.HostConfig{NetworkMode: "sandbox-net", PortBindings: enginenetwork.PortMap{port: {{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: "42222"}}}},
	}
	spec, err := buildNativeSpec(options, "private", []IDMapping{{Size: 1}}, []IDMapping{{Size: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.PortMappings) != 1 || spec.PortMappings[0] != (nativePortMapping{HostIP: "127.0.0.1", HostPort: 42222, ContainerPort: 2222, Protocol: "tcp"}) {
		t.Fatalf("port binding translated incorrectly: %+v", spec.PortMappings)
	}
}

func TestTranslateNativeMountPreservesTmpfsOptions(t *testing.T) {
	m, err := translateNativeMount(enginemount.Mount{
		Type: enginemount.TypeTmpfs, Target: "/run/cache", ReadOnly: true,
		TmpfsOptions: &enginemount.TmpfsOptions{SizeBytes: 8192, Mode: 0o750, Options: [][]string{{"nosuid"}, {"uid", "1000"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ro", "size=8192", "mode=750", "nosuid", "uid=1000"}
	if m.Type != "tmpfs" || m.Destination != "/run/cache" || !slices.Equal(m.Options, want) {
		t.Fatalf("tmpfs translation=%+v, want options %v", m, want)
	}
}

func TestTranslateNativeMountFailsClosedOnUnsupportedVolumeSemantics(t *testing.T) {
	if _, err := translateNativeVolume(enginemount.Mount{Source: "cache", Target: "/cache", VolumeOptions: &enginemount.VolumeOptions{Subpath: "nested"}}); err == nil {
		t.Fatal("unsupported volume subpath accepted")
	}
	for _, mount := range []enginemount.Mount{
		{Type: enginemount.TypeBind, Source: "/src", Target: "/dst", BindOptions: &enginemount.BindOptions{CreateMountpoint: true}},
		{Type: enginemount.TypeImage, Source: "image", Target: "/image"},
	} {
		if _, err := translateNativeMount(mount); err == nil {
			t.Errorf("unsupported mount semantics accepted: %+v", mount)
		}
	}
}

func TestTranslateNativeNamedVolume(t *testing.T) {
	volume, err := translateNativeVolume(enginemount.Mount{Type: enginemount.TypeVolume, Source: "cache", Target: "/cache", ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if volume.Name != "cache" || volume.Dest != "/cache" || !slices.Equal(volume.Options, []string{"ro"}) {
		t.Fatalf("volume translation=%+v", volume)
	}
}

func TestNativeHTTPSClientUsesDockerTLSCertPath(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	certDir := t.TempDir()
	certificate := server.TLS.Certificates[0]
	keyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}),
		"ca.pem":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}),
		"key.pem":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	} {
		if err := os.WriteFile(filepath.Join(certDir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("DOCKER_CERT_PATH", certDir)
	t.Setenv("DOCKER_TLS_VERIFY", "1")
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := nativeEndpoint("tcp://" + serverURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Scheme != "https" {
		t.Fatalf("TLS-enabled tcp endpoint scheme=%q", endpoint.Scheme)
	}
	httpClient, err := nativeHTTPClient("tcp://"+serverURL.Host, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	response, err := httpClient.Get(endpoint.String())
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("TLS response status=%s", response.Status)
	}
}
