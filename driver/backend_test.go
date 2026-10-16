package driver

import (
	"context"
	"errors"
	"reflect"
	"testing"

	core "github.com/cautem/cautem-core"
)

type fakeComputeDriver struct {
	ComputeDriver
	created Spec
	called  bool
}

type tokenAwareFakeComputeDriver struct {
	*fakeComputeDriver
	token       string
	tokenStarts int
}

type policyUpdaterFakeComputeDriver struct {
	*fakeComputeDriver
	policyID   core.ID
	policy     []byte
	policyRuns int
}

type launchSpecRestorerFakeComputeDriver struct {
	*fakeComputeDriver
	restored Spec
	runs     int
}

type credentialRefreshFakeComputeDriver struct {
	*fakeComputeDriver
	refreshed core.ID
	runs      int
}

type platformEventFakeComputeDriver struct {
	*fakeComputeDriver
	request PlatformEventWatchRequest
	results <-chan PlatformEventResult
}

type runtimeValidatorFakeComputeDriver struct {
	*fakeComputeDriver
	err        error
	proxyWaits int
}

type capabilityFakeEngine struct {
	Engine
	info BackendInfo
}

func (engine *capabilityFakeEngine) BackendCapabilityInfo() BackendInfo {
	return engine.info.Clone()
}

func (fake *tokenAwareFakeComputeDriver) StartWithToken(_ context.Context, _ core.ID, token string) error {
	fake.tokenStarts++
	fake.token = token
	return nil
}

func (fake *policyUpdaterFakeComputeDriver) UpdateSandboxPolicy(_ context.Context, id core.ID, policy []byte) error {
	fake.policyRuns++
	fake.policyID = id
	fake.policy = append([]byte(nil), policy...)
	return nil
}

func (fake *launchSpecRestorerFakeComputeDriver) RestoreLaunchSpec(_ context.Context, _ core.ID, spec Spec) error {
	fake.runs++
	fake.restored = spec
	return nil
}

func (fake *credentialRefreshFakeComputeDriver) RefreshSandboxRuntimeCredentials(_ context.Context, id core.ID) error {
	fake.runs++
	fake.refreshed = id
	return nil
}

func (fake *platformEventFakeComputeDriver) WatchPlatformEvents(_ context.Context, request PlatformEventWatchRequest) (<-chan PlatformEventResult, error) {
	fake.request = request
	return fake.results, nil
}

func (fake *runtimeValidatorFakeComputeDriver) ValidateGatewayRuntime() error { return fake.err }
func (fake *runtimeValidatorFakeComputeDriver) WaitProxyReady(context.Context, string) error {
	fake.proxyWaits++
	return nil
}

func (fake *fakeComputeDriver) Create(_ context.Context, spec Spec) (Handle, error) {
	fake.created = spec
	fake.called = true
	return Handle{Name: spec.Name}, nil
}

type validatingFakeComputeDriver struct {
	*fakeComputeDriver
	validated Spec
	err       error
}

func (fake *validatingFakeComputeDriver) ValidateSpec(spec Spec) error {
	fake.validated = spec
	return fake.err
}

func TestComputeDriverAdapterValidatesBeforeCreate(t *testing.T) {
	ctx := context.Background()
	engine := &validatingFakeComputeDriver{fakeComputeDriver: &fakeComputeDriver{}}
	backend, err := AdaptComputeDriver("docker", BackendInfo{Capabilities: map[Capability]struct{}{CapabilityPTY: {}}}, engine, func(request BackendCreateRequest) (Spec, error) {
		return Spec{Name: request.Name, Image: request.Workload.Image, Workspace: request.Workspace.HostPath}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	request := BackendCreateRequest{Name: "demo", Workspace: WorkspaceTarget{ID: "team", HostPath: "/work/team"}, Workload: WorkloadSpec{Image: "agent:latest"}}
	if err := backend.ValidateCreate(ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Create(ctx, request); err != nil {
		t.Fatal(err)
	}
	if engine.validated.Name != "demo" || engine.created.Name != "demo" || engine.created.Workspace != "/work/team" {
		t.Fatalf("validation/create mapping = validated:%+v created:%+v", engine.validated, engine.created)
	}
	engine.err = errors.New("unsupported CDI mapping")
	engine.called = false
	if _, err := backend.Create(ctx, request); err == nil || engine.called {
		t.Fatalf("create must fail validation before calling engine; created=%+v err=%v", engine.created, err)
	}
}

func TestAdaptLegacyEngineKeepsLegacyTranslationInsideDriverBoundary(t *testing.T) {
	ctx := context.Background()
	engine := &capabilityFakeEngine{
		info: BackendInfo{ID: "docker", Capabilities: map[Capability]struct{}{CapabilityPTY: {}}},
	}
	backend, err := AdaptLegacyEngine("docker", engine)
	if err != nil {
		t.Fatal(err)
	}
	info, err := backend.Capabilities(ctx)
	if err != nil || !info.Has(CapabilityPTY) || info.ID != "docker" {
		t.Fatalf("adapted capability info=%+v err=%v", info, err)
	}
	if _, err := AdaptLegacyEngine("podman", engine); err == nil {
		t.Fatal("mismatched legacy capability identity was accepted")
	}
	if _, err := AdaptLegacyEngine("", engine); err == nil {
		t.Fatal("empty backend identity was accepted")
	}
}

func TestComputeDriverAdapterPreservesContextAndCopiesCapabilities(t *testing.T) {
	engine := &fakeComputeDriver{}
	caps := map[Capability]struct{}{CapabilityPTY: {}}
	backend, err := AdaptComputeDriver("podman", BackendInfo{Capabilities: caps}, engine, func(BackendCreateRequest) (Spec, error) { return Spec{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	caps[CapabilityGPU] = struct{}{}
	info, err := backend.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Has(CapabilityGPU) {
		t.Fatal("adapter retained the caller's mutable capability map")
	}
	if err := backend.ValidateCreate(cancelledContext(t), BackendCreateRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("ValidateCreate canceled error = %v", err)
	}
}

func TestRequireExtensionRequiresAdvertisementAndImplementation(t *testing.T) {
	ctx := context.Background()
	makeBackend := func(caps ...Capability) Backend {
		capabilitySet := make(map[Capability]struct{}, len(caps))
		for _, capability := range caps {
			capabilitySet[capability] = struct{}{}
		}
		backend, err := AdaptComputeDriver("docker", BackendInfo{Capabilities: capabilitySet}, &fakeComputeDriver{}, func(BackendCreateRequest) (Spec, error) { return Spec{}, nil })
		if err != nil {
			t.Fatal(err)
		}
		return backend
	}

	backend := makeBackend(CapabilityInteractiveExec)
	if _, err := RequireExtension[InteractiveExec](ctx, backend, CapabilityInteractiveExec, "exec"); err != nil {
		t.Fatalf("advertised and implemented extension was rejected: %v", err)
	}

	if _, err := RequireExtension[InteractiveExec](ctx, makeBackend(), CapabilityInteractiveExec, "exec"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unadvertised extension error = %v, want ErrUnsupported", err)
	}

	// Embedding only the core SPI preserves capability metadata while removing
	// the optional method, exercising a stale or dishonest backend declaration.
	withoutExec := backendWithoutExtensions{Backend: backend}
	if _, err := RequireExtension[InteractiveExec](ctx, withoutExec, CapabilityInteractiveExec, "exec"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("advertised but unimplemented extension error = %v, want ErrUnsupported", err)
	}
}

func TestComputeDriverAdapterForwardsAdvertisedRuntimeTokenStart(t *testing.T) {
	ctx := context.Background()
	engine := &tokenAwareFakeComputeDriver{fakeComputeDriver: &fakeComputeDriver{}}
	backend, err := AdaptComputeDriver("kubernetes", BackendInfo{Capabilities: map[Capability]struct{}{CapabilityTokenAwareStart: {}}}, engine, func(BackendCreateRequest) (Spec, error) { return Spec{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	starter, err := RequireExtension[RuntimeTokenStarter](ctx, backend, CapabilityTokenAwareStart, "restart")
	if err != nil {
		t.Fatal(err)
	}
	if err := starter.StartWithToken(ctx, "sandbox", "fresh-token"); err != nil {
		t.Fatal(err)
	}
	if engine.tokenStarts != 1 || engine.token != "fresh-token" {
		t.Fatalf("token starts/token = %d/%q", engine.tokenStarts, engine.token)
	}
	if _, err := RequireExtension[RuntimeTokenStarter](ctx, backend, CapabilityPTY, "restart"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unadvertised token extension error=%v, want ErrUnsupported", err)
	}
	withoutLegacyMethod, err := AdaptComputeDriver("kubernetes", BackendInfo{Capabilities: map[Capability]struct{}{CapabilityTokenAwareStart: {}}}, &fakeComputeDriver{}, func(BackendCreateRequest) (Spec, error) { return Spec{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	advertised, err := RequireExtension[RuntimeTokenStarter](ctx, withoutLegacyMethod, CapabilityTokenAwareStart, "restart")
	if err != nil {
		t.Fatal(err)
	}
	if err := advertised.StartWithToken(ctx, "sandbox", "fresh-token"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("advertised capability without legacy method error=%v, want ErrUnsupported", err)
	}
}

func TestComputeDriverAdapterForwardsPlatformEventWatch(t *testing.T) {
	ctx := context.Background()
	results := make(chan PlatformEventResult, 1)
	engine := &platformEventFakeComputeDriver{fakeComputeDriver: &fakeComputeDriver{}, results: results}
	backend, err := AdaptComputeDriver("remote", BackendInfo{Capabilities: map[Capability]struct{}{CapabilityPlatformEvents: {}}}, engine, LegacySpecFromBackendRequest)
	if err != nil {
		t.Fatal(err)
	}
	watcher, err := RequireExtension[PlatformEventStream](ctx, backend, CapabilityPlatformEvents, "watch platform events")
	if err != nil {
		t.Fatal(err)
	}
	request := PlatformEventWatchRequest{SandboxID: "stable-id", SandboxName: "runtime-name"}
	stream, err := watcher.WatchPlatformEvents(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if engine.request != request || stream != results {
		t.Fatalf("watch request/stream = %+v/%v, want %+v/%v", engine.request, stream, request, results)
	}

	withoutLegacyMethod, err := AdaptComputeDriver("remote", BackendInfo{Capabilities: map[Capability]struct{}{CapabilityPlatformEvents: {}}}, &fakeComputeDriver{}, LegacySpecFromBackendRequest)
	if err != nil {
		t.Fatal(err)
	}
	advertised, err := RequireExtension[PlatformEventStream](ctx, withoutLegacyMethod, CapabilityPlatformEvents, "watch platform events")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := advertised.WatchPlatformEvents(ctx, request); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("advertised capability without legacy method error=%v, want ErrUnsupported", err)
	}
}

func TestComputeDriverAdapterForwardsAdvertisedPolicyUpdate(t *testing.T) {
	ctx := context.Background()
	engine := &policyUpdaterFakeComputeDriver{fakeComputeDriver: &fakeComputeDriver{}}
	backend, err := AdaptComputeDriver("kubernetes", BackendInfo{Capabilities: map[Capability]struct{}{CapabilityPolicyUpdate: {}}}, engine, func(BackendCreateRequest) (Spec, error) { return Spec{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	updater, err := RequireExtension[RuntimePolicyUpdater](ctx, backend, CapabilityPolicyUpdate, "deliver policy")
	if err != nil {
		t.Fatal(err)
	}
	if err := updater.UpdateSandboxPolicy(ctx, "runtime-id", []byte("policy")); err != nil {
		t.Fatal(err)
	}
	if engine.policyRuns != 1 || engine.policyID != "runtime-id" || string(engine.policy) != "policy" {
		t.Fatalf("policy update was not forwarded: calls=%d id=%q policy=%q", engine.policyRuns, engine.policyID, engine.policy)
	}

	withoutCapability, err := AdaptComputeDriver("docker", BackendInfo{}, engine, func(BackendCreateRequest) (Spec, error) { return Spec{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RequireExtension[RuntimePolicyUpdater](ctx, withoutCapability, CapabilityPolicyUpdate, "deliver policy"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("undeclared policy update error = %v; want ErrUnsupported", err)
	}

	withoutLegacyMethod, err := AdaptComputeDriver("kubernetes", BackendInfo{Capabilities: map[Capability]struct{}{CapabilityPolicyUpdate: {}}}, &fakeComputeDriver{}, func(BackendCreateRequest) (Spec, error) { return Spec{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	advertised, err := RequireExtension[RuntimePolicyUpdater](ctx, withoutLegacyMethod, CapabilityPolicyUpdate, "deliver policy")
	if err != nil {
		t.Fatal(err)
	}
	if err := advertised.UpdateSandboxPolicy(ctx, "runtime-id", []byte("policy")); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("advertised capability without legacy method error = %v; want ErrUnsupported", err)
	}
}

func TestComputeDriverAdapterRestoresLaunchSpecThroughDomainExtension(t *testing.T) {
	ctx := context.Background()
	engine := &launchSpecRestorerFakeComputeDriver{fakeComputeDriver: &fakeComputeDriver{}}
	backend, err := AdaptComputeDriver("vm", BackendInfo{Capabilities: map[Capability]struct{}{CapabilityLaunchSpecRestore: {}}}, engine, LegacySpecFromBackendRequest)
	if err != nil {
		t.Fatal(err)
	}
	restorer, err := RequireExtension[RuntimeLaunchSpecRestorer](ctx, backend, CapabilityLaunchSpecRestore, "restore workload")
	if err != nil {
		t.Fatal(err)
	}
	request := BackendCreateRequest{
		Name:      "demo",
		Workspace: WorkspaceTarget{ID: "/work/demo", HostPath: "/work/demo", Persist: true},
		Workload:  WorkloadSpec{Image: "agent@sha256:abc", Command: []string{"/bin/sh", "-lc", "true"}, RestartPolicy: "on-failure"},
		Runtime:   RuntimeAssets{SupervisorBinary: "/bin/cautem-supervisor", EnableSSH: true},
	}
	if err := restorer.RestoreLaunchSpec(ctx, "runtime-id", request); err != nil {
		t.Fatal(err)
	}
	if engine.runs != 1 || engine.restored.Name != "demo" || engine.restored.Image != "agent@sha256:abc" || !reflect.DeepEqual(engine.restored.Command, request.Workload.Command) || engine.restored.MainProcessRestartPolicy != "on-failure" || engine.restored.SupervisorBin != "/bin/cautem-supervisor" {
		t.Fatalf("launch spec restore did not preserve domain settings: runs=%d spec=%+v", engine.runs, engine.restored)
	}

	withoutLegacyMethod, err := AdaptComputeDriver("vm", BackendInfo{Capabilities: map[Capability]struct{}{CapabilityLaunchSpecRestore: {}}}, &fakeComputeDriver{}, LegacySpecFromBackendRequest)
	if err != nil {
		t.Fatal(err)
	}
	restorer, err = RequireExtension[RuntimeLaunchSpecRestorer](ctx, withoutLegacyMethod, CapabilityLaunchSpecRestore, "restore workload")
	if err != nil {
		t.Fatal(err)
	}
	if err := restorer.RestoreLaunchSpec(ctx, "runtime-id", request); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("missing legacy restorer error = %v; want ErrUnsupported", err)
	}
}

func TestComputeDriverAdapterRefreshesRuntimeCredentialsThroughDomainExtension(t *testing.T) {
	ctx := context.Background()
	engine := &credentialRefreshFakeComputeDriver{fakeComputeDriver: &fakeComputeDriver{}}
	backend, err := AdaptComputeDriver("kubernetes", BackendInfo{Capabilities: map[Capability]struct{}{CapabilityCredentialRefresh: {}}}, engine, LegacySpecFromBackendRequest)
	if err != nil {
		t.Fatal(err)
	}
	refresher, err := RequireExtension[RuntimeCredentialRefresher](ctx, backend, CapabilityCredentialRefresh, "refresh credentials")
	if err != nil {
		t.Fatal(err)
	}
	if err := refresher.RefreshRuntimeCredentials(ctx, "runtime-id"); err != nil {
		t.Fatal(err)
	}
	if engine.runs != 1 || engine.refreshed != "runtime-id" {
		t.Fatalf("credential refresh calls/id = %d/%q", engine.runs, engine.refreshed)
	}
}

func TestComputeDriverAdapterValidatesRuntimeContractThroughDomainExtension(t *testing.T) {
	ctx := context.Background()
	wantErr := errors.New("missing supervisor integration")
	engine := &runtimeValidatorFakeComputeDriver{fakeComputeDriver: &fakeComputeDriver{}, err: wantErr}
	backend, err := AdaptComputeDriver("vm", BackendInfo{Capabilities: map[Capability]struct{}{CapabilityGatewayRuntimeValidation: {}, CapabilityProxyReadiness: {}}}, engine, LegacySpecFromBackendRequest)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := RequireExtension[RuntimeContractValidator](ctx, backend, CapabilityGatewayRuntimeValidation, "validate runtime")
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.ValidateRuntimeContract(ctx); !errors.Is(err, wantErr) {
		t.Fatalf("runtime validation error = %v; want %v", err, wantErr)
	}
	readiness, err := RequireExtension[RuntimeProxyReadiness](ctx, backend, CapabilityProxyReadiness, "wait for proxy")
	if err != nil {
		t.Fatal(err)
	}
	if err := readiness.WaitProxyReady(ctx, "demo"); err != nil || engine.proxyWaits != 1 {
		t.Fatalf("proxy readiness wait calls/error = %d/%v", engine.proxyWaits, err)
	}
}

type backendWithoutExtensions struct{ Backend }

func TestBackendRegistryRejectsDuplicatesAndSortsIDs(t *testing.T) {
	registry := NewBackendRegistry()
	newBackend := func(id BackendID) Backend {
		backend, err := AdaptComputeDriver(id, BackendInfo{ID: id}, &fakeComputeDriver{}, func(BackendCreateRequest) (Spec, error) { return Spec{}, nil })
		if err != nil {
			t.Fatal(err)
		}
		return backend
	}
	for _, id := range []BackendID{"vm", "docker", "podman"} {
		if err := registry.Register(newBackend(id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := registry.Register(newBackend("docker")); err == nil {
		t.Fatal("duplicate backend registration succeeded")
	}
	if got := registry.IDs(); len(got) != 3 || got[0] != "docker" || got[1] != "podman" || got[2] != "vm" {
		t.Fatalf("backend IDs = %v", got)
	}
	if _, err := registry.Get("missing"); err == nil {
		t.Fatal("unknown backend lookup succeeded")
	}
}

func TestLegacySpecAdapterRoundTripsRepresentedFields(t *testing.T) {
	want := Spec{
		Name:                     "demo",
		Image:                    "agent@sha256:abc",
		Workspace:                "/work/demo",
		GatewayID:                "gateway-1",
		Command:                  []string{"/bin/sh", "-lc", "echo ready"},
		TTY:                      true,
		MainProcessRestartPolicy: "on-failure",
		Env:                      []string{"DUP=first", "DUP=second"},
		IKnow:                    true,
		ProxyBin:                 "/bin/cautem-proxy",
		PolicyPath:               "/etc/cautem/policy.yaml",
		ProxyPort:                17777,
		ProxyEnv:                 []string{"TOKEN=short-lived"},
		InitBin:                  "/bin/cautem-init",
		NoHarden:                 true,
		SupervisorBin:            "/bin/cautem-supervisor",
		DisplayMode:              "novnc",
		DisplayPort:              6080,
		DisplayPassword:          "temporary",
		Labels:                   map[string]string{"team": "infra"},
		ExtraHosts:               []string{"host.internal:127.0.0.1"},
		GatewayURL:               "https://gateway.internal",
		PersistVolume:            true,
		EnableSSH:                true,
		SSHBin:                   "/bin/cautem-sshd",
		GPU:                      true,
		GPUCount:                 2,
		CDIDevices:               []string{"nvidia.com/gpu=0"},
		CPU:                      2.5,
		MemoryBytes:              1 << 30,
		PidsLimit:                512,
		ProxyImage:               "proxy@sha256:def",
		PublishPorts:             []PortPublish{{Host: 8080, Guest: 80}},
		DriverConfigJSON:         `{"userns":"keep-id"}`,
	}

	request := BackendCreateRequestFromLegacySpec(want)
	got, err := LegacySpecFromBackendRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy spec round-trip mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestLegacySpecAdapterEncodesDomainConfigAndWorkspaceIdentity(t *testing.T) {
	request := BackendCreateRequest{
		Name:      "demo",
		Workspace: WorkspaceTarget{ID: "team-a", HostPath: "/workspaces/team-a", Persist: true},
		Labels:    map[string]string{WorkspaceLabel: "team-a"},
		Config:    map[string]any{"mode": "isolated", "nested": map[string]any{"retry": float64(3)}},
	}
	spec, err := LegacySpecFromBackendRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Workspace != request.Workspace.HostPath || spec.DriverConfigJSON != `{"mode":"isolated","nested":{"retry":3}}` {
		t.Fatalf("legacy spec workspace=%q config=%q", spec.Workspace, spec.DriverConfigJSON)
	}
	noConfig, err := LegacySpecFromBackendRequest(BackendCreateRequest{Config: map[string]any(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if noConfig.DriverConfigJSON != "" {
		t.Fatalf("nil backend config encoded as %q", noConfig.DriverConfigJSON)
	}
}

func TestLegacySpecAdapterRejectsUnrepresentableFields(t *testing.T) {
	tests := []struct {
		name    string
		request BackendCreateRequest
	}{
		{name: "distinct sandbox id", request: BackendCreateRequest{SandboxID: "internal-id", Name: "runtime-name"}},
		{name: "distinct workspace id", request: BackendCreateRequest{Workspace: WorkspaceTarget{ID: "workspace-id", HostPath: "/work"}}},
		{name: "domain mounts", request: BackendCreateRequest{Mounts: []Mount{{Source: "/src", Destination: "/dst"}}}},
		{name: "typed config", request: BackendCreateRequest{Config: struct{ Value string }{Value: "x"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := LegacySpecFromBackendRequest(test.request); err == nil {
				t.Fatal("legacy encoder silently discarded an unrepresentable field")
			}
		})
	}
}

func cancelledContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

var _ Backend = (*computeDriverAdapter)(nil)
var _ InteractiveExec = (*computeDriverAdapter)(nil)
var _ LogAccess = (*computeDriverAdapter)(nil)
var _ FileTransfer = (*computeDriverAdapter)(nil)
var _ PlatformEventStream = (*computeDriverAdapter)(nil)
var _ SpecValidator = (*validatingFakeComputeDriver)(nil)
