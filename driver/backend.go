package driver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"sync"
	"time"

	core "github.com/cautem/cautem-core"
)

// BackendID is the product-owned identity of a compute implementation.
type BackendID string

// Capability names a behavior that callers may request from a backend.
type Capability string

const (
	CapabilityPTY                      Capability = "pty"
	CapabilityInteractiveExec          Capability = "interactive-exec"
	CapabilityLogAccess                Capability = "log-access"
	CapabilityEventStream              Capability = "event-stream"
	CapabilityPlatformEvents           Capability = "platform-events"
	CapabilityFileTransfer             Capability = "file-transfer"
	CapabilityPersistentData           Capability = "persistent-data"
	CapabilityGPU                      Capability = "gpu"
	CapabilityCDI                      Capability = "cdi"
	CapabilityNativeMounts             Capability = "native-mounts"
	CapabilityServiceForward           Capability = "service-forward"
	CapabilityRootfsImport             Capability = "rootfs-import"
	CapabilityCredentialRotate         Capability = "credential-rotation"
	CapabilityTokenAwareStart          Capability = "token-aware-start"
	CapabilityPolicyUpdate             Capability = "policy-update"
	CapabilityLaunchSpecRestore        Capability = "launch-spec-restore"
	CapabilityCredentialRefresh        Capability = "runtime-credential-refresh"
	CapabilityGatewayRuntimeValidation Capability = "gateway-runtime-validation"
	CapabilityProxyReadiness           Capability = "proxy-readiness"
	CapabilityProcessWait              Capability = "process-wait"
	CapabilityProcessLogs              Capability = "process-logs"
	CapabilityProcessTerminal          Capability = "process-terminal"
	CapabilityExecTerminal             Capability = "exec-terminal"
	CapabilityRootfsTarStaging         Capability = "rootfs-tar-staging"
)

// BackendInfo is safe to expose in control-plane capability negotiation. It
// deliberately contains no upstream protocol type or backend implementation.
type BackendInfo struct {
	ID                  BackendID
	Version             string
	ConfigSchemaVersion string
	Capabilities        map[Capability]struct{}
	MaxUploadBytes      int64
}

// BackendCapabilityProvider lets an implementation report the optional
// contracts it actually supports. Engine wrappers must not infer these from
// methods alone because legacy interfaces can contain unsupported stubs.
type BackendCapabilityProvider interface {
	BackendCapabilityInfo() BackendInfo
}

func (info BackendInfo) Has(capability Capability) bool {
	_, ok := info.Capabilities[capability]
	return ok
}

func (info BackendInfo) Clone() BackendInfo {
	info.Capabilities = maps.Clone(info.Capabilities)
	return info
}

// BackendCreateRequest is the domain request passed from orchestration to a
// backend. Values in Runtime and Network are ephemeral and must not be stored
// by the backend. Config is a backend-owned typed value, not a wire-format map.
type BackendCreateRequest struct {
	SandboxID        core.ID
	Name             string
	Workspace        WorkspaceTarget
	Workload         WorkloadSpec
	Resources        ResourceLimits
	Mounts           []Mount
	Network          NetworkSpec
	Runtime          RuntimeAssets
	Labels           map[string]string
	AllowUnsafeMount bool
	Config           any
}

type WorkspaceTarget struct {
	ID       string
	HostPath string
	Persist  bool
}

type WorkloadSpec struct {
	Image         string
	Command       []string
	Environment   []string
	TTY           bool
	RestartPolicy string
}

type ResourceLimits struct {
	CPUCores    float64
	MemoryBytes int64
	PIDs        int64
	GPU         bool
	GPUCount    int
	CDIDevices  []string
}

// Mount describes a host path admitted by orchestration. Backend validation
// still checks that its engine can honor the requested isolation and mapping.
type Mount struct {
	Source      string
	Destination string
	ReadOnly    bool
	UID         *uint32
	GID         *uint32
}

type NetworkSpec struct {
	GatewayID   string
	GatewayURL  string
	Proxy       *ProxySpec
	ExtraHosts  []string
	PortPublish []PortPublish
}

// ProxySpec includes secret values only for the short-lived Create call.
type ProxySpec struct {
	Binary      string
	Image       string
	PolicyPath  string
	Port        int
	Environment []string
}

type RuntimeAssets struct {
	InitBinary       string
	SupervisorBinary string
	SSHBinary        string
	NoHarden         bool
	EnableSSH        bool
	DisplayMode      string
	DisplayPort      int
	DisplayPassword  string
}

// Backend is the required lifecycle contract. Optional operations live in
// extension interfaces so each backend implements only the features it
// advertises. Backend-specific configuration stays typed inside its package.
type Backend interface {
	ID() BackendID
	Capabilities(context.Context) (BackendInfo, error)
	ValidateCreate(context.Context, BackendCreateRequest) error
	Create(context.Context, BackendCreateRequest) (Handle, error)
	Start(context.Context, core.ID) error
	Stop(context.Context, core.ID) error
	Delete(context.Context, core.ID) error
	List(context.Context) ([]Info, error)
	Inspect(context.Context, string) (Info, error)
}

// InteractiveExec is optional. Backends advertise
// CapabilityInteractiveExec and, for terminal sessions, CapabilityPTY.
type InteractiveExec interface {
	Exec(context.Context, core.ID, ExecRequest) (ExecResult, error)
}

// ExecTerminalRequest starts a command attached to a guest PTY. Columns and
// Rows describe the initial size; subsequent changes use ExecTerminalSession.Resize.
type ExecTerminalRequest struct {
	Argv         []string
	Env          []string
	WorkDir      string
	NoLoginShell bool
	Columns      uint32
	Rows         uint32
}

// ExecTerminalSession is a full-duplex PTY stream. EOF from Read signals the
// process has exited; Wait returns its normalized exit status.
type ExecTerminalSession interface {
	io.ReadWriteCloser
	Resize(context.Context, uint32, uint32) error
	Wait(context.Context) (int, error)
}

// ExecTerminal is an optional streaming PTY contract for interactive command
// sessions. Backends advertise CapabilityExecTerminal only when implemented.
type ExecTerminal interface {
	OpenExecTerminal(context.Context, core.ID, ExecTerminalRequest) (ExecTerminalSession, error)
}

// LogAccess is optional and streams workload logs to the caller.
type LogAccess interface {
	Logs(context.Context, core.ID, bool, io.Writer) error
}

// EventStream is optional until a backend provides durable generation and
// sequence semantics. Callers must negotiate CapabilityEventStream first.
type EventStream interface {
	Watch(context.Context, WatchCursor) (<-chan Event, error)
}

// PlatformEventWatchRequest identifies the sandbox whose backend-native
// platform events are requested. SandboxName supports backends whose native
// platform resource name differs from the product's stable sandbox ID.
type PlatformEventWatchRequest struct {
	SandboxID   core.ID
	SandboxName string
}

// PlatformEvent is a backend-native observation without durable cursor
// guarantees. Implementations must use EventStream instead when they can
// provide resumable generation and sequence semantics.
type PlatformEvent struct {
	// SandboxID must identify the sandbox requested by PlatformEventWatchRequest.
	SandboxID core.ID
	Time      time.Time
	Source    string
	Type      string
	Reason    string
	Message   string
	Metadata  map[string]string
	Terminal  bool
}

// PlatformEventResult carries stream errors that occur after the watch starts.
type PlatformEventResult struct {
	Event PlatformEvent
	Err   error
}

// PlatformEventStream is optional. Unlike EventStream, it does not promise a
// durable cursor and is suitable for adapting a backend's native watch RPC.
type PlatformEventStream interface {
	WatchPlatformEvents(context.Context, PlatformEventWatchRequest) (<-chan PlatformEventResult, error)
}

// FileTransfer is optional. Implementations enforce archive and path limits
// before writing into a sandbox or the host filesystem.
type FileTransfer interface {
	CopyTo(context.Context, core.ID, string, string) error
	CopyFrom(context.Context, core.ID, string, string) error
}

type ServiceForwardRequest struct {
	Name       string
	TargetPort uint16
	BindHost   string
}

type ServiceForwardHandle struct {
	ID      string
	Address string
}

// ServiceForward is optional. Closing the same backend-owned handle more than
// once must be safe.
type ServiceForward interface {
	OpenServiceForward(context.Context, core.ID, ServiceForwardRequest) (ServiceForwardHandle, error)
	CloseServiceForward(context.Context, core.ID, string) error
}

type RootfsImportRequest struct {
	Archive  io.Reader
	MaxBytes uint64
	Digest   string
}

type RootfsArtifact struct {
	ImageRef  string
	Digest    string
	SizeBytes uint64
}

// RootfsImporter is optional. Implementations validate limits, digest and
// archive paths before publishing an immutable artifact.
type RootfsImporter interface {
	ImportRootfs(context.Context, RootfsImportRequest) (RootfsArtifact, error)
}

type CredentialBinding struct {
	Name  string
	Value string
}

// CredentialRotator receives short-lived values and must not retain them in
// durable backend metadata, logs or inspection output.
type CredentialRotator interface {
	RotateCredentials(context.Context, core.ID, []CredentialBinding) error
}

// RuntimeTokenStarter replaces short-lived supervisor credentials before a
// stopped sandbox starts again. The value is transient and must not be stored.
type RuntimeTokenStarter interface {
	StartWithToken(context.Context, core.ID, string) error
}

// RuntimePolicyUpdater delivers an effective policy to a runtime whose policy
// source is not shared with the control plane. The backend must return only
// after the policy is durably attached to the sandbox.
type RuntimePolicyUpdater interface {
	UpdateSandboxPolicy(context.Context, core.ID, []byte) error
}

// RuntimeLaunchSpecRestorer restores process-local workload settings after a
// control-plane restart. Implementations must not persist supplied secrets.
type RuntimeLaunchSpecRestorer interface {
	RestoreLaunchSpec(context.Context, core.ID, BackendCreateRequest) error
}

// RuntimeCredentialRefresher asks a backend to refresh credentials already
// mounted into a running runtime without changing its effective policy.
type RuntimeCredentialRefresher interface {
	RefreshRuntimeCredentials(context.Context, core.ID) error
}

// RuntimeContractValidator checks whether a backend can satisfy the Gateway's
// required runtime guarantees before it consumes one-shot create inputs.
type RuntimeContractValidator interface {
	ValidateRuntimeContract(context.Context) error
}

// RuntimeProxyReadiness waits until the backend-owned egress proxy is ready.
type RuntimeProxyReadiness interface {
	WaitProxyReady(context.Context, string) error
}

// RuntimeProcessWaiter reports the exit status of the canonical sandbox process.
type RuntimeProcessWaiter interface {
	WaitProcess(context.Context, core.ID) (int, error)
}

// RuntimeProcessLogs opens output for the canonical sandbox process.
type RuntimeProcessLogs interface {
	OpenProcessLogs(context.Context, core.ID) (io.ReadCloser, error)
}

// RuntimeProcessTerminal opens and resizes the canonical sandbox terminal.
type RuntimeProcessTerminal interface {
	OpenProcessTerminal(context.Context, core.ID, uint32, uint32) (io.ReadWriteCloser, error)
	ResizeProcessTerminal(context.Context, core.ID, uint32, uint32) error
}

// RuntimeRootfsTarStager allocates a backend-owned staging root for a bounded
// upload. It is a compatibility bridge for transports that upload by path.
type RuntimeRootfsTarStager interface {
	RootfsTarStaging(context.Context) (directory string, maxBytes uint64, err error)
}

type WatchCursor struct {
	Generation uint64
	Sequence   uint64
}

type Event struct {
	Generation uint64
	Sequence   uint64
	Type       string
	SandboxID  core.ID
	Message    string
}

var ErrUnsupported = errors.New("backend capability is unsupported")

// UnsupportedError identifies the requested behavior without leaking backend
// internals into API responses.
type UnsupportedError struct {
	Backend    BackendID
	Capability Capability
	Operation  string
}

func (err *UnsupportedError) Error() string {
	return fmt.Sprintf("backend %q does not support %q for %s", err.Backend, err.Capability, err.Operation)
}

func (err *UnsupportedError) Unwrap() error { return ErrUnsupported }

// RequireExtension verifies that a backend both advertises a capability and
// implements its corresponding extension interface. This prevents a silent
// downgrade when capability metadata and implementation drift apart.
func RequireExtension[T any](ctx context.Context, backend Backend, capability Capability, operation string) (T, error) {
	var zero T
	if backend == nil {
		return zero, errors.New("backend is required")
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	info, err := backend.Capabilities(ctx)
	if err != nil {
		return zero, err
	}
	unsupported := func() (T, error) {
		return zero, &UnsupportedError{Backend: backend.ID(), Capability: capability, Operation: operation}
	}
	if !info.Has(capability) {
		return unsupported()
	}
	extension, ok := any(backend).(T)
	if !ok {
		return unsupported()
	}
	return extension, nil
}

// LegacySpecEncoder is a migration seam for implementations that still accept
// the flat Spec. It belongs at the driver boundary and must not be exposed by
// Gateway or SDK APIs.
type LegacySpecEncoder func(BackendCreateRequest) (Spec, error)

// BackendCreateRequestFromLegacySpec copies a legacy driver spec into the
// product-owned request while that adapter is being migrated.
func BackendCreateRequestFromLegacySpec(spec Spec) BackendCreateRequest {
	request := BackendCreateRequest{
		SandboxID: core.ID(spec.Name),
		Name:      spec.Name,
		Workspace: WorkspaceTarget{ID: spec.Workspace, HostPath: spec.Workspace, Persist: spec.PersistVolume},
		Workload: WorkloadSpec{
			Image:         spec.Image,
			Command:       slices.Clone(spec.Command),
			Environment:   slices.Clone(spec.Env),
			TTY:           spec.TTY,
			RestartPolicy: spec.MainProcessRestartPolicy,
		},
		Resources: ResourceLimits{
			CPUCores:    spec.CPU,
			MemoryBytes: spec.MemoryBytes,
			PIDs:        spec.PidsLimit,
			GPU:         spec.GPU,
			GPUCount:    spec.GPUCount,
			CDIDevices:  slices.Clone(spec.CDIDevices),
		},
		Network: NetworkSpec{
			GatewayID:   spec.GatewayID,
			GatewayURL:  spec.GatewayURL,
			ExtraHosts:  slices.Clone(spec.ExtraHosts),
			PortPublish: slices.Clone(spec.PublishPorts),
		},
		Runtime: RuntimeAssets{
			InitBinary:       spec.InitBin,
			SupervisorBinary: spec.SupervisorBin,
			SSHBinary:        spec.SSHBin,
			NoHarden:         spec.NoHarden,
			EnableSSH:        spec.EnableSSH,
			DisplayMode:      spec.DisplayMode,
			DisplayPort:      spec.DisplayPort,
			DisplayPassword:  spec.DisplayPassword,
		},
		Labels:           maps.Clone(spec.Labels),
		AllowUnsafeMount: spec.IKnow,
		Config:           spec.DriverConfigJSON,
	}
	if spec.ProxyBin != "" || spec.ProxyImage != "" || spec.PolicyPath != "" || spec.ProxyPort != 0 || len(spec.ProxyEnv) != 0 {
		request.Network.Proxy = &ProxySpec{
			Binary:      spec.ProxyBin,
			Image:       spec.ProxyImage,
			PolicyPath:  spec.PolicyPath,
			Port:        spec.ProxyPort,
			Environment: slices.Clone(spec.ProxyEnv),
		}
	}
	return request
}

// LegacySpecFromBackendRequest encodes the subset of the product request that
// the flat driver Spec can represent. It rejects fields that would otherwise
// be silently discarded during migration.
func LegacySpecFromBackendRequest(request BackendCreateRequest) (Spec, error) {
	if request.SandboxID != "" && string(request.SandboxID) != request.Name {
		return Spec{}, errors.New("legacy compute driver cannot honor a distinct sandbox id")
	}
	if request.Workspace.ID != "" && request.Workspace.ID != request.Workspace.HostPath && request.Labels[WorkspaceLabel] != request.Workspace.ID {
		return Spec{}, errors.New("legacy compute driver cannot honor a distinct workspace id without a matching workspace label")
	}
	if len(request.Mounts) != 0 {
		return Spec{}, errors.New("legacy compute driver cannot honor domain mount requests")
	}
	config := ""
	switch value := request.Config.(type) {
	case nil:
	case string:
		config = value
	case map[string]any:
		if value == nil {
			break
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return Spec{}, fmt.Errorf("legacy compute driver config cannot be encoded: %w", err)
		}
		config = string(encoded)
	default:
		return Spec{}, errors.New("legacy compute driver requires its backend config as a string or object")
	}
	spec := Spec{
		Name:                     request.Name,
		Image:                    request.Workload.Image,
		Workspace:                request.Workspace.HostPath,
		GatewayID:                request.Network.GatewayID,
		Command:                  slices.Clone(request.Workload.Command),
		TTY:                      request.Workload.TTY,
		MainProcessRestartPolicy: request.Workload.RestartPolicy,
		Env:                      slices.Clone(request.Workload.Environment),
		IKnow:                    request.AllowUnsafeMount,
		InitBin:                  request.Runtime.InitBinary,
		NoHarden:                 request.Runtime.NoHarden,
		SupervisorBin:            request.Runtime.SupervisorBinary,
		DisplayMode:              request.Runtime.DisplayMode,
		DisplayPort:              request.Runtime.DisplayPort,
		DisplayPassword:          request.Runtime.DisplayPassword,
		Labels:                   maps.Clone(request.Labels),
		ExtraHosts:               slices.Clone(request.Network.ExtraHosts),
		GatewayURL:               request.Network.GatewayURL,
		PersistVolume:            request.Workspace.Persist,
		EnableSSH:                request.Runtime.EnableSSH,
		SSHBin:                   request.Runtime.SSHBinary,
		GPUCount:                 request.Resources.GPUCount,
		CDIDevices:               slices.Clone(request.Resources.CDIDevices),
		CPU:                      request.Resources.CPUCores,
		MemoryBytes:              request.Resources.MemoryBytes,
		PidsLimit:                request.Resources.PIDs,
		PublishPorts:             slices.Clone(request.Network.PortPublish),
		GPU:                      request.Resources.GPU,
		DriverConfigJSON:         config,
	}
	if request.Network.Proxy != nil {
		spec.ProxyBin = request.Network.Proxy.Binary
		spec.ProxyImage = request.Network.Proxy.Image
		spec.PolicyPath = request.Network.Proxy.PolicyPath
		spec.ProxyPort = request.Network.Proxy.Port
		spec.ProxyEnv = slices.Clone(request.Network.Proxy.Environment)
	}
	return spec, nil
}

// AdaptComputeDriver lets an existing implementation satisfy Backend while
// the backend packages migrate to the domain request. New implementations
// should implement Backend directly.
func AdaptComputeDriver(id BackendID, info BackendInfo, engine ComputeDriver, encode LegacySpecEncoder) (Backend, error) {
	if id == "" || engine == nil || encode == nil {
		return nil, errors.New("backend id, engine, and legacy spec encoder are required")
	}
	if info.ID != "" && info.ID != id {
		return nil, fmt.Errorf("backend info id %q does not match adapter id %q", info.ID, id)
	}
	info.ID = id
	return &computeDriverAdapter{id: id, info: info.Clone(), engine: engine, encode: encode}, nil
}

// AdaptLegacyEngine is the single compatibility boundary for existing Engine
// implementations. Gateway callers receive the product Backend contract and
// do not choose the legacy Spec encoder or reconstruct capability metadata.
func AdaptLegacyEngine(id BackendID, engine Engine) (Backend, error) {
	if id == "" || engine == nil {
		return nil, errors.New("backend id and legacy engine are required")
	}
	info := BackendInfo{ID: id}
	if provider, ok := engine.(BackendCapabilityProvider); ok {
		info = provider.BackendCapabilityInfo()
		if info.ID != "" && info.ID != id {
			return nil, fmt.Errorf("compute backend %q reported mismatched capability identity %q", id, info.ID)
		}
		info.ID = id
	}
	return AdaptComputeDriver(id, info, engine, LegacySpecFromBackendRequest)
}

type computeDriverAdapter struct {
	id     BackendID
	info   BackendInfo
	engine ComputeDriver
	encode LegacySpecEncoder
}

func (adapter *computeDriverAdapter) ID() BackendID { return adapter.id }

func (adapter *computeDriverAdapter) Capabilities(ctx context.Context) (BackendInfo, error) {
	if err := ctx.Err(); err != nil {
		return BackendInfo{}, err
	}
	return adapter.info.Clone(), nil
}

func (adapter *computeDriverAdapter) legacySpec(ctx context.Context, request BackendCreateRequest) (Spec, error) {
	if err := ctx.Err(); err != nil {
		return Spec{}, err
	}
	spec, err := adapter.encode(request)
	if err != nil {
		return Spec{}, err
	}
	if validator, ok := adapter.engine.(ContextSpecValidator); ok {
		if err := validator.ValidateSpecContext(ctx, spec); err != nil {
			return Spec{}, err
		}
	} else if validator, ok := adapter.engine.(SpecValidator); ok {
		if err := validator.ValidateSpec(spec); err != nil {
			return Spec{}, err
		}
	}
	return spec, nil
}

func (adapter *computeDriverAdapter) ValidateCreate(ctx context.Context, request BackendCreateRequest) error {
	_, err := adapter.legacySpec(ctx, request)
	return err
}

func (adapter *computeDriverAdapter) Create(ctx context.Context, request BackendCreateRequest) (Handle, error) {
	spec, err := adapter.legacySpec(ctx, request)
	if err != nil {
		return Handle{}, err
	}
	if err := ctx.Err(); err != nil {
		return Handle{}, err
	}
	return adapter.engine.Create(ctx, spec)
}

func (adapter *computeDriverAdapter) Start(ctx context.Context, id core.ID) error {
	return adapter.engine.Start(ctx, id)
}

func (adapter *computeDriverAdapter) StartWithToken(ctx context.Context, id core.ID, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	starter, ok := adapter.engine.(TokenAwareStarter)
	if !ok {
		return &UnsupportedError{Backend: adapter.id, Capability: CapabilityTokenAwareStart, Operation: "restart with a rotated runtime token"}
	}
	return starter.StartWithToken(ctx, id, token)
}

func (adapter *computeDriverAdapter) UpdateSandboxPolicy(ctx context.Context, id core.ID, policy []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	updater, ok := adapter.engine.(SandboxPolicyUpdater)
	if !ok {
		return &UnsupportedError{Backend: adapter.id, Capability: CapabilityPolicyUpdate, Operation: "deliver a runtime policy update"}
	}
	return updater.UpdateSandboxPolicy(ctx, id, policy)
}

func (adapter *computeDriverAdapter) RestoreLaunchSpec(ctx context.Context, id core.ID, request BackendCreateRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	restorer, ok := adapter.engine.(LaunchSpecRestorer)
	if !ok {
		return &UnsupportedError{Backend: adapter.id, Capability: CapabilityLaunchSpecRestore, Operation: "restore a runtime launch spec"}
	}
	spec, err := adapter.legacySpec(ctx, request)
	if err != nil {
		return err
	}
	return restorer.RestoreLaunchSpec(ctx, id, spec)
}

func (adapter *computeDriverAdapter) RefreshRuntimeCredentials(ctx context.Context, id core.ID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	refresher, ok := adapter.engine.(SandboxRuntimeCredentialRefresher)
	if !ok {
		return &UnsupportedError{Backend: adapter.id, Capability: CapabilityCredentialRefresh, Operation: "refresh runtime credentials"}
	}
	return refresher.RefreshSandboxRuntimeCredentials(ctx, id)
}

func (adapter *computeDriverAdapter) ValidateRuntimeContract(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	validator, ok := adapter.engine.(GatewayRuntimeValidator)
	if !ok {
		return &UnsupportedError{Backend: adapter.id, Capability: CapabilityGatewayRuntimeValidation, Operation: "validate Gateway runtime guarantees"}
	}
	return validator.ValidateGatewayRuntime()
}

func (adapter *computeDriverAdapter) WaitProxyReady(ctx context.Context, sandboxName string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	readiness, ok := adapter.engine.(ProxyReadiness)
	if !ok {
		return &UnsupportedError{Backend: adapter.id, Capability: CapabilityProxyReadiness, Operation: "wait for the runtime proxy"}
	}
	return readiness.WaitProxyReady(ctx, sandboxName)
}

func (adapter *computeDriverAdapter) WaitProcess(ctx context.Context, id core.ID) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	waiter, ok := adapter.engine.(MainProcessWaiter)
	if !ok {
		return 0, &UnsupportedError{Backend: adapter.id, Capability: CapabilityProcessWait, Operation: "wait for the canonical process"}
	}
	return waiter.WaitMainProcess(ctx, id)
}

func (adapter *computeDriverAdapter) OpenProcessLogs(ctx context.Context, id core.ID) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	attacher, ok := adapter.engine.(MainProcessLogAttacher)
	if !ok {
		return nil, &UnsupportedError{Backend: adapter.id, Capability: CapabilityProcessLogs, Operation: "attach to canonical process output"}
	}
	return attacher.OpenMainProcessLogs(ctx, id)
}

func (adapter *computeDriverAdapter) OpenProcessTerminal(ctx context.Context, id core.ID, cols, rows uint32) (io.ReadWriteCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	terminal, ok := adapter.engine.(MainProcessTTY)
	if !ok {
		return nil, &UnsupportedError{Backend: adapter.id, Capability: CapabilityProcessTerminal, Operation: "attach to canonical process TTY"}
	}
	return terminal.OpenMainProcessTTY(ctx, id, cols, rows)
}

func (adapter *computeDriverAdapter) ResizeProcessTerminal(ctx context.Context, id core.ID, cols, rows uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	terminal, ok := adapter.engine.(MainProcessTTY)
	if !ok {
		return &UnsupportedError{Backend: adapter.id, Capability: CapabilityProcessTerminal, Operation: "resize canonical process TTY"}
	}
	return terminal.ResizeMainProcessTTY(ctx, id, cols, rows)
}

func (adapter *computeDriverAdapter) RootfsTarStaging(ctx context.Context) (string, uint64, error) {
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	stager, ok := adapter.engine.(RootfsTarStager)
	if !ok {
		return "", 0, &UnsupportedError{Backend: adapter.id, Capability: CapabilityRootfsTarStaging, Operation: "stage a rootfs tar upload"}
	}
	return stager.RootfsTarStaging(ctx)
}

func (adapter *computeDriverAdapter) Stop(ctx context.Context, id core.ID) error {
	return adapter.engine.Stop(ctx, id)
}

func (adapter *computeDriverAdapter) Exec(ctx context.Context, id core.ID, request ExecRequest) (ExecResult, error) {
	return adapter.engine.Exec(ctx, id, request)
}

func (adapter *computeDriverAdapter) OpenExecTerminal(ctx context.Context, id core.ID, request ExecTerminalRequest) (ExecTerminalSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	terminal, ok := adapter.engine.(ExecTerminal)
	if !ok {
		return nil, &UnsupportedError{Backend: adapter.id, Capability: CapabilityExecTerminal, Operation: "open an interactive exec terminal"}
	}
	return terminal.OpenExecTerminal(ctx, id, request)
}

func (adapter *computeDriverAdapter) Delete(ctx context.Context, id core.ID) error {
	return adapter.engine.Delete(ctx, id)
}

func (adapter *computeDriverAdapter) List(ctx context.Context) ([]Info, error) {
	return adapter.engine.List(ctx)
}

func (adapter *computeDriverAdapter) Inspect(ctx context.Context, nameOrID string) (Info, error) {
	return adapter.engine.Inspect(ctx, nameOrID)
}

func (adapter *computeDriverAdapter) Logs(ctx context.Context, id core.ID, follow bool, output io.Writer) error {
	return adapter.engine.Logs(ctx, id, follow, output)
}

func (adapter *computeDriverAdapter) WatchPlatformEvents(ctx context.Context, request PlatformEventWatchRequest) (<-chan PlatformEventResult, error) {
	if backend, ok := adapter.engine.(PlatformEventStream); ok {
		return backend.WatchPlatformEvents(ctx, request)
	}
	return nil, &UnsupportedError{Backend: adapter.id, Capability: CapabilityPlatformEvents, Operation: "watch platform events"}
}

func (adapter *computeDriverAdapter) CopyTo(ctx context.Context, id core.ID, source, destination string) error {
	return adapter.engine.CopyTo(ctx, id, source, destination)
}

func (adapter *computeDriverAdapter) CopyFrom(ctx context.Context, id core.ID, source, destination string) error {
	return adapter.engine.CopyFrom(ctx, id, source, destination)
}

// BackendRegistry provides stable lookup and rejects duplicate IDs at startup.
type BackendRegistry struct {
	mu       sync.RWMutex
	backends map[BackendID]Backend
}

func NewBackendRegistry() *BackendRegistry {
	return &BackendRegistry{backends: make(map[BackendID]Backend)}
}

func (registry *BackendRegistry) Register(backend Backend) error {
	if backend == nil || backend.ID() == "" {
		return errors.New("backend and backend id are required")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.backends == nil {
		registry.backends = make(map[BackendID]Backend)
	}
	if _, exists := registry.backends[backend.ID()]; exists {
		return fmt.Errorf("backend %q is already registered", backend.ID())
	}
	registry.backends[backend.ID()] = backend
	return nil
}

func (registry *BackendRegistry) Get(id BackendID) (Backend, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	backend, ok := registry.backends[id]
	if !ok {
		return nil, fmt.Errorf("backend %q is not registered", id)
	}
	return backend, nil
}

func (registry *BackendRegistry) IDs() []BackendID {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	ids := make([]BackendID, 0, len(registry.backends))
	for id := range registry.backends {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}
