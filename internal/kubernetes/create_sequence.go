package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	bootstrapBoundaryConfigKey = "boundary.json"
	bootstrapBoundaryCertKey   = "tls.crt"
	bootstrapBoundaryKeyKey    = "tls.key"
	bootstrapDescriptorKey     = "runtime-descriptor.json"
	bootstrapSupervisorAuth    = "auth.json"
	bootstrapProxyCACert       = "proxy-ca.crt"
	bootstrapProxyCAKey        = "proxy-ca.key"
)

type agentSandboxFenceEvidence struct {
	PolicyUID       string
	Generation      int64
	ResourceVersion string
}

type agentSandboxResourceIdentity struct {
	Namespace             string
	Name                  string
	APIVersion            string
	UID                   string
	Suspended             bool
	PodTemplateMatches    bool
	CreateMetadataMatches bool
}

type agentSandboxServiceIdentity struct {
	ClusterIP            string
	OwnerSandboxUID      string
	SelectorBoundaryPair string
	SelectorBoundaryRole string
}

type agentSandboxPodIdentity struct {
	Name                            string
	UID                             string
	ServiceAccountName              string
	Image                           string
	Command                         []string
	OwnerSandboxUID                 string
	BoundaryPair                    string
	BoundaryRole                    string
	BootstrapSecretName             string
	ProviderEnvSecretName           string
	ProjectedTokenAudience          string
	BootstrapGatePresent            bool
	ServiceAccountAutomountDisabled bool
	HasProjectedServiceAccountToken bool
	HasRawGatewayCredentialEnv      bool
	HostNamespacesIsolated          bool
	RunAsNonRoot                    bool
	ReadOnlyRootFilesystem          bool
	RuntimeDefaultSeccomp           bool
	DropAllCapabilities             bool
	PrivilegeEscalationDisabled     bool
	AdditionalContainers            bool
	CautemContainerMatches          bool
	CautemVolumeSourcesMatch        bool
	CautemHasRawTokenEnv            bool
}

type agentSandboxWorkloadIdentity struct {
	Name                                    string
	UID                                     string
	Image                                   string
	Command                                 []string
	OwnerSandboxUID                         string
	BoundaryPair                            string
	BoundaryRole                            string
	SandboxBootstrapSecret                  string
	SupervisorSecretReferences              []string
	BootstrapGatePresent                    bool
	SchedulingGatesMatch                    bool
	ServiceAccountAutomountDisabled         bool
	HasProjectedServiceAccountToken         bool
	HasGatewayCredentialEnv                 bool
	AgentMountsBootstrapSecret              bool
	TrustedInitMountsBootstrapSecret        bool
	AgentContainerMatches                   bool
	InitContainerSpecsMatch                 bool
	PodVolumeSourcesMatch                   bool
	PodSecurityContextMatches               bool
	ServiceAccountMatches                   bool
	HostNamespacesIsolated                  bool
	RunAsNonRoot                            bool
	RuntimeDefaultSeccomp                   bool
	DropAllCapabilities                     bool
	PrivilegeEscalationDisabled             bool
	AdditionalApplicationContainers         bool
	OtherInitContainersMountBootstrapSecret bool
	CautemAgentMountsPrivateSecret          bool
	CautemInitMountsPrivateSecret           bool
	CautemSSHDContainerMatches              bool
	InitContainerNames                      []string
}

type agentSandboxCreateIdentity struct {
	Namespace        string
	SandboxName      string
	APIVersion       string
	SandboxUID       string
	SandboxID        string
	Generation       string
	ServiceIP        string
	ControlServiceIP string
	SupervisorName   string
	SupervisorUID    string
	WorkloadName     string
	WorkloadUID      string
	Fence            agentSandboxFenceEvidence
}

type agentSandboxCreateSequenceInput struct {
	SandboxResource       map[string]any
	RuntimeParams         agentSandboxRuntimeRenderParams
	BuildBootstrapSecrets func(agentSandboxCreateIdentity) ([]map[string]any, error)
	BuildCautemSecrets    func(agentSandboxCreateIdentity) ([]map[string]any, error)
}

// agentSandboxCreateSequenceBackend is a narrow control-plane seam. Its
// implementation must apply and read back both policies before returning from
// ApplyAndObserveRuntimeFence, and must resolve ambiguous create responses by
// reading the stable resource name before reporting failure.
type agentSandboxCreateSequenceBackend interface {
	EnsureWorkspaceIsolation(ctx context.Context, namespace, gatewayID, workspace string, namespaceResource, denyAllPolicy map[string]any) error
	ApplyAndObserveRuntimeFence(ctx context.Context, namespace string, workloadPolicy, supervisorPolicy map[string]any) (agentSandboxFenceEvidence, error)
	CreateSuspendedSandbox(ctx context.Context, resource map[string]any) (agentSandboxResourceIdentity, error)
	CreateBoundaryService(ctx context.Context, resource map[string]any) (agentSandboxServiceIdentity, error)
	CreateSupervisorControlService(ctx context.Context, resource map[string]any) (agentSandboxServiceIdentity, error)
	CreateProxyService(ctx context.Context, resource map[string]any) (agentSandboxServiceIdentity, error)
	CreateGatedSupervisor(ctx context.Context, resource map[string]any) (agentSandboxPodIdentity, error)
	ActivateSandboxController(ctx context.Context, namespace, version, name, sandboxUID string) error
	WaitForGatedWorkload(ctx context.Context, namespace, name, sandboxUID string, requestedResource map[string]any) (agentSandboxWorkloadIdentity, error)
	RecordRuntimePairEvidence(ctx context.Context, identity agentSandboxCreateIdentity) error
	CreateBootstrapSecrets(ctx context.Context, secrets []map[string]any) error
	ReleaseSchedulingGate(ctx context.Context, namespace, podName, podUID string) error
	MarkRuntimeReleased(ctx context.Context, namespace, apiVersion, sandboxName, sandboxUID string) error
	// DeleteSandbox must use sandboxUID as a Kubernetes UID precondition so
	// rollback cannot delete a later resource that reused the same name.
	DeleteSandbox(ctx context.Context, namespace, apiVersion, sandboxName, sandboxUID string) error
}

// runAgentSandboxCreateSequence ports OpenShell's security-sensitive order:
// install and observe the network fence, create a suspended Sandbox and gated
// companions, briefly activate only the controller so it creates the gated
// workload Pod, bind all observed UIDs, install split immutable Secrets, then
// release the supervisor before the workload. It is not yet connected to Driver.Create.
func runAgentSandboxCreateSequence(
	ctx context.Context,
	backend agentSandboxCreateSequenceBackend,
	input agentSandboxCreateSequenceInput,
) (agentSandboxCreateIdentity, error) {
	if backend == nil {
		return agentSandboxCreateIdentity{}, fmt.Errorf("kubernetes sandbox Create backend is nil")
	}
	params := input.RuntimeParams
	if params.SandboxResourceUID != "" {
		return agentSandboxCreateIdentity{}, fmt.Errorf("sandbox resource UID must be assigned by the Kubernetes API")
	}
	if strings.TrimSpace(params.Generation) == "" {
		return agentSandboxCreateIdentity{}, fmt.Errorf("sandbox runtime generation is required")
	}
	if params.CautemProxyImage != "" {
		if input.BuildCautemSecrets == nil {
			return agentSandboxCreateIdentity{}, fmt.Errorf("cautem generation Secret builder is required")
		}
	} else if input.BuildBootstrapSecrets == nil {
		return agentSandboxCreateIdentity{}, fmt.Errorf("bootstrap Secret builder is required")
	}
	if err := validateSuspendedAgentSandboxResource(input.SandboxResource, params); err != nil {
		return agentSandboxCreateIdentity{}, err
	}
	workspaceNamespace, namespaceResource, denyAllPolicy, err := renderWorkspaceIsolationResources(params.GatewayID, params.Workspace)
	if err != nil {
		return agentSandboxCreateIdentity{}, err
	}
	if params.Namespace != workspaceNamespace {
		return agentSandboxCreateIdentity{}, fmt.Errorf("namespace %q does not match the gateway/workspace namespace %q", params.Namespace, workspaceNamespace)
	}
	if err := backend.EnsureWorkspaceIsolation(ctx, params.Namespace, params.GatewayID, params.Workspace, namespaceResource, denyAllPolicy); err != nil {
		return agentSandboxCreateIdentity{}, fmt.Errorf("ensure workspace namespace isolation: %w", err)
	}

	preflightParams := params
	preflightParams.SandboxResourceUID = "preflight-owner-uid"
	preflightResources, err := renderAgentSandboxRuntimeResources(preflightParams)
	if err != nil {
		return agentSandboxCreateIdentity{}, fmt.Errorf("validate runtime companion resources: %w", err)
	}
	fenceEvidence, err := backend.ApplyAndObserveRuntimeFence(
		ctx,
		params.Namespace,
		preflightResources["workloadNetworkPolicy"].(map[string]any),
		preflightResources["supervisorNetworkPolicy"].(map[string]any),
	)
	if err != nil {
		return agentSandboxCreateIdentity{}, fmt.Errorf("apply and observe Kubernetes sandbox network fence: %w", err)
	}
	if err := validateAgentSandboxFenceEvidence(fenceEvidence); err != nil {
		return agentSandboxCreateIdentity{}, err
	}

	created, err := backend.CreateSuspendedSandbox(ctx, input.SandboxResource)
	if err != nil {
		if created.UID != "" {
			return rollbackAgentSandboxCreate(ctx, backend, params, created.UID, "create suspended Agent Sandbox", err)
		}
		return agentSandboxCreateIdentity{}, fmt.Errorf("create suspended Agent Sandbox: %w", err)
	}
	if err := validateCreatedSandboxIdentity(created, params); err != nil {
		if created.UID != "" {
			return rollbackAgentSandboxCreate(ctx, backend, params, created.UID, "validate created Agent Sandbox", err)
		}
		return agentSandboxCreateIdentity{}, err
	}

	rollback := func(step string, cause error) (agentSandboxCreateIdentity, error) {
		return rollbackAgentSandboxCreate(ctx, backend, params, created.UID, step, cause)
	}
	params.SandboxResourceUID = created.UID
	resources, err := renderAgentSandboxRuntimeResources(params)
	if err != nil {
		return rollback("render runtime companions", err)
	}
	service, err := backend.CreateBoundaryService(ctx, resources["boundaryService"].(map[string]any))
	if err != nil {
		return rollback("create boundary Service", err)
	}
	if service.OwnerSandboxUID != created.UID || service.SelectorBoundaryPair != strings.ToLower(params.SandboxID) || service.SelectorBoundaryRole != "workload" {
		return rollback("validate boundary Service", fmt.Errorf("boundary Service owner or selector does not match the workload pair"))
	}
	if net.ParseIP(service.ClusterIP) == nil {
		return rollback("validate boundary Service", fmt.Errorf("boundary Service returned invalid ClusterIP %q", service.ClusterIP))
	}
	controlService, err := backend.CreateSupervisorControlService(ctx, resources["controlService"].(map[string]any))
	if err != nil {
		return rollback("create supervisor control Service", err)
	}
	if controlService.OwnerSandboxUID != created.UID || controlService.SelectorBoundaryPair != strings.ToLower(params.SandboxID) || controlService.SelectorBoundaryRole != "supervisor" {
		return rollback("validate supervisor control Service", fmt.Errorf("supervisor control Service owner or selector does not match the paired supervisor"))
	}
	if net.ParseIP(controlService.ClusterIP) == nil {
		return rollback("validate supervisor control Service", fmt.Errorf("supervisor control Service returned invalid ClusterIP %q", controlService.ClusterIP))
	}
	proxyService, err := backend.CreateProxyService(ctx, resources["proxyService"].(map[string]any))
	if err != nil {
		return rollback("create proxy Service", err)
	}
	if proxyService.OwnerSandboxUID != created.UID || proxyService.SelectorBoundaryPair != strings.ToLower(params.SandboxID) || proxyService.SelectorBoundaryRole != "supervisor" {
		return rollback("validate proxy Service", fmt.Errorf("proxy Service owner or selector does not match the paired supervisor"))
	}
	if net.ParseIP(proxyService.ClusterIP) == nil {
		return rollback("validate proxy Service", fmt.Errorf("proxy Service returned invalid ClusterIP %q", proxyService.ClusterIP))
	}
	supervisor, err := backend.CreateGatedSupervisor(ctx, resources["supervisorPod"].(map[string]any))
	if err != nil {
		return rollback("create gated supervisor Pod", err)
	}
	if err := validateAgentSandboxSupervisorIdentity(supervisor, params, created.UID); err != nil {
		return rollback("validate supervisor Pod", err)
	}
	if err := backend.ActivateSandboxController(ctx, params.Namespace, params.SandboxResourceAPIVersion, params.SandboxResourceName, created.UID); err != nil {
		return rollback("activate Agent Sandbox controller", err)
	}
	workload, err := backend.WaitForGatedWorkload(ctx, params.Namespace, params.SandboxResourceName, created.UID, input.SandboxResource)
	if err != nil {
		return rollback("wait for gated workload Pod", err)
	}
	if err := validateAgentSandboxWorkloadIdentity(workload, params, created.UID, input.SandboxResource); err != nil {
		return rollback("validate admitted workload Pod", err)
	}

	identity := agentSandboxCreateIdentity{
		Namespace: params.Namespace, SandboxName: params.SandboxResourceName, APIVersion: params.SandboxResourceAPIVersion,
		SandboxUID: created.UID, SandboxID: params.SandboxID, Generation: params.Generation,
		ServiceIP: service.ClusterIP, ControlServiceIP: controlService.ClusterIP,
		SupervisorName: supervisor.Name, SupervisorUID: supervisor.UID,
		WorkloadName: workload.Name, WorkloadUID: workload.UID, Fence: fenceEvidence,
	}
	if err := backend.RecordRuntimePairEvidence(ctx, identity); err != nil {
		return rollback("record runtime pair evidence", err)
	}
	var secrets []map[string]any
	if params.CautemProxyImage != "" {
		secrets, err = input.BuildCautemSecrets(identity)
		if err == nil {
			err = validateCautemGenerationSecrets(secrets, identity)
		}
	} else {
		secrets, err = input.BuildBootstrapSecrets(identity)
		if err == nil {
			err = attachRuntimeBridgeCredentials(secrets, identity)
		}
		if err == nil {
			err = validateGenerationBootstrapSecrets(secrets, identity)
		}
	}
	if err != nil {
		return rollback("build or validate generation Secrets", err)
	}
	if err := backend.CreateBootstrapSecrets(ctx, secrets); err != nil {
		return rollback("create generation bootstrap Secrets", err)
	}
	if err := backend.ReleaseSchedulingGate(ctx, params.Namespace, supervisor.Name, supervisor.UID); err != nil {
		return rollback("release supervisor scheduling gate", err)
	}
	if err := backend.ReleaseSchedulingGate(ctx, params.Namespace, workload.Name, workload.UID); err != nil {
		return rollback("release workload scheduling gate", err)
	}
	if err := backend.MarkRuntimeReleased(ctx, params.Namespace, params.SandboxResourceAPIVersion, params.SandboxResourceName, created.UID); err != nil {
		return rollback("mark runtime generation released", err)
	}
	return identity, nil
}

func isZeroReplicaCount(value any) bool {
	switch count := value.(type) {
	case int:
		return count == 0
	case int32:
		return count == 0
	case int64:
		return count == 0
	case float64:
		return count == 0
	default:
		return false
	}
}

func rollbackAgentSandboxCreate(
	ctx context.Context,
	backend agentSandboxCreateSequenceBackend,
	params agentSandboxRuntimeRenderParams,
	sandboxUID, step string,
	cause error,
) (agentSandboxCreateIdentity, error) {
	primary := fmt.Errorf("kubernetes sandbox Create %s: %w", step, cause)
	if sandboxUID == "" {
		return agentSandboxCreateIdentity{}, primary
	}
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sandboxAPITimeout)
	defer cancel()
	if err := backend.DeleteSandbox(rollbackCtx, params.Namespace, params.SandboxResourceAPIVersion, params.SandboxResourceName, sandboxUID); err != nil {
		return agentSandboxCreateIdentity{}, errors.Join(primary, fmt.Errorf("rollback Agent Sandbox %s/%s: %w", params.Namespace, params.SandboxResourceName, err))
	}
	return agentSandboxCreateIdentity{}, primary
}
