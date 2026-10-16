package kubernetes

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestCompatAgentSandboxCreateSequenceFencesBeforeCreateAndReleasesLast(t *testing.T) {
	backend := newFakeAgentSandboxCreateBackend()
	identity, err := runAgentSandboxCreateSequence(context.Background(), backend, testAgentSandboxCreateSequenceInput())
	if err != nil {
		t.Fatalf("runAgentSandboxCreateSequence() error = %v", err)
	}
	want := []string{
		"ensure-workspace-isolation",
		"apply-and-observe-fence",
		"create-suspended-sandbox",
		"create-boundary-service",
		"create-supervisor-control-service",
		"create-proxy-service",
		"create-gated-supervisor",
		"activate-sandbox-controller",
		"wait-for-gated-workload",
		"record-pair-evidence",
		"create-bootstrap-secrets",
		"release-supervisor-gate",
		"release-workload-gate",
		"mark-runtime-released",
	}
	if !reflect.DeepEqual(backend.calls, want) {
		t.Fatalf("Create sequence = %#v; want %#v", backend.calls, want)
	}
	if identity.SandboxUID != "sandbox-cr-uid" || identity.WorkloadUID != "workload-pod-uid" || identity.SupervisorUID != "supervisor-pod-uid" || identity.Fence.PolicyUID != "fence-policy-uid" || identity.Generation != "gen1" || identity.ServiceIP == "" || identity.ControlServiceIP == "" {
		t.Fatalf("Create identity = %#v", identity)
	}
}

func TestCautemAgentSandboxCreateSequenceUsesSplitGenerationSecrets(t *testing.T) {
	backend := newFakeAgentSandboxCreateBackend()
	workloadParams := testCautemWorkloadRenderParams()
	workloadParams.Base.Generation = "gen1"
	resource, err := renderCautemAgentSandboxResource(SandboxDriverConfig{}, workloadParams)
	if err != nil {
		t.Fatalf("renderCautemAgentSandboxResource() error = %v", err)
	}
	runtimeParams := testAgentSandboxRuntimeRenderParams()
	runtimeParams.Generation = "gen1"
	runtimeParams.SandboxResourceUID = ""
	runtimeParams.SupervisorImage = ""
	runtimeParams.GatewayEndpoint = ""
	runtimeParams.CautemProxyImage = "ghcr.io/cautem/cautem-proxy@sha256:" + strings.Repeat("b", 64)
	runtimeParams.CautemGatewayURL = "http://gateway.example:443"
	runtimeParams.CautemGatewayGRPCEndpoint = "gateway.example:7443"
	backend.supervisor.Image = runtimeParams.CautemProxyImage
	backend.supervisor.Command = cautemProxyCommandStrings()
	backend.supervisor.ProjectedTokenAudience = ""
	backend.supervisor.HasProjectedServiceAccountToken = false
	backend.supervisor.BootstrapSecretName = generationSecretName("os-supervisor", runtimeParams.SandboxID, runtimeParams.Generation)
	backend.supervisor.ProviderEnvSecretName = generationSecretName(proxyEnvSecretPrefix, runtimeParams.SandboxID, runtimeParams.Generation)
	backend.supervisor.CautemContainerMatches = true
	backend.supervisor.CautemVolumeSourcesMatch = true
	backend.workload.Command = []string{cautemWorkloadRuntimeDir + "/cautem-supervisor"}
	backend.workload.SandboxBootstrapSecret = generationSecretName("os-sandbox", runtimeParams.SandboxID, runtimeParams.Generation)
	backend.workload.InitContainerNames = []string{cautemWorkloadRuntimeInit, workspaceSeedContainerName}
	backend.workload.TrustedInitMountsBootstrapSecret = false
	backend.workload.CautemAgentMountsPrivateSecret = true
	backend.workload.CautemInitMountsPrivateSecret = false
	backend.workload.CautemSSHDContainerMatches = true

	input := agentSandboxCreateSequenceInput{
		SandboxResource: resource,
		RuntimeParams:   runtimeParams,
		BuildCautemSecrets: func(identity agentSandboxCreateIdentity) ([]map[string]any, error) {
			return buildCautemGenerationSecrets(identity, []byte("version: 1\n"), []string{"CAUTEM_SANDBOX_TOKEN=test-token", "OPENAI_API_KEY=test-provider-key"})
		},
	}
	if _, err := runAgentSandboxCreateSequence(context.Background(), backend, input); err != nil {
		t.Fatalf("runAgentSandboxCreateSequence() error = %v", err)
	}
	if len(backend.createdSecrets) != 3 {
		t.Fatalf("created Secret count = %d; want workload, supervisor, and provider env", len(backend.createdSecrets))
	}
}

func TestCompatAgentSandboxCreateSequenceStopsAndRollsBackOnEveryFailure(t *testing.T) {
	steps := []string{
		"ensure-workspace-isolation",
		"apply-and-observe-fence",
		"create-suspended-sandbox",
		"create-boundary-service",
		"create-supervisor-control-service",
		"create-proxy-service",
		"create-gated-supervisor",
		"activate-sandbox-controller",
		"wait-for-gated-workload",
		"record-pair-evidence",
		"create-bootstrap-secrets",
		"release-supervisor-gate",
		"release-workload-gate",
		"mark-runtime-released",
	}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			backend := newFakeAgentSandboxCreateBackend()
			backend.failAt = step
			_, err := runAgentSandboxCreateSequence(context.Background(), backend, testAgentSandboxCreateSequenceInput())
			if err == nil || !strings.Contains(err.Error(), "injected failure") {
				t.Fatalf("runAgentSandboxCreateSequence() error = %v; want injected failure at %s", err, step)
			}
			if !backend.sandboxDeleted && step != "ensure-workspace-isolation" && step != "apply-and-observe-fence" && step != "create-suspended-sandbox" {
				t.Fatalf("sandbox must roll back after failure at %s; calls = %#v", step, backend.calls)
			}
			if backend.sandboxDeleted && (step == "ensure-workspace-isolation" || step == "apply-and-observe-fence") {
				t.Fatalf("sandbox was never created but rollback ran: %#v", backend.calls)
			}
			failureIndex := -1
			for index, call := range backend.calls {
				if call == step {
					failureIndex = index
					break
				}
			}
			if failureIndex >= 0 {
				for _, call := range backend.calls[failureIndex+1:] {
					if call != "delete-sandbox" {
						t.Fatalf("sequence continued after %s failure: %#v", step, backend.calls)
					}
				}
			}
		})
	}
}

func TestCompatAgentSandboxCreateSequenceRejectsChangedWorkloadOwner(t *testing.T) {
	backend := newFakeAgentSandboxCreateBackend()
	backend.workload.OwnerSandboxUID = "recreated-cr-uid"
	_, err := runAgentSandboxCreateSequence(context.Background(), backend, testAgentSandboxCreateSequenceInput())
	if err == nil || !strings.Contains(err.Error(), "owner UID") {
		t.Fatalf("runAgentSandboxCreateSequence() error = %v; want workload owner mismatch", err)
	}
	if !backend.sandboxDeleted {
		t.Fatalf("owner mismatch must roll back the suspended sandbox: %#v", backend.calls)
	}
	if containsString(backend.calls, "create-bootstrap-secrets") || containsString(backend.calls, "release-supervisor-gate") {
		t.Fatalf("owner mismatch must not create secrets or release Pods: %#v", backend.calls)
	}
}

func TestCompatAgentSandboxCreateSequenceRejectsUnpairedControlService(t *testing.T) {
	backend := newFakeAgentSandboxCreateBackend()
	backend.controlService.SelectorBoundaryPair = "another-sandbox"
	_, err := runAgentSandboxCreateSequence(context.Background(), backend, testAgentSandboxCreateSequenceInput())
	if err == nil || !strings.Contains(err.Error(), "control Service owner or selector") {
		t.Fatalf("runAgentSandboxCreateSequence() error = %v; want paired control Service rejection", err)
	}
	if !backend.sandboxDeleted || containsString(backend.calls, "create-gated-supervisor") {
		t.Fatalf("unpaired control Service must roll back before supervisor creation: %#v", backend.calls)
	}
}

func TestCompatAgentSandboxCreateSequenceRejectsAdmittedWorkloadSecurityDowngrade(t *testing.T) {
	backend := newFakeAgentSandboxCreateBackend()
	backend.workload.DropAllCapabilities = false
	_, err := runAgentSandboxCreateSequence(context.Background(), backend, testAgentSandboxCreateSequenceInput())
	if err == nil || !strings.Contains(err.Error(), "security context") {
		t.Fatalf("runAgentSandboxCreateSequence() error = %v; want admitted Pod security rejection", err)
	}
	if !backend.sandboxDeleted || containsString(backend.calls, "create-bootstrap-secrets") || containsString(backend.calls, "release-supervisor-gate") {
		t.Fatalf("security downgrade must be rejected before Secret creation and release: %#v", backend.calls)
	}
}

func TestCompatAgentSandboxCreateSequenceRejectsSupervisorWithWrongTokenAudience(t *testing.T) {
	backend := newFakeAgentSandboxCreateBackend()
	backend.supervisor.ProjectedTokenAudience = "kubernetes.default"
	_, err := runAgentSandboxCreateSequence(context.Background(), backend, testAgentSandboxCreateSequenceInput())
	if err == nil || !strings.Contains(err.Error(), "ServiceAccount credential boundary") {
		t.Fatalf("runAgentSandboxCreateSequence() error = %v; want projected token audience rejection", err)
	}
	if !backend.sandboxDeleted || containsString(backend.calls, "activate-sandbox-controller") || containsString(backend.calls, "create-bootstrap-secrets") {
		t.Fatalf("supervisor audience mismatch must stop before workload activation: %#v", backend.calls)
	}
}

func TestCompatAgentSandboxCreateSequenceRequiresObservedFenceBeforeCreate(t *testing.T) {
	backend := newFakeAgentSandboxCreateBackend()
	backend.incompleteFence = true
	_, err := runAgentSandboxCreateSequence(context.Background(), backend, testAgentSandboxCreateSequenceInput())
	if err == nil || !strings.Contains(err.Error(), "fence observation") {
		t.Fatalf("runAgentSandboxCreateSequence() error = %v; want incomplete fence evidence", err)
	}
	if !reflect.DeepEqual(backend.calls, []string{"ensure-workspace-isolation", "apply-and-observe-fence"}) || backend.sandboxDeleted {
		t.Fatalf("Create must stop before Sandbox API create when fence is not observed: calls=%#v deleted=%v", backend.calls, backend.sandboxDeleted)
	}
}

func TestCompatAgentSandboxCreateSequenceRejectsCrossDomainSecretKey(t *testing.T) {
	backend := newFakeAgentSandboxCreateBackend()
	input := testAgentSandboxCreateSequenceInput()
	build := input.BuildBootstrapSecrets
	input.BuildBootstrapSecrets = func(identity agentSandboxCreateIdentity) ([]map[string]any, error) {
		secrets, err := build(identity)
		if err != nil {
			return nil, err
		}
		secrets[0]["data"].(map[string]any)[bootstrapSupervisorAuth] = "must-not-leak"
		return secrets, nil
	}
	_, err := runAgentSandboxCreateSequence(context.Background(), backend, input)
	if err == nil || !strings.Contains(err.Error(), "unexpected key") {
		t.Fatalf("runAgentSandboxCreateSequence() error = %v; want trust-domain key rejection", err)
	}
	if !backend.sandboxDeleted || containsString(backend.calls, "create-bootstrap-secrets") || containsString(backend.calls, "release-supervisor-gate") {
		t.Fatalf("invalid Secret must be rejected before create/release, then rolled back: %#v", backend.calls)
	}
}

func TestCompatAgentSandboxCreateSequenceRejectsUnsuspendedResourceBeforeSideEffects(t *testing.T) {
	backend := newFakeAgentSandboxCreateBackend()
	input := testAgentSandboxCreateSequenceInput()
	input.SandboxResource["spec"].(map[string]any)["operatingMode"] = "Running"
	if _, err := runAgentSandboxCreateSequence(context.Background(), backend, input); err == nil || !strings.Contains(err.Error(), "Suspended") {
		t.Fatalf("runAgentSandboxCreateSequence() error = %v; want suspended create validation", err)
	}
	if len(backend.calls) != 0 {
		t.Fatalf("invalid initial resource must be rejected before side effects: %#v", backend.calls)
	}
}

func TestCompatAgentSandboxCreateSequencePreservesRollbackFailure(t *testing.T) {
	backend := newFakeAgentSandboxCreateBackend()
	backend.failAt = "create-gated-supervisor"
	backend.failDelete = true
	_, err := runAgentSandboxCreateSequence(context.Background(), backend, testAgentSandboxCreateSequenceInput())
	if !errors.Is(err, backend.injected) || !errors.Is(err, backend.rollbackErr) {
		t.Fatalf("runAgentSandboxCreateSequence() error = %v; want both provisioning and rollback errors", err)
	}
}

func testAgentSandboxCreateSequenceInput() agentSandboxCreateSequenceInput {
	params := testAgentSandboxRenderParams()
	params.Generation = "gen1"
	resource, err := renderAgentSandboxResource(SandboxDriverConfig{}, params)
	if err != nil {
		panic(err)
	}
	runtimeParams := testAgentSandboxRuntimeRenderParams()
	runtimeParams.Generation = "gen1"
	runtimeParams.SandboxResourceUID = ""
	return agentSandboxCreateSequenceInput{
		SandboxResource: resource,
		RuntimeParams:   runtimeParams,
		BuildBootstrapSecrets: func(identity agentSandboxCreateIdentity) ([]map[string]any, error) {
			return testBootstrapSecretObjects(identity), nil
		},
	}
}

func testBootstrapSecretObjects(identity agentSandboxCreateIdentity) []map[string]any {
	return []map[string]any{
		testBootstrapSecret(generationSecretName("os-sandbox", identity.SandboxID, identity.Generation), identity.Namespace, "workload", identity.WorkloadName, identity.WorkloadUID, map[string]any{
			"boundary.json": "boundary-config",
			"tls.crt":       "boundary-certificate",
			"tls.key":       "boundary-private-key",
		}),
		testBootstrapSecret(generationSecretName("os-supervisor", identity.SandboxID, identity.Generation), identity.Namespace, "supervisor", identity.SupervisorName, identity.SupervisorUID, map[string]any{
			"runtime-descriptor.json": "runtime-descriptor",
			"auth.json":               "supervisor-auth",
			"proxy-ca.crt":            "proxy-ca-certificate",
			"proxy-ca.key":            "proxy-ca-private-key",
		}),
	}
}

func testBootstrapSecret(name, namespace, ownerKind, ownerName, ownerUID string, data map[string]any) map[string]any {
	for key, value := range data {
		text, _ := value.(string)
		data[key] = base64.StdEncoding.EncodeToString([]byte(text))
	}
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
			"ownerReferences": []any{map[string]any{
				"apiVersion":         "v1",
				"kind":               "Pod",
				"name":               ownerName,
				"uid":                ownerUID,
				"blockOwnerDeletion": false,
			}},
		},
		"immutable": true,
		"type":      "Opaque",
		"data":      data,
	}
}

type fakeAgentSandboxCreateBackend struct {
	calls                  []string
	failAt                 string
	failDelete             bool
	incompleteFence        bool
	injected               error
	rollbackErr            error
	sandbox                agentSandboxResourceIdentity
	sandboxID              string
	supervisor             agentSandboxPodIdentity
	workload               agentSandboxWorkloadIdentity
	createdSecrets         []map[string]any
	useRequestedCautemPods bool
	controlService         agentSandboxServiceIdentity
	sandboxDeleted         bool
}

func newFakeAgentSandboxCreateBackend() *fakeAgentSandboxCreateBackend {
	namespace, _ := workspaceNamespaceName("gateway-1", "team-a")
	return &fakeAgentSandboxCreateBackend{
		injected:    errors.New("injected failure"),
		rollbackErr: errors.New("injected rollback failure"),
		sandboxID:   "sandbox-123",
		sandbox: agentSandboxResourceIdentity{
			Namespace: namespace, Name: "team-a-demo", APIVersion: "agents.x-k8s.io/v1beta1", UID: "sandbox-cr-uid", Suspended: true, PodTemplateMatches: true, CreateMetadataMatches: true,
		},
		supervisor: agentSandboxPodIdentity{
			Name: "os-supervisor-sandbox-123", UID: "supervisor-pod-uid", OwnerSandboxUID: "sandbox-cr-uid",
			ServiceAccountName: "sandbox-driver", Image: "registry.example/supervisor:v1", Command: supervisorCommandStrings(),
			BoundaryPair: "sandbox-123", BoundaryRole: "supervisor", BootstrapSecretName: "os-supervisor-sandbox-123-gen1",
			ProjectedTokenAudience: "openshell-gateway", BootstrapGatePresent: true, ServiceAccountAutomountDisabled: true, HasProjectedServiceAccountToken: true,
			HostNamespacesIsolated: true, RunAsNonRoot: true, ReadOnlyRootFilesystem: true, RuntimeDefaultSeccomp: true,
			DropAllCapabilities: true, PrivilegeEscalationDisabled: true,
		},
		workload: agentSandboxWorkloadIdentity{
			Name: "team-a-demo", UID: "workload-pod-uid", OwnerSandboxUID: "sandbox-cr-uid",
			Image: "registry.example/sandbox:v1", Command: []string{sandboxRuntimeMountPath + "/openshell-sandbox", "--bootstrap", sandboxBoundaryConfigPath},
			BoundaryPair: "sandbox-123", BoundaryRole: "workload", SandboxBootstrapSecret: "os-sandbox-sandbox-123-gen1",
			BootstrapGatePresent: true, ServiceAccountAutomountDisabled: true, TrustedInitMountsBootstrapSecret: true,
			SchedulingGatesMatch:  true,
			InitContainerNames:    []string{sandboxBootstrapVolume, workspaceSeedContainerName},
			AgentContainerMatches: true, InitContainerSpecsMatch: true, PodVolumeSourcesMatch: true,
			PodSecurityContextMatches: true, ServiceAccountMatches: true,
			HostNamespacesIsolated: true, RunAsNonRoot: true, RuntimeDefaultSeccomp: true, DropAllCapabilities: true, PrivilegeEscalationDisabled: true,
		},
		controlService: agentSandboxServiceIdentity{
			ClusterIP: "10.96.0.43", OwnerSandboxUID: "sandbox-cr-uid",
			SelectorBoundaryPair: "sandbox-123", SelectorBoundaryRole: "supervisor",
		},
	}
}

func (backend *fakeAgentSandboxCreateBackend) step(name string) error {
	backend.calls = append(backend.calls, name)
	if backend.failAt == name {
		return backend.injected
	}
	return nil
}

func (backend *fakeAgentSandboxCreateBackend) EnsureWorkspaceIsolation(_ context.Context, namespace, gatewayID, workspace string, namespaceResource, denyAllPolicy map[string]any) error {
	if err := backend.step("ensure-workspace-isolation"); err != nil {
		return err
	}
	expectedNamespace, expectedResource, expectedPolicy, err := renderWorkspaceIsolationResources(gatewayID, workspace)
	if err != nil {
		return err
	}
	if namespace != expectedNamespace || !reflect.DeepEqual(namespaceResource, expectedResource) || !reflect.DeepEqual(denyAllPolicy, expectedPolicy) {
		return errors.New("workspace isolation resources do not match trusted identity")
	}
	return nil
}

func (backend *fakeAgentSandboxCreateBackend) ApplyAndObserveRuntimeFence(_ context.Context, _ string, _, _ map[string]any) (agentSandboxFenceEvidence, error) {
	if err := backend.step("apply-and-observe-fence"); err != nil {
		return agentSandboxFenceEvidence{}, err
	}
	evidence := agentSandboxFenceEvidence{PolicyUID: "fence-policy-uid", Generation: 3, ResourceVersion: "45"}
	if backend.incompleteFence {
		evidence.PolicyUID = ""
	}
	return evidence, nil
}

func (backend *fakeAgentSandboxCreateBackend) CreateSuspendedSandbox(_ context.Context, _ map[string]any) (agentSandboxResourceIdentity, error) {
	if err := backend.step("create-suspended-sandbox"); err != nil {
		return agentSandboxResourceIdentity{}, err
	}
	return backend.sandbox, nil
}

func (backend *fakeAgentSandboxCreateBackend) CreateBoundaryService(_ context.Context, _ map[string]any) (agentSandboxServiceIdentity, error) {
	if err := backend.step("create-boundary-service"); err != nil {
		return agentSandboxServiceIdentity{}, err
	}
	return agentSandboxServiceIdentity{
		ClusterIP: "10.96.0.42", OwnerSandboxUID: "sandbox-cr-uid",
		SelectorBoundaryPair: backend.sandboxID, SelectorBoundaryRole: "workload",
	}, nil
}

func (backend *fakeAgentSandboxCreateBackend) CreateSupervisorControlService(_ context.Context, _ map[string]any) (agentSandboxServiceIdentity, error) {
	if err := backend.step("create-supervisor-control-service"); err != nil {
		return agentSandboxServiceIdentity{}, err
	}
	service := backend.controlService
	if service.SelectorBoundaryPair == "sandbox-123" && backend.sandboxID != "sandbox-123" {
		service.SelectorBoundaryPair = backend.sandboxID
	}
	return service, nil
}

func (backend *fakeAgentSandboxCreateBackend) CreateProxyService(_ context.Context, _ map[string]any) (agentSandboxServiceIdentity, error) {
	if err := backend.step("create-proxy-service"); err != nil {
		return agentSandboxServiceIdentity{}, err
	}
	return agentSandboxServiceIdentity{
		ClusterIP: "10.96.0.44", OwnerSandboxUID: "sandbox-cr-uid",
		SelectorBoundaryPair: backend.sandboxID, SelectorBoundaryRole: "supervisor",
	}, nil
}

func (backend *fakeAgentSandboxCreateBackend) CreateGatedSupervisor(_ context.Context, resource map[string]any) (agentSandboxPodIdentity, error) {
	if err := backend.step("create-gated-supervisor"); err != nil {
		return agentSandboxPodIdentity{}, err
	}
	if backend.useRequestedCautemPods {
		metadata, _ := resource["metadata"].(map[string]any)
		metadata["uid"] = "supervisor-pod-uid"
		return supervisorIdentityFromPod(&unstructured.Unstructured{Object: resource}, resource), nil
	}
	return backend.supervisor, nil
}

func (backend *fakeAgentSandboxCreateBackend) ActivateSandboxController(_ context.Context, _, _, _, _ string) error {
	return backend.step("activate-sandbox-controller")
}

func (backend *fakeAgentSandboxCreateBackend) WaitForGatedWorkload(_ context.Context, _, _, _ string, requestedResource map[string]any) (agentSandboxWorkloadIdentity, error) {
	if err := backend.step("wait-for-gated-workload"); err != nil {
		return agentSandboxWorkloadIdentity{}, err
	}
	if backend.useRequestedCautemPods {
		spec, _, _ := unstructured.NestedMap(requestedResource, "spec", "podTemplate", "spec")
		actualSpec := cloneAnyMap(spec)
		actualSpec["volumes"] = sandboxPodVolumesWithClaimTemplates(requestedResource, spec)
		templateMetadata, _, _ := unstructured.NestedMap(requestedResource, "spec", "podTemplate", "metadata")
		pod := &unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{
				"name": backend.sandbox.Name, "namespace": backend.sandbox.Namespace, "uid": "workload-pod-uid",
				"labels":          templateMetadata["labels"],
				"ownerReferences": []any{map[string]any{"kind": "Sandbox", "uid": backend.sandbox.UID}},
			},
			"spec": actualSpec,
		}}
		return workloadIdentityFromPod(pod, requestedResource), nil
	}
	return backend.workload, nil
}

func (backend *fakeAgentSandboxCreateBackend) RecordRuntimePairEvidence(_ context.Context, _ agentSandboxCreateIdentity) error {
	return backend.step("record-pair-evidence")
}

func (backend *fakeAgentSandboxCreateBackend) CreateBootstrapSecrets(_ context.Context, secrets []map[string]any) error {
	backend.createdSecrets = secrets
	return backend.step("create-bootstrap-secrets")
}

func (backend *fakeAgentSandboxCreateBackend) ReleaseSchedulingGate(_ context.Context, _, podName, _ string) error {
	step := "release-workload-gate"
	if strings.HasPrefix(podName, "os-supervisor-") {
		step = "release-supervisor-gate"
	}
	return backend.step(step)
}

func (backend *fakeAgentSandboxCreateBackend) MarkRuntimeReleased(_ context.Context, _, _, _, _ string) error {
	return backend.step("mark-runtime-released")
}

func (backend *fakeAgentSandboxCreateBackend) DeleteSandbox(_ context.Context, _, _, _, _ string) error {
	backend.sandboxDeleted = true
	backend.calls = append(backend.calls, "delete-sandbox")
	if backend.failDelete {
		return backend.rollbackErr
	}
	return nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
