package kubernetes

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	core "github.com/cautem/quarshell-core"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestCautemRuntimeParamsRecoverTrustedRestartSettings(t *testing.T) {
	config := EngineConfig{
		GatewayID: "gateway-1", ProxyImage: "ghcr.io/cautem/proxy@sha256:" + strings.Repeat("a", 64),
		GRPCEndpoint: "gateway.example:7443",
	}
	config.applyDefaults()
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": sandboxAPIGroup + "/" + sandboxAPIVersionV1Beta1,
		"kind":       "Sandbox",
		"metadata": map[string]any{
			"name": "sandbox-1", "namespace": "cautem-ws-123", "uid": "sandbox-uid",
			"labels": map[string]any{
				labelGatewayID: "gateway-1", labelSandboxID: "sandbox-1", labelSandboxName: "sandbox-1", labelSandboxWorkspace: "team-a",
			},
			"annotations": map[string]any{
				annotationRuntimeGeneration: "gen123", annotationCautemGatewayURL: "http://gateway.example:7443",
				annotationCautemGatewayRPC: "gateway.example:7443", annotationCautemGatewayTLS: "false",
			},
		},
	}}
	params, err := cautemRuntimeParamsFromSandbox(object, sandboxAPIVersionV1Beta1, config)
	if err != nil {
		t.Fatalf("cautemRuntimeParamsFromSandbox() error = %v", err)
	}
	if params.SandboxResourceUID != "sandbox-uid" || params.Generation != "gen123" || params.GatewayID != "gateway-1" || params.CautemGatewayTLS {
		t.Fatalf("recovered runtime params = %#v", params)
	}
	annotations := object.Object["metadata"].(map[string]any)["annotations"].(map[string]any)
	annotations[annotationCautemGatewayURL] = "http://127.0.0.1:7443"
	if _, err := cautemRuntimeParamsFromSandbox(object, sandboxAPIVersionV1Beta1, config); err == nil {
		t.Fatal("restart accepted a loopback Gateway endpoint")
	}
}

func TestKubernetesStartWaitsForAlreadyRunningRuntime(t *testing.T) {
	fake := newFakeAgentSandboxCreateDynamicClient()
	namespace := seedWorkspaceNamespace(t, fake, "gateway-1", "team-a")
	workloadUID, supervisorUID, sandboxUID := "workload-uid", "supervisor-uid", "sandbox-uid"
	resource := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": sandboxAPIGroup + "/" + sandboxAPIVersionV1Beta1,
		"kind":       "Sandbox",
		"metadata": map[string]any{
			"name": "demo", "namespace": namespace, "uid": sandboxUID,
			"labels": map[string]any{
				labelManagedBy: managedByValue, labelGatewayID: "gateway-1", labelSandboxID: "demo",
				labelSandboxName: "demo", labelSandboxWorkspace: "team-a",
			},
			"annotations": map[string]any{
				annotationRuntimeBootstrapPhase: "released", annotationRuntimeWorkloadUID: workloadUID,
				annotationRuntimeSupervisorUID: supervisorUID,
			},
		},
		"spec": map[string]any{"operatingMode": "Running"},
	}}
	if err := fake.Tracker().Create(agentSandboxGVR(sandboxAPIVersionV1Beta1), resource, namespace); err != nil {
		t.Fatalf("seed Agent Sandbox: %v", err)
	}
	seedReady := func(name, uid string) {
		t.Helper()
		pod := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{
				"name": name, "namespace": namespace, "uid": uid,
				"ownerReferences": []any{map[string]any{"apiVersion": sandboxAPIGroup + "/" + sandboxAPIVersionV1Beta1, "kind": "Sandbox", "uid": sandboxUID}},
			},
			"status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}},
		}}
		if err := fake.Tracker().Create(coreV1GVR("pods"), pod, namespace); err != nil {
			t.Fatalf("seed ready runtime Pod %s: %v", name, err)
		}
	}
	seedReady("demo", workloadUID)
	seedReady("os-supervisor-demo", supervisorUID)
	d := newWithClient(fake, "gateway-1")
	d.apiVersions.version = sandboxAPIVersionV1Beta1
	id := kubernetesRuntimeID(sandboxRuntimeIdentity{Namespace: namespace, Name: "demo", UID: sandboxUID})
	if err := d.Start(context.Background(), core.ID(id)); err != nil {
		t.Fatalf("Start(already running) error = %v", err)
	}
	for _, action := range fake.Actions() {
		if action.GetVerb() == "patch" || action.GetVerb() == "delete" || action.GetVerb() == "create" {
			t.Fatalf("idempotent Start unexpectedly mutated Kubernetes state: %#v", action)
		}
	}
}

func TestSetSandboxRuntimeGenerationRequiresSuspendedMatchingSandbox(t *testing.T) {
	identity := agentSandboxCreateIdentity{
		Namespace: "cautem-ws-123", SandboxName: "demo", APIVersion: sandboxAPIGroup + "/" + sandboxAPIVersionV1Beta1,
		SandboxUID: "sandbox-uid", SandboxID: "demo", Generation: "gen9",
		WorkloadName: "demo", SupervisorName: "os-supervisor-demo",
	}
	fake := newFakeAgentSandboxCreateDynamicClient()
	resource := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": identity.APIVersion, "kind": "Sandbox",
		"metadata": map[string]any{
			"name": identity.SandboxName, "namespace": identity.Namespace, "uid": identity.SandboxUID,
			"annotations": map[string]any{annotationRuntimeGeneration: identity.Generation},
		},
		"spec": map[string]any{
			"operatingMode": "Suspended",
			"podTemplate": map[string]any{"spec": map[string]any{"volumes": []any{
				map[string]any{"name": cautemWorkloadCredentialName, "secret": map[string]any{"secretName": generationSecretName("os-sandbox", identity.SandboxID, identity.Generation), "defaultMode": int64(0o440)}},
			}}},
		},
	}}
	if err := fake.Tracker().Create(agentSandboxGVR(sandboxAPIVersionV1Beta1), resource, identity.Namespace); err != nil {
		t.Fatalf("seed Agent Sandbox: %v", err)
	}
	backend := newDynamicAgentSandboxCreateBackend(fake)
	updated, err := backend.SetSandboxRuntimeGeneration(context.Background(), identity, "gen10")
	if err != nil {
		t.Fatalf("SetSandboxRuntimeGeneration() error = %v", err)
	}
	if got := updated.GetAnnotations()[annotationRuntimeGeneration]; got != "gen10" {
		t.Fatalf("runtime generation annotation = %q; want gen10", got)
	}
	if err := requireSandboxWorkloadSecretReference(updated, generationSecretName("os-sandbox", identity.SandboxID, "gen10")); err != nil {
		t.Fatalf("updated private Secret reference: %v; object=%#v", err, updated.Object)
	}
	if _, err := backend.SetSandboxRuntimeGeneration(context.Background(), identity, "gen11"); err == nil {
		t.Fatal("generation rotation accepted a stale current generation")
	}
}

func TestReadCautemGenerationSecretsRequiresSandboxOwnedCredentials(t *testing.T) {
	identity := agentSandboxCreateIdentity{
		Namespace: "cautem-ws-123", SandboxName: "demo", APIVersion: sandboxAPIGroup + "/" + sandboxAPIVersionV1Beta1,
		SandboxUID: "sandbox-uid", SandboxID: "sandbox-123", Generation: "gen9",
		WorkloadName: "demo", SupervisorName: "os-supervisor-sandbox-123",
		ServiceIP: "10.96.0.12", ControlServiceIP: "10.96.0.13",
	}
	secrets, err := buildCautemGenerationSecrets(identity, []byte("version: 1\n"), []string{"CAUTEM_SANDBOX_TOKEN=token"})
	if err != nil {
		t.Fatalf("buildCautemRuntimeSecrets() error = %v", err)
	}
	fake := newFakeAgentSandboxCreateDynamicClient()
	seed := func() {
		t.Helper()
		for _, secret := range secrets {
			object := &unstructured.Unstructured{Object: secret}
			if err := fake.Tracker().Create(coreV1GVR("secrets"), object, identity.Namespace); err != nil {
				t.Fatalf("seed Cautem Secret %s: %v", object.GetName(), err)
			}
		}
	}
	seed()
	backend := newDynamicAgentSandboxCreateBackend(fake)
	observed, err := backend.ReadCautemGenerationSecrets(context.Background(), identity)
	if err != nil || len(observed) != 3 {
		t.Fatalf("ReadCautemGenerationSecrets() = %d secrets, %v; want all generation credentials", len(observed), err)
	}
	if err := validateStoredBridgeTLS(observed, identity.SandboxID, identity.Generation); err != nil {
		t.Fatalf("validateStoredBridgeTLS(valid) error = %v", err)
	}
	badCredentials := cloneSecretObjects(observed)
	badCredentials[0]["data"].(map[string]any)[bridgeTargetServerCert] = base64.StdEncoding.EncodeToString([]byte("invalid certificate"))
	if err := validateStoredBridgeTLS(badCredentials, identity.SandboxID, identity.Generation); err == nil {
		t.Fatal("validateStoredBridgeTLS accepted an invalid bridge certificate")
	}

	owner := secrets[0]["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)
	owner["uid"] = "foreign-sandbox-uid"
	fake = newFakeAgentSandboxCreateDynamicClient()
	seed()
	if _, err := newDynamicAgentSandboxCreateBackend(fake).ReadCautemGenerationSecrets(context.Background(), identity); err == nil || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("ReadCautemGenerationSecrets() error = %v; want foreign owner rejection", err)
	}
}

func TestValidateStoredGuestTLSRequiresValidUnexpiredCertificate(t *testing.T) {
	now := time.Now()
	ca, caKey, caPEM, err := newBridgeCA("guest-ca", now)
	if err != nil {
		t.Fatalf("newBridgeCA() error = %v", err)
	}
	cert, key, err := newBridgeLeaf("guest-client", nil, ca, caKey, now, x509.ExtKeyUsageClientAuth)
	if err != nil {
		t.Fatalf("newBridgeLeaf() error = %v", err)
	}
	secret := map[string]any{
		"metadata": map[string]any{"name": generationSecretName("os-supervisor", "sandbox-123", "gen9")},
		"data": map[string]any{
			cautemGatewayTLSCAKey:   base64.StdEncoding.EncodeToString(caPEM),
			cautemGatewayTLSCertKey: base64.StdEncoding.EncodeToString(cert),
			cautemGatewayTLSKeyKey:  base64.StdEncoding.EncodeToString(key),
		},
	}
	if err := validateStoredGuestTLS([]map[string]any{secret}, "sandbox-123", "gen9", true); err != nil {
		t.Fatalf("validateStoredGuestTLS(valid) error = %v", err)
	}
	secret["data"].(map[string]any)[cautemGatewayTLSCertKey] = base64.StdEncoding.EncodeToString([]byte("invalid certificate"))
	if err := validateStoredGuestTLS([]map[string]any{secret}, "sandbox-123", "gen9", true); err == nil {
		t.Fatal("validateStoredGuestTLS accepted an invalid client certificate")
	}
}
