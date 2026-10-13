package kubernetes

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestBuildCautemRuntimeSecretsSeparatesWorkloadAndProxyCredentials(t *testing.T) {
	identity := agentSandboxCreateIdentity{
		Namespace: "cautem-ws-123", SandboxID: "sandbox-123", Generation: "gen9",
		SandboxName: "demo", SandboxUID: "sandbox-uid", APIVersion: "agents.x-k8s.io/v1beta1",
		WorkloadName: "demo", WorkloadUID: "workload-uid",
		SupervisorName: "os-supervisor-sandbox-123", SupervisorUID: "supervisor-uid",
	}
	policy := []byte("version: 1\nallow_rules: []\n")
	secrets, err := buildCautemRuntimeSecrets(identity, policy, []string{
		"CAUTEM_GATEWAY_URL=https://gateway.example:443",
		"CAUTEM_SANDBOX=demo",
		"CAUTEM_SANDBOX_TOKEN=secret-token",
		"CAUTEM_LOG_DIR=/var/log",
		"OPENAI_API_KEY=provider-secret",
	})
	if err != nil {
		t.Fatalf("buildCautemRuntimeSecrets() error = %v", err)
	}
	if len(secrets) != 3 {
		t.Fatalf("secret count = %d; want workload, supervisor and proxy environment Secrets", len(secrets))
	}
	workload := secretData(t, secrets[0])
	supervisor := secretData(t, secrets[1])
	proxyEnv := secretData(t, secrets[2])
	if got := string(decodeSecretValue(t, workload, cautemRuntimePolicyKey)); got != string(policy) {
		t.Fatalf("workload policy = %q; want %q", got, policy)
	}
	if _, exists := workload[cautemProxyTokenKey]; exists {
		t.Fatal("workload Secret contains the proxy bearer token")
	}
	if got := string(decodeSecretValue(t, supervisor, cautemProxyTokenKey)); got != "secret-token\n" {
		t.Fatalf("proxy token file content = %q; want newline terminated token", got)
	}
	if got := string(decodeSecretValue(t, proxyEnv, "OPENAI_API_KEY")); got != "provider-secret" {
		t.Fatalf("proxy credential = %q; want provider secret", got)
	}
	for _, key := range []string{"CAUTEM_SANDBOX_TOKEN", "CAUTEM_GATEWAY_URL", "CAUTEM_SANDBOX", "CAUTEM_LOG_DIR"} {
		if _, exists := proxyEnv[key]; exists {
			t.Errorf("proxy environment Secret contains runtime field %q", key)
		}
	}
	for _, secret := range secrets {
		if secret["immutable"] != true || secret["type"] != "Opaque" {
			t.Errorf("Secret %v is not immutable Opaque", secret)
		}
		metadata := renderMap(t, secret["metadata"], "Secret metadata")
		owners, _ := metadata["ownerReferences"].([]any)
		if len(owners) != 1 {
			t.Fatalf("Secret owner references = %#v; want exactly one Agent Sandbox owner", owners)
		}
		owner := renderMap(t, owners[0], "Secret owner")
		if owner["kind"] != "Sandbox" || owner["uid"] != identity.SandboxUID || owner["blockOwnerDeletion"] != false {
			t.Errorf("Secret owner = %#v; want non-controlling Agent Sandbox owner", owner)
		}
	}
	for _, secret := range secrets {
		metadata := renderMap(t, secret["metadata"], "proxy Secret metadata")
		owner := renderMap(t, metadata["ownerReferences"].([]any)[0], "proxy Secret owner")
		if owner["name"] != identity.SandboxName || owner["uid"] != identity.SandboxUID || owner["apiVersion"] != identity.APIVersion {
			t.Errorf("proxy Secret owner = %#v; want current Agent Sandbox", owner)
		}
	}
}

func TestRotateCautemGenerationSecretsReplacesBearerAndBridgeIdentity(t *testing.T) {
	identity := agentSandboxCreateIdentity{
		Namespace: "cautem-ws-123", SandboxID: "sandbox-123", Generation: "gen9",
		SandboxName: "demo", SandboxUID: "sandbox-uid", APIVersion: "agents.x-k8s.io/v1beta1",
		WorkloadName: "demo", SupervisorName: "os-supervisor-sandbox-123",
		ServiceIP: "10.96.0.12", ControlServiceIP: "10.96.0.13",
	}
	policy := []byte("version: 1\nallow_rules: []\n")
	current, err := buildCautemGenerationSecrets(identity, policy, []string{
		"CAUTEM_SANDBOX_TOKEN=old-bearer", "OPENAI_API_KEY=provider-secret",
	})
	if err != nil {
		t.Fatalf("build current generation: %v", err)
	}
	oldSupervisor := secretData(t, secretByName(t, current, generationSecretName("os-supervisor", identity.SandboxID, identity.Generation)))
	oldCert := decodeSecretValue(t, oldSupervisor, bridgeControlServerCert)

	next := identity
	next.Generation = "gen10"
	rotated, err := rotateCautemGenerationSecrets(current, identity.Generation, next, "new-bearer")
	if err != nil {
		t.Fatalf("rotateCautemGenerationSecrets() error = %v", err)
	}
	if err := validateCautemGenerationSecrets(rotated, next); err != nil {
		t.Fatalf("rotated generation validation: %v", err)
	}
	supervisor := secretData(t, secretByName(t, rotated, generationSecretName("os-supervisor", next.SandboxID, next.Generation)))
	if got := string(decodeSecretValue(t, supervisor, cautemProxyTokenKey)); got != "new-bearer\n" {
		t.Fatalf("rotated bearer = %q; want new bearer", got)
	}
	if got := string(decodeSecretValue(t, supervisor, bridgeControlServerCert)); got == string(oldCert) {
		t.Fatal("rotated bridge server certificate reused the old generation")
	}
	providerEnv := secretData(t, secretByName(t, rotated, generationSecretName(proxyEnvSecretPrefix, next.SandboxID, next.Generation)))
	if got := string(decodeSecretValue(t, providerEnv, "OPENAI_API_KEY")); got != "provider-secret" {
		t.Fatalf("provider credential after rotation = %q; want preserved value", got)
	}
	for _, secret := range rotated {
		if strings.Contains(fmt.Sprint(secret), "old-bearer") {
			t.Fatal("rotated generation still contains the old bearer")
		}
	}
}

func TestRotateCautemGenerationSecretsUpdatesPolicyAndPreservesBearer(t *testing.T) {
	identity := agentSandboxCreateIdentity{
		Namespace: "cautem-ws-123", SandboxID: "sandbox-123", Generation: "gen9",
		SandboxName: "demo", SandboxUID: "sandbox-uid", APIVersion: "agents.x-k8s.io/v1beta1",
		WorkloadName: "demo", SupervisorName: "os-supervisor-sandbox-123",
		ServiceIP: "10.96.0.12", ControlServiceIP: "10.96.0.13",
	}
	currentPolicy := []byte("# cautem-policy-revision: 1\nversion: 1\nallow_rules: []\n")
	updatedPolicy := []byte("# cautem-policy-revision: 2\nversion: 1\nallow_rules: []\ndeny_rules: []\n")
	current, err := buildCautemGenerationSecrets(identity, currentPolicy, []string{
		"CAUTEM_SANDBOX_TOKEN=current-bearer", "OPENAI_API_KEY=provider-secret",
	})
	if err != nil {
		t.Fatalf("build current generation: %v", err)
	}

	next := identity
	next.Generation = "gen10"
	updated, err := rotateCautemGenerationSecretsWithPolicy(current, identity.Generation, next, "current-bearer", updatedPolicy)
	if err != nil {
		t.Fatalf("rotateCautemGenerationSecretsWithPolicy() error = %v", err)
	}
	if err := validateCautemGenerationSecrets(updated, next); err != nil {
		t.Fatalf("updated generation validation: %v", err)
	}
	for _, secretName := range []string{
		generationSecretName("os-sandbox", next.SandboxID, next.Generation),
		generationSecretName("os-supervisor", next.SandboxID, next.Generation),
	} {
		secret := secretByName(t, updated, secretName)
		data := secretData(t, secret)
		if got := decodeSecretValue(t, data, cautemRuntimePolicyKey); string(got) != string(updatedPolicy) {
			t.Errorf("%s policy = %q; want %q", secretName, got, updatedPolicy)
		}
	}
	supervisor := secretData(t, secretByName(t, updated, generationSecretName("os-supervisor", next.SandboxID, next.Generation)))
	if got := string(decodeSecretValue(t, supervisor, cautemProxyTokenKey)); got != "current-bearer\n" {
		t.Fatalf("policy update changed the sandbox bearer: %q", got)
	}
	providerEnv := secretData(t, secretByName(t, updated, generationSecretName(proxyEnvSecretPrefix, next.SandboxID, next.Generation)))
	if got := string(decodeSecretValue(t, providerEnv, "OPENAI_API_KEY")); got != "provider-secret" {
		t.Fatalf("provider credential after policy update = %q; want preserved value", got)
	}
}

func TestBuildCautemRuntimeSecretsRejectsUnsafeInputs(t *testing.T) {
	identity := agentSandboxCreateIdentity{
		Namespace: "cautem-ws-123", SandboxID: "sandbox-123", Generation: "gen9",
		SandboxName: "demo", SandboxUID: "sandbox-uid", APIVersion: "agents.x-k8s.io/v1beta1",
		WorkloadName: "demo", WorkloadUID: "workload-uid",
		SupervisorName: "os-supervisor-sandbox-123", SupervisorUID: "supervisor-uid",
	}
	tests := []struct {
		name     string
		policy   []byte
		proxyEnv []string
	}{
		{name: "empty policy", proxyEnv: []string{"CAUTEM_SANDBOX_TOKEN=token"}},
		{name: "missing token", policy: []byte("version: 1\n"), proxyEnv: []string{"OPENAI_API_KEY=secret"}},
		{name: "empty token", policy: []byte("version: 1\n"), proxyEnv: []string{"CAUTEM_SANDBOX_TOKEN= "}},
		{name: "duplicate runtime key", policy: []byte("version: 1\n"), proxyEnv: []string{"CAUTEM_SANDBOX=demo", "CAUTEM_SANDBOX=other", "CAUTEM_SANDBOX_TOKEN=token"}},
		{name: "token file override", policy: []byte("version: 1\n"), proxyEnv: []string{"CAUTEM_SANDBOX_TOKEN=token", "CAUTEM_SANDBOX_TOKEN_FILE=/tmp/token"}},
		{name: "bridge setting override", policy: []byte("version: 1\n"), proxyEnv: []string{"CAUTEM_SANDBOX_TOKEN=token", "CAUTEM_RELAY_TARGET_LISTEN=0.0.0.0:1"}},
		{name: "invalid env key", policy: []byte("version: 1\n"), proxyEnv: []string{"BAD.KEY=value", "CAUTEM_SANDBOX_TOKEN=token"}},
		{name: "NUL in env value", policy: []byte("version: 1\n"), proxyEnv: []string{"OPENAI_API_KEY=secret\x00value", "CAUTEM_SANDBOX_TOKEN=token"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := buildCautemRuntimeSecrets(identity, test.policy, test.proxyEnv); err == nil {
				t.Fatal("buildCautemRuntimeSecrets() succeeded; want rejection")
			}
		})
	}

	tooLarge := make([]byte, maxRuntimePolicyBytes+1)
	if _, err := buildCautemRuntimeSecrets(identity, tooLarge, []string{"CAUTEM_SANDBOX_TOKEN=token"}); err == nil {
		t.Fatal("buildCautemRuntimeSecrets() accepted an oversized policy")
	}
	tooLargeEnv := "OPENAI_API_KEY=" + strings.Repeat("x", maxKubernetesSecretBytes+1)
	if _, err := buildCautemRuntimeSecrets(identity, []byte("version: 1\n"), []string{"CAUTEM_SANDBOX_TOKEN=token", tooLargeEnv}); err == nil {
		t.Fatal("buildCautemRuntimeSecrets() accepted an oversized proxy environment Secret")
	}
	identity.Generation = "---"
	if _, err := buildCautemRuntimeSecrets(identity, []byte("version: 1\n"), []string{"CAUTEM_SANDBOX_TOKEN=token"}); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("buildCautemRuntimeSecrets() error = %v; want invalid generation", err)
	}
}

func TestBuildCautemGenerationSecretsAddsAndValidatesBridgeCredentials(t *testing.T) {
	identity := agentSandboxCreateIdentity{
		Namespace: "cautem-ws-123", SandboxID: "sandbox-123", Generation: "gen9",
		SandboxName: "demo", SandboxUID: "sandbox-uid", APIVersion: "agents.x-k8s.io/v1beta1",
		WorkloadName: "demo", WorkloadUID: "workload-uid",
		SupervisorName: "os-supervisor-sandbox-123", SupervisorUID: "supervisor-uid",
		ServiceIP: "10.96.0.12", ControlServiceIP: "10.96.0.13",
	}
	secrets, err := buildCautemGenerationSecrets(identity, []byte("version: 1\nallow_rules: []\n"), []string{
		"CAUTEM_SANDBOX_TOKEN=token",
		"OPENAI_API_KEY=provider-secret",
	})
	if err != nil {
		t.Fatalf("buildCautemGenerationSecrets() error = %v", err)
	}
	if len(secrets) != 3 {
		t.Fatalf("secret count = %d; want three", len(secrets))
	}
	workloadData := secretData(t, secrets[0])
	if _, exists := workloadData[bridgeTargetServerKey]; !exists {
		t.Fatal("workload Secret is missing its target listener identity")
	}
	if _, exists := workloadData[bridgeControlClientKey]; !exists {
		t.Fatal("workload Secret is missing its control client identity")
	}
	supervisorData := secretData(t, secrets[1])
	if _, exists := supervisorData[bridgeControlServerKey]; !exists {
		t.Fatal("supervisor Secret is missing its control server identity")
	}
	if _, exists := supervisorData[bridgeTargetClientKey]; !exists {
		t.Fatal("supervisor Secret is missing its target client identity")
	}
	if err := validateCautemGenerationSecrets(secrets, identity); err != nil {
		t.Fatalf("validateCautemGenerationSecrets() error = %v", err)
	}

	bad := cloneSecretObjects(secrets)
	bad[2]["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)["uid"] = "stale-supervisor-uid"
	if err := validateCautemGenerationSecrets(bad, identity); err == nil || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("validateCautemGenerationSecrets() error = %v; want stale owner rejection", err)
	}

	bad = cloneSecretObjects(secrets)
	bad[0]["data"].(map[string]any)["OPENAI_API_KEY"] = base64.StdEncoding.EncodeToString([]byte("must-stay-in-proxy"))
	if err := validateCautemGenerationSecrets(bad, identity); err == nil || !strings.Contains(err.Error(), "unexpected key") {
		t.Fatalf("validateCautemGenerationSecrets() error = %v; want workload credential rejection", err)
	}

	bad = cloneSecretObjects(secrets)
	bad[2]["data"].(map[string]any)["CAUTEM_SANDBOX_TOKEN"] = base64.StdEncoding.EncodeToString([]byte("must-stay-in-file"))
	if err := validateCautemGenerationSecrets(bad, identity); err == nil || !strings.Contains(err.Error(), "managed") {
		t.Fatalf("validateCautemGenerationSecrets() error = %v; want managed credential rejection", err)
	}
}

func cloneSecretObjects(secrets []map[string]any) []map[string]any {
	cloned := make([]map[string]any, len(secrets))
	for i, secret := range secrets {
		cloned[i] = make(map[string]any, len(secret))
		for key, value := range secret {
			cloned[i][key] = value
		}
		metadata := make(map[string]any)
		for key, value := range secret["metadata"].(map[string]any) {
			metadata[key] = value
		}
		data := make(map[string]any)
		for key, value := range secret["data"].(map[string]any) {
			data[key] = value
		}
		cloned[i]["data"] = data
		owners := secret["metadata"].(map[string]any)["ownerReferences"].([]any)
		owner := make(map[string]any)
		for key, value := range owners[0].(map[string]any) {
			owner[key] = value
		}
		metadata["ownerReferences"] = []any{owner}
		cloned[i]["metadata"] = metadata
	}
	return cloned
}

func secretData(t *testing.T, secret map[string]any) map[string]any {
	t.Helper()
	data, ok := secret["data"].(map[string]any)
	if !ok {
		t.Fatalf("Secret data has type %T; want map", secret["data"])
	}
	return data
}

func decodeSecretValue(t *testing.T, data map[string]any, key string) []byte {
	t.Helper()
	encoded, ok := data[key].(string)
	if !ok {
		t.Fatalf("Secret value %q has type %T; want base64 string", key, data[key])
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode Secret value %q: %v", key, err)
	}
	return decoded
}
