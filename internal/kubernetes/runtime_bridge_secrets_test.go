package kubernetes

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestAttachRuntimeBridgeCredentialsSeparatesTrustDomainsAndPodIdentities(t *testing.T) {
	identity := agentSandboxCreateIdentity{
		Namespace: "team-a", SandboxID: "sandbox-123", Generation: "gen9",
		ServiceIP: "10.96.0.42", ControlServiceIP: "10.96.0.43",
		WorkloadName: "team-a-demo", WorkloadUID: "workload-uid",
		SupervisorName: "os-supervisor-sandbox-123", SupervisorUID: "supervisor-uid",
	}
	secrets := testBootstrapSecretObjects(identity)
	if err := attachRuntimeBridgeCredentials(secrets, identity); err != nil {
		t.Fatal(err)
	}
	if err := validateGenerationBootstrapSecrets(secrets, identity); err != nil {
		t.Fatalf("validateGenerationBootstrapSecrets() error = %v", err)
	}
	workload := secretByName(t, secrets, generationSecretName("os-sandbox", identity.SandboxID, identity.Generation))
	supervisor := secretByName(t, secrets, generationSecretName("os-supervisor", identity.SandboxID, identity.Generation))
	targetRoots := newRoots(t, secretBytes(t, supervisor, bridgeTargetServerCAFile))
	controlRoots := newRoots(t, secretBytes(t, workload, bridgeControlClientCAFile))

	targetServer := loadSecretIdentity(t, workload, bridgeTargetServerCert, bridgeTargetServerKey)
	verifySecretIdentity(t, targetServer, targetRoots, "10.96.0.42", x509.ExtKeyUsageServerAuth)
	verifySecretIdentity(t, targetServer, targetRoots, runtimeServiceFQDN("os-boundary-"+identity.SandboxID, identity.Namespace), x509.ExtKeyUsageServerAuth)
	controlServer := loadSecretIdentity(t, supervisor, bridgeControlServerCert, bridgeControlServerKey)
	verifySecretIdentity(t, controlServer, controlRoots, "10.96.0.43", x509.ExtKeyUsageServerAuth)
	verifySecretIdentity(t, controlServer, controlRoots, runtimeServiceFQDN("os-supervisor-"+identity.SandboxID, identity.Namespace), x509.ExtKeyUsageServerAuth)
	targetClient := loadSecretIdentity(t, supervisor, bridgeTargetClientCert, bridgeTargetClientKey)
	verifySecretIdentity(t, targetClient, targetRoots, "", x509.ExtKeyUsageClientAuth)
	controlClient := loadSecretIdentity(t, workload, bridgeControlClientCert, bridgeControlClientKey)
	verifySecretIdentity(t, controlClient, controlRoots, "", x509.ExtKeyUsageClientAuth)

	if _, err := targetClient.Leaf.Verify(x509.VerifyOptions{Roots: controlRoots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("target client certificate unexpectedly chains to lifecycle control CA")
	}
	for _, secret := range secrets {
		data := secret["data"].(map[string]any)
		for _, key := range []string{"target-ca.key", "control-ca.key", "target-ca-private.key", "control-ca-private.key"} {
			if _, exists := data[key]; exists {
				t.Fatalf("bootstrap Secret contains a bridge CA private key %q", key)
			}
		}
	}
}

func TestAttachRuntimeBridgeCredentialsRequiresBothServiceIPs(t *testing.T) {
	identity := agentSandboxCreateIdentity{
		Namespace: "team-a", SandboxID: "sandbox-123", Generation: "gen9",
		ServiceIP: "10.96.0.42", ControlServiceIP: "not-an-ip",
		WorkloadName: "team-a-demo", WorkloadUID: "workload-uid",
		SupervisorName: "os-supervisor-sandbox-123", SupervisorUID: "supervisor-uid",
	}
	if err := attachRuntimeBridgeCredentials(testBootstrapSecretObjects(identity), identity); err == nil {
		t.Fatal("invalid control Service IP was accepted")
	}
}

func TestRuntimeBridgeCertificatesNeedRefreshBeforeExpiry(t *testing.T) {
	identity := agentSandboxCreateIdentity{
		Namespace: "cautem-ws-123", SandboxID: "sandbox-123", Generation: "gen9",
		SandboxName: "demo", SandboxUID: "sandbox-uid", APIVersion: "agents.x-k8s.io/v1beta1",
		ServiceIP: "10.96.0.12", ControlServiceIP: "10.96.0.13",
		WorkloadName: "demo", SupervisorName: "os-supervisor-sandbox-123",
	}
	secrets, err := buildCautemGenerationSecrets(identity, []byte("version: 1\n"), []string{"CAUTEM_SANDBOX_TOKEN=bearer"})
	if err != nil {
		t.Fatalf("build Cautem runtime generation: %v", err)
	}
	now := time.Now()
	needsRefresh, err := runtimeBridgeCertificatesNeedRefresh(secrets, identity, now, 30*24*time.Hour)
	if err != nil || needsRefresh {
		t.Fatalf("fresh bridge certificates need refresh = %v, error = %v", needsRefresh, err)
	}
	needsRefresh, err = runtimeBridgeCertificatesNeedRefresh(secrets, identity, now.Add(61*24*time.Hour), 30*24*time.Hour)
	if err != nil || !needsRefresh {
		t.Fatalf("bridge certificates inside refresh window need refresh = %v, error = %v", needsRefresh, err)
	}
	if _, err := runtimeBridgeCertificatesNeedRefresh(secrets, identity, now, 0); err == nil {
		t.Fatal("zero refresh window was accepted")
	}
}

func TestValidateGenerationBootstrapSecretsRejectsInvalidBase64(t *testing.T) {
	identity := agentSandboxCreateIdentity{
		Namespace: "team-a", SandboxID: "sandbox-123", Generation: "gen9",
		ServiceIP: "10.96.0.42", ControlServiceIP: "10.96.0.43",
		WorkloadName: "team-a-demo", WorkloadUID: "workload-uid",
		SupervisorName: "os-supervisor-sandbox-123", SupervisorUID: "supervisor-uid",
	}
	secrets := testBootstrapSecretObjects(identity)
	if err := attachRuntimeBridgeCredentials(secrets, identity); err != nil {
		t.Fatal(err)
	}
	workload := secretByName(t, secrets, generationSecretName("os-sandbox", identity.SandboxID, identity.Generation))
	workload["data"].(map[string]any)[bridgeControlClientKey] = "invalid-base64!"
	if err := validateGenerationBootstrapSecrets(secrets, identity); err == nil || !strings.Contains(err.Error(), "base64") {
		t.Fatalf("validateGenerationBootstrapSecrets() error = %v; want invalid base64 rejection", err)
	}
}

func secretByName(t *testing.T, secrets []map[string]any, name string) map[string]any {
	t.Helper()
	for _, secret := range secrets {
		metadata, _ := secret["metadata"].(map[string]any)
		if metadata["name"] == name {
			return secret
		}
	}
	t.Fatalf("Secret %q not found", name)
	return nil
}

func secretBytes(t *testing.T, secret map[string]any, key string) []byte {
	t.Helper()
	data := secret["data"].(map[string]any)
	encoded, ok := data[key].(string)
	if !ok {
		t.Fatalf("Secret data %q has type %T", key, data[key])
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode Secret data %q: %v", key, err)
	}
	return decoded
}

func newRoots(t *testing.T, pemData []byte) *x509.CertPool {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemData) {
		t.Fatal("CA Secret does not contain a certificate")
	}
	return roots
}

func loadSecretIdentity(t *testing.T, secret map[string]any, certKey, privateKey string) tls.Certificate {
	t.Helper()
	identity, err := tls.X509KeyPair(secretBytes(t, secret, certKey), secretBytes(t, secret, privateKey))
	if err != nil {
		t.Fatalf("load Secret identity %s/%s: %v", certKey, privateKey, err)
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	identity.Leaf = leaf
	return identity
}

func verifySecretIdentity(t *testing.T, identity tls.Certificate, roots *x509.CertPool, serviceIP string, usage x509.ExtKeyUsage) {
	t.Helper()
	_, err := identity.Leaf.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: serviceIP, KeyUsages: []x509.ExtKeyUsage{usage},
	})
	if err != nil {
		t.Fatalf("verify %s certificate for service IP %q: %v", usage, serviceIP, err)
	}
}
