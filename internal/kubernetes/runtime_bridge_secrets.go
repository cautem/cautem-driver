package kubernetes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	bridgeTargetClientCAFile  = "target-client-ca.pem"
	bridgeTargetServerCert    = "target-server.crt"
	bridgeTargetServerKey     = "target-server.key"
	bridgeTargetServerCAFile  = "target-server-ca.pem"
	bridgeTargetClientCert    = "target-client.crt"
	bridgeTargetClientKey     = "target-client.key"
	bridgeControlClientCAFile = "control-client-ca.pem"
	bridgeControlClientCert   = "control-client.crt"
	bridgeControlClientKey    = "control-client.key"
	bridgeControlServerCAFile = "control-server-ca.pem"
	bridgeControlServerCert   = "control-server.crt"
	bridgeControlServerKey    = "control-server.key"
)

const runtimeBridgeCertificateTTL = 90 * 24 * time.Hour

// attachRuntimeBridgeCredentials creates independent control and target mTLS
// trust domains for one sandbox generation and places only each Pod's identity
// and trust anchors in its immutable bootstrap Secret.
func attachRuntimeBridgeCredentials(secrets []map[string]any, identity agentSandboxCreateIdentity) error {
	workloadIP := net.ParseIP(identity.ServiceIP)
	controlIP := net.ParseIP(identity.ControlServiceIP)
	if workloadIP == nil || controlIP == nil {
		return errors.New("runtime bridge credentials require valid workload and supervisor Service IPs")
	}
	now := time.Now()
	targetCA, targetCAKey, targetCAPEM, err := newBridgeCA("cautem-target-"+identity.SandboxID, now)
	if err != nil {
		return err
	}
	controlCA, controlCAKey, controlCAPEM, err := newBridgeCA("cautem-control-"+identity.SandboxID, now)
	if err != nil {
		return err
	}
	targetService := runtimeServiceFQDN("os-boundary-"+strings.ToLower(identity.SandboxID), identity.Namespace)
	controlService := runtimeServiceFQDN("os-supervisor-"+strings.ToLower(identity.SandboxID), identity.Namespace)
	targetServerCert, targetServerKey, err := newBridgeLeafWithDNS("cautem-target-server", workloadIP, []string{targetService}, targetCA, targetCAKey, now, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return err
	}
	targetClientCert, targetClientKey, err := newBridgeLeaf("cautem-target-client", nil, targetCA, targetCAKey, now, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return err
	}
	controlServerCert, controlServerKey, err := newBridgeLeafWithDNS("cautem-control-server", controlIP, []string{controlService}, controlCA, controlCAKey, now, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return err
	}
	controlClientCert, controlClientKey, err := newBridgeLeaf("cautem-control-client", nil, controlCA, controlCAKey, now, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return err
	}

	workloadFiles := encodeSecretFiles(map[string][]byte{
		bridgeTargetClientCAFile:  targetCAPEM,
		bridgeTargetServerCert:    targetServerCert,
		bridgeTargetServerKey:     targetServerKey,
		bridgeControlClientCAFile: controlCAPEM,
		bridgeControlClientCert:   controlClientCert,
		bridgeControlClientKey:    controlClientKey,
	})
	supervisorFiles := encodeSecretFiles(map[string][]byte{
		bridgeTargetServerCAFile:  targetCAPEM,
		bridgeTargetClientCert:    targetClientCert,
		bridgeTargetClientKey:     targetClientKey,
		bridgeControlServerCAFile: controlCAPEM,
		bridgeControlServerCert:   controlServerCert,
		bridgeControlServerKey:    controlServerKey,
	})
	workloadName := generationSecretName("os-sandbox", identity.SandboxID, identity.Generation)
	supervisorName := generationSecretName("os-supervisor", identity.SandboxID, identity.Generation)
	seenWorkload, seenSupervisor := false, false
	for _, secret := range secrets {
		if secret == nil {
			continue
		}
		metadata, _ := secret["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		var files map[string]string
		switch name {
		case workloadName:
			if seenWorkload {
				return errors.New("duplicate workload bootstrap Secret")
			}
			seenWorkload = true
			files = workloadFiles
		case supervisorName:
			if seenSupervisor {
				return errors.New("duplicate supervisor bootstrap Secret")
			}
			seenSupervisor = true
			files = supervisorFiles
		default:
			continue
		}
		data, ok := secret["data"].(map[string]any)
		if !ok {
			return fmt.Errorf("bootstrap Secret %q has no data map", name)
		}
		for key, value := range files {
			if _, exists := data[key]; exists {
				return fmt.Errorf("bootstrap Secret %q already contains runtime bridge key %q", name, key)
			}
			data[key] = value
		}
	}
	if !seenWorkload || !seenSupervisor {
		return errors.New("workload and supervisor bootstrap Secrets are required for runtime bridge credentials")
	}
	return nil
}

func encodeSecretFiles(files map[string][]byte) map[string]string {
	encoded := make(map[string]string, len(files))
	for name, content := range files {
		encoded[name] = base64.StdEncoding.EncodeToString(content)
	}
	return encoded
}

func newBridgeCA(commonName string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate runtime bridge CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate runtime bridge CA serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-2 * time.Minute),
		NotAfter:              now.Add(runtimeBridgeCertificateTTL),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("issue runtime bridge CA: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse runtime bridge CA: %w", err)
	}
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func newBridgeLeaf(commonName string, serviceIP net.IP, ca *x509.Certificate, caKey *ecdsa.PrivateKey, now time.Time, usage x509.ExtKeyUsage) ([]byte, []byte, error) {
	return newBridgeLeafWithDNS(commonName, serviceIP, nil, ca, caKey, now, usage)
}

func newBridgeLeafWithDNS(commonName string, serviceIP net.IP, serviceDNSNames []string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, now time.Time, usage x509.ExtKeyUsage) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate runtime bridge identity key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate runtime bridge identity serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-2 * time.Minute),
		NotAfter:     now.Add(runtimeBridgeCertificateTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     append([]string(nil), serviceDNSNames...),
	}
	if serviceIP != nil {
		template.IPAddresses = []net.IP{serviceIP}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("issue runtime bridge identity: %w", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encode runtime bridge identity key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}), nil
}
