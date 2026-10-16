package docker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cautem/quarshell-driver/driver"
)

func TestDockerEngineUsesMutualTLSFromEnvironment(t *testing.T) {
	ca, serverCert, clientCert := tlsEngineCertificates(t)
	clientCA := x509.NewCertPool()
	clientCA.AddCert(ca)
	var sawClientCertificate atomic.Bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/containers/json") {
			t.Errorf("unexpected Docker API request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 || r.TLS.PeerCertificates[0].Subject.CommonName != "cautem-docker-client" {
			t.Errorf("Docker client certificate = %#v", r.TLS)
		} else {
			sawClientCertificate.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCA,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	certDir := t.TempDir()
	writePEMFile(t, filepath.Join(certDir, "ca.pem"), "CERTIFICATE", ca.Raw)
	writePEMFile(t, filepath.Join(certDir, "cert.pem"), "CERTIFICATE", clientCert.Certificate[0])
	clientKey, err := x509.MarshalPKCS8PrivateKey(clientCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEMFile(t, filepath.Join(certDir, "key.pem"), "PRIVATE KEY", clientKey)

	address := server.Listener.Addr().(*net.TCPAddr)
	t.Setenv("DOCKER_HOST", "tcp://"+net.JoinHostPort("127.0.0.1", fmt.Sprint(address.Port)))
	t.Setenv("DOCKER_TLS_VERIFY", "1")
	t.Setenv("DOCKER_CERT_PATH", certDir)
	t.Setenv("DOCKER_API_VERSION", "1.41")

	engine, err := driver.OpenEngineWithConfig("docker", nil)
	if err != nil {
		t.Fatalf("open Docker Engine from TLS environment: %v", err)
	}
	items, err := engine.List(context.Background())
	if err != nil {
		t.Fatalf("list sandboxes over mutual TLS: %v", err)
	}
	if len(items) != 0 || !sawClientCertificate.Load() {
		t.Fatalf("list=%v; server saw client certificate=%v", items, sawClientCertificate.Load())
	}
}

func tlsEngineCertificates(t *testing.T) (*x509.Certificate, tls.Certificate, tls.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cautem-docker-test-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	makeCert := func(serial int64, commonName string, usage x509.ExtKeyUsage, ips []net.IP) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: commonName},
			NotBefore:    now.Add(-time.Minute),
			NotAfter:     now.Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			DNSNames:     []string{"localhost"},
			IPAddresses:  ips,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}
	}
	serverCert := makeCert(2, "cautem-docker-server", x509.ExtKeyUsageServerAuth, []net.IP{net.ParseIP("127.0.0.1")})
	clientCert := makeCert(3, "cautem-docker-client", x509.ExtKeyUsageClientAuth, nil)
	return ca, serverCert, clientCert
}

func writePEMFile(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	body := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
