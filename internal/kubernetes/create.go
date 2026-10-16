package kubernetes

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	core "github.com/cautem/quarshell-core"
	"github.com/cautem/quarshell-driver/driver"
	"k8s.io/apimachinery/pkg/util/validation"
)

func (d *Driver) create(ctx context.Context, spec driver.Spec) (driver.Handle, error) {
	if ctx == nil {
		return driver.Handle{}, fmt.Errorf("kubernetes Create context is nil")
	}
	if d == nil {
		return driver.Handle{}, fmt.Errorf("kubernetes driver is nil")
	}
	driverConfig, err := ParseSandboxDriverConfig(spec.DriverConfigJSON)
	if err != nil {
		return driver.Handle{}, err
	}
	restartPolicy, err := driver.NormalizeMainProcessRestartPolicy(spec.MainProcessRestartPolicy)
	if err != nil {
		return driver.Handle{}, fmt.Errorf("kubernetes driver: %w", err)
	}
	if err := d.runtimeConfig.Validate(); err != nil {
		return driver.Handle{}, err
	}
	if d.gatewayID == "" || d.gatewayID != d.runtimeConfig.GatewayID {
		return driver.Handle{}, fmt.Errorf("kubernetes driver Gateway ID is missing or inconsistent")
	}
	workspace := strings.TrimSpace(spec.Labels[driver.WorkspaceLabel])
	if workspace == "" || len(validation.IsValidLabelValue(workspace)) != 0 {
		return driver.Handle{}, fmt.Errorf("kubernetes sandbox requires a trusted workspace label")
	}
	if spec.GatewayID != "" && spec.GatewayID != d.gatewayID {
		return driver.Handle{}, fmt.Errorf("kubernetes sandbox Gateway ID does not match this driver")
	}
	if spec.Labels[driver.GatewayIDLabel] != d.gatewayID {
		return driver.Handle{}, fmt.Errorf("kubernetes sandbox requires a trusted Gateway ID label")
	}
	if err := requireDNS1123Label("sandbox name", spec.Name); err != nil {
		return driver.Handle{}, err
	}
	if len(spec.Name) > 63 || len(validation.IsValidLabelValue(spec.Name)) != 0 {
		return driver.Handle{}, fmt.Errorf("sandbox name must fit a Kubernetes label value")
	}
	image := strings.TrimSpace(spec.Image)
	if image == "" {
		image = d.runtimeConfig.DefaultImage
	}
	if image == "" {
		return driver.Handle{}, fmt.Errorf("kubernetes sandbox image is required")
	}
	policy, err := readKubernetesSandboxPolicy(spec.PolicyPath)
	if err != nil {
		return driver.Handle{}, err
	}
	gatewayURL, gatewayGRPCEndpoint, err := resolveKubernetesGatewayEndpoint(spec.GatewayURL, d.runtimeConfig.GRPCEndpoint)
	if err != nil {
		return driver.Handle{}, err
	}
	guestTLS, err := readKubernetesGuestTLS(d.runtimeConfig)
	if err != nil {
		return driver.Handle{}, err
	}
	parsedGatewayURL, _ := url.Parse(gatewayURL)
	if (parsedGatewayURL.Scheme == "https") != (guestTLS != nil) {
		return driver.Handle{}, fmt.Errorf("kubernetes guest TLS files must be configured exactly when the Gateway endpoint uses HTTPS")
	}
	proxyEnv := append([]string(nil), spec.ProxyEnv...)
	if err := requireProxyEnvironmentValue(proxyEnv, "CAUTEM_GATEWAY_URL", gatewayURL); err != nil {
		return driver.Handle{}, err
	}
	if err := requireProxyEnvironmentValue(proxyEnv, "CAUTEM_SANDBOX", spec.Name); err != nil {
		return driver.Handle{}, err
	}
	namespace, _, _, err := renderWorkspaceIsolationResources(d.gatewayID, workspace)
	if err != nil {
		return driver.Handle{}, err
	}
	client, err := d.kubernetesClient()
	if err != nil {
		return driver.Handle{}, err
	}
	version, err := d.apiVersions.Resolve(ctx, newDynamicAgentSandboxAPIClient(client), namespace)
	if err != nil {
		return driver.Handle{}, fmt.Errorf("discover Agent Sandbox API for workspace %q: %w", workspace, err)
	}
	generation, err := newRuntimeGeneration()
	if err != nil {
		return driver.Handle{}, err
	}
	sandboxID := strings.ToLower(spec.Name)
	renderParams := agentSandboxRenderParams{
		APIVersion: version, Namespace: namespace, ResourceName: spec.Name,
		SandboxID: sandboxID, SandboxName: spec.Name, Workspace: workspace, GatewayID: d.gatewayID,
		Generation: generation, Image: image, ImagePullPolicy: "IfNotPresent",
		SandboxRuntimeImage:           d.runtimeConfig.SandboxRuntimeImage,
		SandboxRuntimeImagePullPolicy: d.runtimeConfig.SandboxRuntimeImagePullPolicy,
		SandboxBootstrapSecretName:    generationSecretName("os-sandbox", sandboxID, generation),
		ServiceAccountName:            d.runtimeConfig.ServiceAccountName, ImagePullSecrets: d.runtimeConfig.ImagePullSecrets,
		SandboxUID: d.runtimeConfig.SandboxUID, SandboxGID: d.runtimeConfig.SandboxGID,
		BoundaryPort: d.runtimeConfig.BoundaryPort, EnableUserNamespaces: d.runtimeConfig.EnableUserNamespaces,
		DefaultRuntimeClassName: d.runtimeConfig.DefaultRuntimeClassName,
		WorkspaceStorageSize:    d.runtimeConfig.WorkspaceStorageSize,
		WorkspaceStorageClass:   d.runtimeConfig.WorkspaceStorageClass, GPU: spec.GPU, GPUCount: spec.GPUCount,
	}
	resource, err := renderCautemAgentSandboxResource(driverConfig, cautemWorkloadRenderParams{
		Base: renderParams, Command: append([]string(nil), spec.Command...), Env: append([]string(nil), spec.Env...),
		RestartPolicy: restartPolicy,
		BoundaryPort:  renderParams.BoundaryPort,
	})
	if err != nil {
		return driver.Handle{}, err
	}
	metadata := resource["metadata"].(map[string]any)
	annotations := metadata["annotations"].(map[string]any)
	annotations[annotationCautemGatewayURL] = gatewayURL
	annotations[annotationCautemGatewayRPC] = gatewayGRPCEndpoint
	annotations[annotationCautemGatewayTLS] = fmt.Sprint(guestTLS != nil)
	runtimeParams := agentSandboxRuntimeRenderParams{
		Namespace: namespace, SandboxResourceName: spec.Name, SandboxResourceAPIVersion: sandboxAPIGroup + "/" + version,
		SandboxID: sandboxID, SandboxName: spec.Name, Workspace: workspace, GatewayID: d.gatewayID,
		Generation: generation, CautemProxyImage: d.runtimeConfig.ProxyImage,
		CautemProxyImagePullPolicy: d.runtimeConfig.ProxyImagePullPolicy,
		CautemGatewayURL:           gatewayURL, CautemGatewayGRPCEndpoint: gatewayGRPCEndpoint,
		CautemGatewayTLS:   guestTLS != nil,
		ServiceAccountName: d.runtimeConfig.ServiceAccountName, ImagePullSecrets: d.runtimeConfig.ImagePullSecrets,
		ControlUID: d.runtimeConfig.ControlUID, ControlGID: d.runtimeConfig.ControlGID, BoundaryPort: d.runtimeConfig.BoundaryPort,
	}
	backend := d.createBackend
	if backend == nil {
		backend = newDynamicAgentSandboxCreateBackend(client)
	}
	identity, err := runAgentSandboxCreateSequence(ctx, backend, agentSandboxCreateSequenceInput{
		SandboxResource: resource,
		RuntimeParams:   runtimeParams,
		BuildCautemSecrets: func(identity agentSandboxCreateIdentity) ([]map[string]any, error) {
			return buildCautemGenerationSecretsWithGuestTLS(identity, policy, proxyEnv, guestTLS)
		},
	})
	if err != nil {
		return driver.Handle{}, err
	}
	runtimeID := kubernetesRuntimeID(sandboxRuntimeIdentity{Namespace: identity.Namespace, Name: identity.SandboxName, UID: identity.SandboxUID})
	return driver.Handle{ID: core.ID(runtimeID), Name: spec.Name, Network: namespace, Image: image}, nil
}

func readKubernetesSandboxPolicy(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("kubernetes sandbox policy path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read Kubernetes sandbox policy metadata: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maxRuntimePolicyBytes {
		return nil, fmt.Errorf("kubernetes sandbox policy must be a regular file between 1 byte and %d bytes", maxRuntimePolicyBytes)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Kubernetes sandbox policy: %w", err)
	}
	if len(content) == 0 || len(content) > maxRuntimePolicyBytes {
		return nil, fmt.Errorf("kubernetes sandbox policy must contain between 1 byte and %d bytes", maxRuntimePolicyBytes)
	}
	return content, nil
}

func readKubernetesGuestTLS(config EngineConfig) (*guestTLSMaterial, error) {
	if config.GuestTLSCA == "" && config.GuestTLSCert == "" && config.GuestTLSKey == "" {
		return nil, nil
	}
	read := func(label, path string) ([]byte, error) {
		if path == "" || !filepath.IsAbs(path) {
			return nil, fmt.Errorf("kubernetes guest TLS %s path must be absolute", label)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("read Kubernetes guest TLS %s metadata: %w", label, err)
		}
		const maxTLSFileBytes = 256 << 10
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maxTLSFileBytes {
			return nil, fmt.Errorf("kubernetes guest TLS %s must be a regular file between 1 byte and %d bytes", label, maxTLSFileBytes)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read Kubernetes guest TLS %s: %w", label, err)
		}
		if len(content) == 0 || len(content) > maxTLSFileBytes {
			return nil, fmt.Errorf("kubernetes guest TLS %s has an invalid size", label)
		}
		return content, nil
	}
	ca, err := read("CA", config.GuestTLSCA)
	if err != nil {
		return nil, err
	}
	cert, err := read("certificate", config.GuestTLSCert)
	if err != nil {
		return nil, err
	}
	key, err := read("key", config.GuestTLSKey)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("kubernetes guest TLS CA file contains no certificates")
	}
	if _, err := tls.X509KeyPair(cert, key); err != nil {
		return nil, fmt.Errorf("kubernetes guest TLS certificate and key do not match: %w", err)
	}
	return &guestTLSMaterial{CA: ca, Cert: cert, Key: key}, nil
}

func resolveKubernetesGatewayEndpoint(requested, configured string) (string, string, error) {
	raw := strings.TrimSpace(requested)
	if raw == "" {
		raw = strings.TrimSpace(configured)
	}
	if raw == "" {
		return "", "", fmt.Errorf("kubernetes compute driver requires a reachable Gateway gRPC endpoint")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", "", fmt.Errorf("kubernetes Gateway gRPC endpoint must be an absolute HTTP(S) endpoint")
	}
	if _, _, err := net.SplitHostPort(parsed.Host); err != nil {
		return "", "", fmt.Errorf("kubernetes Gateway gRPC endpoint requires an explicit port")
	}
	endpoint := parsed.Host
	gatewayURL := strings.TrimRight(parsed.String(), "/")
	if err := validateCautemGatewayURL("kubernetes Gateway URL", gatewayURL); err != nil {
		return "", "", err
	}
	if err := validateCautemGatewayEndpoint(endpoint); err != nil {
		return "", "", err
	}
	return gatewayURL, endpoint, nil
}

func requireProxyEnvironmentValue(entries []string, key, expected string) error {
	found := false
	for _, entry := range entries {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || name != key {
			continue
		}
		if found || value != expected {
			return fmt.Errorf("kubernetes proxy environment %s does not match the trusted runtime endpoint", key)
		}
		found = true
	}
	if !found {
		return fmt.Errorf("kubernetes proxy environment is missing trusted runtime value %s", key)
	}
	return nil
}

func newRuntimeGeneration() (string, error) {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate Kubernetes runtime generation: %w", err)
	}
	return "gen" + hex.EncodeToString(value[:]), nil
}
