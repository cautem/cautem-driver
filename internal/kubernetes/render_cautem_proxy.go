package kubernetes

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	cautemProxyListenPort = int64(3128)
	cautemProxyImageName  = "cautem-proxy"
	cautemProxyRuntimeDir = "/var/run/cautem/runtime"
)

type cautemProxyPodRenderParams struct {
	Namespace                 string
	SandboxResourceName       string
	SandboxResourceAPIVersion string
	SandboxResourceUID        string
	SandboxID                 string
	SandboxName               string
	Generation                string
	ProxyImage                string
	ProxyImagePullPolicy      string
	ServiceAccountName        string
	ImagePullSecrets          []string
	GatewayURL                string
	GatewayGRPCEndpoint       string
	GatewayTLS                bool
	BoundaryPort              int64
	ControlUID                int64
	ControlGID                int64
}

// renderCautemProxyPod renders the trusted proxy companion. Its listener is a
// Pod-local bind address; workload clients use the separate Service endpoint.
func renderCautemProxyPod(input cautemProxyPodRenderParams) (map[string]any, error) {
	params, err := validateCautemProxyPodRenderParams(input)
	if err != nil {
		return nil, err
	}
	id := strings.ToLower(params.SandboxID)
	name := "os-supervisor-" + id
	owner := map[string]any{
		"apiVersion":         params.SandboxResourceAPIVersion,
		"kind":               "Sandbox",
		"name":               params.SandboxResourceName,
		"uid":                params.SandboxResourceUID,
		"blockOwnerDeletion": false,
	}
	labels := runtimeCommonLabels(params.SandboxID, "supervisor")
	labels[labelBoundaryPair] = id
	labels[labelBoundaryRole] = "supervisor"
	container := map[string]any{
		"name":            cautemProxyImageName,
		"image":           params.ProxyImage,
		"imagePullPolicy": params.ProxyImagePullPolicy,
		"command":         cautemProxyCommand(),
		"env": []any{
			map[string]any{"name": "CAUTEM_GATEWAY_URL", "value": params.GatewayURL},
			map[string]any{"name": "CAUTEM_GATEWAY_GRPC_ENDPOINT", "value": params.GatewayGRPCEndpoint},
			map[string]any{"name": "CAUTEM_SANDBOX", "value": params.SandboxName},
			map[string]any{"name": "CAUTEM_SANDBOX_TOKEN_FILE", "value": cautemProxyRuntimeDir + "/sandbox-token"},
			map[string]any{"name": "CAUTEM_LOG_DIR", "value": "/tmp/cautem-logs"},
			map[string]any{"name": "CAUTEM_SUPERVISOR_CONTROL_LISTEN", "value": "0.0.0.0:5502"},
			map[string]any{"name": "CAUTEM_SUPERVISOR_CONTROL_SERVER_CA", "value": cautemProxyRuntimeDir + "/control-server-ca.pem"},
			map[string]any{"name": "CAUTEM_SUPERVISOR_CONTROL_SERVER_CERT", "value": cautemProxyRuntimeDir + "/control-server.crt"},
			map[string]any{"name": "CAUTEM_SUPERVISOR_CONTROL_SERVER_KEY", "value": cautemProxyRuntimeDir + "/control-server.key"},
			map[string]any{"name": "CAUTEM_RELAY_TARGET_ENDPOINT", "value": net.JoinHostPort(runtimeServiceFQDN("os-boundary-"+id, params.Namespace), fmt.Sprint(params.BoundaryPort))},
			map[string]any{"name": "CAUTEM_RELAY_TARGET_SERVER_CA", "value": cautemProxyRuntimeDir + "/target-server-ca.pem"},
			map[string]any{"name": "CAUTEM_RELAY_TARGET_CLIENT_CERT", "value": cautemProxyRuntimeDir + "/target-client.crt"},
			map[string]any{"name": "CAUTEM_RELAY_TARGET_CLIENT_KEY", "value": cautemProxyRuntimeDir + "/target-client.key"},
		},
		"envFrom": []any{map[string]any{"secretRef": map[string]any{
			"name": generationSecretName(proxyEnvSecretPrefix, params.SandboxID, params.Generation),
		}}},
		"ports": []any{
			map[string]any{"name": "proxy", "containerPort": cautemProxyListenPort, "protocol": "TCP"},
			map[string]any{"name": "sup-control", "containerPort": supervisorControlPort, "protocol": "TCP"},
		},
		"readinessProbe": map[string]any{
			"tcpSocket":      map[string]any{"port": supervisorControlPort},
			"timeoutSeconds": int64(1), "periodSeconds": int64(2),
			"successThreshold": int64(1), "failureThreshold": int64(15),
		},
		"terminationMessagePolicy": "FallbackToLogsOnError",
		"securityContext": map[string]any{
			"runAsUser": params.ControlUID, "runAsGroup": params.ControlGID,
			"runAsNonRoot": true, "readOnlyRootFilesystem": true,
			"allowPrivilegeEscalation": false,
			"capabilities":             map[string]any{"drop": []any{"ALL"}},
		},
		"volumeMounts": []any{
			map[string]any{"name": "runtime", "mountPath": cautemProxyRuntimeDir, "readOnly": true},
			map[string]any{"name": "tmp", "mountPath": "/tmp"},
		},
	}
	if params.GatewayTLS {
		container["env"] = append(sliceValue(container["env"]),
			map[string]any{"name": "CAUTEM_GUEST_TLS_CA", "value": cautemProxyRuntimeDir + "/" + cautemGatewayTLSCAKey},
			map[string]any{"name": "CAUTEM_GUEST_TLS_CERT", "value": cautemProxyRuntimeDir + "/" + cautemGatewayTLSCertKey},
			map[string]any{"name": "CAUTEM_GUEST_TLS_KEY", "value": cautemProxyRuntimeDir + "/" + cautemGatewayTLSKeyKey},
		)
	}
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name": name, "namespace": params.Namespace,
			"labels":          labels,
			"annotations":     map[string]any{labelSandboxID: params.SandboxID},
			"ownerReferences": []any{owner},
		},
		"spec": map[string]any{
			"terminationGracePeriodSeconds": int64(10),
			"serviceAccountName":            params.ServiceAccountName,
			"imagePullSecrets":              renderImagePullSecretRefs(params.ImagePullSecrets),
			"automountServiceAccountToken":  false,
			"schedulingGates":               []any{map[string]any{"name": sandboxRuntimeBootstrapGate}},
			"restartPolicy":                 "Never",
			"hostNetwork":                   false,
			"hostPID":                       false,
			"hostIPC":                       false,
			"securityContext": map[string]any{
				"fsGroup": params.ControlGID, "fsGroupChangePolicy": "OnRootMismatch",
				"seccompProfile": map[string]any{"type": "RuntimeDefault"},
			},
			"containers": []any{container},
			"volumes": []any{
				map[string]any{"name": "runtime", "secret": map[string]any{
					"secretName":  generationSecretName("os-supervisor", params.SandboxID, params.Generation),
					"defaultMode": int64(0o440),
				}},
				map[string]any{"name": "tmp", "emptyDir": map[string]any{"sizeLimit": "64Mi"}},
			},
		},
	}, nil
}

func cautemProxyCommand() []any {
	return []any{"/usr/local/bin/cautem", "proxy", "--listen", "0.0.0.0:3128", "--policy", cautemProxyRuntimeDir + "/policy.yaml"}
}

func cautemProxyCommandStrings() []string {
	command := cautemProxyCommand()
	result := make([]string, len(command))
	for index, value := range command {
		result[index], _ = value.(string)
	}
	return result
}

func validateCautemProxyPodRenderParams(input cautemProxyPodRenderParams) (cautemProxyPodRenderParams, error) {
	params := input
	if err := requireDNS1123Label("namespace", params.Namespace); err != nil {
		return params, err
	}
	if err := requireDNS1123Subdomain("Agent Sandbox resource name", params.SandboxResourceName); err != nil {
		return params, err
	}
	if params.SandboxResourceAPIVersion != sandboxAPIGroup+"/"+sandboxAPIVersionV1Beta1 && params.SandboxResourceAPIVersion != sandboxAPIGroup+"/"+sandboxAPIVersionV1Alpha1 {
		return params, fmt.Errorf("unsupported Agent Sandbox owner apiVersion %q", params.SandboxResourceAPIVersion)
	}
	if strings.TrimSpace(params.SandboxResourceUID) == "" {
		return params, fmt.Errorf("agent Sandbox resource UID is required for companion owner references")
	}
	if err := requireDNS1123Subdomain("sandbox ID", params.SandboxID); err != nil {
		return params, err
	}
	if len(params.SandboxID) > 63 || len(validation.IsValidLabelValue(params.SandboxID)) != 0 {
		return params, fmt.Errorf("sandbox ID must fit a Kubernetes label value")
	}
	if params.SandboxName == "" || len(validation.IsValidLabelValue(params.SandboxName)) != 0 {
		return params, fmt.Errorf("sandbox name must be a valid Kubernetes label value")
	}
	imageParts := strings.Split(params.ProxyImage, "@sha256:")
	if len(imageParts) != 2 || strings.TrimSpace(imageParts[0]) == "" || len(imageParts[1]) != 64 {
		return params, fmt.Errorf("cautem proxy image must be pinned by sha256 digest")
	}
	if _, err := hex.DecodeString(imageParts[1]); err != nil {
		return params, fmt.Errorf("cautem proxy image must use a valid sha256 digest")
	}
	if err := validateImagePullPolicy("cautem proxy image pull policy", params.ProxyImagePullPolicy); err != nil {
		return params, err
	}
	if params.ProxyImagePullPolicy == "" {
		params.ProxyImagePullPolicy = "IfNotPresent"
	}
	if err := validateCautemGatewayURL("Gateway HTTP URL", params.GatewayURL); err != nil {
		return params, err
	}
	parsedGateway, _ := url.Parse(strings.TrimSpace(params.GatewayURL))
	if (parsedGateway.Scheme == "https") != params.GatewayTLS {
		return params, fmt.Errorf("cautem proxy guest TLS setting must match the Gateway URL scheme")
	}
	if err := validateCautemGatewayEndpoint(params.GatewayGRPCEndpoint); err != nil {
		return params, err
	}
	if params.BoundaryPort < 1024 || params.BoundaryPort > 65535 {
		return params, fmt.Errorf("sandbox runtime boundary port must be between 1024 and 65535")
	}
	if params.ServiceAccountName == "" {
		params.ServiceAccountName = "default"
	}
	if err := requireDNS1123Subdomain("service account name", params.ServiceAccountName); err != nil {
		return params, err
	}
	if params.ControlUID < 1 || params.ControlUID > int64(^uint32(0)) || params.ControlGID < 1 || params.ControlGID > int64(^uint32(0)) {
		return params, fmt.Errorf("proxy identity must use non-root 32-bit UID/GID values")
	}
	seenPullSecrets := make(map[string]struct{}, len(params.ImagePullSecrets))
	for _, name := range params.ImagePullSecrets {
		if err := requireDNS1123Subdomain("image pull Secret name", name); err != nil {
			return params, err
		}
		if _, duplicate := seenPullSecrets[name]; duplicate {
			return params, fmt.Errorf("duplicate image pull Secret %q", name)
		}
		seenPullSecrets[name] = struct{}{}
	}
	if generationSuffix(params.Generation) == "" {
		return params, fmt.Errorf("sandbox runtime generation must contain an ASCII letter or digit")
	}
	return params, nil
}

func validateCautemGatewayURL(field, raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("%s must be an absolute HTTP(S) URL without user info or fragment", field)
	}
	if err := validateKubernetesReachableGatewayHost(parsed.Hostname()); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

func validateCautemGatewayEndpoint(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	host, portText, err := net.SplitHostPort(raw)
	port, parseErr := strconv.ParseUint(portText, 10, 16)
	if err != nil || strings.TrimSpace(host) == "" || parseErr != nil || port == 0 {
		return fmt.Errorf("gateway gRPC endpoint must be host:port with a valid port")
	}
	return validateKubernetesReachableGatewayHost(host)
}

func validateKubernetesReachableGatewayHost(host string) error {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "host.docker.internal" || strings.HasSuffix(host, ".host.docker.internal") {
		return fmt.Errorf("gateway endpoint must be reachable from cluster Pods")
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return fmt.Errorf("gateway endpoint must be reachable from cluster Pods")
	}
	return nil
}
