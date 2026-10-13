package kubernetes

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	sandboxRuntimeBootstrapGate  = "openshell.ai/bootstrap"
	supervisorBootstrapPath      = "/.openshell/supervisor"
	supervisorTokenPath          = "/var/run/secrets/openshell"
	supervisorHealthSocketPath   = "/run/openshell/health.sock"
	supervisorHealthPort         = int64(5501)
	supervisorControlPort        = int64(5502)
	workloadFencePrefix          = "cautem-workload-fence-"
	supervisorEgressPolicyPrefix = "cautem-supervisor-egress-"
	workloadFenceComponent       = "sandbox-workload-fence"
	supervisorFenceComponent     = "sandbox-supervisor-egress"
)

// agentSandboxRuntimeRenderParams are values only known after the AgentSandbox
// API has assigned its UID. The returned resources are still pure render
// output; Create must apply and observe the fence before releasing either pod.
type agentSandboxRuntimeRenderParams struct {
	Namespace                  string
	SandboxResourceName        string
	SandboxResourceAPIVersion  string
	SandboxResourceUID         string
	SandboxID                  string
	SandboxName                string
	Workspace                  string
	GatewayID                  string
	Generation                 string
	SupervisorImage            string
	CautemProxyImage           string
	CautemProxyImagePullPolicy string
	CautemGatewayURL           string
	CautemGatewayGRPCEndpoint  string
	CautemGatewayTLS           bool
	ServiceAccountName         string
	GatewayEndpoint            string
	ImagePullSecrets           []string
	ControlUID                 int64
	ControlGID                 int64
	BoundaryPort               int64
	SATokenTTLSeconds          int64
}

// renderAgentSandboxRuntimeResources renders the supervisor companion, the
// workload-facing ClusterIP Service, and the two namespace network policies
// used by OpenShell's workload/supervisor boundary.
func renderAgentSandboxRuntimeResources(input agentSandboxRuntimeRenderParams) (map[string]any, error) {
	params, err := validateAgentSandboxRuntimeRenderParams(input)
	if err != nil {
		return nil, err
	}
	id := strings.ToLower(params.SandboxID)
	pairLabels := map[string]any{
		labelBoundaryPair: id,
		labelBoundaryRole: "workload",
	}
	owner := map[string]any{
		"apiVersion":         params.SandboxResourceAPIVersion,
		"kind":               "Sandbox",
		"name":               params.SandboxResourceName,
		"uid":                params.SandboxResourceUID,
		"blockOwnerDeletion": false,
	}
	serviceName := "os-boundary-" + id
	supervisorName := "os-supervisor-" + id
	proxyServiceName := "os-proxy-" + id
	supervisorSecretName := generationSecretName("os-supervisor", id, params.Generation)
	for field, name := range map[string]string{
		"boundary Service name":       serviceName,
		"supervisor Pod name":         supervisorName,
		"proxy Service name":          proxyServiceName,
		"supervisor bootstrap Secret": supervisorSecretName,
	} {
		if err := requireDNS1123Subdomain(field, name); err != nil {
			return nil, err
		}
	}

	service := map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name":            serviceName,
			"namespace":       params.Namespace,
			"labels":          runtimeCommonLabels(params.SandboxID, "boundary-service"),
			"ownerReferences": []any{owner},
		},
		"spec": map[string]any{
			"selector": pairLabels,
			"ports": []any{map[string]any{
				"name":       "boundary",
				"protocol":   "TCP",
				"port":       params.BoundaryPort,
				"targetPort": params.BoundaryPort,
			}},
		},
	}

	controlService := map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name":            supervisorName,
			"namespace":       params.Namespace,
			"labels":          runtimeCommonLabels(params.SandboxID, "supervisor-control-service"),
			"ownerReferences": []any{owner},
		},
		"spec": map[string]any{
			"selector": map[string]any{
				labelBoundaryPair: id,
				labelBoundaryRole: "supervisor",
			},
			"ports": []any{map[string]any{
				"name":       "sup-control",
				"protocol":   "TCP",
				"port":       supervisorControlPort,
				"targetPort": supervisorControlPort,
			}},
		},
	}

	proxyService := map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name":            proxyServiceName,
			"namespace":       params.Namespace,
			"labels":          runtimeCommonLabels(params.SandboxID, "proxy-service"),
			"ownerReferences": []any{owner},
		},
		"spec": map[string]any{
			"selector": map[string]any{
				labelBoundaryPair: id,
				labelBoundaryRole: "supervisor",
			},
			"ports": []any{map[string]any{
				"name": "proxy", "protocol": "TCP",
				"port": cautemProxyListenPort, "targetPort": cautemProxyListenPort,
			}},
		},
	}

	supervisorLabels := runtimeCommonLabels(params.SandboxID, "supervisor")
	supervisorLabels[labelBoundaryPair] = id
	supervisorLabels[labelBoundaryRole] = "supervisor"
	supervisorLabels[labelGatewayID] = params.GatewayID
	supervisorPod := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":            supervisorName,
			"namespace":       params.Namespace,
			"labels":          supervisorLabels,
			"annotations":     map[string]any{labelSandboxID: params.SandboxID},
			"ownerReferences": []any{owner},
		},
		"spec": map[string]any{
			"terminationGracePeriodSeconds": int64(30),
			"serviceAccountName":            params.ServiceAccountName,
			"imagePullSecrets":              renderImagePullSecretRefs(params.ImagePullSecrets),
			"automountServiceAccountToken":  false,
			"schedulingGates":               []any{map[string]any{"name": sandboxRuntimeBootstrapGate}},
			"restartPolicy":                 "Never",
			"hostNetwork":                   false,
			"hostPID":                       false,
			"hostIPC":                       false,
			"securityContext": map[string]any{
				"fsGroup":             params.ControlGID,
				"fsGroupChangePolicy": "OnRootMismatch",
				"seccompProfile":      map[string]any{"type": "RuntimeDefault"},
			},
			"containers": []any{map[string]any{
				"name":    "supervisor",
				"image":   params.SupervisorImage,
				"command": supervisorCommand(),
				"env": []any{
					map[string]any{"name": "OPENSHELL_ENDPOINT", "value": params.GatewayEndpoint},
					map[string]any{"name": "OPENSHELL_SANDBOX_ID", "value": params.SandboxID},
					map[string]any{"name": "OPENSHELL_SANDBOX", "value": params.SandboxName},
					map[string]any{"name": "OPENSHELL_K8S_SA_TOKEN_FILE", "value": supervisorTokenPath + "/token"},
				},
				"ports": []any{map[string]any{
					"name":          "control-health",
					"containerPort": supervisorHealthPort,
					"protocol":      "TCP",
				}, map[string]any{
					"name":          "sup-control",
					"containerPort": supervisorControlPort,
					"protocol":      "TCP",
				}},
				"readinessProbe": map[string]any{
					"tcpSocket":        map[string]any{"port": supervisorHealthPort},
					"timeoutSeconds":   int64(1),
					"periodSeconds":    int64(1),
					"successThreshold": int64(1),
					"failureThreshold": int64(3),
				},
				"terminationMessagePolicy": "FallbackToLogsOnError",
				"securityContext": map[string]any{
					"runAsUser":                params.ControlUID,
					"runAsGroup":               params.ControlGID,
					"runAsNonRoot":             true,
					"readOnlyRootFilesystem":   true,
					"allowPrivilegeEscalation": false,
					"capabilities":             map[string]any{"drop": []any{"ALL"}},
				},
				"volumeMounts": []any{
					map[string]any{"name": "bootstrap", "mountPath": supervisorBootstrapPath, "readOnly": true},
					map[string]any{"name": "sa-token", "mountPath": supervisorTokenPath, "readOnly": true},
					map[string]any{"name": "run", "mountPath": "/run/openshell"},
					map[string]any{"name": "logs", "mountPath": "/var/log"},
				},
			}},
			"volumes": []any{
				map[string]any{"name": "bootstrap", "secret": map[string]any{"secretName": supervisorSecretName, "defaultMode": int64(0o440)}},
				map[string]any{"name": "sa-token", "projected": map[string]any{
					"defaultMode": int64(0o440),
					"sources": []any{map[string]any{"serviceAccountToken": map[string]any{
						"audience":          "openshell-gateway",
						"expirationSeconds": params.SATokenTTLSeconds,
						"path":              "token",
					}}},
				}},
				map[string]any{"name": "run", "emptyDir": map[string]any{}},
				map[string]any{"name": "logs", "emptyDir": map[string]any{}},
			},
		},
	}
	if params.CautemProxyImage != "" {
		supervisorPod, err = renderCautemProxyPod(cautemProxyPodRenderParams{
			Namespace: params.Namespace, SandboxResourceName: params.SandboxResourceName,
			SandboxResourceAPIVersion: params.SandboxResourceAPIVersion, SandboxResourceUID: params.SandboxResourceUID,
			SandboxID: params.SandboxID, SandboxName: params.SandboxName, Generation: params.Generation,
			ProxyImage: params.CautemProxyImage, ProxyImagePullPolicy: params.CautemProxyImagePullPolicy,
			ServiceAccountName: params.ServiceAccountName, ImagePullSecrets: params.ImagePullSecrets,
			GatewayURL: params.CautemGatewayURL, GatewayGRPCEndpoint: params.CautemGatewayGRPCEndpoint,
			GatewayTLS:   params.CautemGatewayTLS,
			BoundaryPort: params.BoundaryPort, ControlUID: params.ControlUID, ControlGID: params.ControlGID,
		})
		if err != nil {
			return nil, fmt.Errorf("render Cautem proxy Pod: %w", err)
		}
	}

	workloadFence, supervisorFence, err := renderAgentSandboxRuntimeFence(params.Namespace, params.SandboxID, params.BoundaryPort)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"boundaryService":         service,
		"controlService":          controlService,
		"proxyService":            proxyService,
		"supervisorPod":           supervisorPod,
		"workloadNetworkPolicy":   workloadFence,
		"supervisorNetworkPolicy": supervisorFence,
	}, nil
}

func supervisorCommand() []any {
	command := []string{
		"/openshell-supervisor",
		"--backend-descriptor-file", supervisorBootstrapPath + "/runtime-descriptor.json",
		"--auth-bundle-file", supervisorBootstrapPath + "/auth.json",
		"--workdir", "/sandbox",
		"--health-socket-path", supervisorHealthSocketPath,
		"--health-port", fmt.Sprint(supervisorHealthPort),
	}
	result := make([]any, len(command))
	for i, arg := range command {
		result[i] = arg
	}
	return result
}

func supervisorCommandStrings() []string {
	command := supervisorCommand()
	result := make([]string, len(command))
	for i, arg := range command {
		result[i], _ = arg.(string)
	}
	return result
}

func renderAgentSandboxRuntimeFence(namespace, sandboxID string, boundaryPort int64) (map[string]any, map[string]any, error) {
	if err := requireDNS1123Label("namespace", namespace); err != nil {
		return nil, nil, err
	}
	if sandboxID == "" || len(validation.IsValidLabelValue(sandboxID)) != 0 {
		return nil, nil, fmt.Errorf("sandbox ID must be a Kubernetes label value")
	}
	if boundaryPort < 1024 || boundaryPort > 65535 {
		return nil, nil, fmt.Errorf("sandbox runtime boundary port must be between 1024 and 65535")
	}
	pair := strings.ToLower(sandboxID)
	workloadFenceName, supervisorEgressPolicyName := runtimeFenceNames(pair)
	workloadFence := map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata": map[string]any{
			"name": workloadFenceName, "namespace": namespace,
			"labels": map[string]any{
				labelManagedBy: managedByValue, "openshell.ai/component": workloadFenceComponent,
				labelBoundaryPair: pair,
			},
		},
		"spec": map[string]any{
			"podSelector": map[string]any{"matchLabels": map[string]any{labelBoundaryRole: "workload", labelBoundaryPair: pair}},
			"policyTypes": []any{"Ingress", "Egress"},
			"ingress": []any{map[string]any{
				"from": []any{map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{
					labelBoundaryRole: "supervisor", labelBoundaryPair: pair,
				}}}},
				"ports": []any{map[string]any{"port": boundaryPort, "protocol": "TCP"}},
			}},
			"egress": []any{
				map[string]any{
					"to": []any{map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{
						labelBoundaryRole: "supervisor", labelBoundaryPair: pair,
					}}}},
					"ports": []any{
						map[string]any{"port": supervisorControlPort, "protocol": "TCP"},
						map[string]any{"port": cautemProxyListenPort, "protocol": "TCP"},
					},
				},
				kubernetesDNSPolicyEgressRule(),
			},
		},
	}
	// Supervisor egress is intentionally application-mediated by the trusted
	// companion; the untrusted workload's explicit empty rule list stays deny-all.
	supervisorFence := map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata": map[string]any{
			"name": supervisorEgressPolicyName, "namespace": namespace,
			"labels": map[string]any{
				labelManagedBy: managedByValue, "openshell.ai/component": supervisorFenceComponent,
				labelBoundaryPair: pair,
			},
		},
		"spec": map[string]any{
			"podSelector": map[string]any{"matchLabels": map[string]any{labelBoundaryRole: "supervisor", labelBoundaryPair: pair}},
			"policyTypes": []any{"Ingress", "Egress"},
			"ingress": []any{map[string]any{
				"from": []any{map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{
					labelBoundaryRole: "workload", labelBoundaryPair: pair,
				}}}},
				"ports": []any{
					map[string]any{"port": supervisorControlPort, "protocol": "TCP"},
					map[string]any{"port": cautemProxyListenPort, "protocol": "TCP"},
				},
			}},
			"egress": []any{map[string]any{}},
		},
	}
	return workloadFence, supervisorFence, nil
}

// Kubernetes service discovery requires DNS even though the workload has no
// general network egress. The combined peer selector limits this exception to
// CoreDNS Pods in kube-system, and both transports are needed by common resolvers.
func kubernetesDNSPolicyEgressRule() map[string]any {
	return map[string]any{
		"to": []any{map[string]any{
			"namespaceSelector": map[string]any{"matchLabels": map[string]any{"kubernetes.io/metadata.name": "kube-system"}},
			"podSelector":       map[string]any{"matchLabels": map[string]any{"k8s-app": "kube-dns"}},
		}},
		"ports": []any{
			map[string]any{"port": int64(53), "protocol": "UDP"},
			map[string]any{"port": int64(53), "protocol": "TCP"},
		},
	}
}

func runtimeFenceNames(pair string) (string, string) {
	digest := sha256.Sum256([]byte(strings.ToLower(pair)))
	suffix := hex.EncodeToString(digest[:12])
	return workloadFencePrefix + suffix, supervisorEgressPolicyPrefix + suffix
}

func runtimeServiceFQDN(name, namespace string) string {
	return name + "." + namespace + ".svc.cluster.local"
}

func validateAgentSandboxRuntimeRenderParams(input agentSandboxRuntimeRenderParams) (agentSandboxRuntimeRenderParams, error) {
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
	for field, value := range map[string]string{"sandbox name": params.SandboxName, "workspace": params.Workspace, "gateway ID": params.GatewayID} {
		if value == "" || len(validation.IsValidLabelValue(value)) != 0 {
			return params, fmt.Errorf("%s must be a valid non-empty Kubernetes label value", field)
		}
	}
	if strings.TrimSpace(params.Generation) == "" {
		return params, fmt.Errorf("sandbox runtime generation is required")
	}
	if generationSuffix(params.Generation) == "" {
		return params, fmt.Errorf("sandbox runtime generation %q must contain an ASCII letter or digit", params.Generation)
	}
	if params.CautemProxyImage == "" {
		if strings.TrimSpace(params.SupervisorImage) == "" {
			return params, fmt.Errorf("supervisor image is required")
		}
		if strings.TrimSpace(params.GatewayEndpoint) == "" {
			return params, fmt.Errorf("supervisor gateway endpoint is required")
		}
	}
	if params.ServiceAccountName == "" {
		params.ServiceAccountName = "default"
	}
	if err := requireDNS1123Subdomain("service account name", params.ServiceAccountName); err != nil {
		return params, err
	}
	if params.ControlUID < 1 || params.ControlUID > int64(^uint32(0)) || params.ControlGID < 1 || params.ControlGID > int64(^uint32(0)) {
		return params, fmt.Errorf("supervisor identity must use non-root 32-bit UID/GID values")
	}
	if params.BoundaryPort < 1024 || params.BoundaryPort > 65535 {
		return params, fmt.Errorf("sandbox runtime boundary port must be between 1024 and 65535")
	}
	if params.CautemProxyImage == "" && (params.SATokenTTLSeconds < 600 || params.SATokenTTLSeconds > 86400) {
		return params, fmt.Errorf("projected service-account token TTL must be between 600 and 86400 seconds")
	}
	seenPullSecrets := make(map[string]struct{}, len(params.ImagePullSecrets))
	for _, name := range params.ImagePullSecrets {
		if err := requireDNS1123Subdomain("image pull Secret name", name); err != nil {
			return params, err
		}
		if _, exists := seenPullSecrets[name]; exists {
			return params, fmt.Errorf("duplicate image pull Secret %q", name)
		}
		seenPullSecrets[name] = struct{}{}
	}
	return params, nil
}

func generationSuffix(generation string) string {
	var suffix strings.Builder
	for _, char := range generation {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' {
			suffix.WriteRune(char)
			if suffix.Len() == 12 {
				break
			}
		}
	}
	return strings.ToLower(suffix.String())
}

func generationSecretName(prefix, sandboxID, generation string) string {
	return fmt.Sprintf("%s-%s-%s", prefix, strings.ToLower(sandboxID), generationSuffix(generation))
}

func runtimeCommonLabels(sandboxID, component string) map[string]any {
	return map[string]any{
		labelManagedBy:           managedByValue,
		labelSandboxID:           sandboxID,
		"openshell.ai/component": component,
	}
}

func renderImagePullSecretRefs(names []string) []any {
	refs := make([]any, 0, len(names))
	for _, name := range names {
		refs = append(refs, map[string]any{"name": name})
	}
	return refs
}
