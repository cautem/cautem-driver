package kubernetes

import (
	"fmt"
	"path"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	labelManagedBy              = "openshell.ai/managed-by"
	labelSandboxID              = "openshell.ai/sandbox-id"
	labelSandboxName            = "openshell.ai/sandbox-name"
	labelSandboxWorkspace       = "openshell.ai/sandbox-workspace"
	labelGatewayID              = "openshell.ai/gateway-id"
	labelBoundaryPair           = "openshell.ai/boundary-pair"
	labelBoundaryRole           = "openshell.ai/boundary-role"
	annotationRuntimeGeneration = "openshell.ai/runtime-generation"
	annotationCautemGatewayURL  = "cautem.ai/gateway-url"
	annotationCautemGatewayRPC  = "cautem.ai/gateway-grpc-endpoint"
	annotationCautemGatewayTLS  = "cautem.ai/gateway-tls"

	managedByValue = "openshell"

	sandboxBootstrapGate       = "openshell.ai/bootstrap"
	sandboxRuntimeVolume       = "openshell-runtime"
	sandboxStateVolume         = "openshell-runtime-state"
	sandboxBootstrapVolume     = "openshell-sandbox-bootstrap"
	sandboxPodIdentityVolume   = "openshell-pod-identity"
	sandboxProxyCAVolume       = "openshell-run"
	sandboxRuntimeMountPath    = "/.openshell/runtime"
	sandboxStateMountPath      = "/.openshell/state"
	sandboxBootstrapInputPath  = "/.openshell/bootstrap-input"
	sandboxPodIdentityMount    = "/.openshell/pod-identity"
	sandboxProxyCAMountPath    = "/run"
	sandboxBoundaryConfigPath  = "/.openshell/state/bootstrap/boundary.json"
	workspaceVolumeName        = "workspace"
	workspaceMountPath         = "/sandbox"
	workspaceSeedMountPath     = "/mnt/openshell-workspace"
	workspaceSeedContainerName = "workspace-init"
	defaultWorkspaceStorage    = "2Gi"
)

// agentSandboxRenderParams contains the runtime identity that must be resolved
// before an Agent Sandbox object is submitted. The renderer creates a suspended
// CR and a gated workload Pod template; a separate lifecycle step installs the
// NetworkPolicy fence, creates the supervisor companion, and only then releases
// the scheduling gate.
type agentSandboxRenderParams struct {
	APIVersion                    string
	Namespace                     string
	ResourceName                  string
	SandboxID                     string
	SandboxName                   string
	Workspace                     string
	GatewayID                     string
	Generation                    string
	Image                         string
	ImagePullPolicy               string
	SandboxRuntimeImage           string
	SandboxRuntimeImagePullPolicy string
	SandboxBootstrapSecretName    string
	ServiceAccountName            string
	ImagePullSecrets              []string
	SandboxUID                    int64
	SandboxGID                    int64
	BoundaryPort                  int64
	EnableUserNamespaces          bool
	DefaultRuntimeClassName       string
	WorkspaceStorageSize          string
	WorkspaceStorageClass         string
	GPU                           bool
	GPUCount                      int
}

func renderAgentSandboxResource(config SandboxDriverConfig, input agentSandboxRenderParams) (map[string]any, error) {
	params, err := validateAgentSandboxRenderParams(input)
	if err != nil {
		return nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid kubernetes driver_config: %w", err)
	}
	if err := validateNoManagedRuntimeMountOverlap(config.Containers.Agent.VolumeMounts); err != nil {
		return nil, err
	}
	config, err = configWithRequestedGPU(config, params.GPU, params.GPUCount)
	if err != nil {
		return nil, err
	}

	podTemplate, err := renderAgentSandboxPodTemplate(config, params)
	if err != nil {
		return nil, err
	}
	labels := map[string]any{
		labelManagedBy:        managedByValue,
		labelSandboxID:        params.SandboxID,
		labelSandboxName:      params.SandboxName,
		labelSandboxWorkspace: params.Workspace,
		labelGatewayID:        params.GatewayID,
	}
	annotations := map[string]any{
		labelSandboxID:        params.SandboxID,
		labelSandboxName:      params.SandboxName,
		labelSandboxWorkspace: params.Workspace,
	}
	if params.Generation != "" {
		annotations[annotationRuntimeGeneration] = params.Generation
		if expected := generationSecretName("os-sandbox", params.SandboxID, params.Generation); params.SandboxBootstrapSecretName != expected {
			return nil, fmt.Errorf("sandbox bootstrap Secret %q does not match runtime generation %q", params.SandboxBootstrapSecretName, params.Generation)
		}
	}
	resource := map[string]any{
		"apiVersion": sandboxAPIGroup + "/" + params.APIVersion,
		"kind":       "Sandbox",
		"metadata": map[string]any{
			"name":        params.ResourceName,
			"namespace":   params.Namespace,
			"labels":      labels,
			"annotations": annotations,
		},
		"spec": map[string]any{
			"podTemplate": podTemplate,
		},
	}
	resourceSpec := resource["spec"].(map[string]any)
	if shouldInjectDefaultWorkspace(config) {
		claimSpec := map[string]any{
			"accessModes": []any{"ReadWriteOnce"},
			"resources": map[string]any{
				"requests": map[string]any{"storage": params.WorkspaceStorageSize},
			},
		}
		if params.WorkspaceStorageClass != "" {
			claimSpec["storageClassName"] = params.WorkspaceStorageClass
		}
		resourceSpec["volumeClaimTemplates"] = []any{map[string]any{
			"metadata": map[string]any{"name": workspaceVolumeName},
			"spec":     claimSpec,
		}}
	}
	desiredState, err := sandboxDesiredStateFields(params.APIVersion, false)
	if err != nil {
		return nil, err
	}
	for key, value := range desiredState {
		resourceSpec[key] = value
	}
	return resource, nil
}

func renderAgentSandboxPodTemplate(config SandboxDriverConfig, params agentSandboxRenderParams) (map[string]any, error) {
	fragment, err := renderDriverConfigFragment(config)
	if err != nil {
		return nil, err
	}
	fragmentSpec, ok := fragment["spec"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("driver_config renderer returned an invalid Pod spec")
	}
	fragmentContainers, ok := fragmentSpec["containers"].([]any)
	if !ok || len(fragmentContainers) != 1 {
		return nil, fmt.Errorf("driver_config renderer returned an invalid agent container")
	}
	fragmentAgent, ok := fragmentContainers[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("driver_config renderer returned an invalid agent container")
	}
	userMounts, ok := fragmentAgent["volumeMounts"].([]any)
	if !ok {
		return nil, fmt.Errorf("driver_config renderer returned invalid agent volume mounts")
	}
	userVolumes, ok := fragmentSpec["volumes"].([]any)
	if !ok {
		return nil, fmt.Errorf("driver_config renderer returned invalid Pod volumes")
	}

	container := map[string]any{
		"name":    "agent",
		"image":   params.Image,
		"command": []any{sandboxRuntimeMountPath + "/openshell-sandbox", "--bootstrap", sandboxBoundaryConfigPath},
		"env": []any{
			map[string]any{"name": "OPENSHELL_OCI_IMAGE_USER", "value": ""},
			map[string]any{"name": "OPENSHELL_SANDBOX_UID", "value": fmt.Sprint(params.SandboxUID)},
			map[string]any{"name": "OPENSHELL_SANDBOX_GID", "value": fmt.Sprint(params.SandboxGID)},
		},
		"securityContext": map[string]any{
			"runAsUser":                params.SandboxUID,
			"runAsGroup":               params.SandboxGID,
			"runAsNonRoot":             true,
			"allowPrivilegeEscalation": false,
			"capabilities":             map[string]any{"drop": []any{"ALL"}},
		},
		"ports": []any{map[string]any{
			"name":          "sandbox-control",
			"containerPort": params.BoundaryPort,
			"protocol":      "TCP",
		}},
		"volumeMounts": append(append([]any{}, userMounts...), []any{
			map[string]any{"name": sandboxRuntimeVolume, "mountPath": sandboxRuntimeMountPath, "readOnly": true},
			map[string]any{"name": sandboxStateVolume, "mountPath": sandboxStateMountPath},
			map[string]any{"name": sandboxPodIdentityVolume, "mountPath": sandboxPodIdentityMount, "readOnly": true},
			map[string]any{"name": sandboxProxyCAVolume, "mountPath": sandboxProxyCAMountPath},
		}...),
	}
	if params.ImagePullPolicy != "" {
		container["imagePullPolicy"] = params.ImagePullPolicy
	}
	if resources, ok := fragmentAgent["resources"]; ok {
		container["resources"] = resources
	}
	if shouldInjectDefaultWorkspace(config) {
		container["volumeMounts"] = append(container["volumeMounts"].([]any), map[string]any{
			"name": workspaceVolumeName, "mountPath": workspaceMountPath,
		})
	}

	bootstrap := map[string]any{
		"name":    sandboxBootstrapVolume,
		"image":   params.SandboxRuntimeImage,
		"command": []any{"/openshell-sandbox", "bootstrap"},
		"securityContext": map[string]any{
			"runAsUser":                params.SandboxUID,
			"runAsGroup":               params.SandboxGID,
			"runAsNonRoot":             true,
			"readOnlyRootFilesystem":   true,
			"allowPrivilegeEscalation": false,
			"capabilities":             map[string]any{"drop": []any{"ALL"}},
		},
		"volumeMounts": []any{
			map[string]any{"name": sandboxBootstrapVolume, "mountPath": sandboxBootstrapInputPath, "readOnly": true},
			map[string]any{"name": sandboxRuntimeVolume, "mountPath": sandboxRuntimeMountPath},
			map[string]any{"name": sandboxStateVolume, "mountPath": sandboxStateMountPath},
		},
	}
	if params.SandboxRuntimeImagePullPolicy != "" {
		bootstrap["imagePullPolicy"] = params.SandboxRuntimeImagePullPolicy
	}
	initContainers := []any{bootstrap}
	if shouldInjectDefaultWorkspace(config) {
		workspaceInit := map[string]any{
			"name":    workspaceSeedContainerName,
			"image":   params.Image,
			"command": []any{sandboxRuntimeMountPath + "/openshell-sandbox", "seed-workspace"},
			"securityContext": map[string]any{
				"runAsUser":                params.SandboxUID,
				"runAsGroup":               params.SandboxGID,
				"runAsNonRoot":             true,
				"readOnlyRootFilesystem":   true,
				"allowPrivilegeEscalation": false,
				"capabilities":             map[string]any{"drop": []any{"ALL"}},
			},
			"volumeMounts": []any{
				map[string]any{"name": workspaceVolumeName, "mountPath": workspaceSeedMountPath},
				map[string]any{"name": sandboxRuntimeVolume, "mountPath": sandboxRuntimeMountPath, "readOnly": true},
			},
		}
		if params.ImagePullPolicy != "" {
			workspaceInit["imagePullPolicy"] = params.ImagePullPolicy
		}
		initContainers = append(initContainers, workspaceInit)
	}

	volumes := append(append([]any{}, userVolumes...), []any{
		map[string]any{"name": sandboxRuntimeVolume, "emptyDir": map[string]any{"medium": "Memory"}},
		map[string]any{"name": sandboxStateVolume, "emptyDir": map[string]any{"medium": "Memory"}},
		map[string]any{"name": sandboxBootstrapVolume, "secret": map[string]any{"secretName": params.SandboxBootstrapSecretName, "defaultMode": int64(0o440)}},
		map[string]any{"name": sandboxPodIdentityVolume, "downwardAPI": map[string]any{"defaultMode": int64(0o644), "items": []any{
			map[string]any{"path": "uid", "fieldRef": map[string]any{"apiVersion": "v1", "fieldPath": "metadata.uid"}},
		}}},
		map[string]any{"name": sandboxProxyCAVolume, "emptyDir": map[string]any{"medium": "Memory"}},
	}...)

	podLabels := map[string]any{
		labelSandboxID:    params.SandboxID,
		labelBoundaryPair: strings.ToLower(params.SandboxID),
		labelBoundaryRole: "workload",
	}
	podAnnotations := map[string]any{labelSandboxID: params.SandboxID}
	podSpec := map[string]any{
		"hostNetwork":                  false,
		"hostPID":                      false,
		"hostIPC":                      false,
		"shareProcessNamespace":        false,
		"serviceAccountName":           params.ServiceAccountName,
		"automountServiceAccountToken": false,
		"restartPolicy":                "Never",
		"dnsPolicy":                    "None",
		"dnsConfig": map[string]any{
			"nameservers": []any{"127.0.0.53"},
			"options": []any{
				map[string]any{"name": "ndots", "value": "5"},
				map[string]any{"name": "timeout", "value": "2"},
				map[string]any{"name": "attempts", "value": "2"},
			},
		},
		"schedulingGates": []any{map[string]any{"name": sandboxBootstrapGate}},
		"securityContext": map[string]any{
			"runAsUser":                params.SandboxUID,
			"runAsGroup":               params.SandboxGID,
			"runAsNonRoot":             true,
			"fsGroup":                  params.SandboxGID,
			"fsGroupChangePolicy":      "OnRootMismatch",
			"supplementalGroups":       []any{},
			"supplementalGroupsPolicy": "Strict",
			"seccompProfile":           map[string]any{"type": "RuntimeDefault"},
			"sysctls": []any{map[string]any{
				"name": "net.ipv4.ip_unprivileged_port_start", "value": "0",
			}},
		},
		"containers":     []any{container},
		"initContainers": initContainers,
		"volumes":        volumes,
	}
	for _, key := range []string{"nodeSelector", "tolerations", "priorityClassName"} {
		if value, exists := fragmentSpec[key]; exists {
			podSpec[key] = value
		}
	}
	runtimeClassName := params.DefaultRuntimeClassName
	if config.Pod.RuntimeClassName != "" {
		runtimeClassName = config.Pod.RuntimeClassName
	}
	if runtimeClassName != "" {
		podSpec["runtimeClassName"] = runtimeClassName
	}
	if params.EnableUserNamespaces {
		podSpec["hostUsers"] = false
	}
	if len(params.ImagePullSecrets) != 0 {
		refs := make([]any, 0, len(params.ImagePullSecrets))
		for _, secretName := range params.ImagePullSecrets {
			refs = append(refs, map[string]any{"name": secretName})
		}
		podSpec["imagePullSecrets"] = refs
	}
	return map[string]any{
		"metadata": map[string]any{"labels": podLabels, "annotations": podAnnotations},
		"spec":     podSpec,
	}, nil
}

func validateAgentSandboxRenderParams(input agentSandboxRenderParams) (agentSandboxRenderParams, error) {
	params := input
	if params.GPUCount < 0 || (!params.GPU && params.GPUCount != 0) {
		return params, fmt.Errorf("GPU count must be non-negative and requires GPU to be enabled")
	}
	if params.APIVersion != sandboxAPIVersionV1Beta1 && params.APIVersion != sandboxAPIVersionV1Alpha1 {
		return params, fmt.Errorf("unsupported Agent Sandbox API version %q", params.APIVersion)
	}
	if err := requireDNS1123Label("namespace", params.Namespace); err != nil {
		return params, err
	}
	if err := requireDNS1123Subdomain("resource name", params.ResourceName); err != nil {
		return params, err
	}
	for field, value := range map[string]string{
		"sandbox ID":   params.SandboxID,
		"sandbox name": params.SandboxName,
		"workspace":    params.Workspace,
		"gateway ID":   params.GatewayID,
	} {
		if value == "" || len(validation.IsValidLabelValue(value)) != 0 {
			return params, fmt.Errorf("%s must be a valid non-empty Kubernetes label value", field)
		}
	}
	if strings.TrimSpace(params.Image) == "" {
		return params, fmt.Errorf("sandbox workload image is required")
	}
	if strings.TrimSpace(params.SandboxRuntimeImage) == "" {
		return params, fmt.Errorf("sandbox runtime image is required")
	}
	if err := validateImagePullPolicy("workload image pull policy", params.ImagePullPolicy); err != nil {
		return params, err
	}
	if err := validateImagePullPolicy("sandbox runtime image pull policy", params.SandboxRuntimeImagePullPolicy); err != nil {
		return params, err
	}
	if err := requireDNS1123Subdomain("sandbox bootstrap Secret name", params.SandboxBootstrapSecretName); err != nil {
		return params, err
	}
	if params.ServiceAccountName == "" {
		params.ServiceAccountName = "default"
	}
	if err := requireDNS1123Subdomain("service account name", params.ServiceAccountName); err != nil {
		return params, err
	}
	if params.SandboxUID < 1 || params.SandboxUID > int64(^uint32(0)) || params.SandboxGID < 1 || params.SandboxGID > int64(^uint32(0)) {
		return params, fmt.Errorf("sandbox identity must use non-root 32-bit UID/GID values")
	}
	if params.BoundaryPort < 1024 || params.BoundaryPort > 65535 {
		return params, fmt.Errorf("sandbox runtime boundary port must be between 1024 and 65535")
	}
	if params.WorkspaceStorageSize == "" {
		params.WorkspaceStorageSize = defaultWorkspaceStorage
	}
	quantity, err := resource.ParseQuantity(params.WorkspaceStorageSize)
	if err != nil || quantity.Sign() <= 0 {
		return params, fmt.Errorf("workspace storage size %q must be a positive Kubernetes quantity", params.WorkspaceStorageSize)
	}
	if params.WorkspaceStorageClass != "" {
		if err := requireDNS1123Subdomain("workspace storage class", params.WorkspaceStorageClass); err != nil {
			return params, err
		}
	}
	if params.DefaultRuntimeClassName != "" {
		if err := requireDNS1123Subdomain("default runtime class name", params.DefaultRuntimeClassName); err != nil {
			return params, err
		}
	}
	seenSecrets := make(map[string]struct{}, len(params.ImagePullSecrets))
	for _, secretName := range params.ImagePullSecrets {
		if err := requireDNS1123Subdomain("image pull Secret name", secretName); err != nil {
			return params, err
		}
		if _, exists := seenSecrets[secretName]; exists {
			return params, fmt.Errorf("duplicate image pull Secret %q", secretName)
		}
		seenSecrets[secretName] = struct{}{}
	}
	return params, nil
}

func validateImagePullPolicy(field, value string) error {
	if value == "" || value == "Always" || value == "IfNotPresent" || value == "Never" {
		return nil
	}
	return fmt.Errorf("%s %q must be Always, IfNotPresent, or Never", field, value)
}

func requireDNS1123Label(field, value string) error {
	if value == "" || len(validation.IsDNS1123Label(value)) != 0 {
		return fmt.Errorf("%s %q must be a DNS-1123 label", field, value)
	}
	return nil
}

func requireDNS1123Subdomain(field, value string) error {
	if value == "" || len(validation.IsDNS1123Subdomain(value)) != 0 {
		return fmt.Errorf("%s %q must be a DNS-1123 subdomain", field, value)
	}
	return nil
}

func validateNoManagedRuntimeMountOverlap(mounts []VolumeMountConfig) error {
	for _, mount := range mounts {
		mountPath := path.Clean(mount.MountPath)
		if pathsOverlap(mountPath, "/.openshell") || mountPath == "/run" {
			return fmt.Errorf("driver_config mount path %q overlaps a managed runtime mount", mount.MountPath)
		}
	}
	return nil
}
