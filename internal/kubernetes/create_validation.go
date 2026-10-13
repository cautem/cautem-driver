package kubernetes

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func validateSuspendedAgentSandboxResource(resource map[string]any, params agentSandboxRuntimeRenderParams) error {
	if resource == nil {
		return fmt.Errorf("suspended Agent Sandbox resource is required")
	}
	if resource["kind"] != "Sandbox" || resource["apiVersion"] != params.SandboxResourceAPIVersion {
		return fmt.Errorf("agent Sandbox resource kind or apiVersion does not match Create parameters")
	}
	metadata, ok := resource["metadata"].(map[string]any)
	if !ok || metadata["name"] != params.SandboxResourceName || metadata["namespace"] != params.Namespace {
		return fmt.Errorf("agent Sandbox resource name or namespace does not match Create parameters")
	}
	labels, _ := metadata["labels"].(map[string]any)
	if labels[labelSandboxID] != params.SandboxID {
		return fmt.Errorf("agent Sandbox sandbox-id label does not match Create parameters")
	}
	annotations, _ := metadata["annotations"].(map[string]any)
	if annotations[annotationRuntimeGeneration] != params.Generation {
		return fmt.Errorf("agent Sandbox runtime generation annotation does not match Create parameters")
	}
	spec, ok := resource["spec"].(map[string]any)
	if !ok {
		return fmt.Errorf("agent Sandbox resource has no spec")
	}
	if params.SandboxResourceAPIVersion == sandboxAPIGroup+"/"+sandboxAPIVersionV1Beta1 {
		if spec["operatingMode"] != "Suspended" {
			return fmt.Errorf("v1beta1 Agent Sandbox must be created Suspended")
		}
	} else if !isZeroReplicaCount(spec["replicas"]) {
		return fmt.Errorf("v1alpha1 Agent Sandbox must be created with replicas=0")
	}
	podTemplate, ok := spec["podTemplate"].(map[string]any)
	if !ok {
		return fmt.Errorf("agent Sandbox podTemplate is required")
	}
	podMetadata, _ := podTemplate["metadata"].(map[string]any)
	podLabels, _ := podMetadata["labels"].(map[string]any)
	if podLabels[labelBoundaryRole] != "workload" || podLabels[labelBoundaryPair] != strings.ToLower(params.SandboxID) {
		return fmt.Errorf("agent Sandbox workload Pod template boundary labels do not match the sandbox")
	}
	podSpec, ok := podTemplate["spec"].(map[string]any)
	if !ok || podSpec["automountServiceAccountToken"] != false || podSpec["hostNetwork"] != false || podSpec["hostPID"] != false || podSpec["hostIPC"] != false || podSpec["shareProcessNamespace"] != false || podSpec["restartPolicy"] != "Never" {
		return fmt.Errorf("agent Sandbox workload Pod template violates the token or host namespace boundary")
	}
	if !onlyBootstrapSchedulingGate(podSpec) {
		return fmt.Errorf("agent Sandbox workload Pod template is missing the bootstrap scheduling gate")
	}
	if params.CautemProxyImage != "" {
		return validateCautemSuspendedAgentSandboxPod(podSpec, params)
	}
	secretName := generationSecretName("os-sandbox", params.SandboxID, params.Generation)
	if !podHasSecretReference(podSpec, secretName) {
		return fmt.Errorf("agent Sandbox workload Pod template does not reference its generation bootstrap Secret")
	}
	if podHasProjectedServiceAccountToken(podSpec) {
		return fmt.Errorf("agent Sandbox workload Pod template must not project a ServiceAccount token")
	}
	podSecurity, _ := podSpec["securityContext"].(map[string]any)
	seccomp, _ := podSecurity["seccompProfile"].(map[string]any)
	if podSecurity["runAsNonRoot"] != true || seccomp["type"] != "RuntimeDefault" {
		return fmt.Errorf("agent Sandbox workload Pod template must use non-root RuntimeDefault seccomp")
	}
	agent := namedContainer(podSpec, "containers", "agent")
	if agent == nil || containerHasGatewayCredentialEnv(agent) || containerMountsVolume(agent, sandboxBootstrapVolume) || !containerHasRequiredSecurity(agent) {
		return fmt.Errorf("agent Sandbox workload container violates the runtime security contract")
	}
	bootstrap := namedContainer(podSpec, "initContainers", sandboxBootstrapVolume)
	if bootstrap == nil || !containerMountsVolume(bootstrap, sandboxBootstrapVolume) || containerHasGatewayCredentialEnv(bootstrap) || !containerHasRequiredSecurity(bootstrap) {
		return fmt.Errorf("agent Sandbox trusted bootstrap init must mount its generation Secret")
	}
	if podReferencesSupervisorSecret(podSpec) {
		return fmt.Errorf("agent Sandbox workload Pod template must not reference supervisor credentials")
	}
	return nil
}

func validateCautemSuspendedAgentSandboxPod(podSpec map[string]any, params agentSandboxRuntimeRenderParams) error {
	containers := sliceValue(podSpec["containers"])
	if len(containers) != 2 || namedContainer(podSpec, "containers", "agent") == nil || namedContainer(podSpec, "containers", cautemWorkloadSSHDName) == nil {
		return fmt.Errorf("cautem workload Pod must contain exactly the agent and relay-only sshd containers")
	}
	if podSpec["dnsPolicy"] != "ClusterFirst" {
		return fmt.Errorf("cautem workload Pod must use cluster DNS for paired Service discovery")
	}
	secretName := generationSecretName("os-sandbox", params.SandboxID, params.Generation)
	if podSecretReference(podSpec, cautemWorkloadCredentialName) != secretName {
		return fmt.Errorf("cautem workload Pod template does not reference its generation credential Secret")
	}
	if podHasProjectedServiceAccountToken(podSpec) || podReferencesSupervisorSecret(podSpec) {
		return fmt.Errorf("cautem workload Pod must not project a ServiceAccount token or reference supervisor credentials")
	}
	podSecurity, _ := podSpec["securityContext"].(map[string]any)
	seccomp, _ := podSecurity["seccompProfile"].(map[string]any)
	if podSecurity["runAsNonRoot"] != true || seccomp["type"] != "RuntimeDefault" {
		return fmt.Errorf("cautem workload Pod must use non-root RuntimeDefault seccomp")
	}
	agent := namedContainer(podSpec, "containers", "agent")
	if agent == nil || containerHasGatewayCredentialEnv(agent) || !containerMountsVolume(agent, cautemWorkloadCredentialName) || !containerHasRequiredSecurity(agent) {
		return fmt.Errorf("cautem workload container violates its credential mount or runtime security contract")
	}
	if containerHasRawCautemTokenEnv(agent) {
		return fmt.Errorf("cautem workload container must not receive the gateway bearer token")
	}
	if anyInitContainerMountsVolume(podSpec, cautemWorkloadCredentialName) {
		return fmt.Errorf("cautem trusted init containers must not mount workload credentials")
	}
	helperInit := namedContainer(podSpec, "initContainers", cautemWorkloadRuntimeInit)
	if helperInit == nil || !containerHasRequiredSecurity(helperInit) {
		return fmt.Errorf("cautem runtime helper init must use the required container security context")
	}
	sshd := namedContainer(podSpec, "containers", cautemWorkloadSSHDName)
	if !containerHasRequiredSecurity(sshd) || sshd["image"] != helperInit["image"] || !reflect.DeepEqual(stringSlice(sshd["command"]), []string{cautemWorkloadRuntimeDir + "/cautem-sshd"}) {
		return fmt.Errorf("cautem relay-only sshd must use the trusted helper image and required container security")
	}
	if !reflect.DeepEqual(stringSlice(sshd["args"]), []string{
		"--socket", cautemWorkloadRunDir + "/sshd.sock", "--init", cautemWorkloadRuntimeDir + "/cautem-init",
		"--workdir", "/workspace", "--shell", "/bin/sh",
	}) || !containerMountsVolume(sshd, "cautem-runtime") || !containerMountsVolume(sshd, "cautem-run") || containerMountsVolume(sshd, cautemWorkloadCredentialName) {
		return fmt.Errorf("cautem relay-only sshd command or mounts violate the runtime boundary")
	}
	return nil
}

func validateAgentSandboxFenceEvidence(evidence agentSandboxFenceEvidence) error {
	if strings.TrimSpace(evidence.PolicyUID) == "" || strings.TrimSpace(evidence.ResourceVersion) == "" || evidence.Generation < 1 {
		return fmt.Errorf("workload NetworkPolicy fence observation is missing UID, generation, or resourceVersion")
	}
	return nil
}

func validateCreatedSandboxIdentity(identity agentSandboxResourceIdentity, params agentSandboxRuntimeRenderParams) error {
	if identity.Namespace != params.Namespace || identity.Name != params.SandboxResourceName || identity.APIVersion != params.SandboxResourceAPIVersion || strings.TrimSpace(identity.UID) == "" || !identity.Suspended || !identity.PodTemplateMatches || !identity.CreateMetadataMatches {
		return fmt.Errorf("created Agent Sandbox identity does not match the requested resource")
	}
	return nil
}

func validateAgentSandboxSupervisorIdentity(supervisor agentSandboxPodIdentity, params agentSandboxRuntimeRenderParams, sandboxUID string) error {
	if supervisor.Name != "os-supervisor-"+params.SandboxID || strings.TrimSpace(supervisor.UID) == "" || supervisor.OwnerSandboxUID != sandboxUID {
		return fmt.Errorf("supervisor Pod owner UID or identity does not match the Agent Sandbox")
	}
	if supervisor.BoundaryPair != strings.ToLower(params.SandboxID) || supervisor.BoundaryRole != "supervisor" {
		return fmt.Errorf("supervisor Pod boundary labels do not match the sandbox pair")
	}
	expectedServiceAccount := params.ServiceAccountName
	if expectedServiceAccount == "" {
		expectedServiceAccount = "default"
	}
	if supervisor.ServiceAccountName != expectedServiceAccount || supervisor.AdditionalContainers {
		return fmt.Errorf("supervisor Pod image, command, ServiceAccount, or container count changed")
	}
	if supervisor.BootstrapSecretName != generationSecretName("os-supervisor", params.SandboxID, params.Generation) {
		return fmt.Errorf("supervisor Pod references a stale or unexpected bootstrap Secret generation")
	}
	if params.CautemProxyImage != "" {
		if supervisor.Image != params.CautemProxyImage || !reflect.DeepEqual(supervisor.Command, cautemProxyCommandStrings()) {
			return fmt.Errorf("cautem proxy Pod image or command changed")
		}
		if supervisor.ProviderEnvSecretName != generationSecretName(proxyEnvSecretPrefix, params.SandboxID, params.Generation) {
			return fmt.Errorf("cautem proxy Pod references a stale or unexpected provider environment Secret")
		}
		if !supervisor.BootstrapGatePresent || !supervisor.ServiceAccountAutomountDisabled || supervisor.HasProjectedServiceAccountToken || supervisor.HasRawGatewayCredentialEnv || supervisor.CautemHasRawTokenEnv {
			return fmt.Errorf("cautem proxy Pod violates the Secret-file credential boundary")
		}
		if !supervisor.CautemContainerMatches || !supervisor.CautemVolumeSourcesMatch {
			return fmt.Errorf("admitted Cautem proxy Pod container or Secret volumes changed")
		}
		if !supervisor.HostNamespacesIsolated || !supervisor.RunAsNonRoot || !supervisor.ReadOnlyRootFilesystem || !supervisor.RuntimeDefaultSeccomp || !supervisor.DropAllCapabilities || !supervisor.PrivilegeEscalationDisabled {
			return fmt.Errorf("cautem proxy Pod violates the required non-root isolation and container security context")
		}
		return nil
	}
	if supervisor.Image != params.SupervisorImage || !reflect.DeepEqual(supervisor.Command, supervisorCommandStrings()) {
		return fmt.Errorf("supervisor Pod image or command changed")
	}
	if !supervisor.BootstrapGatePresent || !supervisor.ServiceAccountAutomountDisabled || !supervisor.HasProjectedServiceAccountToken || supervisor.ProjectedTokenAudience != "openshell-gateway" || supervisor.HasRawGatewayCredentialEnv {
		return fmt.Errorf("supervisor Pod violates the generation or ServiceAccount credential boundary")
	}
	if !supervisor.HostNamespacesIsolated || !supervisor.RunAsNonRoot || !supervisor.ReadOnlyRootFilesystem || !supervisor.RuntimeDefaultSeccomp || !supervisor.DropAllCapabilities || !supervisor.PrivilegeEscalationDisabled {
		return fmt.Errorf("supervisor Pod violates the required non-root isolation and container security context")
	}
	return nil
}

func validateAgentSandboxWorkloadIdentity(workload agentSandboxWorkloadIdentity, params agentSandboxRuntimeRenderParams, sandboxUID string, requestedResource map[string]any) error {
	if workload.Name != params.SandboxResourceName || strings.TrimSpace(workload.UID) == "" {
		return fmt.Errorf("gated workload Pod name or UID does not match the Agent Sandbox")
	}
	if workload.OwnerSandboxUID != sandboxUID {
		return fmt.Errorf("gated workload Pod owner UID does not match the created Agent Sandbox UID")
	}
	if workload.BoundaryPair != strings.ToLower(params.SandboxID) || workload.BoundaryRole != "workload" {
		return fmt.Errorf("gated workload Pod boundary labels do not match the sandbox pair")
	}
	requestedPodSpec, _, _ := unstructured.NestedMap(requestedResource, "spec", "podTemplate", "spec")
	expectedAgent := namedContainer(requestedPodSpec, "containers", "agent")
	if expectedAgent == nil || workload.Image != expectedAgent["image"] || !reflect.DeepEqual(workload.Command, stringSlice(expectedAgent["command"])) || workload.AdditionalApplicationContainers {
		return fmt.Errorf("admitted workload Pod image, command, or application container count changed")
	}
	if workload.SandboxBootstrapSecret != generationSecretName("os-sandbox", params.SandboxID, params.Generation) {
		return fmt.Errorf("gated workload Pod references a stale or unexpected bootstrap Secret generation")
	}
	if !workload.BootstrapGatePresent || !workload.SchedulingGatesMatch {
		return fmt.Errorf("gated workload Pod is missing the bootstrap scheduling gate")
	}
	if !workload.ServiceAccountAutomountDisabled || workload.HasProjectedServiceAccountToken {
		return fmt.Errorf("workload Pod must not receive a Kubernetes ServiceAccount token")
	}
	requestedInitNames := initContainerNames(requestedPodSpec)
	if !reflect.DeepEqual(workload.InitContainerNames, requestedInitNames) {
		return fmt.Errorf("admitted workload Pod init container set changed")
	}
	if params.CautemProxyImage != "" {
		if workload.HasGatewayCredentialEnv || !workload.CautemAgentMountsPrivateSecret || workload.CautemInitMountsPrivateSecret {
			return fmt.Errorf("cautem workload Pod violates the private credential mount boundary")
		}
		if !workload.CautemSSHDContainerMatches {
			return fmt.Errorf("admitted Cautem relay-only sshd container changed")
		}
		if !workload.AgentContainerMatches || !workload.InitContainerSpecsMatch || !workload.PodVolumeSourcesMatch || !workload.PodSecurityContextMatches || !workload.ServiceAccountMatches {
			return fmt.Errorf("admitted Cautem workload Pod does not match its requested runtime template")
		}
		if !workload.HostNamespacesIsolated || !workload.RunAsNonRoot || !workload.RuntimeDefaultSeccomp || !workload.DropAllCapabilities || !workload.PrivilegeEscalationDisabled {
			return fmt.Errorf("admitted Cautem workload Pod violates the required non-root isolation and container security context")
		}
		return nil
	}
	if len(workload.SupervisorSecretReferences) != 0 {
		return fmt.Errorf("workload Pod must not reference supervisor credential Secrets")
	}
	var violations []string
	if workload.HasGatewayCredentialEnv {
		violations = append(violations, "gateway credential env")
	}
	if workload.AgentMountsBootstrapSecret {
		violations = append(violations, "agent bootstrap Secret mount")
	}
	if !workload.TrustedInitMountsBootstrapSecret {
		violations = append(violations, "trusted init bootstrap Secret mount")
	}
	if workload.OtherInitContainersMountBootstrapSecret {
		violations = append(violations, "other init container bootstrap Secret mount")
	}
	if !workload.AgentContainerMatches {
		violations = append(violations, "agent container spec")
	}
	if !workload.InitContainerSpecsMatch {
		violations = append(violations, "init container specs")
	}
	if !workload.PodVolumeSourcesMatch {
		violations = append(violations, "Pod volume sources")
	}
	if !workload.PodSecurityContextMatches {
		violations = append(violations, "Pod security context")
	}
	if !workload.ServiceAccountMatches {
		violations = append(violations, "ServiceAccount")
	}
	if len(violations) != 0 {
		return fmt.Errorf("admitted workload Pod violates the gateway credential or bootstrap Secret mount boundary: %s", strings.Join(violations, ", "))
	}
	if !workload.HostNamespacesIsolated || !workload.RunAsNonRoot || !workload.RuntimeDefaultSeccomp || !workload.DropAllCapabilities || !workload.PrivilegeEscalationDisabled {
		return fmt.Errorf("admitted workload Pod violates the required non-root isolation and container security context")
	}
	return nil
}

func validateGenerationBootstrapSecrets(secrets []map[string]any, identity agentSandboxCreateIdentity) error {
	if len(secrets) != 2 {
		return fmt.Errorf("runtime generation must create exactly two trust-separated bootstrap Secrets")
	}
	want := map[string]struct {
		name      string
		ownerName string
		ownerUID  string
		required  []string
		allowed   []string
	}{
		"sandbox": {
			name:      generationSecretName("os-sandbox", identity.SandboxID, identity.Generation),
			ownerName: identity.WorkloadName, ownerUID: identity.WorkloadUID,
			required: []string{
				bootstrapBoundaryConfigKey, bootstrapBoundaryCertKey, bootstrapBoundaryKeyKey,
				bridgeTargetClientCAFile, bridgeTargetServerCert, bridgeTargetServerKey,
				bridgeControlClientCAFile, bridgeControlClientCert, bridgeControlClientKey,
			},
			allowed: []string{
				bootstrapBoundaryConfigKey, bootstrapBoundaryCertKey, bootstrapBoundaryKeyKey,
				bridgeTargetClientCAFile, bridgeTargetServerCert, bridgeTargetServerKey,
				bridgeControlClientCAFile, bridgeControlClientCert, bridgeControlClientKey,
			},
		},
		"supervisor": {
			name:      generationSecretName("os-supervisor", identity.SandboxID, identity.Generation),
			ownerName: identity.SupervisorName, ownerUID: identity.SupervisorUID,
			required: []string{
				bootstrapDescriptorKey, bootstrapSupervisorAuth, bootstrapProxyCACert, bootstrapProxyCAKey,
				bridgeTargetServerCAFile, bridgeTargetClientCert, bridgeTargetClientKey,
				bridgeControlServerCAFile, bridgeControlServerCert, bridgeControlServerKey,
			},
			allowed: []string{
				bootstrapDescriptorKey, bootstrapSupervisorAuth, bootstrapProxyCACert, bootstrapProxyCAKey,
				bridgeTargetServerCAFile, bridgeTargetClientCert, bridgeTargetClientKey,
				bridgeControlServerCAFile, bridgeControlServerCert, bridgeControlServerKey,
				"upstream-proxy-ca.pem", "client-ca.crt",
			},
		},
	}
	seen := make(map[string]struct{}, len(secrets))
	for _, secret := range secrets {
		if secret == nil || secret["apiVersion"] != "v1" || secret["kind"] != "Secret" || secret["immutable"] != true || secret["type"] != "Opaque" {
			return fmt.Errorf("runtime bootstrap Secret must be immutable v1 Opaque")
		}
		metadata, _ := secret["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		if metadata["namespace"] != identity.Namespace {
			return fmt.Errorf("runtime bootstrap Secret namespace does not match the sandbox")
		}
		secretKind := ""
		switch name {
		case want["sandbox"].name:
			secretKind = "sandbox"
		case want["supervisor"].name:
			secretKind = "supervisor"
		default:
			return fmt.Errorf("runtime bootstrap Secret name does not match the active generation")
		}
		if _, duplicate := seen[secretKind]; duplicate {
			return fmt.Errorf("duplicate %s bootstrap Secret", secretKind)
		}
		seen[secretKind] = struct{}{}
		data, ok := secret["data"].(map[string]any)
		if !ok {
			return fmt.Errorf("%s bootstrap Secret data is missing", secretKind)
		}
		for _, key := range want[secretKind].required {
			if _, exists := data[key]; !exists {
				return fmt.Errorf("%s bootstrap Secret is missing required key %q", secretKind, key)
			}
		}
		allowed := make(map[string]struct{}, len(want[secretKind].allowed))
		for _, key := range want[secretKind].allowed {
			allowed[key] = struct{}{}
		}
		for key := range data {
			if _, exists := allowed[key]; !exists {
				return fmt.Errorf("%s bootstrap Secret contains an unexpected key", secretKind)
			}
			encoded, ok := data[key].(string)
			if !ok {
				return fmt.Errorf("%s bootstrap Secret key %q must be base64-encoded data", secretKind, key)
			}
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil || len(decoded) == 0 {
				return fmt.Errorf("%s bootstrap Secret key %q must contain non-empty base64 data", secretKind, key)
			}
		}
		owners, _ := metadata["ownerReferences"].([]any)
		if len(owners) != 1 {
			return fmt.Errorf("%s bootstrap Secret must have exactly one Pod owner", secretKind)
		}
		owner, _ := owners[0].(map[string]any)
		if owner["apiVersion"] != "v1" || owner["kind"] != "Pod" || owner["name"] != want[secretKind].ownerName || owner["uid"] != want[secretKind].ownerUID || owner["blockOwnerDeletion"] != false || owner["controller"] == true {
			return fmt.Errorf("%s bootstrap Secret owner must match the current generation Pod UID", secretKind)
		}
	}
	if len(seen) != 2 {
		return fmt.Errorf("sandbox and supervisor bootstrap Secrets must be separate")
	}
	return nil
}
