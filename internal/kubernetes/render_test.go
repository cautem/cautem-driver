package kubernetes

import (
	"strings"
	"testing"
)

func TestOpenShellAgentSandboxRenderStartsSuspendedWithGatedWorkload(t *testing.T) {
	config, err := ParseSandboxDriverConfig(`{
		"pod": {
			"node_selector": {"pool": "sandbox"},
			"runtime_class_name": "kata",
			"priority_class_name": "sandbox-low"
		},
		"containers": {"agent": {
			"resources": {"requests": {"cpu": "250m"}},
			"volume_mounts": [{"name": "user-data", "mount_path": "/mnt/data"}]
		}},
		"volumes": [{"name": "user-data", "persistent_volume_claim": {"claim_name": "pvc-user-data"}}]
	}`)
	if err != nil {
		t.Fatalf("ParseSandboxDriverConfig() error = %v", err)
	}

	resource, err := renderAgentSandboxResource(config, testAgentSandboxRenderParams())
	if err != nil {
		t.Fatalf("renderAgentSandboxResource() error = %v", err)
	}
	if got := resource["apiVersion"]; got != "agents.x-k8s.io/v1beta1" {
		t.Fatalf("apiVersion = %v; want agents.x-k8s.io/v1beta1", got)
	}
	if got := resource["kind"]; got != "Sandbox" {
		t.Fatalf("kind = %v; want Sandbox", got)
	}
	metadata := renderMap(t, resource["metadata"], "metadata")
	wantNamespace, err := workspaceNamespaceName("gateway-1", "team-a")
	if err != nil {
		t.Fatal(err)
	}
	if metadata["name"] != "team-a-demo" || metadata["namespace"] != wantNamespace {
		t.Fatalf("Agent Sandbox identity = %#v", metadata)
	}
	labels := renderMap(t, metadata["labels"], "metadata.labels")
	if labels["openshell.ai/managed-by"] != "openshell" || labels["openshell.ai/sandbox-id"] != "sandbox-123" || labels["openshell.ai/gateway-id"] != "gateway-1" {
		t.Fatalf("Agent Sandbox ownership labels = %#v", labels)
	}

	spec := renderMap(t, resource["spec"], "spec")
	if spec["operatingMode"] != "Suspended" {
		t.Fatalf("beta operatingMode = %v; want Suspended", spec["operatingMode"])
	}
	if _, exists := spec["replicas"]; exists {
		t.Fatal("beta Agent Sandbox must not set alpha replicas field")
	}
	claimTemplates := renderList(t, spec["volumeClaimTemplates"], "spec.volumeClaimTemplates")
	if len(claimTemplates) != 1 {
		t.Fatalf("volumeClaimTemplates count = %d; want one default workspace claim", len(claimTemplates))
	}
	claim := renderMap(t, claimTemplates[0], "volumeClaimTemplates[0]")
	claimSpec := renderMap(t, claim["spec"], "volumeClaimTemplates[0].spec")
	claimStorage := renderMap(t, renderMap(t, claimSpec["resources"], "claim.resources")["requests"], "claim.resources.requests")
	if claimStorage["storage"] != "5Gi" || claimSpec["storageClassName"] != "fast-ssd" {
		t.Fatalf("workspace claim = %#v", claim)
	}

	podTemplate := renderMap(t, spec["podTemplate"], "spec.podTemplate")
	podMetadata := renderMap(t, podTemplate["metadata"], "podTemplate.metadata")
	podLabels := renderMap(t, podMetadata["labels"], "podTemplate.metadata.labels")
	if podLabels["openshell.ai/boundary-role"] != "workload" || podLabels["openshell.ai/boundary-pair"] != "sandbox-123" {
		t.Fatalf("workload pair labels = %#v", podLabels)
	}
	podSpec := renderMap(t, podTemplate["spec"], "podTemplate.spec")
	for _, field := range []string{"hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace", "automountServiceAccountToken"} {
		if podSpec[field] != false {
			t.Errorf("pod spec %s = %v; want false", field, podSpec[field])
		}
	}
	if podSpec["restartPolicy"] != "Never" || podSpec["runtimeClassName"] != "kata" {
		t.Fatalf("pod restart/runtime class = %v/%v", podSpec["restartPolicy"], podSpec["runtimeClassName"])
	}
	gates := renderList(t, podSpec["schedulingGates"], "podSpec.schedulingGates")
	if len(gates) != 1 || renderMap(t, gates[0], "schedulingGates[0]")["name"] != "openshell.ai/bootstrap" {
		t.Fatalf("workload scheduling gates = %#v", gates)
	}
	if podSpec["dnsPolicy"] != "None" {
		t.Fatalf("dnsPolicy = %v; want None", podSpec["dnsPolicy"])
	}
	imagePullSecrets := renderList(t, podSpec["imagePullSecrets"], "podSpec.imagePullSecrets")
	if len(imagePullSecrets) != 1 || renderMap(t, imagePullSecrets[0], "imagePullSecrets[0]")["name"] != "registry-auth" {
		t.Fatalf("imagePullSecrets = %#v", imagePullSecrets)
	}

	podSecurity := renderMap(t, podSpec["securityContext"], "podSpec.securityContext")
	if podSecurity["runAsUser"] != int64(10001) || podSecurity["runAsGroup"] != int64(10002) || podSecurity["runAsNonRoot"] != true || podSecurity["fsGroup"] != int64(10002) {
		t.Fatalf("pod security context = %#v", podSecurity)
	}
	if renderMap(t, podSecurity["seccompProfile"], "podSecurity.seccompProfile")["type"] != "RuntimeDefault" {
		t.Fatalf("pod seccomp profile = %#v", podSecurity["seccompProfile"])
	}

	containers := renderList(t, podSpec["containers"], "podSpec.containers")
	if len(containers) != 1 {
		t.Fatalf("workload container count = %d; want 1", len(containers))
	}
	agent := renderMap(t, containers[0], "podSpec.containers[0]")
	if agent["name"] != "agent" || agent["image"] != "registry.example/sandbox:v1" {
		t.Fatalf("workload container identity = %#v", agent)
	}
	if agentSecurity := renderMap(t, agent["securityContext"], "agent.securityContext"); agentSecurity["runAsNonRoot"] != true || agentSecurity["allowPrivilegeEscalation"] != false || renderMap(t, agentSecurity["capabilities"], "agent.securityContext.capabilities")["drop"].([]any)[0] != "ALL" {
		t.Fatalf("workload container security context = %#v", agent["securityContext"])
	}
	if !strings.Contains(renderList(t, agent["command"], "agent.command")[0].(string), "openshell-sandbox") {
		t.Fatalf("workload command = %#v", agent["command"])
	}
	if hasVolumeMount(agent, "openshell-sandbox-bootstrap") {
		t.Fatal("untrusted workload container must not mount the bootstrap Secret")
	}
	if hasEnv(agent, "OPENSHELL_ENDPOINT") || hasEnv(agent, "OPENSHELL_SANDBOX_TOKEN") || hasEnv(agent, "OPENSHELL_K8S_SA_TOKEN_FILE") {
		t.Fatalf("gateway credentials or Kubernetes token leaked into workload env: %#v", agent["env"])
	}
	if !hasVolumeMount(agent, "openshell-runtime") || !volumeMountReadOnly(agent, "openshell-runtime") {
		t.Fatal("workload must mount the trusted runtime read-only")
	}
	if !hasVolumeMount(agent, "user-data") {
		t.Fatal("driver_config PVC mount missing from workload container")
	}

	initContainers := renderList(t, podSpec["initContainers"], "podSpec.initContainers")
	bootstrap := findRenderMap(t, initContainers, "openshell-sandbox-bootstrap")
	if !hasVolumeMount(bootstrap, "openshell-sandbox-bootstrap") {
		t.Fatal("trusted bootstrap init container must mount the bootstrap Secret")
	}
	if !hasVolumeMount(bootstrap, "openshell-runtime") || !hasVolumeMount(bootstrap, "openshell-runtime-state") {
		t.Fatalf("bootstrap init container runtime mounts = %#v", bootstrap["volumeMounts"])
	}
	workspaceInit := findRenderMap(t, initContainers, "workspace-init")
	if !hasVolumeMount(workspaceInit, "workspace") {
		t.Fatal("workspace seeding init container must mount the default PVC")
	}

	volumes := renderList(t, podSpec["volumes"], "podSpec.volumes")
	bootstrapSecret := findRenderMap(t, volumes, "openshell-sandbox-bootstrap")
	if renderMap(t, bootstrapSecret["secret"], "bootstrap secret volume")["secretName"] != "os-sandbox-sandbox-123-gen1" {
		t.Fatalf("bootstrap Secret reference = %#v", bootstrapSecret["secret"])
	}
	if renderMap(t, findRenderMap(t, volumes, "openshell-pod-identity")["downwardAPI"], "pod identity volume")["items"] == nil {
		t.Fatal("workload Pod UID downward API volume missing")
	}
	for _, volume := range volumes {
		volumeMap := renderMap(t, volume, "workload volume")
		if secret, ok := volumeMap["secret"].(map[string]any); ok && secret["secretName"] == "os-supervisor-sandbox-123-gen1" {
			t.Fatal("workload Pod must never reference the supervisor credential Secret")
		}
	}
}

func TestAgentSandboxRenderMapsGatewayGPURequestToNVIDIAResources(t *testing.T) {
	params := testAgentSandboxRenderParams()
	params.GPU = true
	params.GPUCount = 2
	resource, err := renderAgentSandboxResource(SandboxDriverConfig{}, params)
	if err != nil {
		t.Fatalf("renderAgentSandboxResource() error = %v", err)
	}
	spec := renderMap(t, resource["spec"], "spec")
	podTemplate := renderMap(t, spec["podTemplate"], "spec.podTemplate")
	podSpec := renderMap(t, podTemplate["spec"], "spec.podTemplate.spec")
	agent := findRenderMap(t, renderList(t, podSpec["containers"], "containers"), "agent")
	resources := renderMap(t, agent["resources"], "agent.resources")
	for _, field := range []string{"requests", "limits"} {
		values := renderMap(t, resources[field], "agent.resources."+field)
		if values[nvidiaGPUResourceName] != "2" {
			t.Errorf("%s[%q] = %v; want 2", field, nvidiaGPUResourceName, values[nvidiaGPUResourceName])
		}
	}
}

func TestAgentSandboxRenderDefaultsGPURequestToOneDevice(t *testing.T) {
	params := testAgentSandboxRenderParams()
	params.GPU = true
	resource, err := renderAgentSandboxResource(SandboxDriverConfig{}, params)
	if err != nil {
		t.Fatalf("renderAgentSandboxResource() error = %v", err)
	}
	spec := renderMap(t, resource["spec"], "spec")
	podTemplate := renderMap(t, spec["podTemplate"], "spec.podTemplate")
	podSpec := renderMap(t, podTemplate["spec"], "spec.podTemplate.spec")
	agent := findRenderMap(t, renderList(t, podSpec["containers"], "containers"), "agent")
	resources := renderMap(t, agent["resources"], "agent.resources")
	limits := renderMap(t, resources["limits"], "agent.resources.limits")
	if limits[nvidiaGPUResourceName] != "1" {
		t.Fatalf("GPU limit = %v; want 1", limits[nvidiaGPUResourceName])
	}
}

func TestParseSandboxDriverConfigRejectsUnaccountedNVIDIAGPU(t *testing.T) {
	_, err := ParseSandboxDriverConfig(`{"containers":{"agent":{"resources":{"limits":{"nvidia.com/gpu":"1"}}}}}`)
	if err == nil || !strings.Contains(err.Error(), "Gateway GPU resource field") {
		t.Fatalf("ParseSandboxDriverConfig() error = %v; want unaccounted GPU request rejection", err)
	}
}

func TestOpenShellAgentSandboxRenderSuppressesWorkspacePVCForExplicitSandboxMount(t *testing.T) {
	config, err := ParseSandboxDriverConfig(`{
		"volumes": [{"name": "user-data", "persistent_volume_claim": {"claim_name": "pvc-user-data"}}],
		"containers": {"agent": {"volume_mounts": [{"name": "user-data", "mount_path": "/sandbox/custom"}]}}
	}`)
	if err != nil {
		t.Fatalf("ParseSandboxDriverConfig() error = %v", err)
	}
	resource, err := renderAgentSandboxResource(config, testAgentSandboxRenderParams())
	if err != nil {
		t.Fatalf("renderAgentSandboxResource() error = %v", err)
	}
	spec := renderMap(t, resource["spec"], "spec")
	if _, exists := spec["volumeClaimTemplates"]; exists {
		t.Fatal("default workspace claim must not compete with driver_config storage under /sandbox")
	}
	podSpec := renderMap(t, renderMap(t, spec["podTemplate"], "podTemplate")["spec"], "podSpec")
	for _, initContainer := range renderList(t, podSpec["initContainers"], "initContainers") {
		if initContainer.(map[string]any)["name"] == "workspace-init" {
			t.Fatal("workspace seeding init must be suppressed with the default workspace PVC")
		}
	}
}

func TestOpenShellAgentSandboxRenderUsesAlphaReplicaField(t *testing.T) {
	params := testAgentSandboxRenderParams()
	params.APIVersion = sandboxAPIVersionV1Alpha1
	params.EnableUserNamespaces = true
	resource, err := renderAgentSandboxResource(SandboxDriverConfig{}, params)
	if err != nil {
		t.Fatalf("renderAgentSandboxResource() error = %v", err)
	}
	spec := renderMap(t, resource["spec"], "spec")
	if spec["replicas"] != 0 {
		t.Fatalf("alpha replicas = %v; want 0 until runtime boundary is installed", spec["replicas"])
	}
	if _, exists := spec["operatingMode"]; exists {
		t.Fatal("alpha Agent Sandbox must not use beta operatingMode field")
	}
	podTemplate := renderMap(t, spec["podTemplate"], "podTemplate")
	if renderMap(t, podTemplate["spec"], "podTemplate.spec")["hostUsers"] != false {
		t.Fatal("user namespace intent must render hostUsers=false")
	}
}

func TestOpenShellAgentSandboxRenderRejectsMountsOverManagedRuntime(t *testing.T) {
	config, err := ParseSandboxDriverConfig(`{
		"volumes": [{"name": "user-data", "persistent_volume_claim": {"claim_name": "pvc-user-data"}}],
		"containers": {"agent": {"volume_mounts": [{"name": "user-data", "mount_path": "/.openshell"}]}}
	}`)
	if err != nil {
		t.Fatalf("ParseSandboxDriverConfig() error = %v", err)
	}
	_, err = renderAgentSandboxResource(config, testAgentSandboxRenderParams())
	if err == nil || !strings.Contains(err.Error(), "managed runtime mount") {
		t.Fatalf("renderAgentSandboxResource() error = %v; want managed runtime mount conflict", err)
	}
}

func TestOpenShellAgentSandboxRenderRejectsMissingBootstrapIdentity(t *testing.T) {
	params := testAgentSandboxRenderParams()
	params.SandboxBootstrapSecretName = ""
	if _, err := renderAgentSandboxResource(SandboxDriverConfig{}, params); err == nil || !strings.Contains(err.Error(), "bootstrap Secret") {
		t.Fatalf("renderAgentSandboxResource() error = %v; want missing bootstrap Secret", err)
	}
	params = testAgentSandboxRenderParams()
	params.SandboxUID = 0
	if _, err := renderAgentSandboxResource(SandboxDriverConfig{}, params); err == nil || !strings.Contains(err.Error(), "non-root") {
		t.Fatalf("renderAgentSandboxResource() error = %v; want non-root identity validation", err)
	}
}

func TestOpenShellSupervisorRenderBindsResourcesToSandboxUID(t *testing.T) {
	resources, err := renderAgentSandboxRuntimeResources(testAgentSandboxRuntimeRenderParams())
	if err != nil {
		t.Fatalf("renderAgentSandboxRuntimeResources() error = %v", err)
	}

	for _, key := range []string{"boundaryService", "controlService", "proxyService", "supervisorPod"} {
		resource := renderMap(t, resources[key], key)
		metadata := renderMap(t, resource["metadata"], key+".metadata")
		owners := renderList(t, metadata["ownerReferences"], key+".metadata.ownerReferences")
		if len(owners) != 1 {
			t.Fatalf("%s owner references = %#v; want one AgentSandbox owner", key, owners)
		}
		owner := renderMap(t, owners[0], key+" owner")
		if owner["apiVersion"] != "agents.x-k8s.io/v1beta1" || owner["kind"] != "Sandbox" || owner["name"] != "team-a-demo" || owner["uid"] != "cr-uid-123" {
			t.Fatalf("%s owner reference = %#v", key, owner)
		}
		if owner["blockOwnerDeletion"] != false {
			t.Fatalf("%s owner reference blockOwnerDeletion = %v; want false", key, owner["blockOwnerDeletion"])
		}
	}

	service := renderMap(t, resources["boundaryService"], "boundaryService")
	serviceSpec := renderMap(t, service["spec"], "boundaryService.spec")
	selector := renderMap(t, serviceSpec["selector"], "boundaryService.spec.selector")
	if selector[labelBoundaryPair] != "sandbox-123" || selector[labelBoundaryRole] != "workload" {
		t.Fatalf("boundary Service selector = %#v", selector)
	}
	ports := renderList(t, serviceSpec["ports"], "boundaryService.spec.ports")
	port := renderMap(t, ports[0], "boundaryService.spec.ports[0]")
	if port["port"] != int64(5500) || port["targetPort"] != int64(5500) || port["protocol"] != "TCP" {
		t.Fatalf("boundary Service port = %#v", port)
	}
	controlService := renderMap(t, resources["controlService"], "controlService")
	controlSpec := renderMap(t, controlService["spec"], "controlService.spec")
	controlSelector := renderMap(t, controlSpec["selector"], "controlService.spec.selector")
	if controlSelector[labelBoundaryPair] != "sandbox-123" || controlSelector[labelBoundaryRole] != "supervisor" {
		t.Fatalf("control Service selector = %#v", controlSelector)
	}
	controlPorts := renderList(t, controlSpec["ports"], "controlService.spec.ports")
	controlPort := renderMap(t, controlPorts[0], "controlService.spec.ports[0]")
	if controlPort["port"] != supervisorControlPort || controlPort["targetPort"] != supervisorControlPort {
		t.Fatalf("control Service port = %#v", controlPort)
	}
	proxyService := renderMap(t, resources["proxyService"], "proxyService")
	proxySpec := renderMap(t, proxyService["spec"], "proxyService.spec")
	proxySelector := renderMap(t, proxySpec["selector"], "proxyService.spec.selector")
	if proxySelector[labelBoundaryPair] != "sandbox-123" || proxySelector[labelBoundaryRole] != "supervisor" {
		t.Fatalf("proxy Service selector = %#v", proxySelector)
	}
	proxyPort := renderMap(t, renderList(t, proxySpec["ports"], "proxyService.spec.ports")[0], "proxyService.spec.ports[0]")
	if proxyPort["port"] != cautemProxyListenPort || proxyPort["targetPort"] != cautemProxyListenPort {
		t.Fatalf("proxy Service port = %#v", proxyPort)
	}
}

func TestOpenShellSupervisorRenderUsesGenerationSecretAndAudienceToken(t *testing.T) {
	params := testAgentSandboxRuntimeRenderParams()
	resources, err := renderAgentSandboxRuntimeResources(params)
	if err != nil {
		t.Fatalf("renderAgentSandboxRuntimeResources() error = %v", err)
	}
	pod := renderMap(t, resources["supervisorPod"], "supervisorPod")
	podSpec := renderMap(t, renderMap(t, pod["spec"], "supervisorPod.spec"), "supervisorPod.spec")
	if podSpec["automountServiceAccountToken"] != false {
		t.Fatalf("supervisor automountServiceAccountToken = %v; want false", podSpec["automountServiceAccountToken"])
	}

	volumes := renderList(t, podSpec["volumes"], "supervisorPod.spec.volumes")
	bootstrap := findRenderMap(t, volumes, "bootstrap")
	if got := renderMap(t, bootstrap["secret"], "bootstrap.secret")["secretName"]; got != "os-supervisor-sandbox-123-gen7" {
		t.Fatalf("supervisor bootstrap Secret = %v; want generation-specific Secret", got)
	}
	token := findRenderMap(t, volumes, "sa-token")
	projected := renderMap(t, token["projected"], "sa-token.projected")
	sources := renderList(t, projected["sources"], "sa-token.projected.sources")
	serviceAccountToken := renderMap(t, renderMap(t, sources[0], "projected source")["serviceAccountToken"], "serviceAccountToken")
	if serviceAccountToken["audience"] != "openshell-gateway" || serviceAccountToken["path"] != "token" || serviceAccountToken["expirationSeconds"] != int64(600) {
		t.Fatalf("projected service account token = %#v", serviceAccountToken)
	}

	container := renderMap(t, renderList(t, podSpec["containers"], "supervisorPod.spec.containers")[0], "supervisor container")
	security := renderMap(t, container["securityContext"], "supervisor.securityContext")
	if security["runAsNonRoot"] != true || security["readOnlyRootFilesystem"] != true || security["allowPrivilegeEscalation"] != false || renderList(t, renderMap(t, security["capabilities"], "supervisor.capabilities")["drop"], "supervisor.capabilities.drop")[0] != "ALL" {
		t.Fatalf("supervisor security context = %#v", security)
	}
	if hasEnv(container, "OPENSHELL_SANDBOX_TOKEN") || hasEnv(container, "OPENSHELL_K8S_SA_TOKEN") {
		t.Fatalf("supervisor token must be projected to a file, not environment: %#v", container["env"])
	}
	if !hasEnv(container, "OPENSHELL_K8S_SA_TOKEN_FILE") {
		t.Fatalf("supervisor token file path missing from environment: %#v", container["env"])
	}

	params.Generation = "gen8"
	rotated, err := renderAgentSandboxRuntimeResources(params)
	if err != nil {
		t.Fatalf("renderAgentSandboxRuntimeResources(rotated) error = %v", err)
	}
	rotatedPod := renderMap(t, rotated["supervisorPod"], "rotated supervisorPod")
	rotatedSpec := renderMap(t, rotatedPod["spec"], "rotated supervisorPod.spec")
	rotatedBootstrap := findRenderMap(t, renderList(t, rotatedSpec["volumes"], "rotated volumes"), "bootstrap")
	if got := renderMap(t, rotatedBootstrap["secret"], "rotated bootstrap.secret")["secretName"]; got != "os-supervisor-sandbox-123-gen8" {
		t.Fatalf("rotated supervisor Secret = %v; want new generation reference", got)
	}
}

func TestOpenShellRuntimeFenceBlocksWorkloadEgress(t *testing.T) {
	resources, err := renderAgentSandboxRuntimeResources(testAgentSandboxRuntimeRenderParams())
	if err != nil {
		t.Fatalf("renderAgentSandboxRuntimeResources() error = %v", err)
	}
	policy := renderMap(t, resources["workloadNetworkPolicy"], "workloadNetworkPolicy")
	if policy["apiVersion"] != "networking.k8s.io/v1" || policy["kind"] != "NetworkPolicy" {
		t.Fatalf("workload fence identity = %#v/%#v", policy["apiVersion"], policy["kind"])
	}
	policyMetadata := renderMap(t, policy["metadata"], "workloadNetworkPolicy.metadata")
	policyLabels := renderMap(t, policyMetadata["labels"], "workloadNetworkPolicy.metadata.labels")
	if policyLabels[labelManagedBy] != managedByValue || policyLabels["openshell.ai/component"] != workloadFenceComponent || policyLabels[labelBoundaryPair] != "sandbox-123" {
		t.Fatalf("workload fence ownership labels = %#v", policyLabels)
	}
	spec := renderMap(t, policy["spec"], "workloadNetworkPolicy.spec")
	selector := renderMap(t, spec["podSelector"], "workloadNetworkPolicy.spec.podSelector")
	selectorLabels := renderMap(t, selector["matchLabels"], "workload selector labels")
	if selectorLabels[labelBoundaryRole] != "workload" || selectorLabels[labelBoundaryPair] != "sandbox-123" {
		t.Fatalf("workload fence selector = %#v", selector)
	}
	egress := renderList(t, spec["egress"], "workloadNetworkPolicy.spec.egress")
	if len(egress) != 2 {
		t.Fatalf("workload fence egress rules = %#v; want paired control/proxy and DNS rules", egress)
	}
	egressRule := renderMap(t, egress[0], "workload control egress rule")
	egressPeer := renderMap(t, renderList(t, egressRule["to"], "workload egress peer")[0], "workload egress peer")
	egressLabels := renderMap(t, renderMap(t, egressPeer["podSelector"], "supervisor egress selector")["matchLabels"], "supervisor egress labels")
	if egressLabels[labelBoundaryRole] != "supervisor" || egressLabels[labelBoundaryPair] != "sandbox-123" {
		t.Fatalf("workload control egress peer = %#v", egressLabels)
	}
	egressPorts := renderList(t, egressRule["ports"], "workload egress ports")
	if len(egressPorts) != 2 {
		t.Fatalf("workload egress ports = %#v; want control and proxy ports", egressPorts)
	}
	egressPort := renderMap(t, egressPorts[0], "workload control egress port")
	if egressPort["port"] != supervisorControlPort || egressPort["protocol"] != "TCP" {
		t.Fatalf("workload control egress port = %#v", egressPort)
	}
	proxyEgressPort := renderMap(t, egressPorts[1], "workload proxy egress port")
	if proxyEgressPort["port"] != cautemProxyListenPort || proxyEgressPort["protocol"] != "TCP" {
		t.Fatalf("workload proxy egress port = %#v", proxyEgressPort)
	}
	dnsRule := renderMap(t, egress[1], "workload DNS egress rule")
	dnsPeer := renderMap(t, renderList(t, dnsRule["to"], "workload DNS egress peer")[0], "workload DNS egress peer")
	namespaceLabels := renderMap(t, renderMap(t, dnsPeer["namespaceSelector"], "DNS namespace selector")["matchLabels"], "DNS namespace labels")
	podLabels := renderMap(t, renderMap(t, dnsPeer["podSelector"], "DNS pod selector")["matchLabels"], "DNS pod labels")
	if namespaceLabels["kubernetes.io/metadata.name"] != "kube-system" || podLabels["k8s-app"] != "kube-dns" {
		t.Fatalf("workload DNS peer = %#v", dnsPeer)
	}
	dnsPorts := renderList(t, dnsRule["ports"], "workload DNS ports")
	if len(dnsPorts) != 2 {
		t.Fatalf("workload DNS ports = %#v; want UDP and TCP 53", dnsPorts)
	}
	for _, raw := range dnsPorts {
		port := renderMap(t, raw, "DNS egress port")
		if port["port"] != int64(53) || (port["protocol"] != "UDP" && port["protocol"] != "TCP") {
			t.Fatalf("workload DNS egress port = %#v", port)
		}
	}
	ingress := renderList(t, spec["ingress"], "workloadNetworkPolicy.spec.ingress")
	if len(ingress) != 1 {
		t.Fatalf("workload fence ingress rules = %#v", ingress)
	}
	ingressRule := renderMap(t, ingress[0], "workload ingress rule")
	from := renderMap(t, renderList(t, ingressRule["from"], "workload ingress from")[0], "workload ingress peer")
	supervisorLabels := renderMap(t, renderMap(t, from["podSelector"], "supervisor selector")["matchLabels"], "supervisor labels")
	if supervisorLabels[labelBoundaryRole] != "supervisor" || supervisorLabels[labelBoundaryPair] != "sandbox-123" {
		t.Fatalf("workload fence ingress peer = %#v", from)
	}
	port := renderMap(t, renderList(t, ingressRule["ports"], "workload ingress ports")[0], "workload boundary port")
	if port["port"] != int64(5500) || port["protocol"] != "TCP" {
		t.Fatalf("workload fence boundary port = %#v", port)
	}

	supervisorPolicy := renderMap(t, resources["supervisorNetworkPolicy"], "supervisorNetworkPolicy")
	supervisorSpec := renderMap(t, supervisorPolicy["spec"], "supervisorNetworkPolicy.spec")
	supervisorSelector := renderMap(t, renderMap(t, supervisorSpec["podSelector"], "supervisor podSelector")["matchLabels"], "supervisor selector labels")
	if supervisorSelector[labelBoundaryRole] != "supervisor" || supervisorSelector[labelBoundaryPair] != "sandbox-123" || len(renderList(t, supervisorSpec["egress"], "supervisor egress")) != 1 {
		t.Fatalf("supervisor policy must select trusted supervisors and permit their mediated egress: %#v", supervisorSpec)
	}
	if got := renderList(t, supervisorSpec["policyTypes"], "supervisor policy types"); len(got) != 2 || got[0] != "Ingress" || got[1] != "Egress" {
		t.Fatalf("supervisor policy types = %#v; want ingress and egress", got)
	}
	supervisorIngress := renderList(t, supervisorSpec["ingress"], "supervisor ingress")
	if len(supervisorIngress) != 1 {
		t.Fatalf("supervisor ingress rules = %#v", supervisorIngress)
	}
	workloadPeer := renderMap(t, renderList(t, renderMap(t, supervisorIngress[0], "supervisor ingress rule")["from"], "supervisor ingress from")[0], "workload ingress peer")
	workloadLabels := renderMap(t, renderMap(t, workloadPeer["podSelector"], "workload ingress selector")["matchLabels"], "workload ingress labels")
	if workloadLabels[labelBoundaryRole] != "workload" || workloadLabels[labelBoundaryPair] != "sandbox-123" {
		t.Fatalf("supervisor control ingress peer = %#v", workloadLabels)
	}
	supervisorPorts := renderList(t, renderMap(t, supervisorIngress[0], "supervisor ingress rule")["ports"], "supervisor ingress ports")
	if len(supervisorPorts) != 2 || renderMap(t, supervisorPorts[0], "supervisor control port")["port"] != supervisorControlPort || renderMap(t, supervisorPorts[1], "supervisor proxy port")["port"] != cautemProxyListenPort {
		t.Fatalf("supervisor ingress ports = %#v; want control and proxy listeners", supervisorPorts)
	}
}

func TestOpenShellRuntimeFencesAreUniquePerSandboxPair(t *testing.T) {
	firstWorkload, firstSupervisor, err := renderAgentSandboxRuntimeFence("team-a", "sandbox-a", 5500)
	if err != nil {
		t.Fatalf("renderAgentSandboxRuntimeFence(first) error = %v", err)
	}
	secondWorkload, secondSupervisor, err := renderAgentSandboxRuntimeFence("team-a", "sandbox-b", 5500)
	if err != nil {
		t.Fatalf("renderAgentSandboxRuntimeFence(second) error = %v", err)
	}
	name := func(resource map[string]any) string {
		metadata := renderMap(t, resource["metadata"], "NetworkPolicy metadata")
		value, _ := metadata["name"].(string)
		return value
	}
	if name(firstWorkload) == name(secondWorkload) || name(firstSupervisor) == name(secondSupervisor) {
		t.Fatalf("sandbox pairs must not share runtime policy names: first=(%s,%s) second=(%s,%s)", name(firstWorkload), name(firstSupervisor), name(secondWorkload), name(secondSupervisor))
	}
	for _, item := range []struct {
		resource map[string]any
		pair     string
	}{{firstWorkload, "sandbox-a"}, {firstSupervisor, "sandbox-a"}, {secondWorkload, "sandbox-b"}, {secondSupervisor, "sandbox-b"}} {
		metadata := renderMap(t, item.resource["metadata"], "NetworkPolicy metadata")
		labels := renderMap(t, metadata["labels"], "NetworkPolicy labels")
		if labels[labelBoundaryPair] != item.pair {
			t.Fatalf("NetworkPolicy for %s has pair label %v", item.pair, labels[labelBoundaryPair])
		}
	}
}

func TestOpenShellSupervisorRenderRejectsUnboundIdentity(t *testing.T) {
	params := testAgentSandboxRuntimeRenderParams()
	params.SandboxResourceUID = ""
	if _, err := renderAgentSandboxRuntimeResources(params); err == nil || !strings.Contains(err.Error(), "UID is required") {
		t.Fatalf("renderAgentSandboxRuntimeResources() error = %v; want CR UID requirement", err)
	}

	params = testAgentSandboxRuntimeRenderParams()
	params.Generation = "---"
	if _, err := renderAgentSandboxRuntimeResources(params); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("renderAgentSandboxRuntimeResources() error = %v; want generation validation", err)
	}

	params = testAgentSandboxRuntimeRenderParams()
	params.SATokenTTLSeconds = 599
	if _, err := renderAgentSandboxRuntimeResources(params); err == nil || !strings.Contains(err.Error(), "TTL") {
		t.Fatalf("renderAgentSandboxRuntimeResources() error = %v; want projected token TTL validation", err)
	}
}

func testAgentSandboxRenderParams() agentSandboxRenderParams {
	namespace, _ := workspaceNamespaceName("gateway-1", "team-a")
	return agentSandboxRenderParams{
		APIVersion:                 sandboxAPIVersionV1Beta1,
		Namespace:                  namespace,
		ResourceName:               "team-a-demo",
		SandboxID:                  "sandbox-123",
		SandboxName:                "demo",
		Workspace:                  "team-a",
		GatewayID:                  "gateway-1",
		Generation:                 "gen1",
		Image:                      "registry.example/sandbox:v1",
		SandboxRuntimeImage:        "registry.example/runtime:v1",
		SandboxBootstrapSecretName: "os-sandbox-sandbox-123-gen1",
		ServiceAccountName:         "default",
		ImagePullSecrets:           []string{"registry-auth"},
		SandboxUID:                 10001,
		SandboxGID:                 10002,
		BoundaryPort:               5500,
		WorkspaceStorageSize:       "5Gi",
		WorkspaceStorageClass:      "fast-ssd",
	}
}

func testAgentSandboxRuntimeRenderParams() agentSandboxRuntimeRenderParams {
	namespace, _ := workspaceNamespaceName("gateway-1", "team-a")
	return agentSandboxRuntimeRenderParams{
		Namespace:                 namespace,
		SandboxResourceName:       "team-a-demo",
		SandboxResourceAPIVersion: "agents.x-k8s.io/v1beta1",
		SandboxResourceUID:        "cr-uid-123",
		SandboxID:                 "sandbox-123",
		SandboxName:               "demo",
		Workspace:                 "team-a",
		GatewayID:                 "gateway-1",
		Generation:                "gen7",
		SupervisorImage:           "registry.example/supervisor:v1",
		ServiceAccountName:        "sandbox-driver",
		GatewayEndpoint:           "https://gateway.example:443",
		ImagePullSecrets:          []string{"registry-auth"},
		ControlUID:                10001,
		ControlGID:                10002,
		BoundaryPort:              5500,
		SATokenTTLSeconds:         600,
	}
}

func renderMap(t *testing.T, value any, path string) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s has type %T; want object", path, value)
	}
	return result
}

func renderList(t *testing.T, value any, path string) []any {
	t.Helper()
	result, ok := value.([]any)
	if !ok {
		t.Fatalf("%s has type %T; want array", path, value)
	}
	return result
}

func findRenderMap(t *testing.T, values []any, name string) map[string]any {
	t.Helper()
	for _, value := range values {
		object := renderMap(t, value, "array item")
		if object["name"] == name {
			return object
		}
	}
	t.Fatalf("object named %q was not found", name)
	return nil
}

func hasVolumeMount(container map[string]any, name string) bool {
	mounts, ok := container["volumeMounts"].([]any)
	if !ok {
		return false
	}
	for _, value := range mounts {
		mount, ok := value.(map[string]any)
		if ok && mount["name"] == name {
			return true
		}
	}
	return false
}

func volumeMountReadOnly(container map[string]any, name string) bool {
	for _, value := range container["volumeMounts"].([]any) {
		mount := value.(map[string]any)
		if mount["name"] == name {
			return mount["readOnly"] == true
		}
	}
	return false
}

func hasEnv(container map[string]any, name string) bool {
	env, ok := container["env"].([]any)
	if !ok {
		return false
	}
	for _, value := range env {
		entry, ok := value.(map[string]any)
		if ok && entry["name"] == name {
			return true
		}
	}
	return false
}
