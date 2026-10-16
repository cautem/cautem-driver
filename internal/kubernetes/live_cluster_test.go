package kubernetes

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cautem/quarshell-driver/driver"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

// TestLiveDriverLifecycle exercises the public ComputeDriver against an
// installed Agent Sandbox controller. It is opt-in because it creates real
// namespaces, PVCs, NetworkPolicies, Pods, and Secrets in the selected cluster.
func TestLiveDriverLifecycle(t *testing.T) {
	if os.Getenv("CAUTEM_TEST_KUBERNETES_DRIVER") != "1" {
		t.Skip("set CAUTEM_TEST_KUBERNETES_DRIVER=1 to run ComputeDriver lifecycle against a disposable cluster")
	}
	proxyImage := strings.TrimSpace(os.Getenv("CAUTEM_TEST_KUBERNETES_PROXY_IMAGE"))
	runtimeImage := strings.TrimSpace(os.Getenv("CAUTEM_TEST_KUBERNETES_RUNTIME_IMAGE"))
	if proxyImage == "" || runtimeImage == "" {
		t.Fatal("set CAUTEM_TEST_KUBERNETES_PROXY_IMAGE and CAUTEM_TEST_KUBERNETES_RUNTIME_IMAGE to digest-pinned images")
	}

	var suffixBytes [5]byte
	if _, err := rand.Read(suffixBytes[:]); err != nil {
		t.Fatalf("generate isolated lifecycle identity: %v", err)
	}
	suffix := hex.EncodeToString(suffixBytes[:])
	gatewayID := "gateway-live-" + suffix
	workspace := "live-workspace-" + suffix
	name := "live-driver-" + suffix
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatalf("write sandbox policy: %v", err)
	}
	config := EngineConfig{
		GatewayID: gatewayID, DefaultImage: runtimeImage, ProxyImage: proxyImage,
		SandboxRuntimeImage: runtimeImage, GRPCEndpoint: "gateway.invalid:7443",
		WorkspaceStorageSize: "1Mi",
	}
	config.applyDefaults()
	if err := config.Validate(); err != nil {
		t.Fatalf("validate live Kubernetes driver configuration: %v", err)
	}
	d := NewWithEngineConfig(config)
	clusterConfig := liveClusterRESTConfig(t)
	client, err := dynamic.NewForConfig(clusterConfig)
	if err != nil {
		t.Fatalf("create live Kubernetes client: %v", err)
	}
	d.client = client
	coreClient, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		t.Fatalf("create live Kubernetes diagnostics client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	handle, err := d.Create(ctx, driver.Spec{
		Name: name, Image: runtimeImage, PolicyPath: policyPath,
		GatewayID: gatewayID, GatewayURL: "http://gateway.invalid:7443",
		Command: []string{"sleep", "infinity"},
		ProxyEnv: []string{
			"CAUTEM_GATEWAY_URL=http://gateway.invalid:7443",
			"CAUTEM_SANDBOX=" + name,
			"CAUTEM_SANDBOX_TOKEN=live-driver-token",
		},
		Labels: map[string]string{driver.WorkspaceLabel: workspace, driver.GatewayIDLabel: gatewayID},
	})
	if err != nil {
		t.Fatalf("ComputeDriver.Create(): %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
		defer cleanupCancel()
		if err := d.Delete(cleanupCtx, handle.ID); err != nil {
			t.Errorf("cleanup ComputeDriver.Delete(): %v", err)
		}
		namespace, err := coreClient.CoreV1().Namespaces().Get(cleanupCtx, handle.Network, metav1.GetOptions{})
		if err == nil {
			uid := namespace.UID
			if err := coreClient.CoreV1().Namespaces().Delete(cleanupCtx, handle.Network, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil {
				t.Errorf("cleanup live workspace Namespace %s: %v", handle.Network, err)
			}
		} else if !apierrors.IsNotFound(err) {
			t.Errorf("read live workspace Namespace during cleanup: %v", err)
		}
	})
	if handle.Name != name || handle.Network == "" || handle.Image != runtimeImage {
		t.Fatalf("ComputeDriver.Create() handle = %#v", handle)
	}

	listed, err := d.List(ctx)
	if err != nil {
		t.Fatalf("ComputeDriver.List(): %v", err)
	}
	if len(listed) != 1 || listed[0].Name != name || listed[0].Image != runtimeImage {
		t.Fatalf("ComputeDriver.List() = %#v; want only the created sandbox", listed)
	}
	inspected, err := d.Inspect(ctx, string(handle.ID))
	if err != nil {
		t.Fatalf("ComputeDriver.Inspect(): %v", err)
	}
	if inspected.Name != name || inspected.Image != runtimeImage || inspected.Network != handle.Network {
		t.Fatalf("ComputeDriver.Inspect() = %#v; want the created sandbox identity", inspected)
	}
	strictGroups, unsupportedNodes, err := liveClusterStrictSupplementalGroupsSupport(ctx, coreClient)
	if err != nil {
		t.Fatalf("inspect Kubernetes node security capabilities: %v", err)
	}
	if !strictGroups {
		t.Skipf("sandbox Start requires strict supplemental group isolation; unsupported schedulable nodes: %s", strings.Join(unsupportedNodes, ", "))
	}
	if err := d.Start(ctx, handle.ID); err != nil {
		dumpLiveDriverDiagnostics(t, ctx, coreClient, handle.Network)
		t.Fatalf("ComputeDriver.Start(): %v", err)
	}
	if err := d.Stop(ctx, handle.ID); err != nil {
		dumpLiveDriverDiagnostics(t, ctx, coreClient, handle.Network)
		t.Fatalf("ComputeDriver.Stop(): %v", err)
	}
	if err := d.Start(ctx, handle.ID); err != nil {
		dumpLiveDriverDiagnostics(t, ctx, coreClient, handle.Network)
		t.Fatalf("ComputeDriver.Start() after Stop(): %v", err)
	}
	if err := d.Delete(ctx, handle.ID); err != nil {
		t.Fatalf("ComputeDriver.Delete(): %v", err)
	}
}

func liveClusterStrictSupplementalGroupsSupport(ctx context.Context, client kubernetes.Interface) (bool, []string, error) {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, nil, err
	}
	var unsupported []string
	eligible := 0
	for _, node := range nodes.Items {
		if node.Spec.Unschedulable {
			continue
		}
		ready := false
		for _, condition := range node.Status.Conditions {
			if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
				ready = true
				break
			}
		}
		if !ready {
			continue
		}
		eligible++
		if node.Status.Features == nil || node.Status.Features.SupplementalGroupsPolicy == nil || !*node.Status.Features.SupplementalGroupsPolicy {
			unsupported = append(unsupported, node.Name)
		}
	}
	if eligible == 0 {
		return false, nil, fmt.Errorf("cluster has no Ready schedulable nodes")
	}
	return len(unsupported) == 0, unsupported, nil
}

func dumpLiveDriverDiagnostics(t *testing.T, ctx context.Context, client kubernetes.Interface, namespace string) {
	t.Helper()
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Logf("live Kubernetes diagnostic Pod list: %v", err)
	} else {
		for _, pod := range pods.Items {
			t.Logf("live Kubernetes Pod %s phase=%s conditions=%#v init=%#v containers=%#v", pod.Name, pod.Status.Phase, pod.Status.Conditions, pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses)
			for _, container := range pod.Spec.Containers {
				logs, logErr := client.CoreV1().Pods(namespace).GetLogs(pod.Name, &corev1.PodLogOptions{Container: container.Name}).Do(ctx).Raw()
				if logErr != nil {
					t.Logf("live Kubernetes Pod %s container %s logs: %v", pod.Name, container.Name, logErr)
				} else if len(logs) != 0 {
					t.Logf("live Kubernetes Pod %s container %s logs: %s", pod.Name, container.Name, strings.TrimSpace(string(logs)))
				}
			}
		}
	}
	events, err := client.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Logf("live Kubernetes diagnostic Event list: %v", err)
		return
	}
	for _, event := range events.Items {
		t.Logf("live Kubernetes Event %s/%s type=%s reason=%s message=%s", event.InvolvedObject.Kind, event.InvolvedObject.Name, event.Type, event.Reason, event.Message)
	}
}

// TestLiveAgentSandboxCreateSequence exercises the Cautem Agent Sandbox
// controller and Kubernetes APIs. It is opt-in so ordinary unit tests never
// need cluster credentials or mutate a developer's cluster.
func TestLiveAgentSandboxCreateSequence(t *testing.T) {
	if os.Getenv("CAUTEM_TEST_KUBERNETES") != "1" {
		t.Skip("set CAUTEM_TEST_KUBERNETES=1 to run against a disposable cluster namespace")
	}

	config := liveClusterRESTConfig(t)
	coreClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("create Kubernetes client: %v", err)
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatalf("create dynamic Kubernetes client: %v", err)
	}

	var suffixBytes [5]byte
	if _, err := rand.Read(suffixBytes[:]); err != nil {
		t.Fatalf("generate isolated namespace suffix: %v", err)
	}
	suffix := hex.EncodeToString(suffixBytes[:])
	gatewayID := "gateway-" + suffix
	workspace := "live-workspace-" + suffix
	namespace, _, _, err := renderWorkspaceIsolationResources(gatewayID, workspace)
	if err != nil {
		t.Fatalf("derive isolated workspace namespace: %v", err)
	}
	workspaceLabels, err := workspaceIdentityLabels(gatewayID, workspace)
	if err != nil {
		t.Fatalf("render isolated workspace labels: %v", err)
	}
	kubeLabels := make(map[string]string, len(workspaceLabels))
	for key, value := range workspaceLabels {
		kubeLabels[key] = value.(string)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	created, err := coreClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: kubeLabels}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create isolated test namespace: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cleanupCancel()
		uid := created.UID
		_ = coreClient.CoreV1().Namespaces().Delete(cleanupCtx, namespace, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	})

	api := newDynamicAgentSandboxAPIClient(dynamicClient)
	version, err := detectSandboxAPIVersion(ctx, api, namespace)
	if err != nil {
		t.Fatalf("discover installed Agent Sandbox API: %v", err)
	}
	sandboxID := "sandbox-" + suffix
	resourceName := "sandbox-" + suffix
	generation := "live1"
	image := "registry.k8s.io/pause:3.10.1"

	workloadParams := testCautemWorkloadRenderParams()
	workloadParams.Base.APIVersion = version
	workloadParams.Base.Namespace = namespace
	workloadParams.Base.ResourceName = resourceName
	workloadParams.Base.SandboxID = sandboxID
	workloadParams.Base.SandboxName = "live-cluster-test"
	workloadParams.Base.Workspace = workspace
	workloadParams.Base.GatewayID = gatewayID
	workloadParams.Base.Generation = generation
	workloadParams.Base.Image = image
	workloadParams.Base.ImagePullPolicy = "IfNotPresent"
	workloadParams.Base.SandboxBootstrapSecretName = generationSecretName("os-sandbox", sandboxID, generation)
	workloadParams.Base.ServiceAccountName = "default"
	workloadParams.Base.ImagePullSecrets = nil
	workloadParams.Base.SandboxRuntimeImage = "registry.k8s.io/pause@sha256:" + strings.Repeat("a", 64)
	workloadParams.Base.SandboxRuntimeImagePullPolicy = "IfNotPresent"
	workloadParams.Base.WorkspaceStorageSize = "1Mi"
	workloadParams.Command = []string{"/bin/true"}
	// Minikube's default provisioner is named "standard". Do not inherit the
	// renderer fixture's production-specific fast-ssd class in this live test.
	workloadParams.Base.WorkspaceStorageClass = ""
	sandboxResource, err := renderCautemAgentSandboxResource(SandboxDriverConfig{}, workloadParams)
	if err != nil {
		t.Fatalf("render Cautem Agent Sandbox resource: %v", err)
	}

	runtimeParams := testAgentSandboxRuntimeRenderParams()
	runtimeParams.Namespace = namespace
	runtimeParams.SandboxResourceName = resourceName
	runtimeParams.SandboxResourceAPIVersion = sandboxAPIGroup + "/" + version
	runtimeParams.SandboxResourceUID = ""
	runtimeParams.SandboxID = sandboxID
	runtimeParams.SandboxName = workloadParams.Base.SandboxName
	runtimeParams.Workspace = workspace
	runtimeParams.GatewayID = gatewayID
	runtimeParams.Generation = generation
	runtimeParams.SupervisorImage = ""
	runtimeParams.ServiceAccountName = "default"
	runtimeParams.GatewayEndpoint = ""
	runtimeParams.ImagePullSecrets = nil
	runtimeParams.CautemProxyImage = "ghcr.io/cautem/cautem-proxy@sha256:" + strings.Repeat("b", 64)
	runtimeParams.CautemGatewayURL = "http://gateway.invalid:7443"
	runtimeParams.CautemGatewayGRPCEndpoint = "gateway.invalid:7443"

	identity, err := runAgentSandboxCreateSequence(ctx, newDynamicAgentSandboxCreateBackend(dynamicClient), agentSandboxCreateSequenceInput{
		SandboxResource: sandboxResource,
		RuntimeParams:   runtimeParams,
		BuildCautemSecrets: func(identity agentSandboxCreateIdentity) ([]map[string]any, error) {
			return buildCautemGenerationSecrets(identity, []byte("version: 1\n"), []string{"CAUTEM_SANDBOX_TOKEN=live-test-token"})
		},
	})
	if err != nil {
		var events string
		if createdEvents, eventErr := coreClient.CoreV1().Events(namespace).List(context.Background(), metav1.ListOptions{}); eventErr == nil {
			var lines []string
			for _, event := range createdEvents.Items {
				lines = append(lines, event.InvolvedObject.Kind+"/"+event.InvolvedObject.Name+": "+event.Message)
			}
			events = strings.Join(lines, "\n")
		}
		t.Fatalf("run Agent Sandbox create sequence: %v\nnamespace events:\n%s", err, events)
	}
	if identity.Namespace != namespace || identity.SandboxName != resourceName || identity.SandboxUID == "" || identity.WorkloadUID == "" || identity.SupervisorUID == "" {
		t.Fatalf("live Agent Sandbox identity is incomplete: %+v", identity)
	}
	if _, err := dynamicClient.Resource(agentSandboxGVR(version)).Namespace(namespace).Get(ctx, resourceName, metav1.GetOptions{}); err != nil {
		t.Fatalf("read back created Agent Sandbox: %v", err)
	}
	readDriver := newWithClient(dynamicClient, gatewayID)
	listed, err := readDriver.List(ctx)
	if err != nil {
		t.Fatalf("list live Gateway-owned Agent Sandboxes: %v", err)
	}
	if len(listed) != 1 || listed[0].Name != workloadParams.Base.SandboxName || listed[0].Network != namespace {
		t.Fatalf("live List() = %#v; want only the created workspace sandbox", listed)
	}
	inspected, err := readDriver.Inspect(ctx, string(listed[0].ID))
	if err != nil {
		t.Fatalf("inspect live Agent Sandbox by runtime ID: %v", err)
	}
	if inspected.ID != listed[0].ID || inspected.Name != workloadParams.Base.SandboxName || inspected.Image != image {
		t.Fatalf("live Inspect() = %#v; want listed identity and workload image", inspected)
	}
}

// TestLiveNetworkPolicyEnforcement proves that the selected cluster CNI applies
// the deny-by-default and narrow allow rules used by the workspace fence.
func TestLiveNetworkPolicyEnforcement(t *testing.T) {
	if os.Getenv("CAUTEM_TEST_KUBERNETES") != "1" {
		t.Skip("set CAUTEM_TEST_KUBERNETES=1 to run against a disposable cluster namespace")
	}

	config := liveClusterRESTConfig(t)
	coreClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("create Kubernetes client: %v", err)
	}
	var suffixBytes [5]byte
	if _, err := rand.Read(suffixBytes[:]); err != nil {
		t.Fatalf("generate isolated namespace suffix: %v", err)
	}
	namespace := "cautem-netpol-" + hex.EncodeToString(suffixBytes[:])
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := coreClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create isolated network policy namespace: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cleanupCancel()
		_ = coreClient.CoreV1().Namespaces().Delete(cleanupCtx, namespace, metav1.DeleteOptions{})
	})

	server := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "server", Namespace: namespace, Labels: map[string]string{"role": "server"}},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:    "server",
				Image:   "busybox:1.36.1",
				Command: []string{"/bin/sh", "-c", "mkdir -p /tmp/www && printf policy-ok > /tmp/www/index.html && exec httpd -f -p 8080 -h /tmp/www"},
				ReadinessProbe: &corev1.Probe{
					ProbeHandler:  corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(8080)}},
					PeriodSeconds: 1, TimeoutSeconds: 1,
				},
			}},
		},
	}
	client := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: namespace, Labels: map[string]string{"role": "client"}},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers:    []corev1.Container{{Name: "client", Image: "busybox:1.36.1", Command: []string{"/bin/sh", "-c", "sleep 3600"}}},
		},
	}
	if _, err := coreClient.CoreV1().Pods(namespace).Create(ctx, server, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create network policy server Pod: %v", err)
	}
	if _, err := coreClient.CoreV1().Pods(namespace).Create(ctx, client, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create network policy client Pod: %v", err)
	}
	serverPod := waitForLivePodReady(t, ctx, coreClient, namespace, server.Name)
	waitForLivePodReady(t, ctx, coreClient, namespace, client.Name)
	probe := []string{"wget", "-q", "-T", "3", "-O", "-", "http://" + serverPod.Status.PodIP + ":8080/"}
	if output, err := execLivePod(ctx, config, coreClient, namespace, client.Name, "client", probe); err != nil || strings.TrimSpace(output) != "policy-ok" {
		t.Fatalf("baseline Pod connectivity output=%q err=%v; want policy-ok", output, err)
	}

	_, err = coreClient.NetworkingV1().NetworkPolicies(namespace).Create(ctx, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "workspace-default-deny"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress:     []networkingv1.NetworkPolicyIngressRule{},
			Egress:      []networkingv1.NetworkPolicyEgressRule{},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create default-deny egress NetworkPolicy: %v", err)
	}
	waitForLivePodProbe(t, ctx, config, coreClient, namespace, client.Name, probe, false, "default-deny policy")

	port := intstr.FromInt32(8080)
	_, err = coreClient.NetworkingV1().NetworkPolicies(namespace).Create(ctx, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-client-egress"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "client"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To:    []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "server"}}}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: protocolPointer(corev1.ProtocolTCP), Port: &port}},
			}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create narrow client egress NetworkPolicy: %v", err)
	}
	waitForLivePodProbe(t, ctx, config, coreClient, namespace, client.Name, probe, false, "egress-only allow")
	_, err = coreClient.NetworkingV1().NetworkPolicies(namespace).Create(ctx, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-server-ingress"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "server"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From:  []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "client"}}}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: protocolPointer(corev1.ProtocolTCP), Port: &port}},
			}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create narrow server ingress NetworkPolicy: %v", err)
	}
	waitForLivePodProbe(t, ctx, config, coreClient, namespace, client.Name, probe, true, "paired narrow allow rules")
}

// TestLiveWorkspaceNamespaceDiscovery verifies the recovery selector against
// the real API server and ensures one Gateway cannot discover another's
// namespace set.
func TestLiveWorkspaceNamespaceDiscovery(t *testing.T) {
	if os.Getenv("CAUTEM_TEST_KUBERNETES") != "1" {
		t.Skip("set CAUTEM_TEST_KUBERNETES=1 to run against a disposable cluster namespace")
	}
	config := liveClusterRESTConfig(t)
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatalf("create dynamic Kubernetes client: %v", err)
	}
	var suffixBytes [5]byte
	if _, err := rand.Read(suffixBytes[:]); err != nil {
		t.Fatalf("generate isolated namespace suffix: %v", err)
	}
	suffix := hex.EncodeToString(suffixBytes[:])
	gatewayID := "gateway-discovery-" + suffix
	identities := []struct{ gateway, workspace string }{
		{gatewayID, "workspace-a-" + suffix},
		{gatewayID, "workspace-b-" + suffix},
		{"other-gateway-" + suffix, "workspace-c-" + suffix},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var created []*unstructured.Unstructured
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cleanupCancel()
		for _, namespace := range created {
			uid := types.UID(namespace.GetUID())
			_ = dynamicClient.Resource(coreV1GVR("namespaces")).Delete(cleanupCtx, namespace.GetName(), metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			})
		}
	})
	for _, identity := range identities {
		name, resource, _, err := renderWorkspaceIsolationResources(identity.gateway, identity.workspace)
		if err != nil {
			t.Fatalf("render workspace namespace: %v", err)
		}
		object, err := dynamicClient.Resource(coreV1GVR("namespaces")).Create(ctx, &unstructured.Unstructured{Object: resource}, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("create disposable workspace namespace %s: %v", name, err)
		}
		created = append(created, object)
	}

	got, err := newDynamicAgentSandboxCreateBackend(dynamicClient).ListWorkspaceNamespaces(ctx, gatewayID)
	if err != nil {
		t.Fatalf("ListWorkspaceNamespaces() error = %v", err)
	}
	want := make(map[string]struct{}, 2)
	for _, identity := range identities[:2] {
		name, err := workspaceNamespaceName(identity.gateway, identity.workspace)
		if err != nil {
			t.Fatal(err)
		}
		want[name] = struct{}{}
	}
	if len(got) != len(want) {
		t.Fatalf("discovered namespaces = %#v; want exactly %d owned workspaces", got, len(want))
	}
	for _, name := range got {
		if _, ok := want[name]; !ok {
			t.Fatalf("discovered namespace %q is not owned by Gateway %q", name, gatewayID)
		}
	}
}

func waitForLivePodReady(t *testing.T, ctx context.Context, client kubernetes.Interface, namespace, name string) *corev1.Pod {
	t.Helper()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		pod, err := client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err == nil && pod.Status.Phase == corev1.PodRunning {
			for _, condition := range pod.Status.Conditions {
				if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
					return pod
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("Pod %s/%s did not become Ready: %v", namespace, name, ctx.Err())
		case <-ticker.C:
		}
	}
}

func execLivePod(ctx context.Context, config *rest.Config, client kubernetes.Interface, namespace, pod, container string, command []string) (string, error) {
	request := client.CoreV1().RESTClient().Post().Resource("pods").Name(pod).Namespace(namespace).SubResource("exec").VersionedParams(&corev1.PodExecOptions{
		Container: container, Command: command, Stdout: true, Stderr: true,
	}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(config, http.MethodPost, request.URL())
	if err != nil {
		return "", err
	}
	var stdout, stderr bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr})
	if err != nil && stderr.Len() != 0 {
		return stdout.String(), fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), err
}

func waitForLivePodProbe(t *testing.T, ctx context.Context, config *rest.Config, client kubernetes.Interface, namespace, pod string, probe []string, wantReachable bool, phase string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := execLivePod(ctx, config, client, namespace, pod, "client", []string{"true"}); err != nil {
			t.Fatalf("Pod exec failed while checking %s: %v", phase, err)
		}
		output, err := execLivePod(ctx, config, client, namespace, pod, "client", probe)
		reachable := err == nil && strings.TrimSpace(output) == "policy-ok"
		if reachable == wantReachable {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("network policy %s probe timed out: %v", phase, ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
	t.Fatalf("network policy %s did not make connectivity reachable=%t", phase, wantReachable)
}

func protocolPointer(protocol corev1.Protocol) *corev1.Protocol { return &protocol }

func liveClusterRESTConfig(t *testing.T) *rest.Config {
	t.Helper()
	path := strings.TrimSpace(os.Getenv("KUBECONFIG"))
	if path == "" {
		path = clientcmd.RecommendedHomeFile
	}
	config, err := clientcmd.BuildConfigFromFlags("", filepath.Clean(path))
	if err == nil {
		return config
	}
	config, inClusterErr := rest.InClusterConfig()
	if inClusterErr != nil {
		t.Fatalf("load kubeconfig (%v) and in-cluster configuration (%v)", err, inClusterErr)
	}
	return config
}
