package kubernetes

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/cautem/quarshell-core"
	"github.com/cautem/quarshell-driver/driver"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const kubernetesRuntimeIDPrefix = "k8s:"

type sandboxRuntimeIdentity struct {
	Namespace string
	Name      string
	UID       string
}

func (d *Driver) list(ctx context.Context) ([]driver.Info, error) {
	if ctx == nil {
		return nil, fmt.Errorf("kubernetes List context is nil")
	}
	client, err := d.kubernetesClient()
	if err != nil {
		return nil, err
	}
	namespaces, err := newDynamicAgentSandboxCreateBackend(client).ListWorkspaceNamespaces(ctx, d.gatewayID)
	if err != nil {
		return nil, err
	}
	apiClient := newDynamicAgentSandboxAPIClient(client)
	items := make([]driver.Info, 0)
	for _, namespace := range namespaces {
		version, err := d.apiVersions.Resolve(ctx, apiClient, namespace)
		if err != nil {
			return nil, fmt.Errorf("discover Agent Sandbox API in workspace namespace %s: %w", namespace, err)
		}
		objects, err := apiClient.ListSandboxObjects(ctx, version, namespace)
		if err != nil {
			return nil, fmt.Errorf("list Agent Sandboxes in workspace namespace %s: %w", namespace, err)
		}
		if objects == nil {
			return nil, fmt.Errorf("kubernetes API returned an empty Agent Sandbox list for namespace %s", namespace)
		}
		for i := range objects.Items {
			object := &objects.Items[i]
			if !sandboxOwnedByGateway(object, d.gatewayID) {
				continue
			}
			info, err := sandboxInfoFromObject(object)
			if err != nil {
				return nil, fmt.Errorf("read owned Agent Sandbox %s/%s: %w", namespace, object.GetName(), err)
			}
			items = append(items, info)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Network != items[j].Network {
			return items[i].Network < items[j].Network
		}
		if items[i].Name != items[j].Name {
			return items[i].Name < items[j].Name
		}
		return items[i].ID < items[j].ID
	})
	return items, nil
}

func (d *Driver) inspect(ctx context.Context, nameOrID string) (driver.Info, error) {
	if ctx == nil {
		return driver.Info{}, fmt.Errorf("kubernetes Inspect context is nil")
	}
	if strings.TrimSpace(nameOrID) == "" || nameOrID != strings.TrimSpace(nameOrID) {
		return driver.Info{}, fmt.Errorf("sandbox name or Kubernetes runtime ID is required")
	}
	if strings.HasPrefix(nameOrID, kubernetesRuntimeIDPrefix) {
		identity, err := parseSandboxRuntimeID(nameOrID)
		if err != nil {
			return driver.Info{}, err
		}
		return d.inspectRuntimeIdentity(ctx, identity)
	}

	items, err := d.list(ctx)
	if err != nil {
		return driver.Info{}, err
	}
	var match *driver.Info
	for i := range items {
		if items[i].Name != nameOrID {
			continue
		}
		if match != nil {
			return driver.Info{}, fmt.Errorf("sandbox name %q is ambiguous across Kubernetes workspaces", nameOrID)
		}
		match = &items[i]
	}
	if match == nil {
		return driver.Info{}, fmt.Errorf("kubernetes sandbox %q not found", nameOrID)
	}
	return *match, nil
}

func (d *Driver) inspectRuntimeIdentity(ctx context.Context, identity sandboxRuntimeIdentity) (driver.Info, error) {
	client, err := d.kubernetesClient()
	if err != nil {
		return driver.Info{}, err
	}
	namespaces, err := newDynamicAgentSandboxCreateBackend(client).ListWorkspaceNamespaces(ctx, d.gatewayID)
	if err != nil {
		return driver.Info{}, err
	}
	if !containsNamespace(namespaces, identity.Namespace) {
		return driver.Info{}, fmt.Errorf("kubernetes sandbox runtime ID is outside this Gateway's workspace namespaces")
	}
	apiClient := newDynamicAgentSandboxAPIClient(client)
	version, err := d.apiVersions.Resolve(ctx, apiClient, identity.Namespace)
	if err != nil {
		return driver.Info{}, fmt.Errorf("discover Agent Sandbox API in workspace namespace %s: %w", identity.Namespace, err)
	}
	object, err := apiClient.GetSandboxObject(ctx, version, identity.Namespace, identity.Name)
	if apierrors.IsNotFound(err) {
		return driver.Info{}, fmt.Errorf("kubernetes sandbox runtime ID %q not found", kubernetesRuntimeID(identity))
	}
	if err != nil {
		return driver.Info{}, fmt.Errorf("get Agent Sandbox %s/%s: %w", identity.Namespace, identity.Name, err)
	}
	if object == nil || object.GetNamespace() != identity.Namespace || object.GetName() != identity.Name {
		return driver.Info{}, fmt.Errorf("kubernetes API returned a different Agent Sandbox than requested")
	}
	if string(object.GetUID()) != identity.UID {
		return driver.Info{}, fmt.Errorf("kubernetes sandbox runtime ID %q is stale because the resource UID changed", kubernetesRuntimeID(identity))
	}
	if !sandboxOwnedByGateway(object, d.gatewayID) {
		return driver.Info{}, fmt.Errorf("kubernetes sandbox runtime ID is not owned by this Gateway")
	}
	return sandboxInfoFromObject(object)
}

func (d *Driver) kubernetesClient() (dynamic.Interface, error) {
	if d == nil {
		return nil, fmt.Errorf("kubernetes driver is nil")
	}
	if strings.TrimSpace(d.gatewayID) == "" || strings.TrimSpace(d.gatewayID) != d.gatewayID {
		return nil, fmt.Errorf("kubernetes Gateway ID is required to scope sandbox discovery")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.client != nil {
		return d.client, nil
	}
	if d.loadClient == nil {
		return nil, fmt.Errorf("kubernetes client is not configured")
	}
	client, err := d.loadClient()
	if err != nil {
		return nil, fmt.Errorf("load Kubernetes API client: %w", err)
	}
	if client == nil {
		return nil, fmt.Errorf("kubernetes client loader returned nil client")
	}
	d.client = client
	return d.client, nil
}

func loadDynamicKubernetesClient() (dynamic.Interface, error) {
	config, inClusterErr := rest.InClusterConfig()
	if inClusterErr != nil {
		var err error
		config, err = clientcmd.BuildConfigFromFlags("", "")
		if err != nil {
			return nil, fmt.Errorf("load in-cluster config (%v) and kubeconfig: %w", inClusterErr, err)
		}
	}
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create dynamic Kubernetes client: %w", err)
	}
	return client, nil
}

func sandboxOwnedByGateway(object *unstructured.Unstructured, gatewayID string) bool {
	if object == nil || object.GetNamespace() == "" || object.GetName() == "" {
		return false
	}
	labels := object.GetLabels()
	if labels[labelManagedBy] != managedByValue || labels[labelGatewayID] != gatewayID {
		return false
	}
	expectedNamespace, err := workspaceNamespaceName(gatewayID, labels[labelSandboxWorkspace])
	return err == nil && object.GetNamespace() == expectedNamespace
}

func sandboxInfoFromObject(object *unstructured.Unstructured) (driver.Info, error) {
	if object == nil {
		return driver.Info{}, fmt.Errorf("agent Sandbox object is nil")
	}
	namespace, name, uid := object.GetNamespace(), object.GetName(), string(object.GetUID())
	if namespace == "" || name == "" || uid == "" {
		return driver.Info{}, fmt.Errorf("kubernetes metadata namespace, name, and UID are required")
	}
	labels := object.GetLabels()
	sandboxName := labels[labelSandboxName]
	if sandboxName == "" {
		sandboxName = name
	}
	image := sandboxAgentImage(object)
	info := driver.Info{
		ID:      core.ID(kubernetesRuntimeID(sandboxRuntimeIdentity{Namespace: namespace, Name: name, UID: uid})),
		Name:    sandboxName,
		Network: namespace,
		Image:   image,
		Status:  sandboxStatus(object),
	}
	return info, nil
}

func sandboxAgentImage(object *unstructured.Unstructured) string {
	containers, found, _ := unstructured.NestedSlice(object.Object, "spec", "podTemplate", "spec", "containers")
	if !found {
		return ""
	}
	for _, raw := range containers {
		container, ok := raw.(map[string]any)
		if !ok || container["name"] != "agent" {
			continue
		}
		image, _ := container["image"].(string)
		return image
	}
	return ""
}

func sandboxStatus(object *unstructured.Unstructured) string {
	if object.GetDeletionTimestamp() != nil {
		return "Terminating"
	}
	desiredStopped := false
	desiredRunning := false
	if mode, found, _ := unstructured.NestedString(object.Object, "spec", "operatingMode"); found {
		desiredStopped = mode == "Suspended"
		desiredRunning = mode == "Running"
	}
	if replicas, found, _ := unstructured.NestedInt64(object.Object, "spec", "replicas"); found {
		desiredStopped = replicas == 0
		desiredRunning = replicas > 0
	}
	ready := false
	if conditions, found, _ := unstructured.NestedSlice(object.Object, "status", "conditions"); found {
		for _, raw := range conditions {
			condition, ok := raw.(map[string]any)
			if !ok || condition["type"] != "Ready" {
				continue
			}
			if condition["status"] == "True" {
				ready = true
				break
			}
		}
	}
	phase, _, _ := unstructured.NestedString(object.Object, "status", "phase")
	if desiredStopped {
		if ready || strings.EqualFold(phase, "Running") {
			return "Stopping"
		}
		return "Stopped"
	}
	if ready {
		return "Running"
	}
	if phase != "" {
		return phase
	}
	if desiredRunning {
		return "Starting"
	}
	return "Unknown"
}

func kubernetesRuntimeID(identity sandboxRuntimeIdentity) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(identity.Namespace + "\x00" + identity.Name + "\x00" + identity.UID))
	return kubernetesRuntimeIDPrefix + encoded
}

func parseSandboxRuntimeID(id string) (sandboxRuntimeIdentity, error) {
	if !strings.HasPrefix(id, kubernetesRuntimeIDPrefix) {
		return sandboxRuntimeIdentity{}, fmt.Errorf("invalid Kubernetes sandbox runtime ID")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(id, kubernetesRuntimeIDPrefix))
	if err != nil {
		return sandboxRuntimeIdentity{}, fmt.Errorf("invalid Kubernetes sandbox runtime ID encoding: %w", err)
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return sandboxRuntimeIdentity{}, fmt.Errorf("invalid Kubernetes sandbox runtime ID fields")
	}
	if problems := validation.IsDNS1123Label(parts[0]); len(problems) != 0 {
		return sandboxRuntimeIdentity{}, fmt.Errorf("invalid Kubernetes sandbox runtime ID namespace: %s", strings.Join(problems, ", "))
	}
	if problems := validation.IsDNS1123Subdomain(parts[1]); len(problems) != 0 {
		return sandboxRuntimeIdentity{}, fmt.Errorf("invalid Kubernetes sandbox runtime ID resource name: %s", strings.Join(problems, ", "))
	}
	identity := sandboxRuntimeIdentity{Namespace: parts[0], Name: parts[1], UID: parts[2]}
	if kubernetesRuntimeID(identity) != id {
		return sandboxRuntimeIdentity{}, fmt.Errorf("non-canonical Kubernetes sandbox runtime ID")
	}
	return identity, nil
}

func containsNamespace(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
