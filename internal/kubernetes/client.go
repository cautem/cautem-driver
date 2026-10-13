package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
)

const (
	sandboxAPIGroup           = "agents.x-k8s.io"
	sandboxAPIVersionV1Beta1  = "v1beta1"
	sandboxAPIVersionV1Alpha1 = "v1alpha1"
)

var supportedSandboxAPIVersions = [...]string{
	sandboxAPIVersionV1Beta1,
	sandboxAPIVersionV1Alpha1,
}

const sandboxAPITimeout = 30 * time.Second

// agentSandboxAPIClient is the typed seam around the Kubernetes API library.
// The production adapter should use the same Kubernetes client stack as the
// driver, while tests can model API behavior without adding a hand-written REST
// client or coupling lifecycle code to HTTP.
type agentSandboxAPIClient interface {
	ListSandboxes(ctx context.Context, version, namespace string, limit int) error
}

type agentSandboxObjectClient interface {
	GetSandboxResourceVersion(ctx context.Context, version, namespace, name string) (string, error)
	PatchSandbox(ctx context.Context, version, namespace, name string, patch map[string]any) error
}

type kubernetesStatusCoder interface {
	StatusCode() int
}

// sandboxAPIVersionResolver caches only a successful probe, matching OpenShell's
// get_or_try_init behavior: transient API errors leave discovery retryable.
type sandboxAPIVersionResolver struct {
	mu      sync.Mutex
	version string
}

func (resolver *sandboxAPIVersionResolver) Resolve(ctx context.Context, client agentSandboxAPIClient, namespace string) (string, error) {
	if resolver == nil {
		return "", fmt.Errorf("agent sandbox API version resolver is nil")
	}
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.version != "" {
		return resolver.version, nil
	}
	version, err := detectSandboxAPIVersion(ctx, client, namespace)
	if err != nil {
		return "", err
	}
	resolver.version = version
	return version, nil
}

// dynamicAgentSandboxAPIClient adapts client-go's dynamic client to the small
// API surface needed by Agent Sandbox. The gateway-facing compute interface
// remains gRPC; this adapter is only for the Kubernetes control plane.
type dynamicAgentSandboxAPIClient struct {
	client dynamic.Interface
}

func newDynamicAgentSandboxAPIClient(client dynamic.Interface) *dynamicAgentSandboxAPIClient {
	return &dynamicAgentSandboxAPIClient{client: client}
}

func agentSandboxGVR(version string) schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    sandboxAPIGroup,
		Version:  version,
		Resource: "sandboxes",
	}
}

func (client *dynamicAgentSandboxAPIClient) resource(version, namespace string) (dynamic.ResourceInterface, error) {
	if client == nil || client.client == nil {
		return nil, fmt.Errorf("kubernetes dynamic client is nil")
	}
	if version != sandboxAPIVersionV1Beta1 && version != sandboxAPIVersionV1Alpha1 {
		return nil, fmt.Errorf("unsupported Agent Sandbox API version %q", version)
	}
	resource := client.client.Resource(agentSandboxGVR(version))
	if namespace != "" {
		return resource.Namespace(namespace), nil
	}
	return resource, nil
}

func (client *dynamicAgentSandboxAPIClient) ListSandboxes(ctx context.Context, version, namespace string, limit int) error {
	if limit < 0 {
		return fmt.Errorf("sandbox list limit must not be negative")
	}
	resource, err := client.resource(version, namespace)
	if err != nil {
		return err
	}
	_, err = resource.List(ctx, metav1.ListOptions{Limit: int64(limit)})
	return err
}

func (client *dynamicAgentSandboxAPIClient) ListSandboxObjects(ctx context.Context, version, namespace string) (*unstructured.UnstructuredList, error) {
	resource, err := client.resource(version, namespace)
	if err != nil {
		return nil, err
	}
	return resource.List(ctx, metav1.ListOptions{})
}

func (client *dynamicAgentSandboxAPIClient) GetSandboxObject(ctx context.Context, version, namespace, name string) (*unstructured.Unstructured, error) {
	resource, err := client.resource(version, namespace)
	if err != nil {
		return nil, err
	}
	return resource.Get(ctx, name, metav1.GetOptions{})
}

func (client *dynamicAgentSandboxAPIClient) WatchSandboxObjects(ctx context.Context, version, namespace, resourceVersion string) (watch.Interface, error) {
	resource, err := client.resource(version, namespace)
	if err != nil {
		return nil, err
	}
	timeoutSeconds := int64(sandboxWatchServerTimeout.Seconds())
	return resource.Watch(ctx, metav1.ListOptions{
		ResourceVersion:     resourceVersion,
		AllowWatchBookmarks: true,
		TimeoutSeconds:      &timeoutSeconds,
	})
}

func (client *dynamicAgentSandboxAPIClient) GetSandboxResourceVersion(ctx context.Context, version, namespace, name string) (string, error) {
	resource, err := client.resource(version, namespace)
	if err != nil {
		return "", err
	}
	sandbox, err := resource.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	return sandbox.GetResourceVersion(), nil
}

func (client *dynamicAgentSandboxAPIClient) PatchSandbox(ctx context.Context, version, namespace, name string, patch map[string]any) error {
	resource, err := client.resource(version, namespace)
	if err != nil {
		return err
	}
	patchJSON, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("encode Agent Sandbox merge patch: %w", err)
	}
	_, err = resource.Patch(ctx, name, types.MergePatchType, patchJSON, metav1.PatchOptions{})
	return err
}

// detectSandboxAPIVersion follows OpenShell's discovery order: prefer v1beta1,
// try v1alpha1 only when the version probe returns NotFound, and keep auth,
// timeout, and server errors as failures. A successful probe lists at most one
// resource, matching kube::Api::list(ListParams::limit(1)).
func detectSandboxAPIVersion(ctx context.Context, client agentSandboxAPIClient, namespace string) (string, error) {
	if client == nil {
		return "", fmt.Errorf("agent sandbox API client is nil")
	}

	for _, version := range supportedSandboxAPIVersions {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		probeCtx, cancel := context.WithTimeout(ctx, sandboxAPITimeout)
		err := client.ListSandboxes(probeCtx, version, namespace, 1)
		probeErr := probeCtx.Err()
		cancel()
		if probeErr != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if errors.Is(probeErr, context.DeadlineExceeded) {
				return "", fmt.Errorf("timed out after %s waiting for Kubernetes API", sandboxAPITimeout)
			}
		}
		if err == nil {
			return version, nil
		}

		if apierrors.IsNotFound(err) {
			continue
		}
		var statusError kubernetesStatusCoder
		if errors.As(err, &statusError) && statusError.StatusCode() == 404 {
			continue
		}
		return "", fmt.Errorf("probe Agent Sandbox API %s/%s: %w", sandboxAPIGroup, version, err)
	}

	return "", fmt.Errorf(
		"agent sandbox API is unavailable; probed %s",
		strings.Join(supportedSandboxAPIVersions[:], ", "),
	)
}

// sandboxDesiredStateFields ports only the Agent Sandbox API-version mapping
// from OpenShell. It deliberately omits lifecycle annotations and does not
// represent a complete Stop/Start operation: those operations must coordinate
// supervisor release, Pod teardown/readiness, and authenticated generations.
func sandboxDesiredStateFields(version string, running bool) (map[string]any, error) {
	switch version {
	case sandboxAPIVersionV1Beta1:
		mode := "Suspended"
		if running {
			mode = "Running"
		}
		return map[string]any{"operatingMode": mode}, nil
	case sandboxAPIVersionV1Alpha1:
		replicas := 0
		if running {
			replicas = 1
		}
		return map[string]any{"replicas": replicas}, nil
	default:
		return nil, fmt.Errorf("unsupported Agent Sandbox API version %q", version)
	}
}

type sandboxPatchFactory func(resourceVersion string) (map[string]any, error)

// patchSandboxWithResourceVersionRetry ports OpenShell's GET → merge PATCH
// loop. It retries only Kubernetes resourceVersion conflicts, fetching a new
// version before rebuilding the patch; other API errors return immediately.
func patchSandboxWithResourceVersionRetry(
	ctx context.Context,
	client agentSandboxObjectClient,
	version, namespace, name string,
	buildPatch sandboxPatchFactory,
) error {
	if client == nil {
		return fmt.Errorf("agent sandbox API client is nil")
	}
	if buildPatch == nil {
		return fmt.Errorf("agent sandbox patch factory is nil")
	}

	operationCtx, cancel := context.WithTimeout(ctx, sandboxAPITimeout)
	defer cancel()

	for {
		if err := operationCtx.Err(); err != nil {
			return sandboxPatchContextError(ctx, operationCtx, name)
		}
		resourceVersion, err := client.GetSandboxResourceVersion(operationCtx, version, namespace, name)
		if err != nil {
			if operationCtx.Err() != nil {
				return sandboxPatchContextError(ctx, operationCtx, name)
			}
			return fmt.Errorf("get Kubernetes sandbox %s before patch: %w", name, err)
		}
		patch, err := buildPatch(resourceVersion)
		if err != nil {
			return fmt.Errorf("build Kubernetes sandbox %s patch: %w", name, err)
		}
		err = client.PatchSandbox(operationCtx, version, namespace, name, patch)
		if err == nil {
			return nil
		}
		if operationCtx.Err() != nil {
			return sandboxPatchContextError(ctx, operationCtx, name)
		}
		if !apierrors.IsConflict(err) {
			return fmt.Errorf("patch Kubernetes sandbox %s: %w", name, err)
		}
		runtime.Gosched()
	}
}

func sandboxPatchContextError(parent, operation context.Context, name string) error {
	if err := parent.Err(); err != nil {
		return err
	}
	if errors.Is(operation.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("timed out after %s updating Kubernetes sandbox %s", sandboxAPITimeout, name)
	}
	return operation.Err()
}
