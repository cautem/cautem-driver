package kubernetes

import (
	"context"
	"fmt"
	"io"
	"strings"

	core "github.com/cautem/cautem-core"
	"github.com/cautem/cautem-driver/driver"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func (d *Driver) Health(ctx context.Context) driver.Probe {
	probe := driver.Probe{Context: "kubernetes", Isolation: "workspace namespace + NetworkPolicy", Capabilities: []string{"sandbox-lifecycle", "workspace-isolation", "runtime-bridge"}}
	if ctx == nil {
		probe.Error = "health context is nil"
		return probe
	}
	if err := d.runtimeConfig.Validate(); err != nil {
		probe.Error = err.Error()
		return probe
	}
	client, err := d.kubernetesClient()
	if err != nil {
		probe.Error = err.Error()
		return probe
	}
	if _, err := newDynamicAgentSandboxCreateBackend(client).ListWorkspaceNamespaces(ctx, d.gatewayID); err != nil {
		probe.Error = err.Error()
		return probe
	}
	probe.OK = true
	return probe
}

func (d *Driver) ImagePresent(ctx context.Context, ref string) bool {
	if ctx == nil || strings.TrimSpace(ref) == "" {
		return false
	}
	client, err := d.kubernetesClient()
	if err != nil {
		return false
	}
	nodes, err := client.Resource(coreV1GVR("nodes")).List(ctx, metav1.ListOptions{})
	if err != nil || nodes == nil {
		return false
	}
	for i := range nodes.Items {
		images, _, _ := unstructured.NestedSlice(nodes.Items[i].Object, "status", "images")
		for _, raw := range images {
			image, _ := raw.(map[string]any)
			names, _ := image["names"].([]any)
			for _, name := range names {
				if imageReferenceMatches(stringValue(name), ref) {
					return true
				}
			}
		}
	}
	return false
}

func imageReferenceMatches(observed, requested string) bool {
	observed = strings.TrimPrefix(strings.TrimSpace(observed), "docker-pullable://")
	requested = strings.TrimSpace(requested)
	if observed == requested {
		return true
	}
	requestedImage, requestedDigest, hasDigest := strings.Cut(requested, "@sha256:")
	if !hasDigest {
		return false
	}
	observedImage, observedDigest, observedHasDigest := strings.Cut(observed, "@sha256:")
	return observedHasDigest && observedImage == requestedImage && observedDigest == requestedDigest
}

func (d *Driver) RunProbe(ctx context.Context, initBin string) (string, error) {
	if ctx == nil {
		return "", fmt.Errorf("kubernetes probe context is nil")
	}
	if strings.TrimSpace(initBin) == "" {
		return "", fmt.Errorf("kubernetes probe requires a runtime image command; host init binaries cannot run in the cluster")
	}
	return "", fmt.Errorf("kubernetes driver cannot execute a host init binary in a cluster Pod")
}

func (d *Driver) PolicyHostPath(context.Context, string) (string, error) {
	return "", fmt.Errorf("kubernetes policies are stored as namespace Secrets and do not have a local host path")
}

func (d *Driver) ContainerIP(ctx context.Context, containerID, networkName string) (string, error) {
	if ctx == nil {
		return "", fmt.Errorf("kubernetes container IP context is nil")
	}
	identity, err := parseSandboxRuntimeID(containerID)
	if err != nil {
		return "", err
	}
	if networkName != "" && networkName != identity.Namespace {
		return "", fmt.Errorf("kubernetes runtime ID does not belong to requested workspace network")
	}
	_, _, identity, apiClient, err := d.runtimeSandbox(ctx, core.ID(containerID))
	if err != nil {
		return "", err
	}
	podResource := apiClient.client.Resource(coreV1GVR("pods")).Namespace(identity.Namespace)
	pod, err := podResource.Get(ctx, identity.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get Kubernetes workload Pod: %w", err)
	}
	if ownerSandboxUID(pod) != identity.UID {
		return "", fmt.Errorf("workload Pod is not owned by the requested Agent Sandbox")
	}
	ip, _, _ := unstructured.NestedString(pod.Object, "status", "podIP")
	if strings.TrimSpace(ip) == "" {
		return "", fmt.Errorf("kubernetes workload Pod has no assigned IP")
	}
	return ip, nil
}

func (d *Driver) WaitProxyReady(ctx context.Context, sandboxName string) error {
	info, err := d.inspect(ctx, sandboxName)
	if err != nil {
		return err
	}
	return d.start(ctx, info.ID)
}

func (d *Driver) Exec(context.Context, core.ID, driver.ExecRequest) (driver.ExecResult, error) {
	return driver.ExecResult{}, unsupportedKubernetesDataOperation("Exec")
}

func (d *Driver) Logs(context.Context, core.ID, bool, io.Writer) error {
	return unsupportedKubernetesDataOperation("Logs")
}

func (d *Driver) CopyTo(context.Context, core.ID, string, string) error {
	return unsupportedKubernetesDataOperation("CopyTo")
}

func (d *Driver) CopyFrom(context.Context, core.ID, string, string) error {
	return unsupportedKubernetesDataOperation("CopyFrom")
}

func (d *Driver) EnsureSSHDaemon(context.Context, core.ID) error {
	return unsupportedKubernetesDataOperation("EnsureSSHDaemon")
}

func unsupportedKubernetesDataOperation(name string) error {
	return fmt.Errorf("kubernetes driver: %s requires the authenticated Cautem runtime relay", name)
}

var _ driver.Engine = (*Driver)(nil)
var _ driver.ProxyReadiness = (*Driver)(nil)
