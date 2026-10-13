package kubernetes

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/labels"
)

const (
	workspaceManagedByLabel    = "cautem.ai/managed-by"
	workspaceGatewayHashLabel  = "cautem.ai/gateway-hash"
	workspaceIdentityHashLabel = "cautem.ai/workspace-hash"
	workspaceIsolationPolicy   = "cautem-default-deny"
)

// workspaceNamespaceName returns a stable, non-identifying namespace for one
// gateway/workspace pair. The raw workspace key is not copied into the
// namespace name or its identity labels.
func workspaceNamespaceName(gatewayID, workspace string) (string, error) {
	if strings.TrimSpace(gatewayID) == "" || strings.TrimSpace(workspace) == "" {
		return "", fmt.Errorf("gateway and workspace identifiers are required")
	}
	if gatewayID != strings.TrimSpace(gatewayID) || workspace != strings.TrimSpace(workspace) {
		return "", fmt.Errorf("gateway and workspace identifiers must not contain surrounding whitespace")
	}
	identity := sha256.Sum256([]byte(gatewayID + "\x00" + workspace))
	return "cautem-ws-" + hex.EncodeToString(identity[:16]), nil
}

func workspaceIdentityLabels(gatewayID, workspace string) (map[string]any, error) {
	if strings.TrimSpace(gatewayID) == "" || strings.TrimSpace(workspace) == "" {
		return nil, fmt.Errorf("gateway and workspace identifiers are required")
	}
	if gatewayID != strings.TrimSpace(gatewayID) || workspace != strings.TrimSpace(workspace) {
		return nil, fmt.Errorf("gateway and workspace identifiers must not contain surrounding whitespace")
	}
	gatewayHash, err := workspaceGatewayHash(gatewayID)
	if err != nil {
		return nil, err
	}
	workspaceHash := sha256.Sum256([]byte(workspace))
	return map[string]any{
		workspaceManagedByLabel:    "cautem",
		workspaceGatewayHashLabel:  gatewayHash,
		workspaceIdentityHashLabel: hex.EncodeToString(workspaceHash[:16]),
	}, nil
}

func workspaceGatewayHash(gatewayID string) (string, error) {
	if strings.TrimSpace(gatewayID) == "" || gatewayID != strings.TrimSpace(gatewayID) {
		return "", fmt.Errorf("gateway identifier must be non-empty and have no surrounding whitespace")
	}
	hash := sha256.Sum256([]byte(gatewayID))
	return hex.EncodeToString(hash[:16]), nil
}

func validWorkspaceIdentityHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == value
}

func workspaceNamespaceSelector(gatewayID string) (string, error) {
	hash, err := workspaceGatewayHash(gatewayID)
	if err != nil {
		return "", err
	}
	return labels.Set{
		workspaceManagedByLabel:   "cautem",
		workspaceGatewayHashLabel: hash,
	}.AsSelector().String(), nil
}

func renderWorkspaceIsolationResources(gatewayID, workspace string) (string, map[string]any, map[string]any, error) {
	namespace, err := workspaceNamespaceName(gatewayID, workspace)
	if err != nil {
		return "", nil, nil, err
	}
	labels, err := workspaceIdentityLabels(gatewayID, workspace)
	if err != nil {
		return "", nil, nil, err
	}
	namespaceResource := map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name":   namespace,
			"labels": labels,
		},
	}
	denyAll := map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata": map[string]any{
			"name":      workspaceIsolationPolicy,
			"namespace": namespace,
			"labels": map[string]any{
				workspaceManagedByLabel: "cautem",
				"cautem.ai/component":   "workspace-default-deny",
			},
		},
		"spec": map[string]any{
			"podSelector": map[string]any{},
			"policyTypes": []any{"Ingress", "Egress"},
			"ingress":     []any{},
			"egress":      []any{},
		},
	}
	return namespace, namespaceResource, denyAll, nil
}
