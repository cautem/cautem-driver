package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	core "github.com/cautem/cautem-core"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const sandboxPolicyUpdateTimeout = 3 * time.Minute
const runtimeBridgeCertificateRefreshWindow = 30 * 24 * time.Hour

func (d *Driver) start(ctx context.Context, id core.ID) error {
	return d.startRuntime(ctx, id, "")
}

func (d *Driver) startWithToken(ctx context.Context, id core.ID, token string) error {
	if strings.TrimSpace(token) == "" || token != strings.TrimSpace(token) {
		return fmt.Errorf("kubernetes StartWithToken requires a non-empty sandbox bearer")
	}
	return d.startRuntime(ctx, id, token)
}

func (d *Driver) startRuntime(ctx context.Context, id core.ID, replacementToken string) error {
	if ctx == nil {
		return fmt.Errorf("kubernetes Start context is nil")
	}
	object, version, identity, apiClient, err := d.runtimeSandbox(ctx, id)
	if err != nil {
		return err
	}
	backend := newDynamicAgentSandboxCreateBackend(apiClient.client)
	sandboxID := object.GetLabels()[labelSandboxID]
	mode := sandboxOperatingMode(object, version)
	phase, _, _ := unstructured.NestedString(object.Object, "metadata", "annotations", annotationRuntimeBootstrapPhase)
	workloadUID, _, _ := unstructured.NestedString(object.Object, "metadata", "annotations", annotationRuntimeWorkloadUID)
	supervisorUID, _, _ := unstructured.NestedString(object.Object, "metadata", "annotations", annotationRuntimeSupervisorUID)
	if replacementToken == "" && mode == "Running" && phase == "released" && workloadUID != "" && supervisorUID != "" {
		return backend.WaitForRuntimePodsReady(ctx, identity.Namespace, "os-supervisor-"+sandboxID, supervisorUID, identity.Name, workloadUID, identity.UID)
	}
	if mode != "Suspended" && mode != "Running" {
		return fmt.Errorf("agent Sandbox operating mode %q cannot be started safely", mode)
	}
	if err := d.runtimeConfig.Validate(); err != nil {
		return err
	}
	params, err := cautemRuntimeParamsFromSandbox(object, version, d.runtimeConfig)
	if err != nil {
		return err
	}
	if mode == "Running" {
		if _, err := backend.DeleteRuntimePod(ctx, identity.Namespace, "os-supervisor-"+sandboxID, identity.UID); err != nil {
			return err
		}
		if err := backend.WaitForRuntimePodAbsent(ctx, identity.Namespace, "os-supervisor-"+sandboxID, identity.UID); err != nil {
			return err
		}
		if err := backend.SuspendSandboxController(ctx, identity.Namespace, version, identity.Name, identity.UID); err != nil {
			return fmt.Errorf("suspend incomplete Kubernetes runtime before restart: %w", err)
		}
		if err := backend.WaitForOwnedWorkloadAbsent(ctx, identity.Namespace, identity.Name, identity.UID); err != nil {
			return err
		}
		apiVersion, _, _ := unstructured.NestedString(object.Object, "apiVersion")
		if err := backend.MarkRuntimeSuspended(ctx, identity.Namespace, apiVersion, identity.Name, identity.UID); err != nil {
			return fmt.Errorf("record suspended Kubernetes runtime before restart: %w", err)
		}
		object, _, _, _, err = d.runtimeSandbox(ctx, id)
		if err != nil {
			return err
		}
		params, err = cautemRuntimeParamsFromSandbox(object, version, d.runtimeConfig)
		if err != nil {
			return err
		}
	}
	previousGeneration := ""
	if replacementToken != "" {
		previousGeneration = params.Generation
		object, params, err = rotateCautemRuntimeGeneration(ctx, backend, object, params, replacementToken, nil)
		if err != nil {
			return err
		}
	}
	if err := startCautemRuntime(ctx, backend, object, params); err != nil {
		return err
	}
	if previousGeneration != "" {
		previousIdentity := agentSandboxCreateIdentity{
			Namespace: params.Namespace, SandboxName: params.SandboxResourceName, APIVersion: params.SandboxResourceAPIVersion,
			SandboxUID: params.SandboxResourceUID, SandboxID: params.SandboxID, Generation: previousGeneration,
			WorkloadName: params.SandboxResourceName, SupervisorName: "os-supervisor-" + params.SandboxID,
		}
		if err := backend.DeleteCautemGenerationSecrets(ctx, previousIdentity); err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sandboxAPITimeout)
			defer cancel()
			stopErr := d.stop(cleanupCtx, id)
			return errors.Join(fmt.Errorf("remove previous Cautem runtime credentials: %w", err), stopErr)
		}
	}
	return nil
}

func rotateCautemRuntimeGeneration(
	ctx context.Context,
	backend *dynamicAgentSandboxCreateBackend,
	sandbox *unstructured.Unstructured,
	params agentSandboxRuntimeRenderParams,
	token string,
	policyOverride []byte,
) (*unstructured.Unstructured, agentSandboxRuntimeRenderParams, error) {
	oldGeneration := params.Generation
	newGeneration, err := newRuntimeGeneration()
	if err != nil {
		return nil, params, err
	}
	resources, err := renderAgentSandboxRuntimeResources(params)
	if err != nil {
		return nil, params, err
	}
	service, err := backend.CreateBoundaryService(ctx, resources["boundaryService"].(map[string]any))
	if err != nil {
		return nil, params, fmt.Errorf("resolve workload Service before credential rotation: %w", err)
	}
	controlService, err := backend.CreateSupervisorControlService(ctx, resources["controlService"].(map[string]any))
	if err != nil {
		return nil, params, fmt.Errorf("resolve control Service before credential rotation: %w", err)
	}
	if service.OwnerSandboxUID != params.SandboxResourceUID || controlService.OwnerSandboxUID != params.SandboxResourceUID ||
		service.SelectorBoundaryRole != "workload" || controlService.SelectorBoundaryRole != "supervisor" {
		return nil, params, fmt.Errorf("runtime Service identity changed before credential rotation")
	}
	oldIdentity := agentSandboxCreateIdentity{
		Namespace: params.Namespace, SandboxName: params.SandboxResourceName, APIVersion: params.SandboxResourceAPIVersion,
		SandboxUID: params.SandboxResourceUID, SandboxID: params.SandboxID, Generation: oldGeneration,
		ServiceIP: service.ClusterIP, ControlServiceIP: controlService.ClusterIP,
		WorkloadName: params.SandboxResourceName, SupervisorName: "os-supervisor-" + params.SandboxID,
	}
	currentSecrets, err := backend.ReadCautemGenerationSecrets(ctx, oldIdentity)
	if err != nil {
		return nil, params, err
	}
	newIdentity := oldIdentity
	newIdentity.Generation = newGeneration
	newSecrets, err := rotateCautemGenerationSecretsWithPolicy(currentSecrets, oldGeneration, newIdentity, token, policyOverride)
	if err != nil {
		return nil, params, fmt.Errorf("build replacement Cautem runtime generation: %w", err)
	}
	if err := backend.CreateBootstrapSecrets(ctx, newSecrets); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sandboxAPITimeout)
		defer cancel()
		_ = backend.DeleteCautemGenerationSecrets(cleanupCtx, newIdentity)
		return nil, params, fmt.Errorf("create replacement Cautem runtime Secrets: %w", err)
	}
	updatedSandbox, err := backend.SetSandboxRuntimeGeneration(ctx, oldIdentity, newGeneration)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sandboxAPITimeout)
		defer cancel()
		_ = backend.DeleteCautemGenerationSecrets(cleanupCtx, newIdentity)
		return nil, params, fmt.Errorf("switch Agent Sandbox to replacement runtime generation: %w", err)
	}
	params.Generation = newGeneration
	return updatedSandbox, params, nil
}

func (d *Driver) updateSandboxPolicy(ctx context.Context, id core.ID, policy []byte) (result error) {
	if ctx == nil {
		return fmt.Errorf("kubernetes policy update context is nil")
	}
	operationCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sandboxPolicyUpdateTimeout)
	defer cancel()
	ctx = operationCtx
	if len(policy) == 0 || len(policy) > maxRuntimePolicyBytes {
		return fmt.Errorf("kubernetes sandbox policy must contain between 1 byte and %d bytes", maxRuntimePolicyBytes)
	}
	object, version, identity, apiClient, err := d.runtimeSandbox(ctx, id)
	if err != nil {
		return err
	}
	wasRunning := sandboxOperatingMode(object, version) == "Running"
	if !wasRunning && sandboxOperatingMode(object, version) != "Suspended" {
		return fmt.Errorf("agent Sandbox operating mode %q cannot accept a policy update safely", sandboxOperatingMode(object, version))
	}
	params, err := cautemRuntimeParamsFromSandbox(object, version, d.runtimeConfig)
	if err != nil {
		return err
	}
	backend := newDynamicAgentSandboxCreateBackend(apiClient.client)
	sandboxID := object.GetLabels()[labelSandboxID]
	secretIdentity := agentSandboxCreateIdentity{
		Namespace: identity.Namespace, SandboxName: identity.Name, APIVersion: sandboxAPIGroup + "/" + version,
		SandboxUID: identity.UID, SandboxID: sandboxID, Generation: params.Generation,
		WorkloadName: identity.Name, SupervisorName: "os-supervisor-" + sandboxID,
	}
	currentSecrets, err := backend.ReadCautemGenerationSecrets(ctx, secretIdentity)
	if err != nil {
		return err
	}
	currentPolicy, err := cautemGenerationPolicy(currentSecrets, secretIdentity)
	if err != nil {
		return err
	}
	refreshCredentials, err := runtimeBridgeCertificatesNeedRefresh(currentSecrets, secretIdentity, time.Now(), runtimeBridgeCertificateRefreshWindow)
	if err != nil {
		return err
	}
	if string(currentPolicy) == string(policy) && !refreshCredentials {
		return nil
	}
	previousIdentity := secretIdentity
	generationSwitched := false
	if wasRunning {
		defer func() {
			if result == nil {
				return
			}
			recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sandboxAPITimeout)
			defer cancel()
			if recoveryErr := d.start(recoveryCtx, id); recoveryErr != nil {
				result = errors.Join(result, fmt.Errorf("restore Kubernetes runtime after policy update failure: %w", recoveryErr))
			} else if generationSwitched {
				if cleanupErr := backend.DeleteCautemGenerationSecrets(recoveryCtx, previousIdentity); cleanupErr != nil {
					result = errors.Join(result, fmt.Errorf("remove previous Cautem policy generation after recovery: %w", cleanupErr))
				}
			}
		}()
		if err := d.stop(ctx, id); err != nil {
			return fmt.Errorf("suspend Kubernetes runtime before policy update: %w", err)
		}
		object, version, identity, apiClient, err = d.runtimeSandbox(ctx, id)
		if err != nil {
			return err
		}
		params, err = cautemRuntimeParamsFromSandbox(object, version, d.runtimeConfig)
		if err != nil {
			return err
		}
		backend = newDynamicAgentSandboxCreateBackend(apiClient.client)
		secretIdentity.Generation = params.Generation
	}
	resources, err := renderAgentSandboxRuntimeResources(params)
	if err != nil {
		return err
	}
	service, err := backend.CreateBoundaryService(ctx, resources["boundaryService"].(map[string]any))
	if err != nil {
		return fmt.Errorf("resolve workload Service before policy update: %w", err)
	}
	controlService, err := backend.CreateSupervisorControlService(ctx, resources["controlService"].(map[string]any))
	if err != nil {
		return fmt.Errorf("resolve control Service before policy update: %w", err)
	}
	if service.OwnerSandboxUID != identity.UID || controlService.OwnerSandboxUID != identity.UID ||
		service.SelectorBoundaryRole != "workload" || controlService.SelectorBoundaryRole != "supervisor" {
		return fmt.Errorf("runtime Service identity changed before policy update")
	}
	secretIdentity.ServiceIP = service.ClusterIP
	secretIdentity.ControlServiceIP = controlService.ClusterIP
	currentSecrets, err = backend.ReadCautemGenerationSecrets(ctx, secretIdentity)
	if err != nil {
		return err
	}
	currentPolicy, err = cautemGenerationPolicy(currentSecrets, secretIdentity)
	if err != nil {
		return err
	}
	refreshCredentials, err = runtimeBridgeCertificatesNeedRefresh(currentSecrets, secretIdentity, time.Now(), runtimeBridgeCertificateRefreshWindow)
	if err != nil {
		return err
	}
	if string(currentPolicy) == string(policy) && !refreshCredentials {
		if wasRunning {
			return d.start(ctx, id)
		}
		return nil
	}
	token, err := cautemGenerationSandboxToken(currentSecrets, secretIdentity)
	if err != nil {
		return err
	}
	if _, _, err := rotateCautemRuntimeGeneration(ctx, backend, object, params, token, policy); err != nil {
		return err
	}
	generationSwitched = true
	previousIdentity.Generation = params.Generation
	if !wasRunning {
		if err := backend.DeleteCautemGenerationSecrets(ctx, previousIdentity); err != nil {
			return fmt.Errorf("remove previous Cautem policy generation: %w", err)
		}
		return nil
	}
	updatedObject, _, _, _, err := d.runtimeSandbox(ctx, id)
	if err != nil {
		return err
	}
	updatedParams, err := cautemRuntimeParamsFromSandbox(updatedObject, version, d.runtimeConfig)
	if err != nil {
		return err
	}
	if err := startCautemRuntime(ctx, backend, updatedObject, updatedParams); err != nil {
		return fmt.Errorf("start Kubernetes runtime with updated policy: %w", err)
	}
	if err := backend.DeleteCautemGenerationSecrets(ctx, previousIdentity); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sandboxAPITimeout)
		defer cancel()
		stopErr := d.stop(cleanupCtx, id)
		return errors.Join(fmt.Errorf("remove previous Cautem policy generation: %w", err), stopErr)
	}
	return nil
}

func (d *Driver) refreshSandboxRuntimeCredentials(ctx context.Context, id core.ID) error {
	if ctx == nil {
		return fmt.Errorf("kubernetes runtime credential refresh context is nil")
	}
	object, version, identity, apiClient, err := d.runtimeSandbox(ctx, id)
	if err != nil {
		return err
	}
	if sandboxOperatingMode(object, version) != "Running" {
		return nil
	}
	params, err := cautemRuntimeParamsFromSandbox(object, version, d.runtimeConfig)
	if err != nil {
		return err
	}
	sandboxID := object.GetLabels()[labelSandboxID]
	secretIdentity := agentSandboxCreateIdentity{
		Namespace: identity.Namespace, SandboxName: identity.Name, APIVersion: sandboxAPIGroup + "/" + version,
		SandboxUID: identity.UID, SandboxID: sandboxID, Generation: params.Generation,
		WorkloadName: identity.Name, SupervisorName: "os-supervisor-" + sandboxID,
	}
	secrets, err := newDynamicAgentSandboxCreateBackend(apiClient.client).ReadCautemGenerationSecrets(ctx, secretIdentity)
	if err != nil {
		return err
	}
	policy, err := cautemGenerationPolicy(secrets, secretIdentity)
	if err != nil {
		return err
	}
	return d.updateSandboxPolicy(ctx, id, policy)
}

func runtimeBridgeCertificatesNeedRefresh(
	secrets []map[string]any,
	identity agentSandboxCreateIdentity,
	now time.Time,
	refreshWindow time.Duration,
) (bool, error) {
	if refreshWindow <= 0 {
		return false, fmt.Errorf("runtime bridge certificate refresh window must be positive")
	}
	certificateKeys := map[string][]string{
		generationSecretName("os-sandbox", identity.SandboxID, identity.Generation): {
			bridgeTargetServerCert, bridgeControlClientCert, bridgeTargetClientCAFile, bridgeControlClientCAFile,
		},
		generationSecretName("os-supervisor", identity.SandboxID, identity.Generation): {
			bridgeTargetClientCert, bridgeControlServerCert, bridgeTargetServerCAFile, bridgeControlServerCAFile,
		},
	}
	certificates := 0
	for _, secret := range secrets {
		metadata, _ := secret["metadata"].(map[string]any)
		keys, ok := certificateKeys[stringValue(metadata["name"])]
		if !ok {
			continue
		}
		data, _ := secret["data"].(map[string]any)
		for _, key := range keys {
			content, err := decodeSecretData(data, key)
			if err != nil {
				return false, err
			}
			block, _ := pem.Decode(content)
			if block == nil || block.Type != "CERTIFICATE" {
				return false, fmt.Errorf("stored runtime bridge certificate %q is not PEM encoded", key)
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return false, fmt.Errorf("parse stored runtime bridge certificate %q: %w", key, err)
			}
			if now.Before(certificate.NotBefore) {
				return false, fmt.Errorf("stored runtime bridge certificate %q is not valid yet", key)
			}
			certificates++
			if !certificate.NotAfter.After(now.Add(refreshWindow)) {
				return true, nil
			}
		}
	}
	if certificates != 8 {
		return false, fmt.Errorf("stored runtime bridge generation has %d certificates; want 8", certificates)
	}
	return false, nil
}

func cautemGenerationPolicy(secrets []map[string]any, identity agentSandboxCreateIdentity) ([]byte, error) {
	for _, secret := range secrets {
		metadata, _ := secret["metadata"].(map[string]any)
		if stringValue(metadata["name"]) != generationSecretName("os-supervisor", identity.SandboxID, identity.Generation) {
			continue
		}
		data, _ := secret["data"].(map[string]any)
		return decodeSecretData(data, cautemRuntimePolicyKey)
	}
	return nil, fmt.Errorf("cautem supervisor Secret is missing from the active generation")
}

func cautemGenerationSandboxToken(secrets []map[string]any, identity agentSandboxCreateIdentity) (string, error) {
	for _, secret := range secrets {
		metadata, _ := secret["metadata"].(map[string]any)
		if stringValue(metadata["name"]) != generationSecretName("os-supervisor", identity.SandboxID, identity.Generation) {
			continue
		}
		data, _ := secret["data"].(map[string]any)
		value, err := decodeSecretData(data, cautemProxyTokenKey)
		if err != nil {
			return "", err
		}
		token := strings.TrimSpace(string(value))
		if token == "" || strings.ContainsAny(token, "\r\n") {
			return "", fmt.Errorf("stored Cautem sandbox token is invalid")
		}
		return token, nil
	}
	return "", fmt.Errorf("cautem supervisor Secret is missing from the active generation")
}

func (d *Driver) stop(ctx context.Context, id core.ID) error {
	if ctx == nil {
		return fmt.Errorf("kubernetes Stop context is nil")
	}
	object, version, identity, apiClient, err := d.runtimeSandbox(ctx, id)
	if err != nil {
		return err
	}
	backend := newDynamicAgentSandboxCreateBackend(apiClient.client)
	supervisorName := "os-supervisor-" + object.GetLabels()[labelSandboxID]
	if _, err := backend.DeleteRuntimePod(ctx, identity.Namespace, supervisorName, identity.UID); err != nil {
		return err
	}
	if err := backend.WaitForRuntimePodAbsent(ctx, identity.Namespace, supervisorName, identity.UID); err != nil {
		return err
	}
	if sandboxOperatingMode(object, version) != "Suspended" {
		if err := backend.SuspendSandboxController(ctx, identity.Namespace, version, identity.Name, identity.UID); err != nil {
			return fmt.Errorf("suspend Kubernetes Agent Sandbox: %w", err)
		}
	}
	if err := backend.WaitForOwnedWorkloadAbsent(ctx, identity.Namespace, identity.Name, identity.UID); err != nil {
		return err
	}
	apiVersion, _, _ := unstructured.NestedString(object.Object, "apiVersion")
	if err := backend.MarkRuntimeSuspended(ctx, identity.Namespace, apiVersion, identity.Name, identity.UID); err != nil {
		return fmt.Errorf("record suspended Kubernetes runtime: %w", err)
	}
	return nil
}

func (d *Driver) delete(ctx context.Context, id core.ID) error {
	if ctx == nil {
		return fmt.Errorf("kubernetes Delete context is nil")
	}
	identity, err := parseSandboxRuntimeID(string(id))
	if err != nil {
		return err
	}
	client, err := d.kubernetesClient()
	if err != nil {
		return err
	}
	namespaces, err := newDynamicAgentSandboxCreateBackend(client).ListWorkspaceNamespaces(ctx, d.gatewayID)
	if err != nil {
		return err
	}
	if !containsNamespace(namespaces, identity.Namespace) {
		return fmt.Errorf("kubernetes sandbox runtime ID is outside this Gateway's workspace namespaces")
	}
	apiClient := newDynamicAgentSandboxAPIClient(client)
	version, err := d.apiVersions.Resolve(ctx, apiClient, identity.Namespace)
	if err != nil {
		return fmt.Errorf("discover Agent Sandbox API in workspace namespace %s: %w", identity.Namespace, err)
	}
	object, err := apiClient.GetSandboxObject(ctx, version, identity.Namespace, identity.Name)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get Agent Sandbox before delete: %w", err)
	}
	if object == nil || string(object.GetUID()) != identity.UID || !sandboxOwnedByGateway(object, d.gatewayID) {
		return fmt.Errorf("refusing to delete a Kubernetes Agent Sandbox with a different identity or Gateway owner")
	}
	if err := d.stop(ctx, id); err != nil {
		return fmt.Errorf("stop Kubernetes runtime before delete: %w", err)
	}
	backend := newDynamicAgentSandboxCreateBackend(client)
	apiVersion, _, _ := unstructured.NestedString(object.Object, "apiVersion")
	if err := backend.DeleteSandbox(ctx, identity.Namespace, apiVersion, identity.Name, identity.UID); err != nil {
		return fmt.Errorf("delete Kubernetes Agent Sandbox: %w", err)
	}
	return waitForSandboxDeletion(ctx, apiClient, version, identity)
}

func (d *Driver) runtimeSandbox(ctx context.Context, id core.ID) (*unstructured.Unstructured, string, sandboxRuntimeIdentity, *dynamicAgentSandboxAPIClient, error) {
	identity, err := parseSandboxRuntimeID(string(id))
	if err != nil {
		return nil, "", sandboxRuntimeIdentity{}, nil, err
	}
	client, err := d.kubernetesClient()
	if err != nil {
		return nil, "", sandboxRuntimeIdentity{}, nil, err
	}
	namespaces, err := newDynamicAgentSandboxCreateBackend(client).ListWorkspaceNamespaces(ctx, d.gatewayID)
	if err != nil {
		return nil, "", sandboxRuntimeIdentity{}, nil, err
	}
	if !containsNamespace(namespaces, identity.Namespace) {
		return nil, "", sandboxRuntimeIdentity{}, nil, fmt.Errorf("kubernetes sandbox runtime ID is outside this Gateway's workspace namespaces")
	}
	apiClient := newDynamicAgentSandboxAPIClient(client)
	version, err := d.apiVersions.Resolve(ctx, apiClient, identity.Namespace)
	if err != nil {
		return nil, "", sandboxRuntimeIdentity{}, nil, fmt.Errorf("discover Agent Sandbox API in workspace namespace %s: %w", identity.Namespace, err)
	}
	object, err := apiClient.GetSandboxObject(ctx, version, identity.Namespace, identity.Name)
	if apierrors.IsNotFound(err) {
		return nil, "", sandboxRuntimeIdentity{}, nil, fmt.Errorf("kubernetes sandbox runtime ID %q not found", kubernetesRuntimeID(identity))
	}
	if err != nil {
		return nil, "", sandboxRuntimeIdentity{}, nil, fmt.Errorf("get Agent Sandbox for lifecycle operation: %w", err)
	}
	if object == nil || object.GetNamespace() != identity.Namespace || object.GetName() != identity.Name || string(object.GetUID()) != identity.UID || !sandboxOwnedByGateway(object, d.gatewayID) {
		return nil, "", sandboxRuntimeIdentity{}, nil, fmt.Errorf("kubernetes Agent Sandbox identity or Gateway owner does not match the runtime ID")
	}
	return object, version, identity, apiClient, nil
}

func cautemRuntimeParamsFromSandbox(object *unstructured.Unstructured, version string, config EngineConfig) (agentSandboxRuntimeRenderParams, error) {
	labels := object.GetLabels()
	annotations := object.GetAnnotations()
	resourceVersion, _, _ := unstructured.NestedString(object.Object, "apiVersion")
	if resourceVersion != sandboxAPIGroup+"/"+version {
		return agentSandboxRuntimeRenderParams{}, fmt.Errorf("agent Sandbox apiVersion does not match discovered version")
	}
	params := agentSandboxRuntimeRenderParams{
		Namespace: object.GetNamespace(), SandboxResourceName: object.GetName(), SandboxResourceAPIVersion: resourceVersion,
		SandboxResourceUID: string(object.GetUID()), SandboxID: labels[labelSandboxID], SandboxName: labels[labelSandboxName],
		Workspace: labels[labelSandboxWorkspace], GatewayID: labels[labelGatewayID], Generation: annotations[annotationRuntimeGeneration],
		CautemProxyImage: config.ProxyImage, CautemProxyImagePullPolicy: config.ProxyImagePullPolicy,
		CautemGatewayURL: annotations[annotationCautemGatewayURL], CautemGatewayGRPCEndpoint: annotations[annotationCautemGatewayRPC],
		ServiceAccountName: config.ServiceAccountName, ImagePullSecrets: config.ImagePullSecrets,
		ControlUID: config.ControlUID, ControlGID: config.ControlGID, BoundaryPort: config.BoundaryPort,
	}
	parsedTLS, err := strconv.ParseBool(annotations[annotationCautemGatewayTLS])
	if err != nil {
		return agentSandboxRuntimeRenderParams{}, fmt.Errorf("agent Sandbox Cautem TLS annotation is missing or invalid")
	}
	params.CautemGatewayTLS = parsedTLS
	if strings.TrimSpace(params.SandboxName) == "" || params.GatewayID != config.GatewayID || params.Workspace == "" {
		return agentSandboxRuntimeRenderParams{}, fmt.Errorf("agent Sandbox runtime labels do not match this Gateway")
	}
	if err := validateCautemGatewayURL("stored Kubernetes Gateway URL", params.CautemGatewayURL); err != nil {
		return agentSandboxRuntimeRenderParams{}, err
	}
	if err := validateCautemGatewayEndpoint(params.CautemGatewayGRPCEndpoint); err != nil {
		return agentSandboxRuntimeRenderParams{}, err
	}
	parsedURL, _ := url.Parse(params.CautemGatewayURL)
	grpcHost, _, _ := net.SplitHostPort(params.CautemGatewayGRPCEndpoint)
	if !strings.EqualFold(strings.TrimSuffix(parsedURL.Hostname(), "."), strings.TrimSuffix(grpcHost, ".")) {
		return agentSandboxRuntimeRenderParams{}, fmt.Errorf("stored Gateway URL and gRPC endpoint host do not match")
	}
	return params, nil
}

func startCautemRuntime(ctx context.Context, backend *dynamicAgentSandboxCreateBackend, sandbox *unstructured.Unstructured, params agentSandboxRuntimeRenderParams) (result error) {
	resources, err := renderAgentSandboxRuntimeResources(params)
	if err != nil {
		return err
	}
	fence, err := backend.ApplyAndObserveRuntimeFence(ctx, params.Namespace, resources["workloadNetworkPolicy"].(map[string]any), resources["supervisorNetworkPolicy"].(map[string]any))
	if err != nil {
		return fmt.Errorf("verify Kubernetes runtime NetworkPolicy fence before Start: %w", err)
	}
	service, err := backend.CreateBoundaryService(ctx, resources["boundaryService"].(map[string]any))
	if err != nil {
		return fmt.Errorf("verify workload boundary Service before Start: %w", err)
	}
	controlService, err := backend.CreateSupervisorControlService(ctx, resources["controlService"].(map[string]any))
	if err != nil {
		return fmt.Errorf("verify supervisor control Service before Start: %w", err)
	}
	proxyService, err := backend.CreateProxyService(ctx, resources["proxyService"].(map[string]any))
	if err != nil {
		return fmt.Errorf("verify proxy Service before Start: %w", err)
	}
	if service.OwnerSandboxUID != params.SandboxResourceUID || controlService.OwnerSandboxUID != params.SandboxResourceUID || proxyService.OwnerSandboxUID != params.SandboxResourceUID || service.SelectorBoundaryRole != "workload" || controlService.SelectorBoundaryRole != "supervisor" || proxyService.SelectorBoundaryRole != "supervisor" {
		return fmt.Errorf("runtime Service ownership or boundary selectors changed before Start")
	}
	identity := agentSandboxCreateIdentity{
		Namespace: params.Namespace, SandboxName: params.SandboxResourceName, APIVersion: params.SandboxResourceAPIVersion,
		SandboxUID: params.SandboxResourceUID, SandboxID: params.SandboxID, Generation: params.Generation,
		ServiceIP: service.ClusterIP, ControlServiceIP: controlService.ClusterIP,
		WorkloadName: params.SandboxResourceName, SupervisorName: "os-supervisor-" + params.SandboxID,
	}
	secrets, err := backend.ReadCautemGenerationSecrets(ctx, identity)
	if err != nil {
		return err
	}
	if err := validateStoredBridgeTLS(secrets, params.SandboxID, params.Generation); err != nil {
		return err
	}
	if err := validateStoredGuestTLS(secrets, params.SandboxID, params.Generation, params.CautemGatewayTLS); err != nil {
		return err
	}
	supervisor, err := backend.CreateGatedSupervisor(ctx, resources["supervisorPod"].(map[string]any))
	if err != nil {
		return fmt.Errorf("create gated Cautem proxy Pod: %w", err)
	}
	if err := validateAgentSandboxSupervisorIdentity(supervisor, params, params.SandboxResourceUID); err != nil {
		return err
	}
	active := false
	defer func() {
		if result == nil {
			return
		}
		cleanupCtx := context.WithoutCancel(ctx)
		cleanupCtx, cancel := context.WithTimeout(cleanupCtx, sandboxAPITimeout)
		defer cancel()
		_, _ = backend.DeleteRuntimePod(cleanupCtx, params.Namespace, supervisor.Name, params.SandboxResourceUID)
		_ = backend.WaitForRuntimePodAbsent(cleanupCtx, params.Namespace, supervisor.Name, params.SandboxResourceUID)
		if active {
			_ = backend.SuspendSandboxController(cleanupCtx, params.Namespace, params.SandboxResourceAPIVersion, params.SandboxResourceName, params.SandboxResourceUID)
			_ = backend.WaitForOwnedWorkloadAbsent(cleanupCtx, params.Namespace, params.SandboxResourceName, params.SandboxResourceUID)
			_ = backend.MarkRuntimeSuspended(cleanupCtx, params.Namespace, params.SandboxResourceAPIVersion, params.SandboxResourceName, params.SandboxResourceUID)
		}
	}()
	if err := backend.ActivateSandboxController(ctx, params.Namespace, params.SandboxResourceAPIVersion, params.SandboxResourceName, params.SandboxResourceUID); err != nil {
		return fmt.Errorf("activate Agent Sandbox controller: %w", err)
	}
	active = true
	workload, err := backend.WaitForGatedWorkload(ctx, params.Namespace, params.SandboxResourceName, params.SandboxResourceUID, sandbox.Object)
	if err != nil {
		return err
	}
	if err := validateAgentSandboxWorkloadIdentity(workload, params, params.SandboxResourceUID, sandbox.Object); err != nil {
		return err
	}
	pair := agentSandboxCreateIdentity{
		Namespace: params.Namespace, SandboxName: params.SandboxResourceName, APIVersion: params.SandboxResourceAPIVersion,
		SandboxUID: params.SandboxResourceUID, SandboxID: params.SandboxID, Generation: params.Generation,
		ServiceIP: service.ClusterIP, ControlServiceIP: controlService.ClusterIP,
		SupervisorName: supervisor.Name, SupervisorUID: supervisor.UID,
		WorkloadName: workload.Name, WorkloadUID: workload.UID, Fence: fence,
	}
	if err := backend.RecordRuntimePairEvidence(ctx, pair); err != nil {
		return fmt.Errorf("record Cautem runtime Pod identities: %w", err)
	}
	if err := backend.ReleaseSchedulingGate(ctx, params.Namespace, supervisor.Name, supervisor.UID); err != nil {
		return fmt.Errorf("release Cautem proxy scheduling gate: %w", err)
	}
	if err := backend.ReleaseSchedulingGate(ctx, params.Namespace, workload.Name, workload.UID); err != nil {
		return fmt.Errorf("release workload scheduling gate: %w", err)
	}
	if err := backend.WaitForRuntimePodsReady(ctx, params.Namespace, supervisor.Name, supervisor.UID, workload.Name, workload.UID, params.SandboxResourceUID); err != nil {
		return err
	}
	if err := backend.MarkRuntimeReleased(ctx, params.Namespace, params.SandboxResourceAPIVersion, params.SandboxResourceName, params.SandboxResourceUID); err != nil {
		return fmt.Errorf("mark Cautem runtime released: %w", err)
	}
	active = false
	return nil
}

func validateStoredBridgeTLS(secrets []map[string]any, sandboxID, generation string) error {
	workloadName := generationSecretName("os-sandbox", sandboxID, generation)
	supervisorName := generationSecretName("os-supervisor", sandboxID, generation)
	for _, secret := range secrets {
		metadata, _ := secret["metadata"].(map[string]any)
		name := stringValue(metadata["name"])
		data, _ := secret["data"].(map[string]any)
		var pairs [][2]string
		var certificates []string
		switch name {
		case workloadName:
			pairs = [][2]string{{bridgeTargetServerCert, bridgeTargetServerKey}, {bridgeControlClientCert, bridgeControlClientKey}}
			certificates = []string{bridgeTargetClientCAFile, bridgeControlClientCAFile}
		case supervisorName:
			pairs = [][2]string{{bridgeTargetClientCert, bridgeTargetClientKey}, {bridgeControlServerCert, bridgeControlServerKey}}
			certificates = []string{bridgeTargetServerCAFile, bridgeControlServerCAFile}
		default:
			continue
		}
		for _, pair := range pairs {
			cert, err := decodeSecretData(data, pair[0])
			if err != nil {
				return err
			}
			key, err := decodeSecretData(data, pair[1])
			if err != nil {
				return err
			}
			if _, err := tls.X509KeyPair(cert, key); err != nil {
				return fmt.Errorf("stored runtime bridge certificate %q and key do not match: %w", pair[0], err)
			}
			if err := validatePEMCertificateValidity("runtime bridge certificate", cert); err != nil {
				return err
			}
		}
		for _, key := range certificates {
			certificate, err := decodeSecretData(data, key)
			if err != nil {
				return err
			}
			if err := validatePEMCertificateValidity("runtime bridge CA", certificate); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateStoredGuestTLS(secrets []map[string]any, sandboxID, generation string, gatewayTLS bool) error {
	want := 0
	if gatewayTLS {
		want = 3
	}
	for _, secret := range secrets {
		metadata, _ := secret["metadata"].(map[string]any)
		if metadata["name"] != generationSecretName("os-supervisor", sandboxID, generation) {
			continue
		}
		data, _ := secret["data"].(map[string]any)
		count := 0
		for _, key := range []string{cautemGatewayTLSCAKey, cautemGatewayTLSCertKey, cautemGatewayTLSKeyKey} {
			if _, ok := data[key]; ok {
				count++
			}
		}
		if count != want {
			return fmt.Errorf("stored guest TLS Secret does not match the Gateway endpoint scheme")
		}
		if gatewayTLS {
			ca, err := decodeSecretData(data, cautemGatewayTLSCAKey)
			if err != nil {
				return err
			}
			cert, err := decodeSecretData(data, cautemGatewayTLSCertKey)
			if err != nil {
				return err
			}
			key, err := decodeSecretData(data, cautemGatewayTLSKeyKey)
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(ca) {
				return fmt.Errorf("stored guest TLS CA has no valid PEM certificate")
			}
			if _, err := tls.X509KeyPair(cert, key); err != nil {
				return fmt.Errorf("stored guest TLS certificate and key do not match: %w", err)
			}
			if err := validatePEMCertificateValidity("guest TLS certificate", cert); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("stored Cautem supervisor Secret is missing")
}

func decodeSecretData(data map[string]any, key string) ([]byte, error) {
	encoded, ok := data[key].(string)
	if !ok || encoded == "" {
		return nil, fmt.Errorf("stored runtime Secret is missing %q", key)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 {
		return nil, fmt.Errorf("stored runtime Secret key %q is invalid base64", key)
	}
	return decoded, nil
}

func validatePEMCertificateValidity(name string, content []byte) error {
	block, _ := pem.Decode(content)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("stored %s is not a PEM certificate", name)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse stored %s: %w", name, err)
	}
	now := time.Now()
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return fmt.Errorf("stored %s is outside its validity period", name)
	}
	return nil
}

func sandboxOperatingMode(object *unstructured.Unstructured, version string) string {
	if version == sandboxAPIVersionV1Beta1 {
		mode, _, _ := unstructured.NestedString(object.Object, "spec", "operatingMode")
		return mode
	}
	if version == sandboxAPIVersionV1Alpha1 {
		replicas, _, _ := unstructured.NestedInt64(object.Object, "spec", "replicas")
		if replicas == 0 {
			return "Suspended"
		}
		return "Running"
	}
	return "Unknown"
}

func waitForSandboxDeletion(ctx context.Context, client *dynamicAgentSandboxAPIClient, version string, identity sandboxRuntimeIdentity) error {
	// The owner-reference garbage collector removes Pods and Secrets after the
	// CR disappears; this wait makes Delete's result observable to callers.
	waitCtx, cancel := context.WithTimeout(ctx, sandboxAPITimeout)
	defer cancel()
	for {
		_, err := client.GetSandboxObject(waitCtx, version, identity.Namespace, identity.Name)
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			if waitCtx.Err() != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return fmt.Errorf("timed out waiting for Kubernetes Agent Sandbox deletion")
			}
			return fmt.Errorf("wait for Kubernetes Agent Sandbox deletion: %w", err)
		}
		if err := waitForPatchRetry(waitCtx, 100*time.Millisecond); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("timed out waiting for Kubernetes Agent Sandbox deletion")
		}
	}
}
