package kubernetes

import (
	"strings"
)

func podHasProjectedServiceAccountToken(podSpec map[string]any) bool {
	volumes, _ := podSpec["volumes"].([]any)
	for _, value := range volumes {
		volume, _ := value.(map[string]any)
		projected, _ := volume["projected"].(map[string]any)
		sources, _ := projected["sources"].([]any)
		for _, sourceValue := range sources {
			source, _ := sourceValue.(map[string]any)
			if _, exists := source["serviceAccountToken"]; exists {
				return true
			}
		}
	}
	return false
}

func namedContainer(podSpec map[string]any, field, name string) map[string]any {
	containers, _ := podSpec[field].([]any)
	for _, value := range containers {
		container, _ := value.(map[string]any)
		if container["name"] == name {
			return container
		}
	}
	return nil
}

func initContainerNames(podSpec map[string]any) []string {
	containers, _ := podSpec["initContainers"].([]any)
	names := make([]string, 0, len(containers))
	for _, value := range containers {
		container, _ := value.(map[string]any)
		name, _ := container["name"].(string)
		names = append(names, name)
	}
	return names
}

func onlyBootstrapSchedulingGate(podSpec map[string]any) bool {
	gates, _ := podSpec["schedulingGates"].([]any)
	if len(gates) != 1 {
		return false
	}
	gate, _ := gates[0].(map[string]any)
	return gate["name"] == sandboxRuntimeBootstrapGate
}

func containerHasGatewayCredentialEnv(container map[string]any) bool {
	env, _ := container["env"].([]any)
	for _, value := range env {
		item, _ := value.(map[string]any)
		name, _ := item["name"].(string)
		if name == "OPENSHELL_ENDPOINT" || name == "OPENSHELL_SANDBOX_TOKEN" || name == "OPENSHELL_K8S_SA_TOKEN" || name == "OPENSHELL_K8S_SA_TOKEN_FILE" {
			return true
		}
	}
	return false
}

func containerHasRequiredSecurity(container map[string]any) bool {
	security, _ := container["securityContext"].(map[string]any)
	capabilities, _ := security["capabilities"].(map[string]any)
	dropped, _ := capabilities["drop"].([]any)
	dropsAll := false
	for _, capability := range dropped {
		if capability == "ALL" {
			dropsAll = true
			break
		}
	}
	return security["runAsNonRoot"] == true && security["allowPrivilegeEscalation"] == false && dropsAll
}

func containerMountsVolume(container map[string]any, expected string) bool {
	mounts, _ := container["volumeMounts"].([]any)
	for _, value := range mounts {
		mount, _ := value.(map[string]any)
		if mount["name"] == expected {
			return true
		}
	}
	return false
}

func podReferencesSupervisorSecret(podSpec map[string]any) bool {
	volumes, _ := podSpec["volumes"].([]any)
	for _, value := range volumes {
		volume, _ := value.(map[string]any)
		secret, _ := volume["secret"].(map[string]any)
		secretName, _ := secret["secretName"].(string)
		if strings.HasPrefix(secretName, "os-supervisor-") {
			return true
		}
	}
	return false
}

func hasSchedulingGate(podSpec map[string]any, expected string) bool {
	gates, _ := podSpec["schedulingGates"].([]any)
	for _, value := range gates {
		gate, _ := value.(map[string]any)
		if gate["name"] == expected {
			return true
		}
	}
	return false
}

func podHasSecretReference(podSpec map[string]any, secretName string) bool {
	volumes, _ := podSpec["volumes"].([]any)
	for _, value := range volumes {
		volume, _ := value.(map[string]any)
		secret, _ := volume["secret"].(map[string]any)
		if secret["secretName"] == secretName {
			return true
		}
	}
	return false
}
