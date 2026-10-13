package kubernetes

import (
	"strings"
)

func podSecretReference(podSpec map[string]any, volumeName string) string {
	volumes, _ := podSpec["volumes"].([]any)
	for _, value := range volumes {
		volume, _ := value.(map[string]any)
		if volume["name"] != volumeName {
			continue
		}
		secret, _ := volume["secret"].(map[string]any)
		name, _ := secret["secretName"].(string)
		return name
	}
	return ""
}

func projectedServiceAccountToken(podSpec map[string]any) (bool, string) {
	volumes, _ := podSpec["volumes"].([]any)
	found := false
	audience := ""
	for _, value := range volumes {
		volume, _ := value.(map[string]any)
		projected, _ := volume["projected"].(map[string]any)
		sources, _ := projected["sources"].([]any)
		for _, sourceValue := range sources {
			source, _ := sourceValue.(map[string]any)
			token, ok := source["serviceAccountToken"].(map[string]any)
			if ok {
				if found {
					return true, "multiple"
				}
				found = true
				audience, _ = token["audience"].(string)
			}
		}
	}
	return found, audience
}

func containerHasRawSupervisorCredentialEnv(container map[string]any) bool {
	env, _ := container["env"].([]any)
	for _, value := range env {
		item, _ := value.(map[string]any)
		name, _ := item["name"].(string)
		if name == "OPENSHELL_SANDBOX_TOKEN" || name == "OPENSHELL_K8S_SA_TOKEN" {
			return true
		}
	}
	return false
}

func podNamespacesAreIsolated(spec map[string]any) bool {
	for _, key := range []string{"hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"} {
		if boolValue(spec[key]) {
			return false
		}
	}
	return true
}

func podUsesRuntimeDefaultSeccomp(spec map[string]any) bool {
	security, _ := spec["securityContext"].(map[string]any)
	profile, _ := security["seccompProfile"].(map[string]any)
	return profile["type"] == "RuntimeDefault"
}

func containerSecurity(container map[string]any) map[string]any {
	security, _ := container["securityContext"].(map[string]any)
	return security
}

func containerDropsAllCapabilities(security map[string]any) bool {
	capabilities, _ := security["capabilities"].(map[string]any)
	dropped, _ := capabilities["drop"].([]any)
	for _, capability := range dropped {
		if capability == "ALL" {
			return true
		}
	}
	return false
}

func boolValue(value any) bool {
	valueBool, _ := value.(bool)
	return valueBool
}

func workloadRunsAsNonRoot(spec, container map[string]any) bool {
	podSecurity, _ := spec["securityContext"].(map[string]any)
	return boolValue(podSecurity["runAsNonRoot"]) && boolValue(containerSecurity(container)["runAsNonRoot"])
}

func supervisorSecretReferences(podSpec map[string]any) []string {
	volumes, _ := podSpec["volumes"].([]any)
	var names []string
	for _, value := range volumes {
		volume, _ := value.(map[string]any)
		secret, _ := volume["secret"].(map[string]any)
		name, _ := secret["secretName"].(string)
		if strings.HasPrefix(name, "os-supervisor-") {
			names = append(names, name)
		}
	}
	return names
}

func podHasGatewayCredentialEnv(spec map[string]any) bool {
	for _, field := range []string{"containers", "initContainers"} {
		containers, _ := spec[field].([]any)
		for _, value := range containers {
			container, _ := value.(map[string]any)
			if containerHasGatewayCredentialEnv(container) {
				return true
			}
		}
	}
	return false
}
