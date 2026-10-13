package kubernetes

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

const internalGatewayIDConfigKey = "cautem_internal_gateway_id"

// EngineConfig contains operator-owned Kubernetes runtime settings. Per-sandbox
// driver_config remains limited to workload resources, PVC mounts, and Pod
// scheduling preferences.
type EngineConfig struct {
	GatewayID                     string
	DefaultImage                  string
	ProxyImage                    string
	ProxyImagePullPolicy          string
	SandboxRuntimeImage           string
	SandboxRuntimeImagePullPolicy string
	GRPCEndpoint                  string
	GuestTLSCA                    string
	GuestTLSCert                  string
	GuestTLSKey                   string
	ServiceAccountName            string
	ImagePullSecrets              []string
	SandboxUID                    int64
	SandboxGID                    int64
	ControlUID                    int64
	ControlGID                    int64
	BoundaryPort                  int64
	WorkspaceStorageSize          string
	WorkspaceStorageClass         string
	EnableUserNamespaces          bool
	DefaultRuntimeClassName       string
}

func EngineConfigFromMap(values map[string]any) (EngineConfig, error) {
	config := EngineConfigFromEnvironment()
	for key, raw := range values {
		var err error
		switch key {
		case internalGatewayIDConfigKey:
			config.GatewayID, err = engineString(raw, key)
		case "default_image":
			config.DefaultImage, err = engineString(raw, key)
		case "proxy_image":
			config.ProxyImage, err = engineString(raw, key)
		case "proxy_image_pull_policy":
			config.ProxyImagePullPolicy, err = engineString(raw, key)
		case "sandbox_runtime_image":
			config.SandboxRuntimeImage, err = engineString(raw, key)
		case "sandbox_runtime_image_pull_policy":
			config.SandboxRuntimeImagePullPolicy, err = engineString(raw, key)
		case "grpc_endpoint":
			config.GRPCEndpoint, err = engineString(raw, key)
		case "guest_tls_ca":
			config.GuestTLSCA, err = engineString(raw, key)
		case "guest_tls_cert":
			config.GuestTLSCert, err = engineString(raw, key)
		case "guest_tls_key":
			config.GuestTLSKey, err = engineString(raw, key)
		case "service_account_name":
			config.ServiceAccountName, err = engineString(raw, key)
		case "image_pull_secrets":
			config.ImagePullSecrets, err = engineStrings(raw, key)
		case "sandbox_uid":
			config.SandboxUID, err = engineInt64(raw, key)
		case "sandbox_gid":
			config.SandboxGID, err = engineInt64(raw, key)
		case "control_uid":
			config.ControlUID, err = engineInt64(raw, key)
		case "control_gid":
			config.ControlGID, err = engineInt64(raw, key)
		case "boundary_port":
			config.BoundaryPort, err = engineInt64(raw, key)
		case "workspace_storage_size":
			config.WorkspaceStorageSize, err = engineString(raw, key)
		case "workspace_storage_class":
			config.WorkspaceStorageClass, err = engineString(raw, key)
		case "enable_user_namespaces":
			config.EnableUserNamespaces, err = engineBool(raw, key)
		case "runtime_class_name":
			config.DefaultRuntimeClassName, err = engineString(raw, key)
		default:
			return EngineConfig{}, fmt.Errorf("unknown kubernetes compute driver setting %q", key)
		}
		if err != nil {
			return EngineConfig{}, err
		}
	}
	config.applyDefaults()
	if err := config.Validate(); err != nil {
		return EngineConfig{}, err
	}
	return config, nil
}

func EngineConfigFromEnvironment() EngineConfig {
	config := EngineConfig{
		GatewayID:                     strings.TrimSpace(os.Getenv("CAUTEM_GATEWAY_ID")),
		DefaultImage:                  strings.TrimSpace(os.Getenv("CAUTEM_KUBERNETES_DEFAULT_IMAGE")),
		ProxyImage:                    strings.TrimSpace(os.Getenv("CAUTEM_KUBERNETES_PROXY_IMAGE")),
		SandboxRuntimeImage:           strings.TrimSpace(os.Getenv("CAUTEM_KUBERNETES_RUNTIME_IMAGE")),
		GRPCEndpoint:                  strings.TrimSpace(os.Getenv("CAUTEM_KUBERNETES_GRPC_ENDPOINT")),
		GuestTLSCA:                    strings.TrimSpace(os.Getenv("CAUTEM_KUBERNETES_GUEST_TLS_CA")),
		GuestTLSCert:                  strings.TrimSpace(os.Getenv("CAUTEM_KUBERNETES_GUEST_TLS_CERT")),
		GuestTLSKey:                   strings.TrimSpace(os.Getenv("CAUTEM_KUBERNETES_GUEST_TLS_KEY")),
		ServiceAccountName:            strings.TrimSpace(os.Getenv("CAUTEM_KUBERNETES_SERVICE_ACCOUNT")),
		WorkspaceStorageClass:         strings.TrimSpace(os.Getenv("CAUTEM_KUBERNETES_STORAGE_CLASS")),
		ProxyImagePullPolicy:          strings.TrimSpace(os.Getenv("CAUTEM_KUBERNETES_PROXY_IMAGE_PULL_POLICY")),
		SandboxRuntimeImagePullPolicy: strings.TrimSpace(os.Getenv("CAUTEM_KUBERNETES_RUNTIME_IMAGE_PULL_POLICY")),
		WorkspaceStorageSize:          strings.TrimSpace(os.Getenv("CAUTEM_KUBERNETES_STORAGE_SIZE")),
	}
	config.applyDefaults()
	return config
}

func (config *EngineConfig) applyDefaults() {
	if config.ServiceAccountName == "" {
		config.ServiceAccountName = "default"
	}
	if config.ProxyImagePullPolicy == "" {
		config.ProxyImagePullPolicy = "IfNotPresent"
	}
	if config.SandboxRuntimeImagePullPolicy == "" {
		config.SandboxRuntimeImagePullPolicy = "IfNotPresent"
	}
	if config.SandboxUID == 0 {
		config.SandboxUID = 10001
	}
	if config.SandboxGID == 0 {
		config.SandboxGID = 10001
	}
	if config.ControlUID == 0 {
		config.ControlUID = 10001
	}
	if config.ControlGID == 0 {
		config.ControlGID = 10001
	}
	if config.BoundaryPort == 0 {
		config.BoundaryPort = cautemWorkloadBoundaryPort
	}
	if config.WorkspaceStorageSize == "" {
		config.WorkspaceStorageSize = defaultWorkspaceStorage
	}
}

func (config EngineConfig) Validate() error {
	if strings.TrimSpace(config.GatewayID) == "" || config.GatewayID != strings.TrimSpace(config.GatewayID) {
		return fmt.Errorf("kubernetes compute driver requires the internal Gateway ID")
	}
	if errs := validation.IsValidLabelValue(config.GatewayID); len(errs) != 0 {
		return fmt.Errorf("kubernetes compute driver Gateway ID must be a Kubernetes label value")
	}
	for _, entry := range []struct{ name, image string }{
		{"proxy image", config.ProxyImage}, {"sandbox runtime image", config.SandboxRuntimeImage},
	} {
		parts := strings.Split(entry.image, "@sha256:")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || len(parts[1]) != 64 {
			return fmt.Errorf("kubernetes %s must be pinned by sha256 digest", entry.name)
		}
		if _, err := hex.DecodeString(parts[1]); err != nil {
			return fmt.Errorf("kubernetes %s must use a valid sha256 digest", entry.name)
		}
	}
	if config.GRPCEndpoint == "" {
		return fmt.Errorf("kubernetes compute driver grpc_endpoint is required")
	}
	gatewayURL, _, err := resolveKubernetesGatewayEndpoint("", config.GRPCEndpoint)
	if err != nil {
		return fmt.Errorf("invalid kubernetes grpc_endpoint: %w", err)
	}
	parsedGateway, _ := url.Parse(gatewayURL)
	guestTLSConfigured := config.GuestTLSCA != "" && config.GuestTLSCert != "" && config.GuestTLSKey != ""
	if (parsedGateway.Scheme == "https") != guestTLSConfigured {
		return fmt.Errorf("kubernetes guest TLS CA, certificate, and key must be set exactly for an HTTPS grpc_endpoint")
	}
	if config.GuestTLSCA != "" && config.GuestTLSCert != "" && config.GuestTLSKey != "" {
		for _, path := range []string{config.GuestTLSCA, config.GuestTLSCert, config.GuestTLSKey} {
			if !filepath.IsAbs(path) {
				return fmt.Errorf("kubernetes guest TLS file paths must be absolute")
			}
		}
	}
	if err := requireDNS1123Subdomain("kubernetes service account name", config.ServiceAccountName); err != nil {
		return err
	}
	if config.SandboxUID < 1 || config.SandboxGID < 1 || config.ControlUID < 1 || config.ControlGID < 1 {
		return fmt.Errorf("kubernetes runtime UID and GID values must be non-root")
	}
	if config.BoundaryPort < 1024 || config.BoundaryPort > 65535 {
		return fmt.Errorf("kubernetes runtime boundary port must be between 1024 and 65535")
	}
	if len(config.GuestTLSCA) == 0 != (len(config.GuestTLSCert) == 0) || len(config.GuestTLSCert) == 0 != (len(config.GuestTLSKey) == 0) {
		return fmt.Errorf("guest TLS CA, certificate, and key paths must be configured together")
	}
	for _, secret := range config.ImagePullSecrets {
		if err := requireDNS1123Subdomain("image pull Secret name", secret); err != nil {
			return err
		}
	}
	return nil
}

func engineString(raw any, key string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("kubernetes compute driver setting %q must be a string", key)
	}
	return strings.TrimSpace(value), nil
}

func engineInt64(raw any, key string) (int64, error) {
	switch value := raw.(type) {
	case int:
		return int64(value), nil
	case int32:
		return int64(value), nil
	case int64:
		return value, nil
	case float64:
		return int64(value), nil
	default:
		return 0, fmt.Errorf("kubernetes compute driver setting %q must be an integer", key)
	}
}

func engineBool(raw any, key string) (bool, error) {
	value, ok := raw.(bool)
	if !ok {
		return false, fmt.Errorf("kubernetes compute driver setting %q must be a boolean", key)
	}
	return value, nil
}

func engineStrings(raw any, key string) ([]string, error) {
	switch values := raw.(type) {
	case []string:
		return append([]string(nil), values...), nil
	case []any:
		result := make([]string, len(values))
		for index, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("kubernetes compute driver setting %q must contain only strings", key)
			}
			result[index] = strings.TrimSpace(text)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("kubernetes compute driver setting %q must be a string array", key)
	}
}
