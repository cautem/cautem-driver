package driver

import (
	"fmt"
	"strings"
	"sync"
)

var (
	mu                   sync.RWMutex
	openers              = map[string]func() (ComputeDriver, error){}
	engineOpeners        = map[string]func() (Engine, error){}
	engineConfigOpeners  = map[string]func(map[string]any) (Engine, error){}
	backendConfigOpeners = map[string]func(map[string]any) (Backend, error){}
)

// Register binds a ComputeDriver factory (called from backend init).
func Register(kind string, open func() (ComputeDriver, error)) {
	mu.Lock()
	defer mu.Unlock()
	openers[normalizeKind(kind)] = open
}

// RegisterEngine binds a Docker/Podman Engine factory.
func RegisterEngine(kind string, open func() (Engine, error)) {
	mu.Lock()
	defer mu.Unlock()
	engineOpeners[normalizeKind(kind)] = open
}

// RegisterEngineWithConfig binds a factory that consumes driver-specific
// configuration. Config-aware factories are preferred by OpenEngineWithConfig.
func RegisterEngineWithConfig(kind string, open func(map[string]any) (Engine, error)) {
	mu.Lock()
	defer mu.Unlock()
	engineConfigOpeners[normalizeKind(kind)] = open
}

// RegisterBackendWithConfig binds a native Backend factory. New backends
// should register this product contract directly instead of implementing the
// legacy Engine interface. The returned backend ID must match the normalized
// kind supplied at registration.
func RegisterBackendWithConfig(kind string, open func(map[string]any) (Backend, error)) error {
	name := strings.TrimSpace(kind)
	if name == "" || open == nil {
		return fmt.Errorf("driver: backend kind and factory are required")
	}
	name = normalizeKind(name)
	mu.Lock()
	defer mu.Unlock()
	if _, exists := backendConfigOpeners[name]; exists {
		return fmt.Errorf("driver: backend kind %q is already registered", name)
	}
	backendConfigOpeners[name] = open
	return nil
}

// OpenRegisteredBackendWithConfig opens a native Backend factory when one is
// registered. registered is true even when factory construction fails, so the
// caller can distinguish a broken native backend from an absent registration
// and must not silently fall back to a legacy Engine in that case.
func OpenRegisteredBackendWithConfig(kind string, config map[string]any) (backend Backend, registered bool, err error) {
	name := normalizeKind(kind)
	mu.RLock()
	factory := backendConfigOpeners[name]
	mu.RUnlock()
	if factory == nil {
		return nil, false, nil
	}
	backend, err = factory(cloneBackendConfig(config))
	if err != nil {
		return nil, true, fmt.Errorf("driver: open backend %q: %w", name, err)
	}
	if backend == nil {
		return nil, true, fmt.Errorf("driver: backend factory %q returned nil", name)
	}
	if got := backend.ID(); got != BackendID(name) {
		return nil, true, fmt.Errorf("driver: backend factory %q returned mismatched id %q", name, got)
	}
	return backend, true, nil
}

// HasRegisteredBackend reports whether kind has a native Backend factory.
// Configuration validation can use it without constructing the backend.
func HasRegisteredBackend(kind string) bool {
	mu.RLock()
	defer mu.RUnlock()
	return backendConfigOpeners[normalizeKind(kind)] != nil
}

func cloneBackendConfig(config map[string]any) map[string]any {
	if config == nil {
		return nil
	}
	cloned := make(map[string]any, len(config))
	for key, value := range config {
		cloned[key] = cloneBackendConfigValue(value)
	}
	return cloned
}

func cloneBackendConfigValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneBackendConfig(typed)
	case []any:
		cloned := make([]any, len(typed))
		for i, item := range typed {
			cloned[i] = cloneBackendConfigValue(item)
		}
		return cloned
	case []string:
		return append([]string(nil), typed...)
	case []byte:
		return append([]byte(nil), typed...)
	default:
		return value
	}
}

// Open returns a ComputeDriver for kind: docker | podman | vm | kubernetes.
// Import driver/all (blank) once from main so backends register.
func Open(kind string) (ComputeDriver, error) {
	mu.RLock()
	f := openers[normalizeKind(kind)]
	mu.RUnlock()
	if f == nil {
		return nil, fmt.Errorf("driver: unknown kind %q (import _ \"…/driver/all\"?)", kind)
	}
	return f()
}

// OpenEngine returns a Docker/Podman Engine (ComputeDriver + host API helpers).
func OpenEngine(kind string) (Engine, error) {
	mu.RLock()
	f := engineOpeners[normalizeKind(kind)]
	mu.RUnlock()
	if f == nil {
		return nil, fmt.Errorf("driver: kind %q has no Engine API (want docker|podman; import _ \"…/driver/all\"?)", kind)
	}
	return f()
}

// OpenEngineWithConfig opens an Engine using its backend-specific options.
// Non-empty config is rejected when the backend has no config-aware factory.
func OpenEngineWithConfig(kind string, config map[string]any) (Engine, error) {
	mu.RLock()
	f := engineConfigOpeners[normalizeKind(kind)]
	mu.RUnlock()
	if f != nil {
		return f(config)
	}
	if len(config) != 0 {
		return nil, fmt.Errorf("driver: kind %q does not accept driver configuration", kind)
	}
	return OpenEngine(kind)
}

func normalizeKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "podman":
		return "podman"
	case "vm", "microvm":
		return "vm"
	case "kubernetes", "k8s":
		return "kubernetes"
	case "", "docker":
		return "docker"
	default:
		return strings.ToLower(strings.TrimSpace(kind))
	}
}

// CanonicalBackendID maps supported aliases to their product backend identity.
func CanonicalBackendID(kind string) BackendID { return BackendID(normalizeKind(kind)) }
