package driver

import (
	"fmt"
	"testing"
	"time"
)

type nativeOpenTestBackend struct {
	Backend
	id BackendID
}

func (backend *nativeOpenTestBackend) ID() BackendID { return backend.id }

func TestRegisteredNativeBackendOpener(t *testing.T) {
	kind := fmt.Sprintf("test-native-%d", time.Now().UnixNano())
	var calls int
	if err := RegisterBackendWithConfig(kind, func(config map[string]any) (Backend, error) {
		calls++
		settings, ok := config["settings"].(map[string]any)
		if !ok || settings["mode"] != "isolated" {
			return nil, fmt.Errorf("factory received config %v", config)
		}
		config["mutated"] = true
		settings["mode"] = "factory-mutated"
		return &nativeOpenTestBackend{id: BackendID(kind)}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if !HasRegisteredBackend(kind) {
		t.Fatal("registered native backend was not discoverable")
	}
	if err := RegisterBackendWithConfig(kind, func(map[string]any) (Backend, error) {
		return &nativeOpenTestBackend{id: BackendID(kind)}, nil
	}); err == nil {
		t.Fatal("duplicate native backend registration succeeded")
	}

	config := map[string]any{"settings": map[string]any{"mode": "isolated", "features": []any{"exec", "copy"}}}
	backend, registered, err := OpenRegisteredBackendWithConfig(kind, config)
	if err != nil {
		t.Fatal(err)
	}
	if !registered || backend == nil || backend.ID() != BackendID(kind) {
		t.Fatalf("opened backend = %v, registered=%t", backend, registered)
	}
	if calls != 1 {
		t.Fatalf("factory calls = %d, want 1", calls)
	}
	if _, mutated := config["mutated"]; mutated {
		t.Fatalf("factory mutated caller config: %v", config)
	}
	settings := config["settings"].(map[string]any)
	if settings["mode"] != "isolated" || settings["features"].([]any)[0] != "exec" {
		t.Fatalf("factory mutated nested caller config: %v", config)
	}
	if backend, registered, err := OpenRegisteredBackendWithConfig(kind+"-missing", nil); err != nil || registered || backend != nil {
		t.Fatalf("missing opener = backend:%v registered:%t err:%v", backend, registered, err)
	}
}

func TestRegisteredNativeBackendRejectsMismatchedIdentity(t *testing.T) {
	kind := fmt.Sprintf("test-native-mismatch-%d", time.Now().UnixNano())
	if err := RegisterBackendWithConfig(kind, func(map[string]any) (Backend, error) {
		return &nativeOpenTestBackend{id: "other"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	backend, registered, err := OpenRegisteredBackendWithConfig(kind, nil)
	if err == nil || !registered || backend != nil {
		t.Fatalf("mismatched opener = backend:%v registered:%t err:%v", backend, registered, err)
	}
}
