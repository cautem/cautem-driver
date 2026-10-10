package podman

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/distribution/reference"
	"github.com/moby/moby/api/pkg/authconfig"
	registrytypes "github.com/moby/moby/api/types/registry"

	"github.com/cautem/cautem-driver/internal/docker"
)

const maxRegistryAuthFileBytes = 1 << 20

type podmanAuthFile struct {
	Auths map[string]podmanRegistryCredential `json:"auths"`
}

type podmanRegistryCredential struct {
	Auth          string `json:"auth"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	IdentityToken string `json:"identitytoken"`
	RegistryToken string `json:"registrytoken"`
}

func validateRegistryAuthFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("registry_auth_file must be an absolute clean path")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxRegistryAuthFileBytes {
		return fmt.Errorf("registry_auth_file must be a readable regular file no larger than 1 MiB")
	}
	if f, err := os.Open(path); err != nil {
		return fmt.Errorf("registry_auth_file must be readable")
	} else {
		_ = f.Close()
	}
	return nil
}

func podmanRegistryAuth(imageRef, configuredPath string) (string, error) {
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(imageRef))
	if err != nil {
		return "", fmt.Errorf("podman registry credentials: invalid image reference")
	}
	registry := reference.Domain(named)
	path, err := findPodmanAuthFile(configuredPath)
	if err != nil {
		return "", err
	}
	if path == "" {
		return dockerAuthFallback(imageRef)
	}
	if err := validateRegistryAuthFile(path); err != nil {
		return "", fmt.Errorf("podman: %w", err)
	}
	fileHandle, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("podman registry credentials file is unreadable")
	}
	data, readErr := io.ReadAll(io.LimitReader(fileHandle, maxRegistryAuthFileBytes+1))
	_ = fileHandle.Close()
	if readErr != nil || len(data) > maxRegistryAuthFileBytes {
		return "", fmt.Errorf("podman registry credentials file is invalid")
	}
	var file podmanAuthFile
	if err := json.Unmarshal(data, &file); err != nil {
		return "", fmt.Errorf("podman registry credentials file is invalid")
	}
	for key, entry := range file.Auths {
		if normalizeAuthRegistry(key) != registry {
			continue
		}
		if entry.Auth != "" {
			decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
			if err != nil {
				decoded, err = base64.RawStdEncoding.DecodeString(entry.Auth)
			}
			if err != nil {
				return "", fmt.Errorf("podman registry credentials are invalid for %s", registry)
			}
			username, password, ok := strings.Cut(string(decoded), ":")
			if !ok {
				return "", fmt.Errorf("podman registry credentials are invalid for %s", registry)
			}
			entry.Username, entry.Password = username, password
		}
		encoded, err := authconfig.Encode(registrytypes.AuthConfig{
			Username: entry.Username, Password: entry.Password,
			ServerAddress: registry, IdentityToken: entry.IdentityToken,
			RegistryToken: entry.RegistryToken,
		})
		if err != nil {
			return "", fmt.Errorf("podman registry credentials could not be encoded for %s", registry)
		}
		return encoded, nil
	}
	return dockerAuthFallback(imageRef)
}

func findPodmanAuthFile(configuredPath string) (path string, err error) {
	if strings.TrimSpace(configuredPath) != "" {
		return configuredPath, nil
	}
	if envPath := strings.TrimSpace(os.Getenv("REGISTRY_AUTH_FILE")); envPath != "" {
		return envPath, nil
	}
	var candidates []string
	if runtimeDir := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); runtimeDir != "" {
		candidates = append(candidates, filepath.Join(runtimeDir, "containers", "auth.json"))
	}
	if home, homeErr := os.UserHomeDir(); homeErr == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, ".config", "containers", "auth.json"))
	}
	for _, candidate := range candidates {
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate, nil
		} else if !os.IsNotExist(statErr) {
			return "", fmt.Errorf("podman registry credentials file is unavailable")
		}
	}
	return "", nil
}

func normalizeAuthRegistry(value string) string {
	value = strings.TrimSpace(value)
	if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
		value = parsed.Host
	}
	value = strings.TrimSuffix(value, "/")
	value = strings.TrimSuffix(value, "/v1")
	if value == "index.docker.io" {
		return "docker.io"
	}
	return value
}

func dockerAuthFallback(imageRef string) (string, error) {
	return docker.DockerRegistryAuthForPodman(imageRef)
}
