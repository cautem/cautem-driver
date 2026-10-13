// Package docker implements driver.ComputeDriver via the Docker Engine API.
package docker

import (
	"errors"
	"strings"

	cerrdefs "github.com/containerd/errdefs"
)

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if cerrdefs.IsNotFound(err) {
		return true
	}
	var notFound interface{ NotFound() }
	return errors.As(err, &notFound)
}

func mergeEnv(base, extra []string) []string {
	keys := map[string]int{}
	out := make([]string, 0, len(base)+len(extra))
	add := func(entry string) {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			return
		}
		if i, exists := keys[key]; exists {
			out[i] = entry
			return
		}
		keys[key] = len(out)
		out = append(out, entry)
	}
	for _, e := range base {
		add(e)
	}
	for _, e := range extra {
		add(e)
	}
	return out
}

func filterIdentityEnv(env []string) []string {
	reserved := map[string]struct{}{
		"OPENSHELL_OCI_IMAGE_USER": {},
		"OPENSHELL_SANDBOX_UID":    {},
		"OPENSHELL_SANDBOX_GID":    {},
	}
	out := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if _, blocked := reserved[key]; blocked {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// ImagePresent reports whether ref exists locally (no pull).
