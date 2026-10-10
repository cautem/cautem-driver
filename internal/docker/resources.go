// SPDX-FileCopyrightText: Copyright (c) 2026 cautem
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"os"
	"strconv"
	"strings"

	"github.com/cautem/cautem-core/defaults"
)

const (
	envProxyImage       = "CAUTEM_PROXY_IMAGE"
	envSandboxPidsLimit = "CAUTEM_SANDBOX_PIDS_LIMIT"
)

// resolveProxyImage returns the OCI image for the egress sidecar.
// Prefer Spec.ProxyImage, then CAUTEM_PROXY_IMAGE, then defaults.ImageProxy.
// Never reuse the fat agent/sandbox image unless the operator points ProxyImage at it.
func resolveProxyImage(explicit string) string {
	if s := strings.TrimSpace(explicit); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv(envProxyImage)); s != "" {
		return s
	}
	return defaults.ImageProxy
}

// resolvePidsLimit returns the Docker PidsLimit pointer.
// Spec 0 → env CAUTEM_SANDBOX_PIDS_LIMIT or OpenShell-aligned 2048.
// Spec -1 or env 0 → unlimited (nil).
// Spec > 0 → that value.
func resolvePidsLimit(specLimit int64) *int64 {
	if specLimit < 0 {
		return nil
	}
	if specLimit > 0 {
		v := specLimit
		return &v
	}
	raw := strings.TrimSpace(os.Getenv(envSandboxPidsLimit))
	if raw == "" {
		v := defaults.SandboxPidsLimit
		return &v
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		v := defaults.SandboxPidsLimit
		return &v
	}
	if n == 0 {
		return nil
	}
	return &n
}
