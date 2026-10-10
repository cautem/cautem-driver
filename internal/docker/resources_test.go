// SPDX-FileCopyrightText: Copyright (c) 2026 cautem
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"testing"

	"github.com/cautem/cautem-core/defaults"
)

func TestResolveProxyImage(t *testing.T) {
	t.Setenv(envProxyImage, "")
	if got := resolveProxyImage(""); got != defaults.ImageProxy {
		t.Fatalf("default=%q want %q", got, defaults.ImageProxy)
	}
	if got := resolveProxyImage("custom:proxy"); got != "custom:proxy" {
		t.Fatalf("explicit=%q", got)
	}
	t.Setenv(envProxyImage, "env:proxy")
	if got := resolveProxyImage(""); got != "env:proxy" {
		t.Fatalf("env=%q", got)
	}
	if got := resolveProxyImage("explicit:wins"); got != "explicit:wins" {
		t.Fatalf("explicit over env=%q", got)
	}
}

func TestResolvePidsLimit(t *testing.T) {
	t.Setenv(envSandboxPidsLimit, "")
	got := resolvePidsLimit(0)
	if got == nil || *got != defaults.SandboxPidsLimit {
		t.Fatalf("default=%v want %d", got, defaults.SandboxPidsLimit)
	}
	got = resolvePidsLimit(4096)
	if got == nil || *got != 4096 {
		t.Fatalf("explicit=%v", got)
	}
	if resolvePidsLimit(-1) != nil {
		t.Fatal("want unlimited for -1")
	}
	t.Setenv(envSandboxPidsLimit, "0")
	if resolvePidsLimit(0) != nil {
		t.Fatal("env 0 → unlimited")
	}
	t.Setenv(envSandboxPidsLimit, "1024")
	got = resolvePidsLimit(0)
	if got == nil || *got != 1024 {
		t.Fatalf("env=%v", got)
	}
}
