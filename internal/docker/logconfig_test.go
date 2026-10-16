// SPDX-FileCopyrightText: Copyright (c) 2026 cautem
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"testing"
)

func TestSandboxLogConfigDefault(t *testing.T) {
	t.Setenv(envDockerLogDriver, "")
	t.Setenv(envDockerLogMaxSize, "")
	t.Setenv(envDockerLogMaxFile, "")
	cfg := sandboxLogConfig("")
	if cfg.Type != "json-file" {
		t.Fatalf("Type=%q want json-file", cfg.Type)
	}
	if cfg.Config["max-size"] != "10m" {
		t.Fatalf("max-size=%q want 10m", cfg.Config["max-size"])
	}
	if cfg.Config["max-file"] != "3" {
		t.Fatalf("max-file=%q want 3", cfg.Config["max-file"])
	}
}

func TestSandboxLogConfigNone(t *testing.T) {
	t.Setenv(envDockerLogDriver, "none")
	cfg := sandboxLogConfig("")
	if cfg.Type != "none" {
		t.Fatalf("Type=%q want none", cfg.Type)
	}
	if len(cfg.Config) != 0 {
		t.Fatalf("Config=%v want empty", cfg.Config)
	}
}

func TestSandboxLogConfigOverrides(t *testing.T) {
	t.Setenv(envDockerLogDriver, "json-file")
	t.Setenv(envDockerLogMaxSize, "5m")
	t.Setenv(envDockerLogMaxFile, "2")
	cfg := sandboxLogConfig("")
	if cfg.Config["max-size"] != "5m" || cfg.Config["max-file"] != "2" {
		t.Fatalf("Config=%v", cfg.Config)
	}
}

func TestSandboxLogConfigInvalidMaxFile(t *testing.T) {
	t.Setenv(envDockerLogDriver, "json-file")
	t.Setenv(envDockerLogMaxFile, "0")
	cfg := sandboxLogConfig("")
	if cfg.Config["max-file"] != defaultLogMaxFile {
		t.Fatalf("max-file=%q want %s", cfg.Config["max-file"], defaultLogMaxFile)
	}
}

func TestSandboxLogConfigUnknownDriverFallsBack(t *testing.T) {
	t.Setenv(envDockerLogDriver, "syslog")
	cfg := sandboxLogConfig("")
	if cfg.Type != "json-file" {
		t.Fatalf("Type=%q want json-file fallback", cfg.Type)
	}
}

func TestSandboxLogConfigRuntimeDefault(t *testing.T) {
	t.Setenv(envDockerLogDriver, "")
	cfg := sandboxLogConfig("k8s-file")
	if cfg.Type != "k8s-file" || len(cfg.Config) != 0 {
		t.Fatalf("LogConfig=%+v, want bare k8s-file", cfg)
	}
}

func TestSandboxLogConfigEnvironmentOverridesRuntimeDefault(t *testing.T) {
	t.Setenv(envDockerLogDriver, "none")
	cfg := sandboxLogConfig("k8s-file")
	if cfg.Type != "none" {
		t.Fatalf("Type=%q want environment override none", cfg.Type)
	}
}
