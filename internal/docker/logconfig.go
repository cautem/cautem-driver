// SPDX-FileCopyrightText: Copyright (c) 2026 cautem
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"os"
	"strconv"
	"strings"

	"github.com/moby/moby/api/types/container"
)

const (
	envDockerLogDriver  = "CAUTEM_DOCKER_LOG_DRIVER"
	envDockerLogMaxSize = "CAUTEM_DOCKER_LOG_MAX_SIZE"
	envDockerLogMaxFile = "CAUTEM_DOCKER_LOG_MAX_FILE"

	defaultLogDriver  = "json-file"
	defaultLogMaxSize = "10m"
	defaultLogMaxFile = "3"
)

// sandboxLogConfig returns HostConfig.LogConfig for sandbox and proxy sidecars.
// Unbounded docker json-file logs inflate Desktop/LinuxKit VM disk and page cache;
// OpenShell leaves daemon defaults, but we cap rotation unless overridden.
//
// Env:
//
//	CAUTEM_DOCKER_LOG_DRIVER   — json-file (default) or none
//	CAUTEM_DOCKER_LOG_MAX_SIZE — json-file max-size (default 10m)
//	CAUTEM_DOCKER_LOG_MAX_FILE — json-file max-file (default 3)
func sandboxLogConfig() container.LogConfig {
	driver := strings.ToLower(strings.TrimSpace(os.Getenv(envDockerLogDriver)))
	if driver == "" {
		driver = defaultLogDriver
	}
	switch driver {
	case "none":
		return container.LogConfig{Type: "none"}
	case "json-file":
		maxSize := strings.TrimSpace(os.Getenv(envDockerLogMaxSize))
		if maxSize == "" {
			maxSize = defaultLogMaxSize
		}
		maxFile := strings.TrimSpace(os.Getenv(envDockerLogMaxFile))
		if maxFile == "" {
			maxFile = defaultLogMaxFile
		}
		if n, err := strconv.Atoi(maxFile); err != nil || n < 1 {
			maxFile = defaultLogMaxFile
		}
		return container.LogConfig{
			Type: "json-file",
			Config: map[string]string{
				"max-size": maxSize,
				"max-file": maxFile,
			},
		}
	default:
		// Unknown driver: fall back to bounded json-file rather than silent unbounded.
		return container.LogConfig{
			Type: defaultLogDriver,
			Config: map[string]string{
				"max-size": defaultLogMaxSize,
				"max-file": defaultLogMaxFile,
			},
		}
	}
}
