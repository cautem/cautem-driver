// Package all blank-imports compute backends so they register with driver.Open.
//
//	import _ "github.com/cautem/quarshell-driver/driver/all"
package all

import (
	_ "github.com/cautem/quarshell-driver/internal/docker"
	_ "github.com/cautem/quarshell-driver/internal/kubernetes"
	_ "github.com/cautem/quarshell-driver/internal/podman"
	_ "github.com/cautem/quarshell-driver/internal/vm"
)
