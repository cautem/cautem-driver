// Package all blank-imports compute backends so they register with driver.Open.
//
//	import _ "github.com/cautem/cautem-driver/driver/all"
package all

import (
	_ "github.com/cautem/cautem-driver/internal/docker"
	_ "github.com/cautem/cautem-driver/internal/kubernetes"
	_ "github.com/cautem/cautem-driver/internal/podman"
	_ "github.com/cautem/cautem-driver/internal/vm"
)
