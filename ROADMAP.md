# Roadmap — cautem-driver

Status: **v0.3.1** (release prepared) · Depends on [quarshell-core](https://github.com/cautem/quarshell-core) `v0.3.1` and quarshell-proxy `v0.3.1`

## This module

| ID | Item | Notes |
|----|------|-------|
| D1 | **Kubernetes driver** | Experimental Agent Sandbox lifecycle, PVC workspace, runtime and proxy Pods; direct exec/log/copy remains unsupported |
| D2 | **MicroVM driver** | Experimental libkrun lifecycle, per-VM policy/network broker, guest supervisor and SSH relay; safe host workspace isolation and live Linux KVM acceptance remain open |
| D3 | **GPU / CDI polish** | Inventory-based device pick; Podman parity |
| D4 | **Windows build matrix** | Keep SIGWINCH / TTY paths build-tagged clean |

## Release

Requires quarshell-core `v0.3.1` and quarshell-proxy `v0.3.1` · release after core and proxy.
