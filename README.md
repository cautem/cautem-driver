<h1 align="center">cautem-driver</h1>

<p align="center">
  <strong>Compute drivers</strong><br>
  Docker-first sandbox runtime — mounts, ExtraHosts, egress sidecar wiring.
</p>
<p align="center">
  <a href="https://github.com/cautem/cautem-driver/actions/workflows/ci.yml"><img src="https://github.com/cautem/cautem-driver/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pkg.go.dev/github.com/cautem/cautem-driver"><img src="https://pkg.go.dev/badge/github.com/cautem/cautem-driver.svg" alt="Go Reference"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/cautem/cautem-driver"><img src="https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go" alt="Go Version"></a>
</p>
<p align="center">
  <sub>Part of the <a href="https://github.com/cautem">cautem / cautem</a> ecosystem</sub>
</p>

---

## Overview

Backend setup and runtime limits are maintained in the [Docker](https://cautem.github.io/sandbox.dev/providers/docker/) and [Podman](https://cautem.github.io/sandbox.dev/providers/podman/) guides. The [OpenShell compatibility page](https://cautem.github.io/sandbox.dev/reference/openshell-compatibility/) records the current comparison scope.

**cautem-driver** implements `ComputeDriver` for cautem. Docker and Podman provide the local container lifecycle; Kubernetes provisions Agent Sandbox workloads and a paired Cautem proxy companion. The Kubernetes backend remains experimental until the target cluster passes the live runtime and NetworkPolicy checks in the [Gateway packaging guide](https://github.com/cautem/cautem-gateway/blob/main/packaging/README.md).

### Key Features

| Category | Capabilities |
|----------|--------------|
| **Docker** | Engine API create/exec/logs (Podman-compatible socket) |
| **Kubernetes** | Agent Sandbox lifecycle, workspace namespace/PVC, gated workload and proxy Pods, immutable credential generations |
| **Sidecar** | Proxy container on dual-home network + CA bundle env |
| **Hosts** | `HostGatewayExtraHosts()` → `host.cautem.internal` / `host.docker.internal` |
| **Mounts** | Workdir + reserved system paths validation |
| **Experimental** | Kubernetes requires Agent Sandbox, digest-pinned Cautem images, persistent storage, and a CNI that enforces NetworkPolicy |
| **Stubs** | VM placeholder |

---

## Installation

Run `go test ./...` from this checkout. The module is also available as a standalone Go dependency.

**Requirements:** Go 1.27+, Docker-compatible Engine API 1.40 or newer.

The driver uses the separate Moby `client` and `api` SDK modules pinned in
`go.mod`. API negotiation is enabled by default; Docker configuration uses
`DOCKER_*`, while Podman selects its compatible socket. SDK dependency checks
cover the client code; keep the Engine daemon updated independently.

---

## Quick Start

```go
import (
    "github.com/cautem/cautem-driver/driver"
    _ "github.com/cautem/cautem-driver/driver/all" // register backends
)

d, err := driver.OpenEngine("docker")
_ = d
_ = err
hosts := driver.HostGatewayExtraHosts()
// []string{"host.cautem.internal:host-gateway", "host.docker.internal:host-gateway"}
_ = hosts
```

---

## Package Structure

| Path | Purpose |
|------|---------|
| `driver/` | Public API: `ComputeDriver`, `Engine`, `Open` / `OpenEngine`, helpers |
| `driver/all/` | Blank-import to register backends |
| `internal/docker/` | Docker Engine implementation |
| `internal/podman/` | Podman socket discovery → Docker API client |
| `internal/vm/` | Stub driver |
| `internal/kubernetes/` | Agent Sandbox lifecycle, workspace isolation, immutable runtime Secrets, and paired Cautem Pods |
| `internal/mounts/` | Bind-mount policy |
| `internal/sidecar/` | CA / env helpers for the proxy sidecar |

## Kubernetes status

The Kubernetes driver creates and recovers Agent Sandbox resources, uses a PVC
for the default workspace, and rotates bearer and mTLS credentials on restart.
Policy changes replace immutable Secret generations; an active sandbox is
restarted so the workload and proxy load the same policy. The Gateway waits for
the supervisor to report the new revision.

Configure `CAUTEM_KUBERNETES_PROXY_IMAGE` and
`CAUTEM_KUBERNETES_RUNTIME_IMAGE` with immutable `@sha256:` references, and set
`CAUTEM_KUBERNETES_GRPC_ENDPOINT` to an endpoint reachable from Pods. HTTPS
endpoints also require the `CAUTEM_KUBERNETES_GUEST_TLS_CA`,
`CAUTEM_KUBERNETES_GUEST_TLS_CERT`, and `CAUTEM_KUBERNETES_GUEST_TLS_KEY`
files. The cluster needs the Agent Sandbox controller, a working PVC storage
class, and a NetworkPolicy-enforcing CNI. Run the live traffic probe against
the target cluster before enabling this experimental backend; fake API tests
and object admission do not verify workload startup or traffic isolation.


---

## Related

| Resource | Link |
|----------|------|
| Roadmap | [ROADMAP.md](./ROADMAP.md) |
| Organization | [https://github.com/cautem](https://github.com/cautem) |
| Organization overview | [github.com/cautem](https://github.com/cautem) |
| pkg.go.dev | [`github.com/cautem/cautem-driver`](https://pkg.go.dev/github.com/cautem/cautem-driver) |

## License

[Apache-2.0](./LICENSE) © cautem
