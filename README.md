<h1 align="center">cautem-driver</h1>

<p align="center">
  <strong>Compute drivers</strong><br>
  Docker-first sandbox runtime — mounts, ExtraHosts, egress sidecar wiring.
</p>
<p align="center">
  <a href="https://github.com/cautem/quarshell-driver/actions/workflows/ci.yml"><img src="https://github.com/cautem/quarshell-driver/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pkg.go.dev/github.com/cautem/quarshell-driver"><img src="https://pkg.go.dev/badge/github.com/cautem/quarshell-driver.svg" alt="Go Reference"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/cautem/quarshell-driver"><img src="https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go" alt="Go Version"></a>
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
| **Experimental** | MicroVM has per-VM policy networking, supervisor/readiness control, SSH relay, one-shot and interactive PTY exec, logs, authenticated file copy and macOS ARM64/HVF live acceptance; isolated host workspace mounts, GPU and Linux KVM acceptance remain open |

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
    "github.com/cautem/quarshell-driver/driver"
    _ "github.com/cautem/quarshell-driver/driver/all" // register backends
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
| `internal/vm/` | OpenShell-style libkrun MicroVM driver (worker supervision, persisted lifecycle, guest vsock control, one-shot Exec, logs, and file copy; see MicroVM status below) |
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

## MicroVM status

The VM backend is experimental and is not yet a production replacement for
Docker or OpenShell. It implements Create/Start/Stop/Delete/List/Inspect,
one-shot Exec, console logs, and file copy. The driver launches an isolated
`cautem-vm-worker`; the guest runs a static Go control agent on a host-initiated
virtio-vsock port. The authenticated host↔guest control channel uses
length-prefixed JSON protocol v1, and each side rejects unsupported versions.
Worker settings and command environments travel over a
private pipe/control socket and are not written to sandbox state. On Linux the
worker starts in private user and mount namespaces and makes mount propagation
private; it fails closed when namespace support is unavailable or the Gateway
runs as host root. The namespace UID maps to the Gateway account, so this is not
a separate host UID. On macOS the worker is a separate process but remains under
the Gateway account. Neither platform currently accepts host workspace mounts.
The worker receives only the configured libkrun loader path from the host
environment. Non-TTY Exec
captures stdout/stderr (up to 8 MiB per stream) in `driver.ExecResult`, accepts
guest stdin, and applies context cancellation to the guest process group. State
and VM workers can be recovered after the Gateway process restarts.

Create accepts either an OCI image reference in `driver.Spec.Image` or
`rootfs_tar_path` in VM `driver_config`. Gateway-issued
`rootfs_tar_staging_token` resolves to a single-use upload slot;
`cautem-sdk`'s `UploadRootfsTar` streams the archive there, while local
integrations may supply a driver-owned path. Registry pulls use the default
Docker/Podman credential keychain. Tags are resolved to manifest digests, and
the driver selects the Linux image for the host architecture. It checks the
image config platform, layer digest and size, supports plain, gzip and zstd
layers, and applies normal and opaque whiteouts with root-confined paths.

The rootfs cache lives under `<state_dir>/images`; base ext4 images are
immutable and keyed by source manifest, selected platform manifest, platform,
rootfs layout version and guest-agent digest. The default quota is 64 GiB and
can be changed with `CAUTEM_VM_IMAGE_CACHE_MAX_BYTES`. GC keeps images referenced
by durable sandbox state or protected by an active create lease. Uploaded rootfs
archives are limited to 10 GiB compressed; decompressed layer/rootfs data is
limited to 32 GiB. The image must match the host architecture and provide Linux
`mount`, `chroot`, ext4 and overlayfs support. Rootfs preparation requires
e2fsprogs.

OCI image `Entrypoint`, `Cmd`, `Env`, `User` and `WorkingDir` are applied to the
in-memory VM workload spec. After Gateway recovery, the driver reloads the image
config by its pinned platform manifest digest instead of following the tag.
Environment and identity values are not written to durable VM state; workload
input cannot override the guest's reserved identity variables, and root OCI
identities fail closed. Unit tests cover config merge, defaults, validation and
digest-pinned recovery. The rootfs must include any runtime files needed by the
guest. Gateway runtime validation remains fail-closed until host mounts use an
fd-backed allowlist and a dedicated host identity with tested UID/GID mapping.
Live OCI workload behavior, Linux KVM and macOS ARM64 Gateway-to-workload lanes
also remain required.

Build the native worker, static Linux guest agent, `cautem-init`,
`cautem-supervisor`, and `cautem-sshd` with `scripts/build-vm-runtime.sh`
(Docker is used for the reproducible static guest-agent build), then set
`CAUTEM_VM_WORKER` and `CAUTEM_VM_GUEST_AGENT` to the resulting files. Set
`CAUTEM_VM_RUNTIME_DIR` to a compatible libkrun runtime bundle,
`CAUTEM_VM_STATE_DIR` to the private sandbox state directory, and
`CAUTEM_VM_ROOTFS_TAR_DIR` to the private Gateway upload staging directory.
The driver and guest agent must be built from the same release: every guest
vsock control request is authenticated with a per-sandbox token stored in the
private VM state directory and excluded from workload environment variables.
Linux requires read/write access to `/dev/kvm`; preflight opens the configured
KVM character device and checks its KVM API version, so a regular file or
unrelated device cannot satisfy the check. macOS support targets Apple
Silicon with Hypervisor.framework. The macOS build signs the worker with the
Hypervisor and library-loading entitlements; set `CAUTEM_VM_CODESIGN_IDENTITY`
to the signing identity for a distributable build (local builds use ad-hoc
signing). The worker sets its dynamic loader search path from the configured
runtime bundle and strips inherited loader overrides.

The opt-in live acceptance test exercises guest boot, broker health and an
actual default-deny HTTP 403 from the Cautem policy engine over guest vsock,
supervisor control handshake, SSH command execution over vsock, file copy,
worker recovery, stop/start and delete against a real host hypervisor.
Provide an ext4 rootfs tar with a `sandbox` user (UID/GID 1000 by default), the
matching static guest agent and runtime helpers, worker and libkrun bundle, then
run:

```sh
CAUTEM_VM_ACCEPTANCE=1 \
CAUTEM_VM_TEST_ROOTFS_TAR=/path/to/rootfs.tar \
CAUTEM_VM_TEST_GUEST_AGENT=/path/to/cautem-vm-guest-agent-linux-arm64 \
CAUTEM_VM_TEST_INIT_BIN=/path/to/cautem-init-linux-arm64 \
CAUTEM_VM_TEST_SUPERVISOR_BIN=/path/to/cautem-supervisor-linux-arm64 \
CAUTEM_VM_TEST_SSH_BIN=/path/to/cautem-sshd-linux-arm64 \
CAUTEM_VM_TEST_E2FS_FORMATTER=/path/to/mke2fs \
CAUTEM_VM_WORKER=/path/to/cautem-vm-worker \
CAUTEM_VM_RUNTIME_DIR=/path/to/libkrun-runtime \
go test ./internal/vm -run '^TestLiveMicroVMLifecycle$' -count=1 -v
```

For a reproducible Linux KVM run, configure a self-hosted GitHub Actions runner
with the `cautem-kvm` label, Docker, e2fsprogs, read/write access to `/dev/kvm`,
and a compatible Linux libkrun bundle. Set the repository variable
`CAUTEM_VM_RUNTIME_DIR` to the bundle path and run the manual **Live VM KVM
acceptance** workflow, or invoke `scripts/run-live-kvm-acceptance.sh` directly.
The script builds the worker, guest agent, and runtime helpers; it prepares an
Alpine rootfs with the `sandbox` user through Docker when one is not supplied,
then runs the full lifecycle acceptance test.

When `proxy_bin` and `policy_path` are supplied, each VM worker starts its own
Cautem policy proxy on a mode-0600 Unix socket. libkrun maps guest-initiated
vsock port 5501 to that socket. The guest agent exposes only a loopback HTTP
proxy and forces workload HTTP(S) proxy variables to it. The VM has no
virtio-net device, and `krun_add_vsock` receives TSI feature mask `0`, which
disables libkrun's transparent IP and Unix socket interception. This leaves the
policy broker as the only guest egress route. The worker waits for the proxy
health endpoint before creating the VM and stops the VM if the broker exits.
Policy file reload and Gateway policy acknowledgements use the existing proxy
implementation.

When `supervisor_bin` is configured, the driver installs the supervisor, hardening
init, and policy into the private writable overlay. The guest agent launches the
workload through that supervisor, exposes its bounded lifecycle control socket
over guest-initiated vsock port 5503, and wraps one-shot Exec with the same
hardening init. Gateway lifecycle readiness still waits for its authenticated
supervisor session.

SSH uses the same host proxy relay pattern as the container backends. The host
proxy connects to a private UDS mapped through vsock port 5502; inside the VM,
the guest agent bridges it to `cautem-sshd` on a private Unix socket. The daemon
does not listen on guest TCP, and SSH only becomes available when the policy
proxy and supervisor relay are configured.

The VM driver provides authenticated full-duplex PTY sessions with stdin,
resize and terminal signal handling; macOS ARM64/HVF live acceptance covers
resize, Ctrl-C, exit status and OCI env/workdir inheritance. Gateway VM creation
remains fail-closed while host workspace mounts, a dedicated host identity and
Linux KVM acceptance are open. GPU passthrough remains unsupported.
libkrun warns that virtiofs can escape the selected host directory without host
mount-namespace isolation, so the Gateway rejects VM before consuming rootfs
staging or writing sandbox state. The Linux KVM live acceptance workflow still
needs a self-hosted runner with `/dev/kvm`; macOS and Linux live runs are release
gates. The driver rejects every other `driver.Spec` field whose behavior it
does not implement instead of silently ignoring it.


---

## Related

| Resource | Link |
|----------|------|
| Roadmap | [ROADMAP.md](./ROADMAP.md) |
| Organization | [https://github.com/cautem](https://github.com/cautem) |
| Organization overview | [github.com/cautem](https://github.com/cautem) |
| pkg.go.dev | [`github.com/cautem/quarshell-driver`](https://pkg.go.dev/github.com/cautem/quarshell-driver) |

## License

[Apache-2.0](./LICENSE) © cautem
