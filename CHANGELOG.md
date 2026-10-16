# Changelog

## [Unreleased]

## [v0.3.0] - 2026-10-16

### Added

- Capture VM non-interactive exec stdout/stderr in `driver.ExecResult` and pass stdin to the guest agent; cancellation still kills the guest process group.
- Add a fail-closed VM policy/network broker: a per-VM host proxy listens on a private Unix socket, libkrun exposes a guest-initiated vsock mapping with TSI disabled, and the guest agent forces workload HTTP(S) traffic through its loopback endpoint. Broker startup is health-checked and an unexpected proxy exit stops the worker.
- Extend live MicroVM acceptance to boot the real supervisor/init/SSH helpers, exercise the Cautem policy engine's default-deny response through the guest vsock broker, observe the supervisor control handshake, execute a command through the SSH vsock relay, and verify restart and recovery paths.
- Start the guest workload through `cautem-supervisor` and hardening init; bridge supervisor lifecycle RPCs over vsock to the host proxy, force Exec through init, and wait for the proxy relay control socket before boot.
- Add relay-only guest SSH: the host proxy connects through a private UDS/vsock mapping to a guest-agent bridge and `cautem-sshd`; no guest TCP listener is opened.
- Validate VM Gateway gRPC endpoint and mTLS client files, pass them only to the host proxy, and keep loopback Gateway URLs reachable from a host-owned VM worker.
- Reject remaining unsupported VM `driver.Spec` capabilities explicitly, including host workspace mounts, PTY/TTY, GPU, display, persistent volumes, and host integration fields.
- Add an opt-in native MicroVM live acceptance test for boot, exec, file copy, inspect/list/logs, worker recovery, stop/start, and delete.
- Verify Linux `/dev/kvm` is a character device that answers `KVM_GET_API_VERSION`; add a self-hosted Linux KVM lifecycle acceptance workflow and runner script.
- Sign the macOS ARM64 VM worker with Hypervisor and library-loading entitlements and scope the dynamic loader path to the configured runtime bundle.
- Build VM worker and static guest-agent artifacts in a dedicated Linux CI job and verify guest architecture plus static linking.

### Fixed

- Authenticate every guest vsock control request with a per-sandbox 256-bit token; keep it out of durable JSON state and guest workload environment, and reject unauthorized requests before dispatch.
- Keep VM control sockets below the portable Unix socket path limit and use the relocated worker socket when refreshing sandbox status.
- Preserve proxy-owned host Unix listeners for guest-initiated vsock mappings; remove stale sockets only for worker-owned host listeners.
- Create guest init mountpoints before formatting rootfs images and keep guest root/overlay roots traversable by the unprivileged sandbox user.
- Reject negative, non-finite, or unrepresentable VM CPU and memory limits instead of silently replacing them with defaults or clamping them.
- Resolve guest copy paths one directory descriptor at a time and refuse symlinks, preventing copy operations from escaping through workload-controlled parent directories.
- Accept `init_bin` when its complete supervisor/SSH contract is configured; keep incomplete helper combinations rejected before provisioning.
- Add an optional `LaunchSpecRestorer` contract so durable control planes can restore backend process-local workload argv/environment after driver restart.

## [v0.2.1] - 2026-10-13

### Fixed

- Initialize the persistent guest PATH with `/bin/sh` from the sandbox user profile, without requiring write access to `/etc`.

## [v0.2.0] - 2026-10-13

### Added

- Add an experimental Agent Sandbox Kubernetes backend with sandbox lifecycle, listing, inspection, PVC workspaces, and paired Cautem workload/proxy runtimes.
- Rotate immutable Kubernetes runtime credential generations and deliver policy updates by restarting the affected runtime.
- Renew Kubernetes bridge certificates within 30 days of expiry during the Gateway's daily maintenance pass.

### Changed

- Split the Docker driver implementation into focused lifecycle, networking, copy, and runtime files.
- Keep Kubernetes exec, logs, and file transfer on the authenticated Cautem relay; direct Kubernetes data-plane methods remain unsupported.
- Refresh Docker, Moby, Kubernetes client, and terminal dependencies to their latest compatible releases.

## [v0.1.7] - 2026-10-11

### Fixed

- Use the published cautem sandbox base when no local sandbox image is available, so the default hardened sandbox has the required `sandbox` user and `cautem-init` entrypoint.

## [v0.1.6] - 2026-10-11

### Changed

- Rename the module, runtime identifiers and project references to the `cautem` namespace.

## [v0.1.0-beta.2] - 2026-10-10

### Added

- Resolve Docker CLI and Podman authfile credentials for private image pulls without exposing secrets in sandbox metadata or errors.
- Report rootless mode and engine security options for CLI diagnostics.
- Run Podman 6.1.3 rootful and rootless lifecycle and user namespace checks in Linux CI.

### Changed

- Resolve `cautem-core` from published v0.1.0-beta.2.

### Fixed

- Validate OCI driver configuration and certificate bundles at the backend boundary.

## [v0.1.0-beta.1] - 2026-10-08

### Changed

- Classify Docker Desktop isolation from the host platform instead of daemon-provided labels.
- Use platform-specific supervisor executable checks and keep POSIX file-mode tests off Windows.
- Update the core dependency to v0.1.0-beta.1.

## [v0.1.0-alpha.2] - 2026-10-07

### Added

- Support typed Docker and Podman driver configuration, runtime defaults, and provider-specific resource settings.
- Validate driver payloads, mounts, reserved paths, GPU configuration, and SDK-facing container options.
- Configure bounded health, create, and cleanup operations.

### Changed

- Use the Moby API/client modules instead of the deprecated monolithic Docker SDK.
- Update Testcontainers to v0.44.0, Moby API/client to v1.56.1/v0.6.1, and go-archive to v0.3.3.
- Update the core dependency to v0.1.0-alpha.2 and distribute this module under Apache-2.0.

### Fixed

- Keep archive extraction, mount handling, and container cleanup fail-closed on invalid paths or partial failures.
- Update `golang.org/x/crypto` to v0.57.0 to remove reachable SSH vulnerabilities in the Testcontainers test path.

## [v0.0.2-alpha.1] - 2026-09-28

### Security

- `CopyFrom` extracts archives under `os.OpenRoot` with path sanitization and symlink rejection.
