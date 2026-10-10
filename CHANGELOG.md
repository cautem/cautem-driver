# Changelog

## [Unreleased]

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
