# Agent instructions

## Scope

This repository implements Docker and Podman compute drivers, including sandbox
creation, mounts, networking, resources, and egress sidecar wiring.

## Working rules

- Treat container privileges, mounts, host aliases, networking, and cleanup as
  security-sensitive. Check both Docker and Podman behavior for shared changes.
- Keep driver behavior aligned with the core policy, runtime image, and proxy
  contracts. Update the provider guides when user-visible limits change.
- Keep local Go workspace replacements in the parent workspace's `go.work`,
  never in this repository's `go.mod`.

## Checks

- Run `go test ./...` from this checkout for Go changes.
- Use the Docker or Podman integration checks for lifecycle changes; they need
  the corresponding engine and configured test images.
- From the parent workspace, `task check` runs the shared Go gate.
