# Driver integration and E2E tests

Backend lifecycle tests belong here and must own their container cleanup and
diagnostics. Unit tests for Docker/Podman request translation stay beside the
implementation. The existing legacy engine tests are migration sources; new
container-backed scenarios must be added under `tests/e2e`.

`tests/internal/testenv` provides the opt-in Alpine and isolated
Docker-in-Docker fixtures. Enable them with `CAUTEM_TESTCONTAINERS=1`.

From a native macOS ARM64 host with Docker Desktop running,
`task e2e:docker-desktop` checks workspace bind reads/writes and stop/start
persistence, then verifies IPv4 and IPv6 host reachability from a dual-stack
control sandbox and isolation from the proxy-backed sandbox. The host-boundary
test is opt-in through the task and requires the configured helper, proxy, and
sandbox images; running the Go package without those settings skips that lane.
