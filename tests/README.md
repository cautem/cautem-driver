# Driver integration and E2E tests

Backend lifecycle tests belong here and must own their container cleanup and
diagnostics. Unit tests for Docker/Podman request translation stay beside the
implementation. The existing legacy engine tests are migration sources; new
container-backed scenarios must be added under `tests/e2e`.

`tests/internal/testenv` provides the opt-in Alpine and isolated
Docker-in-Docker fixtures. Enable them with `CAUTEM_TESTCONTAINERS=1`.
