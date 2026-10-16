#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 the cautem authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
gateway_repo="${CAUTEM_GATEWAY_REPO:-$repo_root/../cautem-gateway}"
cli_repo="${CAUTEM_CLI_REPO:-$repo_root/../cautem-cli}"
runtime_repo="${CAUTEM_RUNTIME_REPO:-$repo_root/../cautem-runtime}"
service="${CAUTEM_PODMAN_SERVICE_CONTAINER:-cautem-podman-rootless}"
arch="$(go env GOARCH)"
tmp_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
tmp="$(mktemp -d "$tmp_root/quarshell-podman-gateway.XXXXXX")"
owner="$(basename "$tmp")"
remote_dir="/tmp/$owner"
sandbox_image="localhost/quarshell-podman-gateway-sandbox:$owner"
proxy_image="localhost/quarshell-podman-gateway-proxy:$owner"
image_context="$tmp/image-context"
helpers="$tmp/helpers"

cleanup() {
	local status=$?
	if docker inspect "$service" >/dev/null 2>&1; then
		docker exec --user podman \
			-e HOME=/home/podman -e XDG_RUNTIME_DIR=/run/user/1000 -e STORAGE_DRIVER=vfs \
			"$service" podman image rm -f "$sandbox_image" "$proxy_image" >/dev/null 2>&1 || true
		docker exec "$service" rm -rf -- "$remote_dir" >/dev/null 2>&1 || true
	fi
	docker image rm -f "$sandbox_image" "$proxy_image" >/dev/null 2>&1 || true
	rm -rf -- "$tmp"
	return "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for path in "$gateway_repo/go.mod" "$cli_repo/go.mod" "$runtime_repo/go.mod"; do
	if [[ ! -f "$path" ]]; then
		echo "required source checkout is missing: $path" >&2
		exit 2
	fi
done
if ! docker inspect "$service" >/dev/null 2>&1; then
	echo "rootless Podman service container is unavailable: $service" >&2
	exit 2
fi

mkdir -p "$helpers" "$image_context"
echo "Building pinned Gateway, CLI, runtime helpers, and process-event fixture for linux/$arch..."
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
	go -C "$gateway_repo" test -c -o "$tmp/httpapi.test" ./tests/e2e
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
	go -C "$cli_repo" build -o "$helpers/cautem" ./cmd/cautem
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
	go -C "$runtime_repo" build -o "$helpers/cautem-init" ./cmd/cautem-init
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
	go -C "$runtime_repo" build -o "$helpers/cautem-sshd" ./cmd/cautem-sshd
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
	go -C "$runtime_repo" build -o "$helpers/cautem-supervisor" ./cmd/cautem-supervisor
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
	go -C "$repo_root" build -o "$image_context/tcp-echo" ./tests/e2e/podman/testdata/tcp-echo
cp "$repo_root/tests/e2e/podman/Containerfile.policy-e2e" "$image_context/Containerfile"
chmod 755 "$tmp/httpapi.test" "$helpers"/* "$image_context/tcp-echo"

echo "Building and exporting rootless Gateway E2E fixture images..."
docker build --platform "linux/$arch" --build-arg E2E_USER=sandbox \
	-f "$image_context/Containerfile" -t "$sandbox_image" "$image_context"
docker build --platform "linux/$arch" --build-arg E2E_USER=root \
	-f "$image_context/Containerfile" -t "$proxy_image" "$image_context"
docker save -o "$tmp/images.tar" "$sandbox_image" "$proxy_image"
chmod 644 "$tmp/images.tar"

echo "Copying test artifacts into the disposable rootless Podman service..."
docker exec "$service" mkdir -p "$remote_dir/helpers"
docker cp "$tmp/httpapi.test" "$service:$remote_dir/httpapi.test"
docker cp "$helpers/." "$service:$remote_dir/helpers/"
docker cp "$tmp/images.tar" "$service:$remote_dir/images.tar"
docker exec "$service" sh -lc "chown -R podman:podman '$remote_dir' && chmod 755 '$remote_dir/httpapi.test' '$remote_dir/helpers'/*"
docker exec --user podman \
	-e HOME=/home/podman -e XDG_RUNTIME_DIR=/run/user/1000 -e STORAGE_DRIVER=vfs \
	"$service" podman load -i "$remote_dir/images.tar"

log="$tmp/gateway-rootless.log"
echo "Running Gateway → Podman 6.1.4 rootless → supervisor relay → SSH E2E..."
docker exec --user podman \
	-e HOME=/home/podman \
	-e XDG_RUNTIME_DIR=/run/user/1000 \
	-e STORAGE_DRIVER=vfs \
	-e DOCKER_HOST=tcp://127.0.0.1:18501 \
	-e CAUTEM_ENGINE_E2E=1 \
	-e CAUTEM_E2E_DRIVER=podman \
	-e CAUTEM_E2E_ROOTLESS_PODMAN=1 \
	-e CAUTEM_E2E_LISTEN_ADDR=0.0.0.0:17443 \
	-e CAUTEM_E2E_RELAY_ENDPOINT=http://host.containers.internal:17443 \
	-e CAUTEM_E2E_GATEWAY_URL=http://127.0.0.1:17443 \
	-e CAUTEM_E2E_SANDBOX_IMAGE="$sandbox_image" \
	-e CAUTEM_PROXY_IMAGE="$proxy_image" \
	-e CAUTEM_HELPERS_DIR="$remote_dir/helpers" \
	"$service" "$remote_dir/httpapi.test" \
	-test.run '^TestEngineGatewayConnectE2E$' -test.count=1 -test.timeout=6m -test.v \
	2>&1 | tee "$log"

if ! grep -F -- '--- PASS: TestEngineGatewayConnectE2E' "$log" >/dev/null; then
	echo "rootless Podman Gateway relay E2E did not pass the required test" >&2
	exit 1
fi
echo "PASS: Podman 6.1.4 rootless Gateway relay E2E (nested service container; native-host acceptance remains separate)."
