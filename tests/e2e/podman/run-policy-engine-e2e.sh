#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 the cautem authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

mode="${1:-}"
if [[ "$mode" != "rootful" && "$mode" != "rootless" ]]; then
	echo "usage: $0 rootful|rootless" >&2
	exit 2
fi
if [[ "$(go env GOOS)" != "linux" ]]; then
	echo "Podman policy Engine E2E must run on a Linux CI host" >&2
	exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root"
driver_work="$repo_root/tests/e2e/podman"
podman_image="${CAUTEM_TEST_PODMAN_IMAGE:-cautem-podman6-e2e:local}"
arch="$(go env GOARCH)"
owner="$(basename "$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/cautem-podman-policy-${mode}.XXXXXX")")"
e2e_tmp="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/$owner"
container_name="cautem-podman-policy-${mode}-${owner}"
container_port=18500
host_port=""
sandbox_image="localhost/cautem-podman-policy-sandbox:${owner}"
proxy_image="localhost/cautem-podman-policy-proxy:${owner}"

if [[ "$mode" == "rootless" ]]; then
	container_port=18501
fi

cleanup() {
	local status=$?
	local actual_owner=""
	actual_owner="$(docker inspect -f '{{index .Config.Labels "cautem.podman.e2e.owner"}}' "$container_name" 2>/dev/null || true)"
	if [[ "$actual_owner" == "$owner" ]]; then
		if [[ "$status" != "0" ]]; then
			docker logs "$container_name" >&2 || true
			docker exec "$container_name" sh -lc 'cat /tmp/podman-policy-service.log 2>/dev/null || true' >&2 || true
		fi
		# Podman runs as root or in a user namespace and creates files with
		# container-side owners in the host bind. Make the private temp workspace
		# removable by the runner after the service container exits.
		docker exec "$container_name" chmod -R a+rwX /cautem-podman-e2e/workspace >/dev/null 2>&1 || true
		docker rm -f "$container_name" >/dev/null 2>&1 || true
	fi
	docker image rm -f "$sandbox_image" "$proxy_image" >/dev/null 2>&1 || true
	rm -rf "$e2e_tmp"
	return "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$e2e_tmp/helpers" "$e2e_tmp/workspace" "$e2e_tmp/image-context"
chmod 755 "$e2e_tmp" "$e2e_tmp/helpers" "$e2e_tmp/workspace"

echo "Building the pinned CLI proxy helper and Podman Engine E2E binary..."
GOBIN="$e2e_tmp/helpers" GOWORK=off CGO_ENABLED=0 \
	go install github.com/cautem/cautem-cli/cmd/cautem@v0.3.0
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
	-o "$e2e_tmp/image-context/tcp-echo" \
	./tests/e2e/podman/testdata/tcp-echo
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c \
	-o "$e2e_tmp/podman.test" ./tests/e2e/podman
chmod 755 "$e2e_tmp/helpers/cautem" "$e2e_tmp/image-context/tcp-echo" "$e2e_tmp/podman.test"
cp "$driver_work/Containerfile.policy-e2e" "$e2e_tmp/image-context/Containerfile"

echo "Building and exporting disposable Podman policy E2E images..."
docker build --platform "linux/$arch" --build-arg E2E_USER=sandbox \
	-f "$e2e_tmp/image-context/Containerfile" -t "$sandbox_image" "$e2e_tmp/image-context"
docker build --platform "linux/$arch" --build-arg E2E_USER=root \
	-f "$e2e_tmp/image-context/Containerfile" -t "$proxy_image" "$e2e_tmp/image-context"
docker save -o "$e2e_tmp/images.tar" "$sandbox_image" "$proxy_image"
chmod 644 "$e2e_tmp/images.tar"

echo "Starting a disposable $mode Podman $arch service..."
docker run -d --name "$container_name" --privileged --device /dev/fuse \
	--security-opt label=disable \
	--label "cautem.podman.e2e.owner=$owner" \
	-e STORAGE_DRIVER=vfs \
	-v "$e2e_tmp:/cautem-podman-e2e" \
	-p "127.0.0.1::$container_port" \
	"$podman_image" sh -lc '
		id podman >/dev/null 2>&1 || useradd --create-home --uid 1000 podman
		printf "root:100000:65536\\npodman:100000:65536\\n" > /etc/subuid
		printf "root:100000:65536\\npodman:100000:65536\\n" > /etc/subgid
		mkdir -p /run/user/1000
		chown -R podman:podman /run/user/1000 /cautem-podman-e2e/workspace
		chmod 700 /run/user/1000
		exec sleep infinity
	' >/dev/null
host_port="$(docker port "$container_name" "$container_port/tcp" | sed -E 's/.*:([0-9]+)$/\1/')"
if [[ -z "$host_port" ]]; then
	echo "could not map the $mode Podman Engine API port" >&2
	exit 1
fi

if [[ "$mode" == "rootless" ]]; then
	docker exec --user podman -d \
		-e HOME=/home/podman \
		-e XDG_RUNTIME_DIR=/run/user/1000 \
		-e STORAGE_DRIVER=vfs \
		"$container_name" sh -lc \
		'while true; do podman system service --time=0 tcp:0.0.0.0:18501 >>/tmp/podman-policy-service.log 2>&1 & pid=$!; wait "$pid"; sleep 2; done'
else
	# Podman defaults to a 2048 PID limit on cgroup-capable hosts. The nested
	# hosted-runner cgroup does not delegate the pids controller, so disable only
	# that default for this disposable rootful test service.
	docker exec "$container_name" sh -lc 'printf "[containers]\npids_limit = 0\n" > /etc/containers/containers.conf'
	docker exec -d -e STORAGE_DRIVER=vfs "$container_name" sh -lc \
		'while true; do podman system service --time=0 tcp:0.0.0.0:18500 >>/tmp/podman-policy-service.log 2>&1 & pid=$!; wait "$pid"; sleep 2; done'
fi

ready=0
for _ in $(seq 1 90); do
	if curl --fail --silent "http://127.0.0.1:$host_port/_ping" >/dev/null; then
		ready=1
		break
	fi
	sleep 1
done
if [[ "$ready" != "1" ]]; then
	docker exec "$container_name" sh -lc 'cat /tmp/podman-policy-service.log 2>/dev/null || true' >&2
	echo "$mode Podman Engine API did not become ready" >&2
	exit 1
fi

if [[ "$mode" == "rootless" ]]; then
	docker exec --user podman \
		-e HOME=/home/podman -e XDG_RUNTIME_DIR=/run/user/1000 -e STORAGE_DRIVER=vfs \
		"$container_name" podman load -i /cautem-podman-e2e/images.tar
	docker exec --user podman \
		-e HOME=/home/podman -e XDG_RUNTIME_DIR=/run/user/1000 -e STORAGE_DRIVER=vfs \
		-e DOCKER_HOST="tcp://127.0.0.1:$container_port" \
		-e CAUTEM_PODMAN_E2E=1 -e CAUTEM_PODMAN_ROOTLESS=1 \
		-e CAUTEM_PODMAN_WORKSPACE=/cautem-podman-e2e/workspace \
		-e CAUTEM_E2E_SANDBOX_IMAGE="$sandbox_image" -e CAUTEM_PROXY_IMAGE="$proxy_image" \
		-e CAUTEM_HELPERS_DIR=/cautem-podman-e2e/helpers \
		"$container_name" /cautem-podman-e2e/podman.test -test.run '^TestPodmanEngineE2E$' -test.count=1 -test.v \
		2>&1 | tee "$e2e_tmp/podman-policy.log"
else
	docker exec -e STORAGE_DRIVER=vfs "$container_name" podman load -i /cautem-podman-e2e/images.tar
	docker exec \
		-e STORAGE_DRIVER=vfs -e DOCKER_HOST="tcp://127.0.0.1:$container_port" \
		-e CAUTEM_PODMAN_E2E=1 -e CAUTEM_PODMAN_WORKSPACE=/cautem-podman-e2e/workspace \
		-e CAUTEM_PODMAN_E2E_DISABLE_PIDS_LIMIT=1 \
		-e CAUTEM_E2E_SANDBOX_IMAGE="$sandbox_image" -e CAUTEM_PROXY_IMAGE="$proxy_image" \
		-e CAUTEM_HELPERS_DIR=/cautem-podman-e2e/helpers \
		"$container_name" /cautem-podman-e2e/podman.test -test.run '^TestPodmanEngineE2E$' -test.count=1 -test.v \
		2>&1 | tee "$e2e_tmp/podman-policy.log"
fi

if ! grep -F -- '--- PASS: TestPodmanEngineE2E' "$e2e_tmp/podman-policy.log" >/dev/null; then
	echo "$mode Podman policy E2E did not run and pass the required test" >&2
	exit 1
fi

echo "PASS: Podman 6.1.4 $mode proxy isolation and host-gateway denial E2E (nested service container; native-host acceptance remains separate)."
