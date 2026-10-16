#!/bin/sh
set -eu
unset GOROOT

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
module_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
host_os=$(go env GOOS)
host_arch=$(go env GOARCH)

if [ "$host_os/$host_arch" != darwin/arm64 ]; then
  echo "live Hypervisor.framework acceptance requires native macOS/arm64; found $host_os/$host_arch" >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to prepare the default Alpine Linux rootfs" >&2
  exit 2
fi

build_dir=${CAUTEM_VM_BUILD_DIR:-"$module_dir/dist/vm-live-darwin-arm64"}
mkdir -p "$build_dir"

runtime_dir=${CAUTEM_VM_RUNTIME_DIR:-"$build_dir/libkrun"}
if [ -z "${CAUTEM_VM_RUNTIME_DIR:-}" ]; then
  if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew libkrun is required; set CAUTEM_VM_RUNTIME_DIR to a runtime bundle" >&2
    exit 2
  fi
  libkrun_prefix=$(brew --prefix libkrun)
  libkrunfw_prefix=$(brew --prefix libkrunfw)
  mkdir -p "$runtime_dir"
  ln -sf "$libkrun_prefix/lib/libkrun.dylib" "$runtime_dir/libkrun.dylib"
  ln -sf "$libkrunfw_prefix/lib/libkrunfw.5.dylib" "$runtime_dir/libkrunfw.5.dylib"
fi
if [ ! -s "$runtime_dir/libkrun.dylib" ] || [ ! -s "$runtime_dir/libkrunfw.5.dylib" ]; then
  echo "libkrun macOS runtime bundle is incomplete in $runtime_dir" >&2
  exit 2
fi

guest_arch=${CAUTEM_VM_GUEST_ARCH:-arm64}
worker=${CAUTEM_VM_WORKER:-"$build_dir/cautem-vm-worker"}
guest_agent=${CAUTEM_VM_TEST_GUEST_AGENT:-"$build_dir/cautem-vm-guest-agent-linux-$guest_arch"}
init_bin=${CAUTEM_VM_TEST_INIT_BIN:-"$build_dir/cautem-init-linux-$guest_arch"}
supervisor_bin=${CAUTEM_VM_TEST_SUPERVISOR_BIN:-"$build_dir/cautem-supervisor-linux-$guest_arch"}
ssh_bin=${CAUTEM_VM_TEST_SSH_BIN:-"$build_dir/cautem-sshd-linux-$guest_arch"}
security_probe=${CAUTEM_VM_TEST_SECURITY_PROBE:-"$build_dir/cautem-vm-security-probe-linux-$guest_arch"}
# Rebuild from the current checkout on every acceptance run. Existence checks
# alone can leave an old guest protocol binary beside a newer host driver.
CAUTEM_VM_BUILD_DIR=$build_dir CAUTEM_VM_GUEST_ARCH=$guest_arch \
  "$script_dir/build-vm-runtime.sh"
for artifact in "$worker" "$guest_agent" "$init_bin" "$supervisor_bin" "$ssh_bin" "$security_probe"; do
  if [ ! -x "$artifact" ]; then
    echo "MicroVM acceptance artifact is missing or not executable: $artifact" >&2
    exit 2
  fi
done

rootfs_tar=${CAUTEM_VM_TEST_ROOTFS_TAR:-"$build_dir/alpine-rootfs.tar"}
container_id=
cleanup() {
  if [ -n "$container_id" ]; then
    docker stop "$container_id" >/dev/null 2>&1 || true
    docker rm "$container_id" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT HUP INT TERM
if [ ! -s "$rootfs_tar" ]; then
  container_id=$(docker run -d --platform "linux/$guest_arch" alpine:3.22 /bin/sh -c 'while :; do sleep 3600; done')
  docker exec "$container_id" adduser -D -u 1000 sandbox
  docker stop "$container_id" >/dev/null
  docker export --output "$rootfs_tar" "$container_id"
  docker rm "$container_id" >/dev/null
  container_id=
fi
if [ ! -s "$rootfs_tar" ]; then
  echo "live MicroVM rootfs tar is missing or empty: $rootfs_tar" >&2
  exit 2
fi

formatter=${CAUTEM_VM_TEST_E2FS_FORMATTER:-}
if [ -z "$formatter" ]; then
  formatter=$(command -v mke2fs || command -v mkfs.ext4 || true)
fi
if [ -z "$formatter" ] && command -v brew >/dev/null 2>&1; then
  e2fsprogs_prefix=$(brew --prefix e2fsprogs 2>/dev/null || true)
  for candidate in "$e2fsprogs_prefix/sbin/mke2fs" "$e2fsprogs_prefix/bin/mke2fs"; do
    if [ -n "$e2fsprogs_prefix" ] && [ -x "$candidate" ]; then
      formatter=$candidate
      break
    fi
  done
fi
if [ -z "$formatter" ] || [ ! -x "$formatter" ]; then
  echo "e2fsprogs is required; set CAUTEM_VM_TEST_E2FS_FORMATTER or install mke2fs" >&2
  exit 2
fi

cd "$module_dir"
CAUTEM_VM_ACCEPTANCE=1 \
CAUTEM_VM_TEST_ROOTFS_TAR=$rootfs_tar \
CAUTEM_VM_TEST_GUEST_AGENT=$guest_agent \
CAUTEM_VM_TEST_INIT_BIN=$init_bin \
CAUTEM_VM_TEST_SUPERVISOR_BIN=$supervisor_bin \
CAUTEM_VM_TEST_SSH_BIN=$ssh_bin \
CAUTEM_VM_TEST_SECURITY_PROBE=$security_probe \
CAUTEM_VM_TEST_E2FS_FORMATTER=$formatter \
CAUTEM_VM_WORKER=$worker \
CAUTEM_VM_RUNTIME_DIR=$runtime_dir \
CAUTEM_VM_CODESIGN_IDENTITY=${CAUTEM_VM_CODESIGN_IDENTITY:--} \
DYLD_LIBRARY_PATH=$runtime_dir \
go test ./internal/vm -run '^TestLiveMicroVMLifecycle$' -count=1 -v
