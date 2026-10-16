#!/bin/sh
set -eu
unset GOROOT

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
module_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
host_os=$(go env GOOS)
host_arch=$(go env GOARCH)

if [ "$host_os" != linux ]; then
  echo "live KVM acceptance requires a native Linux host; found $host_os/$host_arch" >&2
  exit 2
fi
case "$host_arch" in
  amd64|arm64) ;;
  *) echo "live KVM acceptance does not support Linux/$host_arch" >&2; exit 2 ;;
esac

kvm_device=${CAUTEM_KVM_DEVICE:-/dev/kvm}
if [ ! -c "$kvm_device" ] || [ ! -r "$kvm_device" ] || [ ! -w "$kvm_device" ]; then
  echo "live KVM acceptance requires a readable and writable KVM character device at $kvm_device" >&2
  exit 2
fi

runtime_dir=${CAUTEM_VM_RUNTIME_DIR:-}
if [ -z "$runtime_dir" ]; then
  echo "CAUTEM_VM_RUNTIME_DIR must point to a compatible libkrun Linux runtime bundle" >&2
  exit 2
fi
if [ ! -s "$runtime_dir/libkrun.so" ] || [ ! -s "$runtime_dir/libkrunfw.so.5" ]; then
  echo "libkrun Linux runtime bundle is incomplete in $runtime_dir" >&2
  exit 2
fi

build_dir=${CAUTEM_VM_BUILD_DIR:-"$(mktemp -d "${TMPDIR:-/tmp}/cautem-kvm-acceptance.XXXXXX")"}
mkdir -p "$build_dir"
cleanup_dir=
if [ -z "${CAUTEM_VM_BUILD_DIR:-}" ]; then
  cleanup_dir=$build_dir
fi
container_id=
cleanup() {
  if [ -n "$container_id" ]; then
    docker rm -f "$container_id" >/dev/null 2>&1 || true
  fi
  if [ -n "$cleanup_dir" ]; then
    rm -rf "$cleanup_dir"
  fi
}
trap cleanup EXIT HUP INT TERM

guest_agent=${CAUTEM_VM_TEST_GUEST_AGENT:-"$build_dir/cautem-vm-guest-agent-linux-$host_arch"}
worker=${CAUTEM_VM_WORKER:-"$build_dir/cautem-vm-worker"}
security_probe=${CAUTEM_VM_TEST_SECURITY_PROBE:-"$build_dir/cautem-vm-security-probe-linux-$host_arch"}
if [ ! -s "$guest_agent" ] || [ ! -s "$worker" ]; then
  CAUTEM_VM_BUILD_DIR=$build_dir CAUTEM_VM_GUEST_ARCH=$host_arch "$script_dir/build-vm-runtime.sh"
fi
if [ ! -x "$guest_agent" ] || [ ! -x "$worker" ]; then
  echo "VM worker and static guest agent build did not produce executable artifacts" >&2
  exit 1
fi

rootfs_tar=${CAUTEM_VM_TEST_ROOTFS_TAR:-}
if [ -z "$rootfs_tar" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required to prepare the default Alpine Linux rootfs" >&2
    exit 2
  fi
  container_id=$(docker run -d --platform "linux/$host_arch" alpine:3.22 /bin/sh -c 'while :; do sleep 3600; done')
  docker exec "$container_id" adduser -D -u 1000 sandbox
  rootfs_tar="$build_dir/alpine-rootfs.tar"
  docker export --output "$rootfs_tar" "$container_id"
  docker rm "$container_id" >/dev/null
  container_id=
fi
if [ ! -s "$rootfs_tar" ]; then
  echo "live KVM rootfs tar is missing or empty: $rootfs_tar" >&2
  exit 2
fi

formatter=${CAUTEM_VM_TEST_E2FS_FORMATTER:-}
if [ -z "$formatter" ]; then
  formatter=$(command -v mke2fs || command -v mkfs.ext4 || true)
fi
if [ -z "$formatter" ] || [ ! -x "$formatter" ]; then
  echo "e2fsprogs is required; set CAUTEM_VM_TEST_E2FS_FORMATTER or install mke2fs" >&2
  exit 2
fi

cd "$module_dir"
CAUTEM_KVM_DEVICE=$kvm_device \
CAUTEM_VM_ACCEPTANCE=1 \
CAUTEM_VM_TEST_ROOTFS_TAR=$rootfs_tar \
CAUTEM_VM_TEST_GUEST_AGENT=$guest_agent \
CAUTEM_VM_TEST_INIT_BIN=${CAUTEM_VM_TEST_INIT_BIN:-"$build_dir/cautem-init-linux-$host_arch"} \
CAUTEM_VM_TEST_SUPERVISOR_BIN=${CAUTEM_VM_TEST_SUPERVISOR_BIN:-"$build_dir/cautem-supervisor-linux-$host_arch"} \
CAUTEM_VM_TEST_SSH_BIN=${CAUTEM_VM_TEST_SSH_BIN:-"$build_dir/cautem-sshd-linux-$host_arch"} \
CAUTEM_VM_TEST_SECURITY_PROBE=$security_probe \
CAUTEM_VM_TEST_E2FS_FORMATTER=$formatter \
CAUTEM_VM_WORKER=$worker \
CAUTEM_VM_RUNTIME_DIR=$runtime_dir \
go test ./internal/vm -run '^TestLiveMicroVMLifecycle$' -count=1 -v
