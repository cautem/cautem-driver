#!/bin/sh
set -eu
unset GOROOT

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
module_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
workspace_dir=$(CDPATH= cd -- "$module_dir/.." && pwd)
runtime_module_dir="$workspace_dir/cautem-runtime"
output_dir=${CAUTEM_VM_BUILD_DIR:-"$module_dir/dist/vm"}
guest_arch=${CAUTEM_VM_GUEST_ARCH:-$(go env GOARCH)}
host_os=$(go env GOOS)
host_arch=$(go env GOARCH)
module_cache=$(go env GOMODCACHE)

case "$host_os/$host_arch" in
  linux/amd64|linux/arm64|darwin/arm64) ;;
  *) echo "unsupported libkrun worker host: $host_os/$host_arch" >&2; exit 1 ;;
esac
case "$guest_arch" in
  amd64|arm64) ;;
  *) echo "unsupported Linux guest architecture: $guest_arch" >&2; exit 1 ;;
esac

mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)
(
  cd "$module_dir"
  CGO_ENABLED=0 go build -trimpath -o "$output_dir/cautem-vm-worker" ./cmd/cautem-vm-worker
)
for helper in cautem-init cautem-supervisor cautem-sshd; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$guest_arch" go -C "$runtime_module_dir" build \
    -trimpath -ldflags="-s -w" -o "$output_dir/$helper-linux-$guest_arch" "./cmd/$helper"
done
CGO_ENABLED=0 GOOS=linux GOARCH="$guest_arch" go -C "$module_dir" build \
  -trimpath -ldflags="-s -w" \
  -o "$output_dir/cautem-vm-security-probe-linux-$guest_arch" \
  ./internal/vm/testdata/guest-security-probe
docker run --rm --platform "linux/$guest_arch" \
  -v "$module_dir:/src" -v "$output_dir:/out" -v "$module_cache:/go/pkg/mod:ro" -w /src \
  golang:1.27.2-alpine sh -c \
  'GOMODCACHE=/go/pkg/mod CGO_ENABLED=0 GOOS=linux GOARCH="$1" go build -trimpath -ldflags="-s -w" -o "/out/cautem-vm-guest-agent-linux-$1" ./cmd/cautem-vm-guest-agent' \
  _ "$guest_arch"
chmod 0755 "$output_dir/cautem-vm-worker" "$output_dir/cautem-vm-guest-agent-linux-$guest_arch"
chmod 0755 "$output_dir/cautem-init-linux-$guest_arch" "$output_dir/cautem-supervisor-linux-$guest_arch" "$output_dir/cautem-sshd-linux-$guest_arch"
chmod 0755 "$output_dir/cautem-vm-security-probe-linux-$guest_arch"
if [ "$host_os/$host_arch" = darwin/arm64 ]; then
  codesign_identity=${CAUTEM_VM_CODESIGN_IDENTITY:--}
  codesign --force --sign "$codesign_identity" \
    --entitlements "$script_dir/vm-worker-entitlements.plist" \
    "$output_dir/cautem-vm-worker"
fi
echo "Built worker, linux/$guest_arch guest agent and runtime helpers in $output_dir"
