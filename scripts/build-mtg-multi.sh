#!/bin/sh
set -eu

# Build the MTProto sidecar from an exact upstream tree with VanillaProxy's relay patch.
version=1.16.1
commit=a45ebefed80e16949426381ef53fb5f1c1e4958d
case "$1" in
    amd64 | arm64 | 386) GOARCH=$1 ;;
    armv6) GOARCH=arm; GOARM=6 ;;
    armv7) GOARCH=arm; GOARM=7 ;;
    *) echo "build-mtg-multi: unsupported platform '$1'" >&2; exit 1 ;;
esac

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=$(CDPATH= cd -- "$(dirname -- "$2")" && pwd)/$(basename -- "$2")
temp_root=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)
source_dir=$(mktemp -d "$temp_root/vanillaproxy-mtg-multi.XXXXXXXXXX")
cleanup() {
    case "$source_dir" in "$temp_root"/vanillaproxy-mtg-multi.*) ;; *) return 1 ;; esac
    [ -d "$source_dir" ] && [ ! -L "$source_dir" ] || return 1
    [ "$(CDPATH= cd -- "$source_dir" && pwd -P)" = "$source_dir" ] || return 1
    cd -- "$temp_root"
    rm -rf -- "$source_dir"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

cd "$source_dir"
git init --quiet
git config --local core.autocrlf false
git fetch --quiet --depth=1 https://github.com/mhsanaei/mtg-multi.git "$commit"
if [ "$(git rev-parse FETCH_HEAD)" != "$commit" ]; then
    echo 'build-mtg-multi: upstream commit does not match the pinned source' >&2
    exit 1
fi
git checkout --quiet --detach "$commit"
git apply --index "$project_dir/patches/mtg-multi-bandwidth.patch"
mkdir -p internal/vanillabandwidthipc internal/vanillalaunch
cp "$project_dir/internal/bandwidthipc/ipc.go" internal/vanillabandwidthipc/ipc.go
cp "$project_dir/internal/xraybandwidthchild/launch/ready.go" internal/vanillalaunch/ready.go

export CGO_ENABLED=0 GOOS=linux GOARCH GOARM
export GOENV=off GOWORK=off GOTOOLCHAIN=go1.27.3
export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
export GOFLAGS= GOPRIVATE= GONOPROXY= GONOSUMDB= GOINSECURE=
go build -trimpath -mod=readonly -buildvcs=false \
    -ldflags "-s -w -X main.version=${version}+vanilla.${commit}" -o "$output" .
