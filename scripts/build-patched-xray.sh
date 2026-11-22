#!/bin/sh
set -eu

fail() {
    printf 'build-patched-xray: %s\n' "$*" >&2
    exit 1
}

case "${1:-}" in
    build | test) command=$1; shift ;;
    *) fail 'usage: sh scripts/build-patched-xray.sh {build|test} [Go arguments]' ;;
esac
for arg do
    case "$arg" in
        -args | --) break ;;
        -mod | --mod | -mod=* | --mod=* | -modfile | --modfile | -modfile=* | --modfile=*)
            fail 'the script sets -mod and -modfile' ;;
    esac
done

module=github.com/xtls/xray-core
version=v1.260327.1-0.20261021115930-1b1647cd9ddf
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
[ -f "$project_dir/patches/xray-core-hysteria-udp.patch" ] || fail 'required Hysteria UDP patch is missing'
temp_root=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P)
work_dir=$(mktemp -d "$temp_root/vanillaproxy-xray.XXXXXXXXXX")

cleanup() {
    case "$work_dir" in "$temp_root"/vanillaproxy-xray.*) ;; *) return 1 ;; esac
    [ -d "$work_dir" ] && [ ! -L "$work_dir" ] || return 1
    [ "$(CDPATH= cd -- "$work_dir" && pwd -P)" = "$work_dir" ] || return 1
    links=$(PATH="/usr/bin:$PATH" find "$work_dir" -type l -print)
    [ -z "$links" ] || return 1
    rm -rf -- "$work_dir"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

export GOWORK=off
cd -- "$project_dir"

if command -v cygpath >/dev/null 2>&1; then
    go_work_dir=$(cygpath -m "$work_dir")
else
    go_work_dir=$work_dir
fi
modfile=$go_work_dir/project.mod
verify_modfile=$go_work_dir/verify.mod
snapshot=$work_dir/xray-core
cp go.mod "$work_dir/project.mod"
cp go.sum "$work_dir/project.sum"
required=$(go list -mod=readonly -modfile="$modfile" -m -f '{{.Version}}{{with .Replace}} replaced{{end}}' "$module")
[ "$required" = "$version" ] || fail "go.mod must require unreplaced $module@$version"

# Verify the upstream snapshot against both hashes from the project's lockfile.
go_version=$(awk '$1 == "go" { print $2 }' go.mod)
printf 'module xray-source-verification\n\ngo %s\n\nrequire %s %s\n' \
    "$go_version" "$module" "$version" > "$work_dir/verify.mod"
cp go.sum "$work_dir/verify.sum"
download=$(go mod download -modfile="$verify_modfile" -json "$module@$version")
for kind in Sum GoModSum; do
    key=$version
    if [ "$kind" = GoModSum ]; then
        key=$version/go.mod
    fi
    expected=$(awk -v module="$module" -v key="$key" '$1 == module && $2 == key { print $3 }' go.sum)
    actual=$(printf '%s\n' "$download" | awk -F '"' -v field="$kind" '$2 == field { print $4 }')
    [ -n "$expected" ] && [ "$actual" = "$expected" ] || fail "$kind mismatch for $module@$version"
done
go mod verify -modfile="$verify_modfile" >/dev/null

modcache=$(go env GOMODCACHE)
if command -v cygpath >/dev/null 2>&1; then
    modcache=$(cygpath -u "$modcache")
fi
cp -R "$modcache/$module@$version" "$snapshot"
chmod -R u+w "$snapshot"

# Use a stable order when multiple Xray patches are present.
export LC_ALL=C
for patch in "$project_dir"/patches/xray-core-*.patch; do
    git -C "$snapshot" --git-dir="$go_work_dir/no-repository" apply --check "$patch"
    git -C "$snapshot" --git-dir="$go_work_dir/no-repository" apply "$patch"
done

go mod edit -modfile="$modfile" -replace "$module=$go_work_dir/xray-core"
go "$command" -mod=readonly -modfile="$modfile" "$@"
