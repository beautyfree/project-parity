#!/bin/sh
# Public one-command installer. It downloads a tagged source bundle for the
# skill and a prebuilt CLI, then delegates surface installation to install.sh.
set -eu

REPO=${PROJECT_PARITY_REPO:-beautyfree/project-parity}
VERSION=${PROJECT_PARITY_VERSION:-v0.1.2}
BASE="https://github.com/$REPO"
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/project-parity-install.XXXXXX")
trap 'find "$TMP_DIR" -type f -delete 2>/dev/null || true; find "$TMP_DIR" -type d -depth -empty -delete 2>/dev/null || true' EXIT INT TERM

os=$(uname -s)
arch=$(uname -m)
case "$os:$arch" in
  Darwin:arm64) target=aarch64-apple-darwin ;;
  Darwin:x86_64) target=x86_64-apple-darwin ;;
  Linux:x86_64) target=x86_64-unknown-linux-gnu ;;
  *)
    echo "project-parity: no prebuilt binary for $os/$arch; install Rust and use the repository installer" >&2
    exit 1
    ;;
esac

command -v curl >/dev/null 2>&1 || { echo 'project-parity: curl is required' >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo 'project-parity: tar is required' >&2; exit 1; }

archive="$TMP_DIR/source.tar.gz"
binary_archive="$TMP_DIR/binary.tar.gz"
curl -fsSL "$BASE/archive/refs/tags/$VERSION.tar.gz" -o "$archive"
curl -fsSL "$BASE/releases/download/$VERSION/project-parity-$target.tar.gz" -o "$binary_archive"
tar -xzf "$archive" -C "$TMP_DIR"
source_dir=$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d -name 'project-parity-*' | head -n 1)
mkdir -p "$source_dir/target/release"
tar -xzf "$binary_archive" -C "$source_dir/target/release"
chmod 755 "$source_dir/target/release/project-parity"

if [ "$#" -eq 0 ]; then
  set -- --target=auto --yes
fi
exec sh "$source_dir/install.sh" --skip-build "$@"
