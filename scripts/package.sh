#!/usr/bin/env bash
# Builds a release tarball on Linux. Publishes nothing.
#
#   scripts/package.sh            -> dist/trustauto-VERSION-ARCH-linux.tar.gz and .sha256
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[[ "$(uname -s)" == Linux ]] || { echo "Linux only: the broker links against PAM" >&2; exit 1; }

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
ARCH="$(uname -m)"
NAME="trustauto-$VERSION-$ARCH-linux"

cargo test --release
cargo build --release --bins

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/$NAME/target/release"
for f in trustauto trustauto-broker trustauto-facts; do
  install -m 0755 "target/release/$f" "$STAGE/$NAME/target/release/$f"
done
cp -R config scripts docs "$STAGE/$NAME/"
cp README.md CHANGELOG.md "$STAGE/$NAME/"
rm -f "$STAGE/$NAME/scripts/package.sh"

mkdir -p dist
tar -C "$STAGE" -czf "dist/$NAME.tar.gz" "$NAME"
(cd dist && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
echo "dist/$NAME.tar.gz"
cat "dist/$NAME.tar.gz.sha256"
