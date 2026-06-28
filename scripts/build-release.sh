#!/usr/bin/env bash
# Build stripped release binaries for SCRUB's supported targets and package them
# into dist/. Targets that require an unavailable toolchain are skipped with a
# warning (e.g. Apple targets need the macOS SDK).
#
# Usage: scripts/build-release.sh [version]
set -euo pipefail

cd "$(dirname "$0")/.."
VERSION="${1:-$(git describe --tags --always 2>/dev/null || echo dev)}"
mkdir -p dist

# Cross-linkers are configured in .cargo/config.toml.
TARGETS=(
  x86_64-unknown-linux-gnu
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-gnu
  aarch64-unknown-linux-musl
  x86_64-pc-windows-gnu
  x86_64-apple-darwin
  aarch64-apple-darwin
)

for target in "${TARGETS[@]}"; do
  if ! rustup target list --installed | grep -qx "$target"; then
    echo ">> skip $target (target not installed)"
    continue
  fi
  echo ">> build $target"
  if ! cargo build --release --target "$target" -p scrub 2>/dev/null; then
    echo ">> skip $target (build failed — toolchain/linker unavailable)"
    continue
  fi

  bin="scrub"
  [[ "$target" == *windows* ]] && bin="scrub.exe"
  out="scrub-${VERSION}-${target}"
  staging="dist/${out}"
  mkdir -p "$staging"
  cp "target/${target}/release/${bin}" "$staging/"
  cp README.md LICENSE scrub.example.yaml "$staging/" 2>/dev/null || true

  if [[ "$target" == *windows* ]]; then
    (cd dist && zip -qr "${out}.zip" "${out}")
  else
    tar -C dist -czf "dist/${out}.tar.gz" "${out}"
  fi
  rm -rf "$staging"
  echo ">> packaged dist/${out}.*"
done

echo "done. artifacts:"
ls -1 dist/ 2>/dev/null || true
