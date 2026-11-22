#!/usr/bin/env bash
# Builds Linux release binaries and packages each as tldr_linux_<arch>.tar.gz,
# the naming the install script expects. Linux-only.
#
# Binaries are dynamically linked against glibc (gnu targets), which is fine for
# any reasonably recent distro and matches the sibling keep-at project. Fully
# static musl is used for the Docker image (built natively in Alpine), not here:
# cross-linking musl for arm64 fails because ring emits an arm64-only
# `--fix-cortex-a53-843419` linker flag that the host's x86_64 ld rejects.
#
# Needs (once):
#   rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
#     armv7-unknown-linux-gnueabihf i686-unknown-linux-gnu
#   sudo apt-get install -y gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf gcc-i686-linux-gnu
set -euo pipefail

cd "$(dirname "$0")/.."

OUT_DIR="${OUT_DIR:-dist}"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
# Stamp the release version into the binary (build.rs reads this).
export TLDR_VERSION_OVERRIDE="${VERSION#v}"

# target triple -> asset arch -> cross C compiler (empty for the native target)
TARGETS=(
  "x86_64-unknown-linux-gnu amd64 "
  "aarch64-unknown-linux-gnu arm64 aarch64-linux-gnu-gcc"
  "armv7-unknown-linux-gnueabihf arm arm-linux-gnueabihf-gcc"
  "i686-unknown-linux-gnu 386 i686-linux-gnu-gcc"
)

for spec in "${TARGETS[@]}"; do
  read -r triple arch cross_cc <<<"$spec"
  name="tldr_linux_${arch}"

  if [ -n "${cross_cc:-}" ] && ! command -v "$cross_cc" >/dev/null; then
    echo "skipping ${name}: missing cross compiler ${cross_cc}" >&2
    continue
  fi

  echo "building ${name} (${triple})..."
  if [ -n "${cross_cc:-}" ]; then
    # Point both the C compiler and the Rust linker at the cross gcc. The
    # linker must be the target gcc: ring emits an arm64-only
    # --fix-cortex-a53-843419 flag that the host x86_64 ld does not accept.
    cc_var="CC_${triple//-/_}"
    export "${cc_var}=${cross_cc}"
    linker_var="CARGO_TARGET_$(echo "$triple" | tr 'a-z-' 'A-Z_')_LINKER"
    export "${linker_var}=${cross_cc}"
  fi

  cargo build --release --locked --target "$triple" --bin tldr

  build_dir="$(mktemp -d)"
  cp "target/${triple}/release/tldr" "${build_dir}/tldr"
  tar -C "$build_dir" -czf "${OUT_DIR}/${name}.tar.gz" tldr
  rm -rf "$build_dir"
done

# Checksums so downloads can be verified.
if command -v sha256sum >/dev/null; then
  ( cd "$OUT_DIR" && sha256sum ./*.tar.gz > SHA256SUMS )
fi

echo "artifacts in ${OUT_DIR}/:"
ls -la "$OUT_DIR"
