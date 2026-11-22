#!/usr/bin/env bash
# Cross-compiles TLDR for Linux targets and packages each as
# tldr_linux_<arch>.tar.gz, the naming the install script expects.
#
# Binaries are fully static (x86_64/aarch64 musl) so they run on any Linux
# regardless of glibc version and can be dropped into a scratch container. The
# 32-bit ARM/386 targets use musl too via their gnu-toolchain cross gcc, which
# is the pragmatic choice for the rarely-used arches.
#
# Needs (once):
#   rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
#     armv7-unknown-linux-musleabihf i686-unknown-linux-musl
#   sudo apt-get install -y musl-tools gcc-aarch64-linux-gnu \
#     gcc-arm-linux-gnueabihf gcc-i686-linux-gnu
set -euo pipefail

cd "$(dirname "$0")/.."

OUT_DIR="${OUT_DIR:-dist}"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
# Stamp the release version into the binary (build.rs reads this).
export TLDR_VERSION_OVERRIDE="${VERSION#v}"

# target triple -> asset arch -> cross C compiler (for ring/zstd C deps)
TARGETS=(
  "x86_64-unknown-linux-musl amd64 musl-gcc"
  "aarch64-unknown-linux-musl arm64 aarch64-linux-gnu-gcc"
  "armv7-unknown-linux-musleabihf arm arm-linux-gnueabihf-gcc"
  "i686-unknown-linux-musl 386 i686-linux-gnu-gcc"
)

for spec in "${TARGETS[@]}"; do
  read -r triple arch cross_cc <<<"$spec"
  name="tldr_linux_${arch}"

  if [ -n "${cross_cc:-}" ] && ! command -v "$cross_cc" >/dev/null; then
    echo "skipping ${name}: missing cross compiler ${cross_cc}" >&2
    continue
  fi

  echo "building ${name} (${triple})..."
  # Point the C compiler for this target at the cross toolchain so ring/zstd
  # build for the right libc. Do NOT override the Rust linker: the musl target
  # already links static-pie correctly through musl-gcc, and overriding it
  # produced broken dynamic binaries in testing.
  cc_var="CC_${triple//-/_}"
  export "${cc_var}=${cross_cc}"

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
