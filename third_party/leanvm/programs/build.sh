#!/bin/sh
# Build every guest and refresh its checked-in ELF file (programs/<name>/<name>.elf), which the tests load.
# Each guest is its own workspace, with its own toolchain file (a dated nightly with rust-src) and cargo config;
# they share one target directory, so `core` and the runtime (sdk/) are built once.
set -e
export RUSTC_BOOTSTRAP=1
cd "$(dirname "$0")"
for guest in */guest; do
  name=${guest%/guest}
  (cd "$guest" && cargo build --release --target-dir ../../target)
  bin="target/riscv64im-unknown-none-elf/release/${name}-guest"
  if [ ! -f "$bin" ]; then
    bin="target/riscv64im-unknown-none-elf/release/$name"
  fi
  cp "$bin" "$name/$name.elf"
done
