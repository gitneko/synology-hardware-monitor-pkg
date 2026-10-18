#!/bin/sh
# Pinned C toolchain for bundled SQLite/ring and the static Rust linker.
set -eu
cd "$(dirname "$0")/.."
mkdir -p "${1:-.build/musl}"
musl_install_dir=$(cd "${1:-.build/musl}" && pwd)
if [ -x "$musl_install_dir/bin/musl-gcc" ] && [ -f "$musl_install_dir/COPYRIGHT" ]; then
    echo "Using existing musl compiler: $musl_install_dir/bin/musl-gcc"
    exit 0
fi
mkdir -p .build/toolchain
cd .build/toolchain
curl --fail --location --connect-timeout 20 --max-time 120 --retry 3 --output musl-1.2.5.tar.gz https://musl.libc.org/releases/musl-1.2.5.tar.gz
printf '%s  %s\n' a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4 musl-1.2.5.tar.gz | sha256sum --check
tar -xzf musl-1.2.5.tar.gz
cd musl-1.2.5
CFLAGS='-O2 -march=x86-64 -mtune=generic' ./configure --prefix="$musl_install_dir" --disable-shared
make -j2
make install
cp COPYRIGHT "$musl_install_dir/COPYRIGHT"
