#!/bin/bash

set -e

toolchain="$1"

mkdir -p toolchains
toolchain_dir="${TOOLCHAINS_DIR:-toolchains}/$toolchain"

if ! [ -d "$toolchain_dir" ]; then
	git clone --branch 2025.02 --depth 1 https://github.com/buildroot/buildroot.git "$toolchain_dir"
fi

if [ -x "$toolchain_dir/output/host/bin/$toolchain-gcc" ]; then
	# Build likely already went through
	exit 0
fi

cd "$toolchain_dir"
toolchain_config="../../buildroot-configs/$toolchain"

if ! [ -f "$toolchain_config" ]; then
	echo "There is no config for toolchain: $toolchain"
	exit 1
fi

cp "$toolchain_config" .config
make -j$(nproc)
