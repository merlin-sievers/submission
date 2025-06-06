#!/bin/bash

set -e
set -x

# export PATH="$(realpath ../buildroot/output/host/bin):$PATH"

QEMU_LD_PREFIX="$SYSROOT" LD_LIBRARY_PATH="$PWD:$SYSROOT/lib:$SYSROOT/usr/lib" qemu-arm-static ./cvetest
