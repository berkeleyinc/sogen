#!/usr/bin/env bash
# Builds the MuPDF fuzz target used by sogen's guest fuzzer (src/fuzzer).
#
#   ./build-harness.sh /path/to/mupdf-source.tar.gz-extracted-dir
#
# Then, from the build preset's artifacts dir:
#
#   cp <this dir>/mupdf-harness.exe root/filesys/c/
#   FUZZ_SEEDS=<this dir>/seeds ./fuzzer -e root c:/mupdf-harness.exe
#
# MuPDF is cross compiled with the mingw toolchain: the SLEIGH icicle backend lacks a handful of SSE
# helpers, so the library is built with -msse4.2 (see deps/icicle/icicle-cpu/src/exec/helpers.rs).

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mupdf_src="${1:-/tmp/mupdf/mupdf-1.28.5-source}"

if [ ! -d "$mupdf_src/include/mupdf" ]; then
    echo "usage: $0 <mupdf source dir>" >&2
    exit 1
fi

if [ ! -f "$mupdf_src/build/release/libmupdf.a" ]; then
    make -j"$(nproc)" -C "$mupdf_src" build=release libs \
        USE_SYSTEM_LIBS=no HAVE_X11=no HAVE_GLUT=no HAVE_OBJCOPY=no HAVE_LIBCRYPTO=no \
        XCFLAGS="-msse4.2" \
        CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ \
        AR=x86_64-w64-mingw32-ar RANLIB=x86_64-w64-mingw32-ranlib
fi

x86_64-w64-mingw32-g++ -O2 -std=c++20 -DNDEBUG -I "$mupdf_src/include" \
    "$here/mupdf-harness.cpp" -o "$here/mupdf-harness.exe" \
    -L "$mupdf_src/build/release" -lmupdf -lmupdf-third \
    -static -static-libgcc -static-libstdc++ \
    -lws2_32 -lcomdlg32 -lgdi32 -luser32 -ladvapi32 -lshell32 -lole32 -loleaut32 -luuid -lwinpthread

x86_64-w64-mingw32-gcc -O2 -mssse3 "$here/pshufb-test.c" -o "$here/pshufb-test.exe"

echo "built: $here/mupdf-harness.exe $here/pshufb-test.exe"
