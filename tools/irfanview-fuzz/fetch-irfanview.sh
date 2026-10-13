#!/usr/bin/env bash
# Downloads and extracts a 64-bit IrfanView into a directory, ready to be dropped into an emulation root:
#
#   ./fetch-irfanview.sh /tmp/ivroot
#   cp -r /tmp/ivroot <emulation-root>/filesys/c/irfanview
#
# Then fuzz it (the batch conversion mode decodes the input and exits, so the whole process can be used as
# the fuzz target - it has no `vulnerable` export):
#
#   FUZZ_SEEDS=<repo>/tools/irfanview-fuzz/seeds <artifacts-dir>/fuzzer -e <root> -w 32 \
#     -i 'c:\fuzz.bin' -a 'c:\fuzz.bin' -a '/convert=c:\out.bmp' -a '/silent' c:/irfanview/i_view64.exe
#
# Note: IrfanView only accepts backslash paths on the command line, forward slashes make it exit silently.

set -euo pipefail

target="${1:-/tmp/ivroot}"
version="476"
workdir="$(mktemp -d)"

# The download host answers the first request with a "click again" page (and is flaky), so retry until the
# expected PE header shows up.
fetch() {
    local url="$1" out="$2"

    for _ in 1 2 3 4 5; do
        curl -sL --max-time 900 -c "$workdir/jar" -b "$workdir/jar" -A "Mozilla/5.0" -e "$url" -o "$out" "$url"

        if [ "$(head -c 2 "$out" 2>/dev/null)" = "MZ" ]; then
            return 0
        fi
    done

    echo "failed to download $url" >&2
    return 1
}

fetch "https://www.irfanview.info/files/iview${version}g_x64_setup.exe" "$workdir/iview.exe"
fetch "https://www.irfanview.info/files/iview${version}_plugins_x64_setup.exe" "$workdir/plugins.exe"

mkdir -p "$target"
7z x -y -o"$target" "$workdir/iview.exe" > /dev/null
7z x -y -o"$target" "$workdir/plugins.exe" > /dev/null

rm -rf "$workdir"
echo "extracted IrfanView $version to $target"
