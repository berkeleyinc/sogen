#!/usr/bin/env bash
# Downloads and extracts 32-bit UltraISO into an emulation root, ready to run/fuzz:
#
#   ./fetch-ultraiso.sh <emulation-root>            # installs into <root>/filesys/c/ultraiso
#
# Notes:
# - The tree is lowercased: the emulator resolves host paths case sensitively for the application path
#   and the shipped tree mixes case (UltraISO.exe, IsoCmd.exe, ...).
# - UltraISO imports OLEDLG.DLL, which the emulation root does not ship; install the stub from
#   tools/oledlg-stub (./tools/oledlg-stub/build.sh <root>) before running it, otherwise the 32 bit
#   loader aborts with STATUS_DLL_NOT_FOUND (C0000135).
#
# Then fuzz it (whole process target, the UI path is what runs; ISOs are handed over as a file):
#
#   FUZZ_SEEDS=<repo>/tools/ultraiso-fuzz/seeds <artifacts-dir>/fuzzer -e <root> -w 16 -m 20000000 \
#     --dump-windows /tmp/uiso-windows -i 'c:\fuzz.iso' -a 'c:\fuzz.iso' c:/ultraiso/ultraiso.exe
#
# `-m` is required here: UltraISO runs a message loop and never exits on its own, so a testcase has to
# end on an instruction budget.

set -euo pipefail

root="${1:?usage: fetch-ultraiso.sh <emulation-root>}"
workdir="$(mktemp -d)"

# The download host answers the first request with a "click again" page.
for _ in 1 2 3 4 5; do
    curl -sL --max-time 900 -A "Mozilla/5.0" -e "https://www.ultraiso.com/download.html" -o "$workdir/uiso.exe" \
        "https://www.ultraiso.com/uiso9_pe.exe"

    if [ "$(head -c 2 "$workdir/uiso.exe" 2>/dev/null)" = "MZ" ]; then
        break
    fi
done

innoextract -q -d "$workdir/out" "$workdir/uiso.exe"

target="$root/filesys/c/ultraiso"
rm -rf "$target"
mkdir -p "$(dirname "$target")"
cp -r "$workdir/out/app" "$target"

# Lowercase every path, see above.
(cd "$target" && find . -depth | sort -r | while read -r path; do
    dir="$(dirname "$path")"
    base="$(basename "$path")"
    lower="$(echo "$base" | tr 'A-Z' 'a-z')"
    [ "$base" != "$lower" ] && mv "$path" "$dir/$lower"
done; true)

rm -rf "$workdir"
echo "installed UltraISO into $target"
