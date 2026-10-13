#!/usr/bin/env bash
# Builds stub oledlg.dll (the OLE common dialogs) for the emulation root: the emulation root does not
# ship it, but applications import OLEDLG.dll at load time, so a missing one aborts the loader with
# STATUS_DLL_NOT_FOUND before anything runs. The stubs are generated from Wine's oledlg.spec (names,
# ordinals and argument counts), report success and show no dialogs.
#
#   ./build.sh <emulation-root>   # installs into <root>/filesys/c/windows/{syswow64,system32}
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="${1:?usage: build.sh <emulation-root>}"

cd "$here"
i686-w64-mingw32-gcc    -O2 -shared -o oledlg.dll     oledlg_stub.c   oledlg.def   -Wl,--kill-at
x86_64-w64-mingw32-gcc  -O2 -shared -o oledlg_x64.dll oledlg_stub.c   oledlg64.def

install -Dm644 oledlg.dll     "$root/filesys/c/windows/syswow64/oledlg.dll"
install -Dm644 oledlg_x64.dll "$root/filesys/c/windows/system32/oledlg.dll"
echo "installed oledlg.dll (32 and 64 bit) into $root"
