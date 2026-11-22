#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
# Safe fastboot boot helper for Google Pixel (Tensor G1-G4) running GrapheneOS.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOT_IMG="${1:-$SCRIPT_DIR/qyronex-pixel-boot.img}"

cat <<'EOF'
===========================================================================
  Qyronex OS - Google Pixel / GrapheneOS Boot Image v4 Helper
===========================================================================
WICHTIGER HINWEIS ZU PHYSISCHER PIXEL-HARDWARE:
  - Dieses Paket enthaelt sowohl `qyronex-pixel-boot.img` (AOSP GKI Boot Image v4,
    `ANDROID!` Header v4) als auch `qyronex-pixel-vendor-boot.img` (`VNDRBOOT` v4
    mit bootconfig, DTB & Vendor-Ramdisk-Table).
  - Der sichere Test auf einem entsperrten Google Pixel (Pixel 6/7/8/9)
    erfolgt NICHT-DESTRUKTIV im RAM per `fastboot boot`:
      fastboot boot qyronex-pixel-boot.img
  - Hinweis zu proprietaeren Blobs: Die Open-Source-HALs fuer Mali-G715 CSF GPU,
    Tensor Edge TPU, Camera LWIS, Shannon 5G Modem IOMMU, eBPF, dm-verity, EROFS/F2FS
    und die Qyronex-ART-Dalvik-VM (`pm`/`am`) sind enthalten. Signierte, proprietaere
    Google/ARM/Samsung-Binaerfirmwares und das komplette AOSP-Java-`system_server`
    muessen fuer Stock-Pixel-Factory-Images separat aus dem Factory-Image extrahiert
    werden.
  - Teste das System daher IMMER zuerst im Qyronex Android-Emulator:
      ./start-android-emulator.sh
===========================================================================
EOF

if [ ! -f "$BOOT_IMG" ]; then
  echo "Fehler: Boot-Image nicht gefunden: $BOOT_IMG" >&2
  exit 1
fi

if ! command -v fastboot >/dev/null 2>&1; then
  echo "Hinweis: 'fastboot' (Android Platform Tools) ist auf diesem Host nicht installiert." >&2
  echo "Installation (macOS): brew install android-platform-tools" >&2
  exit 1
fi

echo "Pruefe angeschlossene Pixel-Geraete im Fastboot-Modus ..."
fastboot devices
echo ""
echo "Zum nicht-destruktiven RAM-Boot auf dem verbundenen Pixel ausfuehren:"
echo "  fastboot boot \"$BOOT_IMG\""
echo ""
echo "(Fuer dauerhaftes Flashen der Boot-Partition mit eigenem AVB-Key:"
echo "  fastboot flash boot \"$BOOT_IMG\")"
