#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
# Fastboot RAM-boot (`--boot`) and partition flash (`--flash`) helper for Google Pixel
# (Tensor G1-G4: Pixel 6 / 7 / 8 / 9) running Standard GrapheneOS with the Qyronex Kernel.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." 2>/dev/null || pwd)"
DIST_DIR="${DIST_DIR:-$REPO_DIR/dist}"

ACTION="boot"
BOOT_IMG="$DIST_DIR/qyronex-pixel-boot.img"
VENDOR_BOOT_IMG="$DIST_DIR/qyronex-pixel-vendor-boot.img"

if [ ! -f "$BOOT_IMG" ] && [ -f "$SCRIPT_DIR/qyronex-pixel-boot.img" ]; then
  BOOT_IMG="$SCRIPT_DIR/qyronex-pixel-boot.img"
  VENDOR_BOOT_IMG="$SCRIPT_DIR/qyronex-pixel-vendor-boot.img"
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --boot)  ACTION="boot"; shift ;;
    --flash) ACTION="flash"; shift ;;
    *)       BOOT_IMG="$1"; shift ;;
  esac
done

cat <<'EOF'
===========================================================================
  Qyronex OS v0.7.0 — Google Pixel / Standard GrapheneOS Kernel Installer
===========================================================================
SO FUNKTIONIERT DIE INSTALLATION AUF DEM GOOGLE PIXEL (Pixel 6 / 7 / 8 / 9):
  1. Installiere zuerst das normale Standard-GrapheneOS auf deinem Pixel
     (ueber https://grapheneos.org/install/web), damit Bootloader, UFS-
     Partitionen (`super` -> `system`, `vendor`, `product`) und Tensor-
     Firmware-Partitionen eingerichtet sind.
  2. Bringe das Pixel in den Fastboot-Modus (Power + Leiser beim Starten
     oder `adb reboot bootloader`) und verbinde es per USB-C mit dem Mac.
  3. Nicht-destruktiver RAM-Boot des Qyronex-Kernels (empfohlen!):
       ./tools/android/flash-pixel-grapheneos.sh --boot
     -> Fuehrt `fastboot boot dist/qyronex-pixel-boot.img` aus.
     -> Das Pure-Android-First-Stage-`/init` im Qyronex-Boot-Image laedt
        `sepolicy` v33, mountet die vorhandene Standard-GrapheneOS-
        Systempartition und verkettet in `/system/bin/init second_stage`.
     -> Bei einem normalen Neustart bootet wieder der unveraenderte
        Original-GrapheneOS-Kernel.
  4. Dauerhaftes Flashen von `boot` + `vendor_boot`:
       ./tools/android/flash-pixel-grapheneos.sh --flash
===========================================================================
EOF

if [ ! -f "$BOOT_IMG" ]; then
  echo "Fehler: Boot-Image nicht gefunden: $BOOT_IMG" >&2
  echo "Bitte zuerst './tools/build-android-iso.sh' ausfuehren." >&2
  exit 1
fi

if ! command -v fastboot >/dev/null 2>&1; then
  echo "Hinweis: 'fastboot' (Android Platform Tools) ist auf diesem Mac noch nicht installiert." >&2
  echo "Jetzt installieren mit:  brew install android-platform-tools" >&2
  exit 1
fi

echo "Suche angeschlossenes Google Pixel im Fastboot-Modus ..."
DEV_OUT="$(fastboot devices)"
if [ -z "$DEV_OUT" ]; then
  echo "Kein Google Pixel im Fastboot-Modus erkannt." >&2
  echo "Bitte Pixel im Bootloader/Fastboot-Modus (Power + Volume Down) per USB-C anschliessen." >&2
  exit 1
fi
echo "Gefundenes Geraet: $DEV_OUT"

if [ "$ACTION" = "flash" ]; then
  echo "Flashe Qyronex Boot Image v4 -> boot ..."
  fastboot flash boot "$BOOT_IMG"
  if [ -f "$VENDOR_BOOT_IMG" ]; then
    echo "Flashe Qyronex Vendor Boot Image v4 -> vendor_boot ..."
    fastboot flash vendor_boot "$VENDOR_BOOT_IMG"
  fi
  echo "Starte Google Pixel neu ..."
  fastboot reboot
else
  echo "Starte Qyronex Kernel nicht-destruktiv im RAM (fastboot boot) ..."
  fastboot boot "$BOOT_IMG"
fi
