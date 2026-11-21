#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${OUT_DIR:-$REPO_DIR/dist}"
STAGING_DIR="$OUT_DIR/x86-iso-staging"
USB_IMG="$OUT_DIR/qyronex-x86_64-uefi.img"
ISO_FILE="$OUT_DIR/qyronex-x86_64-uefi.iso"

mkdir -p "$OUT_DIR" "$STAGING_DIR/EFI/BOOT" "$STAGING_DIR/KERNAL"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "Docker laeuft nicht. Bitte zuerst Docker Desktop starten." >&2
  exit 1
fi

echo "[1/3] Baue x86_64 UEFI Loader (BOOTX64.EFI) & Kernel Core (KERNAL.ELF) ..."
docker run --rm \
  -v "$REPO_DIR:/workspace" \
  -v kernal-docker-target:/workspace/target \
  -v kernal-docker-cargo-registry:/usr/local/cargo/registry \
  -v "$OUT_DIR:/out" \
  -w /workspace \
  kernal-dev:bookworm-arm64 \
  bash -c '
    set -euo pipefail
    cargo xtask image
    cp /workspace/target/esp/EFI/BOOT/BOOTX64.EFI /out/x86-iso-staging/EFI/BOOT/BOOTX64.EFI
    cp /workspace/target/esp/KERNAL/CORE.ELF /out/x86-iso-staging/KERNAL/CORE.ELF

    # Erstelle 64 MiB MBR-partitioniertes UEFI-FAT32-USB-Image
    ESP_FAT="/tmp/qyronex-x86-esp.fat32"
    rm -f "$ESP_FAT"
    truncate -s 64M "$ESP_FAT"
    mkfs.vfat -F 32 -n QYRONEXX64 "$ESP_FAT" >/dev/null
    mmd -i "$ESP_FAT" ::/EFI ::/EFI/BOOT ::/KERNAL
    mcopy -i "$ESP_FAT" /out/x86-iso-staging/EFI/BOOT/BOOTX64.EFI ::/EFI/BOOT/BOOTX64.EFI
    mcopy -i "$ESP_FAT" /out/x86-iso-staging/KERNAL/CORE.ELF ::/KERNAL/CORE.ELF

    python3 - "$ESP_FAT" "/out/qyronex-x86_64-uefi.img" << "PY"
import os, struct, sys
esp_path, out_path = sys.argv[1:3]
SECTOR = 512
START = 2048
SECTORS = os.path.getsize(esp_path) // SECTOR
mbr = bytearray(512)
struct.pack_into("<I", mbr, 440, 0x51595836)
mbr[446:462] = struct.pack("<B3sB3sII", 0x80, b"\xfe\xff\xff", 0xEF, b"\xfe\xff\xff", START, SECTORS)
mbr[510:512] = b"\x55\xaa"
with open(out_path, "wb") as out:
    out.write(mbr)
    out.seek(START * SECTOR)
    with open(esp_path, "rb") as f:
        out.write(f.read())
PY
    rm -f "$ESP_FAT"
  '

echo "[2/3] Erstelle x86_64 UEFI ISO ($ISO_FILE) ..."
cp "$USB_IMG" "$STAGING_DIR/qyronex-x86_64-uefi.img"
rm -f "$ISO_FILE"
hdiutil makehybrid -iso -joliet -default-volume-name "QYRONEX_X64" -o "$ISO_FILE" "$STAGING_DIR"

echo "[3/3] Fertig:"
ls -lh "$ISO_FILE" "$USB_IMG"
rm -rf "$STAGING_DIR"
