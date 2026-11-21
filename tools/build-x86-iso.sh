#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${OUT_DIR:-$REPO_DIR/dist}"
STAGING_DIR="$OUT_DIR/x86-iso-staging"
USB_IMG="$OUT_DIR/qyronex-x86_64-uefi.img"
ISO_FILE="$OUT_DIR/qyronex-x86_64-uefi.iso"

mkdir -p "$OUT_DIR" "$STAGING_DIR/EFI/BOOT" "$STAGING_DIR/KERNAL" "$STAGING_DIR/boot"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "Docker laeuft nicht. Bitte zuerst Docker Desktop starten." >&2
  exit 1
fi

echo "[1/3] Baue x86_64 UEFI Loader (BOOTX64.EFI) & Kernel Core (CORE.ELF) ..."
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

    # Erstelle 16 MiB FAT16 El-Torito UEFI-ESP-Image (32768 Sektoren <= u16::MAX fuer El-Torito!)
    ESP_FAT="/out/x86-iso-staging/boot/efiboot.img"
    rm -f "$ESP_FAT"
    truncate -s 16M "$ESP_FAT"
    mkfs.vfat -F 16 -n QYRONEXX64 "$ESP_FAT" >/dev/null
    mmd -i "$ESP_FAT" ::/EFI ::/EFI/BOOT ::/KERNAL
    mcopy -i "$ESP_FAT" /out/x86-iso-staging/EFI/BOOT/BOOTX64.EFI ::/EFI/BOOT/BOOTX64.EFI
    mcopy -i "$ESP_FAT" /out/x86-iso-staging/KERNAL/CORE.ELF ::/KERNAL/CORE.ELF

    # Erstelle 64 MiB MBR-partitioniertes UEFI-USB-Disk-Image
    USB_FAT="/tmp/qyronex-x86-usb.fat32"
    rm -f "$USB_FAT"
    truncate -s 64M "$USB_FAT"
    mkfs.vfat -F 32 -n QYRONEXX64 "$USB_FAT" >/dev/null
    mmd -i "$USB_FAT" ::/EFI ::/EFI/BOOT ::/KERNAL
    mcopy -i "$USB_FAT" /out/x86-iso-staging/EFI/BOOT/BOOTX64.EFI ::/EFI/BOOT/BOOTX64.EFI
    mcopy -i "$USB_FAT" /out/x86-iso-staging/KERNAL/CORE.ELF ::/KERNAL/CORE.ELF

    python3 - "$USB_FAT" "/out/qyronex-x86_64-uefi.img" << "PY"
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
    rm -f "$USB_FAT"
  '

echo "[2/3] Erstelle bootfaehige El-Torito UEFI x86_64 ISO ($ISO_FILE) ..."
cp "$USB_IMG" "$STAGING_DIR/qyronex-x86_64-uefi.img"
rm -f "$ISO_FILE"
hdiutil makehybrid \
  -iso -joliet \
  -default-volume-name "QYRONEX_X64" \
  -eltorito-boot "$STAGING_DIR/boot/efiboot.img" \
  -no-emul-boot \
  -o "$ISO_FILE" "$STAGING_DIR"

# Patch El-Torito Boot Catalog: Platform ID -> 0xEF (UEFI), System Type -> 0xEF, Sector Count -> 16384 (8 MiB)
python3 - "$ISO_FILE" "$STAGING_DIR/boot/efiboot.img" <<'PY'
import os, struct, sys

iso_path, esp_path = sys.argv[1:3]
esp_sectors = os.path.getsize(esp_path) // 512
assert esp_sectors <= 0xFFFF, f"ESP image too large for 16-bit El-Torito sector count: {esp_sectors}"
with open(iso_path, "r+b") as f:
    catalog_lba = None
    for lba in range(16, 32):
        f.seek(lba * 2048)
        sec = f.read(2048)
        if len(sec) < 2048:
            break
        if sec[0] == 0 and sec[1:6] == b"CD001" and b"EL TORITO SPECIFICATION" in sec[7:39]:
            catalog_lba = struct.unpack_from("<I", sec, 0x47)[0]
            break
    if catalog_lba is None:
        raise SystemExit("Fehler: Kein El-Torito Boot Record in ISO gefunden!")
    f.seek(catalog_lba * 2048)
    cat = bytearray(f.read(2048))
    assert cat[0] == 0x01 and cat[30] == 0x55 and cat[31] == 0xAA, "Ungueltiger El-Torito Validation Entry"
    # Validation Entry: Platform ID = 0xEF (UEFI) + 16-bit two's-complement checksum
    cat[1] = 0xEF
    cat[28] = 0
    cat[29] = 0
    word_sum = sum(struct.unpack_from("<16H", cat, 0)) & 0xFFFF
    checksum = (-word_sum) & 0xFFFF
    struct.pack_into("<H", cat, 28, checksum)
    assert (sum(struct.unpack_from("<16H", cat, 0)) & 0xFFFF) == 0
    # Initial/Default Entry (bytes 32..64): Bootable=0x88, No-Emul=0x00, SysType=0xEF, SectorCount=esp_sectors
    cat[32] = 0x88
    cat[33] = 0x00
    cat[36] = 0xEF
    struct.pack_into("<H", cat, 38, esp_sectors)
    f.seek(catalog_lba * 2048)
    f.write(cat)
    print(f"El-Torito UEFI Boot Catalog patched at LBA {catalog_lba} (Platform=0xEF, sectors={esp_sectors}, checksum=0x{checksum:04x})")
PY

echo "[3/3] Fertig:"
ls -lh "$ISO_FILE" "$USB_IMG"
rm -rf "$STAGING_DIR"
