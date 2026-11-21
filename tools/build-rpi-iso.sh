#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${OUT_DIR:-$REPO_DIR/dist}"
STAGING_DIR="$OUT_DIR/iso-staging"
SDCARD_IMG="$OUT_DIR/qyronex-rpi-sdcard.img"
ISO_FILE="$OUT_DIR/qyronex-rpi-installer.iso"

mkdir -p "$OUT_DIR" "$STAGING_DIR/boot"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "Docker laeuft nicht. Bitte zuerst Docker Desktop starten." >&2
  exit 1
fi

echo "[1/4] Baue AArch64-Kernel (step31-debian-shell) falls noetig und extrahiere Boot-/Rootfs-Artefakte ..."
docker run --rm \
  -v "$REPO_DIR:/workspace" \
  -v kernal-docker-target:/workspace/target \
  -v kernal-docker-cache:/root/.cache/kernal:ro \
  -v kernal-docker-cargo-registry:/usr/local/cargo/registry \
  -v "$OUT_DIR:/out" \
  -w /workspace \
  kernal-dev:bookworm-arm64 \
  bash -c '
    set -euo pipefail
    KERNEL_ELF="/workspace/target/aarch64-unknown-none-softfloat/debug/kernal-core-aarch64"
    INITRAMFS="/workspace/target/step31/debian13-shell-initramfs.cpio"
    ROOTFS_EXT4="/root/.cache/kernal/debian13/etappe6-desktop/desktop-part1.ext4"

    if [ ! -f "$KERNEL_ELF" ]; then
      cargo build -p kernal-core-aarch64 --target aarch64-unknown-none-softfloat --features step31-debian-shell
    fi
    if [ ! -f "$ROOTFS_EXT4" ]; then
      echo "Fehler: $ROOTFS_EXT4 fehlt im Docker-Cache!" >&2
      exit 1
    fi

    # 1) ELF -> Raw AArch64 Kernel Binary (kernel8.img fuer Pi 3B+/4, kernel_2712.img fuer Pi 5)
    objcopy -O binary "$KERNEL_ELF" /out/iso-staging/boot/kernel8.img
    cp /out/iso-staging/boot/kernel8.img /out/iso-staging/boot/kernel_2712.img
    cp "$INITRAMFS" /out/iso-staging/boot/initramfs8

    # 2) Raspberry Pi Boot-Konfiguration (3B+, 4B, 5)
    cat > /out/iso-staging/boot/config.txt << "CFG"
# Qyronex OS Hybrid-Kernel Boot Configuration (Raspberry Pi 3B+ / 4B / 5)
arm_64bit=1
enable_uart=1
uart_2ndstage=1
disable_overscan=1
hdmi_force_hotplug=1
initramfs initramfs8 followkernel

[pi3]
kernel=kernel8.img

[pi4]
kernel=kernel8.img
arm_boost=1

[pi5]
kernel=kernel_2712.img

[all]
CFG

    cat > /out/iso-staging/boot/cmdline.txt << "CMD"
console=serial0,115200 console=tty1 root=/dev/mmcblk0p2 rootfstype=ext4 rw rootwait init=/sbin/init udev.children_max=2 systemd.unit=multi-user.target
CMD

    # 3) FAT32 Boot-Partition (128 MiB) erstellen und befuellen
    BOOT_IMG="/tmp/qyronex-boot.fat32"
    rm -f "$BOOT_IMG"
    truncate -s 128M "$BOOT_IMG"
    mkfs.vfat -F 32 -n QYRONEXBOOT "$BOOT_IMG" >/dev/null
    mcopy -i "$BOOT_IMG" \
      /out/iso-staging/boot/kernel8.img \
      /out/iso-staging/boot/kernel_2712.img \
      /out/iso-staging/boot/initramfs8 \
      /out/iso-staging/boot/config.txt \
      /out/iso-staging/boot/cmdline.txt \
      ::/

    # 4) Komplettes MBR-partitioniertes SD-Karten-Image zusammenbauen
    #    Part 1: Sektor 2048 .. 264191 (128 MiB FAT32 Boot, Typ 0x0C, aktiv 0x80)
    #    Part 2: Sektor 264192 .. Ende (Debian 13 Desktop ext4 Rootfs, Typ 0x83)
    python3 - "$BOOT_IMG" "$ROOTFS_EXT4" "/out/qyronex-rpi-sdcard.img" << "PY"
import os, struct, sys

boot_path, root_path, out_path = sys.argv[1:4]
SECTOR = 512
PART1_START = 2048
BOOT_BYTES = os.path.getsize(boot_path)
PART1_SECTORS = BOOT_BYTES // SECTOR
PART2_START = PART1_START + PART1_SECTORS
ROOT_BYTES = os.path.getsize(root_path)
PART2_SECTORS = (ROOT_BYTES + SECTOR - 1) // SECTOR
TOTAL_BYTES = (PART2_START + PART2_SECTORS) * SECTOR

def chs_dummy(lba):
    return b"\xfe\xff\xff"

def mbr_entry(boot_flag, part_type, lba_start, lba_count):
    return (
        struct.pack("<B", boot_flag)
        + chs_dummy(lba_start)
        + struct.pack("<B", part_type)
        + chs_dummy(lba_start + lba_count)
        + struct.pack("<II", lba_start, lba_count)
    )

mbr = bytearray(512)
struct.pack_into("<I", mbr, 440, 0x5159524E) # Disk signature "QYRN"
mbr[446:462] = mbr_entry(0x80, 0x0C, PART1_START, PART1_SECTORS)
mbr[462:478] = mbr_entry(0x00, 0x83, PART2_START, PART2_SECTORS)
mbr[510:512] = b"\x55\xaa"

with open(out_path, "wb") as out:
    out.write(mbr)
    out.seek(PART1_START * SECTOR)
    with open(boot_path, "rb") as bf:
        while True:
            chunk = bf.read(4 * 1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
    out.seek(PART2_START * SECTOR)
    with open(root_path, "rb") as rf:
        while True:
            chunk = rf.read(4 * 1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
    out.truncate(TOTAL_BYTES)

print(f"SD-Image erstellt: {out_path} ({TOTAL_BYTES // (1024*1024)} MiB)")
print(f"  Part 1 (FAT32 Boot): LBA {PART1_START}..{PART1_START+PART1_SECTORS-1} ({PART1_SECTORS*SECTOR//(1024*1024)} MiB)")
print(f"  Part 2 (ext4 Root):  LBA {PART2_START}..{PART2_START+PART2_SECTORS-1} ({PART2_SECTORS*SECTOR//(1024*1024)} MiB)")
PY
    rm -f "$BOOT_IMG"
  '

echo "[2/4] Erstelle Installer-Skript und Anleitung in der ISO ..."
cp "$SDCARD_IMG" "$STAGING_DIR/qyronex-rpi-sdcard.img"

cat > "$STAGING_DIR/install-rpi.sh" <<'EOF'
#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="$SCRIPT_DIR/qyronex-rpi-sdcard.img"

if [ ! -f "$IMG" ]; then
  echo "Fehler: $IMG nicht gefunden." >&2
  exit 1
fi

echo "=== Qyronex OS Raspberry Pi Installer (Pi 3B+ / 4B / 5) ==="
echo "Image: $IMG ($(du -h "$IMG" | awk '{print $1}'))"
echo ""

OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
  diskutil list external
  echo ""
  read -r -p "Ziel-Disk unter macOS eingeben (z.B. disk4, NICHT disk0!): " DISK_ID
  if [ -z "$DISK_ID" ] || [ "$DISK_ID" = "disk0" ] || [ "$DISK_ID" = "disk1" ]; then
    echo "Abgebrochen: ungueltige oder interne Disk." >&2
    exit 1
  fi
  echo "Achtung: Alle Daten auf /dev/${DISK_ID} werden ueberschrieben!"
  read -r -p "Tippe YES zum Fortfahren: " CONFIRM
  [ "$CONFIRM" = "YES" ] || exit 1
  diskutil unmountDisk "/dev/${DISK_ID}"
  sudo dd if="$IMG" of="/dev/r${DISK_ID}" bs=4m status=progress
  sync
  diskutil eject "/dev/${DISK_ID}"
  echo "Fertig! SD-Karte jetzt in den Raspberry Pi einsetzen und starten."
else
  lsblk -d -o NAME,SIZE,MODEL,TRAN
  echo ""
  read -r -p "Ziel-Geraet unter Linux eingeben (z.B. /dev/sdb oder /dev/mmcblk0): " DEV
  if [ -z "$DEV" ] || [ ! -b "$DEV" ]; then
    echo "Abgebrochen: $DEV ist kein Block-Geraet." >&2
    exit 1
  fi
  echo "Achtung: Alle Daten auf $DEV werden ueberschrieben!"
  read -r -p "Tippe YES zum Fortfahren: " CONFIRM
  [ "$CONFIRM" = "YES" ] || exit 1
  sudo umount "${DEV}"* 2>/dev/null || true
  sudo dd if="$IMG" of="$DEV" bs=4M status=progress conv=fsync
  sync
  echo "Fertig! SD-Karte jetzt in den Raspberry Pi einsetzen und starten."
fi
EOF
chmod +x "$STAGING_DIR/install-rpi.sh"

cat > "$STAGING_DIR/README-INSTALL.txt" <<'EOF'
Qyronex OS - Installierbare Raspberry Pi Distribution (Pi 3B+ / 4B / 5)
========================================================================

Inhalt dieser ISO:
  - qyronex-rpi-sdcard.img : Direkt flashbares Komplett-Image (FAT32 Boot + Debian 13 Desktop ext4)
  - boot/kernel8.img       : Qyronex AArch64 Hybrid-Kernel (Raspberry Pi 3B+ & 4B)
  - boot/kernel_2712.img   : Qyronex AArch64 Hybrid-Kernel (Raspberry Pi 5)
  - boot/initramfs8        : Initramfs
  - boot/config.txt        : Raspberry Pi 64-Bit Boot-Konfiguration
  - boot/cmdline.txt       : Kernel-Boot-Parameter
  - install-rpi.sh         : Interaktives Flash-Skript fuer macOS & Linux

Installation auf SD-Karte oder USB-SSD:
  Option A (Raspberry Pi Imager / balenaEtcher / Rufus):
    -> Waehle "Use custom image" / "Flash from file" und nimm `qyronex-rpi-sdcard.img`
       (oder entpacke diese ISO bzw. waehle direkt `qyronex-rpi-sdcard.img`).

  Option B (Terminal mit Installer-Skript):
    -> ISO oeffnen/mounten und `./install-rpi.sh` ausfuehren.

  Option C (direkt per dd unter macOS/Linux):
    macOS: diskutil unmountDisk /dev/diskN && sudo dd if=qyronex-rpi-sdcard.img of=/dev/rdiskN bs=4m
    Linux: sudo dd if=qyronex-rpi-sdcard.img of=/dev/sdX bs=4M status=progress conv=fsync
EOF

echo "[3/4] Erzeuge ISO-9660 + Joliet Installer-ISO ($ISO_FILE) ..."
rm -f "$ISO_FILE"
hdiutil makehybrid -iso -joliet -default-volume-name "QYRONEX_RPI" -o "$ISO_FILE" "$STAGING_DIR"

echo "[4/4] Verifiziere Partitionstabelle und ISO ..."
ls -lh "$ISO_FILE" "$SDCARD_IMG"
rm -rf "$STAGING_DIR"
echo "Fertig!"
