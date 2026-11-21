#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${OUT_DIR:-$REPO_DIR/dist}"
FW_DIR="$OUT_DIR/rpi-firmware"
STAGING_DIR="$OUT_DIR/iso-staging"
SDCARD_IMG="$OUT_DIR/qyronex-rpi-sdcard.img"
ISO_FILE="$OUT_DIR/qyronex-rpi-installer.iso"

mkdir -p "$OUT_DIR" "$FW_DIR/overlays" "$STAGING_DIR/boot/overlays"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "Docker laeuft nicht. Bitte zuerst Docker Desktop starten." >&2
  exit 1
fi

echo "[1/5] Stelle offizielle Raspberry Pi Firmware & DTBs (Pi 3B+, 4B, 5) bereit ..."
FW_FILES=(
  bootcode.bin
  start.elf
  fixup.dat
  start4.elf
  fixup4.dat
  bcm2710-rpi-3-b.dtb
  bcm2710-rpi-3-b-plus.dtb
  bcm2711-rpi-4-b.dtb
  bcm2712-rpi-5-b.dtb
  overlays/disable-bt.dtbo
)
for f in "${FW_FILES[@]}"; do
  if [ ! -s "$FW_DIR/$f" ]; then
    echo "  Lade $f ..."
    curl -fsSL "https://raw.githubusercontent.com/raspberrypi/firmware/master/boot/$f" -o "$FW_DIR/$f"
  fi
done

echo "[2/5] Baue nativen Raspberry-Pi-AArch64-Kernel (rpi-native + linker-rpi.ld @ 0x00080000) & SD-Image ..."
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
    RUSTFLAGS="-C link-arg=-Tkernel/core-aarch64/linker-rpi.ld" \
      cargo build -p kernal-core-aarch64 \
      --target aarch64-unknown-none-softfloat \
      --features step31-debian-shell,rpi-native \
      --target-dir /workspace/target/rpi-native

    KERNEL_ELF="/workspace/target/rpi-native/aarch64-unknown-none-softfloat/debug/kernal-core-aarch64"
    INITRAMFS="/workspace/target/step31/debian13-shell-initramfs.cpio"
    ROOTFS_EXT4="/root/.cache/kernal/debian13/etappe6-desktop/desktop-part1.ext4"

    if [ ! -f "$ROOTFS_EXT4" ]; then
      echo "Fehler: $ROOTFS_EXT4 fehlt im Docker-Cache!" >&2
      exit 1
    fi

    # 1) ELF -> Raw ARM64 Image Binary mit 64-Byte ARM64-Header (0x00080000)
    objcopy -O binary "$KERNEL_ELF" /out/iso-staging/boot/kernel8.img
    cp /out/iso-staging/boot/kernel8.img /out/iso-staging/boot/kernel_2712.img
    cp "$INITRAMFS" /out/iso-staging/boot/initramfs8
    cp -r /out/rpi-firmware/* /out/iso-staging/boot/

    # 2) Raspberry Pi Boot-Konfiguration (3B+, 4B, 5)
    # WICHTIG: DTB @ 0x07000000 (112 MiB) & initramfs8 @ 0x08000000 (128 MiB) liegen sicher
    # oberhalb des Kernel-.bss-Segments (~86 MiB), damit echte RPi-Firmware sie nicht ueberlappt.
    cat > /out/iso-staging/boot/config.txt << "CFG"
# Qyronex OS Hybrid-Kernel Boot Configuration (Raspberry Pi 3B+ / 4B / 5)
arm_64bit=1
enable_uart=1
uart_2ndstage=1
dtoverlay=disable-bt
disable_overscan=1
hdmi_force_hotplug=1
framebuffer_width=1280
framebuffer_height=800
framebuffer_depth=32
device_tree_address=0x07000000
initramfs initramfs8 0x08000000

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
console=ttyAMA0,115200 console=tty1 root=/dev/mmcblk0p2 rootfstype=ext4 rw rootwait init=/sbin/init udev.children_max=2 systemd.unit=multi-user.target
CMD

    # 3) FAT32 Boot-Partition (128 MiB) mit offizieller RPi-Firmware, DTBs, Overlays & Kernel
    BOOT_IMG="/tmp/qyronex-boot.fat32"
    rm -f "$BOOT_IMG"
    truncate -s 128M "$BOOT_IMG"
    mkfs.vfat -F 32 -n QYRONEXBOOT "$BOOT_IMG" >/dev/null
    mcopy -s -i "$BOOT_IMG" /out/iso-staging/boot/* ::/

    # 4) Temporaere RootFS-Kopie fuer Raspberry Pi anpassen (/etc/fstab -> /dev/mmcblk0p2)
    RPI_ROOTFS="/tmp/qyronex-rpi-rootfs.ext4"
    cp --sparse=always "$ROOTFS_EXT4" "$RPI_ROOTFS"
    printf "/dev/mmcblk0p2 / ext4 rw,errors=remount-ro 0 1\n" > /tmp/rpi-fstab
    debugfs -w -R "rm /etc/fstab" "$RPI_ROOTFS" >/dev/null 2>&1 || true
    debugfs -w -R "write /tmp/rpi-fstab /etc/fstab" "$RPI_ROOTFS" >/dev/null
    rm -f /tmp/rpi-fstab

    # 5) Komplettes MBR-partitioniertes SD-Karten-Image zusammenbauen
    python3 - "$BOOT_IMG" "$RPI_ROOTFS" "/out/qyronex-rpi-sdcard.img" << "PY"
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

def mbr_entry(boot_flag, part_type, lba_start, lba_count):
    return (
        struct.pack("<B", boot_flag)
        + b"\xfe\xff\xff"
        + struct.pack("<B", part_type)
        + b"\xfe\xff\xff"
        + struct.pack("<II", lba_start, lba_count)
    )

mbr = bytearray(512)
struct.pack_into("<I", mbr, 440, 0x5159524E)
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
PY
    rm -f "$BOOT_IMG" "$RPI_ROOTFS"
  '

echo "[3/5] Erstelle Installer-Skript und Anleitung in der ISO ..."
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
  - boot/bootcode.bin, start.elf, fixup.dat, start4.elf, fixup4.dat : Offizielle Raspberry Pi Firmware
  - boot/bcm2710-rpi-3-b*.dtb, bcm2711-rpi-4-b.dtb, bcm2712-rpi-5-b.dtb : Offizielle DTBs
  - boot/kernel8.img       : Qyronex AArch64 Hybrid-Kernel (ARM64 Image Header @ 0x00080000, Pi 3B+ & 4B)
  - boot/kernel_2712.img   : Qyronex AArch64 Hybrid-Kernel (Raspberry Pi 5)
  - boot/initramfs8        : Initramfs
  - boot/config.txt / cmdline.txt : Raspberry Pi 64-Bit Boot-Konfiguration
  - install-rpi.sh         : Interaktives Flash-Skript fuer macOS & Linux
EOF

echo "[4/5] Erzeuge ISO-9660 + Joliet Installer-ISO ($ISO_FILE) ..."
rm -f "$ISO_FILE"
hdiutil makehybrid -iso -joliet -default-volume-name "QYRONEX_RPI" -o "$ISO_FILE" "$STAGING_DIR"

echo "[5/5] Verifiziere Artefakte ..."
ls -lh "$ISO_FILE" "$SDCARD_IMG"
rm -rf "$STAGING_DIR"
echo "Fertig!"
