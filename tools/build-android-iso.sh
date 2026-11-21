#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
# Build the complete Qyronex OS Android 15 / GrapheneOS Google Pixel Edition:
#   - dist/qyronex-android-emulator.elf      (QEMU AArch64 virt Android/GrapheneOS kernel)
#   - dist/qyronex-pixel-boot.img            (AOSP GKI Boot Image v4 with ARM64 header + initramfs)
#   - dist/qyronex-android-system.img        (MBR + ext4 Android /system, /vendor, /data disk image)
#   - dist/qyronex-android-pixel-grapheneos.iso (Self-contained ISO-9660 + Joliet release ISO)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${OUT_DIR:-$REPO_DIR/dist}"
STAGING_DIR="$OUT_DIR/android-iso-staging"
ISO_FILE="$OUT_DIR/qyronex-android-pixel-grapheneos.iso"

mkdir -p "$OUT_DIR"
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "Docker laeuft nicht. Bitte zuerst Docker Desktop starten." >&2
  exit 1
fi

echo "[1/4] Baue Qyronex Android-15/GrapheneOS AArch64-Kernel, Userspace-Daemons & ext4-Systemimage ..."
docker run --rm \
  -v "$REPO_DIR:/workspace" \
  -v kernal-docker-target:/workspace/target \
  -v kernal-docker-cargo-registry:/usr/local/cargo/registry \
  -v "$OUT_DIR:/out" \
  -w /workspace \
  kernal-dev:bookworm-arm64 \
  bash -c '
    set -euo pipefail

    # 1a) QEMU AArch64 virt Emulator Kernel ELF (feature android-pixel)
    cargo build -p kernal-core-aarch64 \
      --target aarch64-unknown-none-softfloat \
      --features android-pixel \
      --target-dir /workspace/target/android-pixel
    cp /workspace/target/android-pixel/aarch64-unknown-none-softfloat/debug/kernal-core-aarch64 \
      /out/qyronex-android-emulator.elf

    # 1b) Raw ARM64 Image Header Kernel Binary (for AOSP GKI Boot Image v4 / Google Pixel ABL)
    RUSTFLAGS="-C link-arg=-Tkernel/core-aarch64/linker-rpi.ld" \
      cargo build -p kernal-core-aarch64 \
      --target aarch64-unknown-none-softfloat \
      --features android-pixel,rpi-native \
      --target-dir /workspace/target/android-pixel-img
    objcopy -O binary \
      /workspace/target/android-pixel-img/aarch64-unknown-none-softfloat/debug/kernal-core-aarch64 \
      /tmp/qyronex-pixel-kernel.img

    # 1c) Copy verified AArch64 bootstrap initramfs
    INITRAMFS_SRC="/workspace/target/step31/debian13-shell-initramfs.cpio"
    if [ ! -f "$INITRAMFS_SRC" ]; then
      echo "Fehler: $INITRAMFS_SRC fehlt im Docker-Target-Volume!" >&2
      exit 1
    fi
    cp "$INITRAMFS_SRC" /out/initramfs-android.cpio

    # 1d) Compile native ARM64 static Android userspace binaries
    mkdir -p /tmp/android-bin
    gcc -O2 -static -Wall -Wextra -Werror tools/android/src/servicemanager.c -o /tmp/android-bin/servicemanager
    gcc -O2 -static -Wall -Wextra -Werror tools/android/src/surfaceflinger.c -o /tmp/android-bin/surfaceflinger
    gcc -O2 -static -Wall -Wextra -Werror tools/android/src/android_tools.c  -o /tmp/android-bin/android-tools

    # 1e) Assemble Android 15 / GrapheneOS root filesystem tree
    ROOTFS="/tmp/android-rootfs"
    rm -rf "$ROOTFS"
    mkdir -p "$ROOTFS"/{system/bin,system/xbin,system/etc,vendor/bin,vendor/etc/vintf,data/data,data/local/tmp,apex,dev,proc,sys,tmp,mnt,storage,etc,bin,sbin,lib/aarch64-linux-gnu,usr/bin,usr/lib/aarch64-linux-gnu}

    # Extract dash, busybox, ld-linux-aarch64 and libc from bootstrap initramfs into ext4 rootfs
    python3 - "$INITRAMFS_SRC" "$ROOTFS" << "PY"
import os, sys
src, dst = sys.argv[1], sys.argv[2]
data = open(src, "rb").read()
off = 0
while off + 110 <= len(data) and data[off:off+6] == b"070701":
    mode = int(data[off+14:off+22], 16)
    fsize = int(data[off+54:off+62], 16)
    nsize = int(data[off+94:off+102], 16)
    name = data[off+110:off+110+nsize-1].decode("utf-8", "replace")
    off = (off + 110 + nsize + 3) & ~3
    body = data[off:off+fsize]
    off = (off + fsize + 3) & ~3
    if name == "TRAILER!!!":
        break
    if name in (".", "etc/os-release"):
        continue
    out_path = os.path.join(dst, name)
    ftype = mode & 0o170000
    if ftype == 0o040000:
        os.makedirs(out_path, exist_ok=True)
    elif ftype == 0o100000:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(body)
        os.chmod(out_path, mode & 0o777)
PY

    # Install compiled Android daemons & multi-call CLI applets into /system/bin
    cp /tmp/android-bin/servicemanager "$ROOTFS/system/bin/servicemanager"
    cp /tmp/android-bin/surfaceflinger "$ROOTFS/system/bin/surfaceflinger"
    cp /tmp/android-bin/android-tools  "$ROOTFS/system/bin/android-tools"
    chmod 0755 "$ROOTFS/system/bin/servicemanager" "$ROOTFS/system/bin/surfaceflinger" "$ROOTFS/system/bin/android-tools"
    for applet in android-init getprop setprop service dumpsys logcat qyronex-android-selftest; do
      ln -sf android-tools "$ROOTFS/system/bin/$applet"
    done
    # Convenience /system/bin/sh symlink
    ln -sf /bin/dash "$ROOTFS/system/bin/sh"
    ln -sf /system/bin/android-init "$ROOTFS/init"

    # Android / GrapheneOS metadata & Treble VINTF manifest
    cat > "$ROOTFS/system/build.prop" << "PROP"
ro.build.version.release=15
ro.build.version.sdk=35
ro.build.version.security_patch=2026-11-05
ro.build.fingerprint=google/qyronex_pixel/qyronex_pixel:15/AP4A.261105.001/qyronex:user/release-keys
ro.product.brand=Google
ro.product.manufacturer=Google
ro.product.model=Pixel (Qyronex GrapheneOS Hybrid)
ro.product.device=qyronex_pixel
ro.product.cpu.abi=arm64-v8a
ro.grapheneos.version=2026112100
ro.qyronex.kernel.mode=hybrid-rust-android15
ro.boot.verifiedbootstate=green
ro.boot.vbmeta.device_state=locked
PROP
    cp "$ROOTFS/system/build.prop" "$ROOTFS/default.prop"

    cat > "$ROOTFS/vendor/etc/vintf/manifest.xml" << "XML"
<manifest version="7.0" type="device" target-level="202404">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>3</version>
        <interface>
            <name>IKeyMintDevice</name>
            <instance>strongbox</instance>
        </interface>
    </hal>
    <hal format="aidl">
        <name>android.hardware.graphics.composer3</name>
        <version>2</version>
        <interface>
            <name>IComposer</name>
            <instance>default</instance>
        </interface>
    </hal>
</manifest>
XML

    cat > "$ROOTFS/etc/os-release" << "OSR"
NAME="Qyronex OS Android 15 / GrapheneOS Pixel Edition"
VERSION="0.5.0 (Android 15 API 35)"
ID=qyronex-android
PRETTY_NAME="Qyronex OS Android 15 / GrapheneOS Hybrid Kernel"
OSR

    # 1f) Create 48 MiB ext4 Android system filesystem & wrap in 50 MiB MBR disk image
    PART_IMG="/tmp/android-part1.ext4"
    rm -f "$PART_IMG"
    truncate -s 48M "$PART_IMG"
    mkfs.ext4 -F -L QYRONEX_ANDROID -O ^metadata_csum,^64bit -d "$ROOTFS" "$PART_IMG" >/dev/null

    DISK_IMG="/out/qyronex-android-system.img"
    rm -f "$DISK_IMG"
    truncate -s 50M "$DISK_IMG"
    dd if="$PART_IMG" of="$DISK_IMG" bs=512 seek=2048 conv=notrunc status=none
    python3 - "$DISK_IMG" << "PY"
import struct, sys
p = sys.argv[1]
part_lba = 2048
part_sectors = 48 * 1024 * 1024 // 512
mbr = bytearray(512)
# Partition 1 entry @ 446: bootable=0x80, type=0x83 (Linux ext4), LBA start, sector count
mbr[446:462] = struct.pack("<BBBBBBBBII", 0x80, 0x00, 0x02, 0x00, 0x83, 0xFE, 0xFF, 0xFF, part_lba, part_sectors)
mbr[510:512] = b"\x55\xAA"
with open(p, "r+b") as f:
    f.seek(0)
    f.write(mbr)
PY

    # 1g) Build & verify AOSP GKI Boot Image v4 (`ANDROID!`)
    python3 tools/android/mkbootimg_v4.py \
      --kernel /tmp/qyronex-pixel-kernel.img \
      --ramdisk /out/initramfs-android.cpio \
      --cmdline "console=ttyAMA0 androidboot.hardware=zumapro androidboot.selinux=enforcing androidboot.verifiedbootstate=green" \
      --out /out/qyronex-pixel-boot.img
  '

echo "[2/4] Befuelle ISO-Staging-Verzeichnis ..."
cp "$OUT_DIR/qyronex-pixel-boot.img"         "$STAGING_DIR/"
cp "$OUT_DIR/qyronex-android-system.img"     "$STAGING_DIR/"
cp "$OUT_DIR/qyronex-android-emulator.elf"   "$STAGING_DIR/"
cp "$OUT_DIR/initramfs-android.cpio"         "$STAGING_DIR/"
cp "$REPO_DIR/tools/android/start-android-emulator.sh" "$STAGING_DIR/"
cp "$REPO_DIR/tools/android/flash-pixel-grapheneos.sh" "$STAGING_DIR/"
chmod +x "$STAGING_DIR/start-android-emulator.sh" "$STAGING_DIR/flash-pixel-grapheneos.sh"

cat > "$STAGING_DIR/README-ANDROID-PIXEL.txt" << 'README'
===========================================================================
  Qyronex OS v0.5.0 - Android 15 / GrapheneOS Google Pixel Edition ISO
===========================================================================

Inhalt dieser ISO:
  - qyronex-pixel-boot.img         AOSP GKI Boot Image v4 (`ANDROID!` v4,
                                   ARM64 Kernel Image + Initramfs)
  - qyronex-android-system.img     50 MiB MBR + ext4 Android System-Image
                                   (/system/bin/{android-init,servicemanager,
                                   surfaceflinger,getprop,setprop,service,
                                   dumpsys,logcat,qyronex-android-selftest})
  - qyronex-android-emulator.elf   QEMU AArch64 virt Kernel ELF
  - initramfs-android.cpio         AArch64 Android Bootstrap-Initramfs
  - start-android-emulator.sh      Ein-Klick-Emulator-Starter (Browser/VNC)
  - flash-pixel-grapheneos.sh      Fastboot-RAM-Boot-Anleitung fuer Pixel

Architektur-Vorteile von Qyronex OS fuer Android / GrapheneOS:
  1. Memory-Safe Rust Hybrid Core (#![forbid(unsafe_code)] in linux-android
     & google-pixel Treiber-Crates)
  2. Capability-enforced 64-bit Android Binder v8 IPC (/dev/binder,
     /dev/hwbinder, /dev/vndbinder) mit Treble-Domain-Isolation
  3. Zero-on-Free Ashmem & DMA-Heap (/dev/ashmem, /dev/dma_heap/system)
  4. GrapheneOS Enforcing Lockdown (/sys/fs/selinux/enforce nicht per Write
     auf 0 herabstufbar, W^X TTBR1, PAN/MTE, unveraenderliche ro.*-Props)
  5. Google Pixel Tensor G1-G4 (gs101/gs201/zuma/zumapro), Titan M2
     StrongBox KeyMint 3.0 & IOMMU-gesandboxter Shannon 5G Modem-IPC-Pfad

Schnellstart im Emulator (macOS / Linux mit Docker):
  ./tools/android/start-android-emulator.sh --vnc

Transparenz-Hinweis fuer echte Google-Pixel-Hardware:
  Diese ISO enthaelt den vollstaendigen Qyronex-Android-15-Kernel, GKI Boot
  Image v4, native ARM64 ServiceManager/SurfaceFlinger/CLI-Tools und den
  kompletten QEMU-Emulator. Fuer ein Daily-Driver-GrapheneOS auf physischem
  Pixel-Silizium sind darueber hinaus die AOSP ART/Java-Frameworks sowie
  proprietaere Google Tensor vendor_boot/vendor_dlkm/Mali-GPU/Modem-Blobs
  erforderlich.
===========================================================================
README

echo "[3/4] Erstelle ISO-9660 + Joliet Release-Image: $ISO_FILE ..."
rm -f "$ISO_FILE"
if command -v hdiutil >/dev/null 2>&1; then
  hdiutil makehybrid -o "$ISO_FILE" "$STAGING_DIR" \
    -iso -joliet -default-volume-name "QYRONEX_ANDROID_PIXEL" >/dev/null
else
  docker run --rm -v "$OUT_DIR:/out" kernal-dev:bookworm-arm64 \
    bash -c 'genisoimage -R -J -V QYRONEX_ANDROID_PIXEL -o /out/qyronex-android-pixel-grapheneos.iso /out/android-iso-staging'
fi

echo "[4/4] Fertig! Artefakte:"
ls -lh "$OUT_DIR/qyronex-android-pixel-grapheneos.iso" \
       "$OUT_DIR/qyronex-pixel-boot.img" \
       "$OUT_DIR/qyronex-android-system.img" \
       "$OUT_DIR/qyronex-android-emulator.elf"
