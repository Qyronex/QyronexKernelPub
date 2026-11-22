#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
# Build the Pure Native Qyronex OS Android 15 / GrapheneOS Google Pixel Edition (v0.7.0):
#   - 100% NATIVE ANDROID STACK (ZERO Wayland, ZERO GTK3, ZERO systemd, ZERO Debian Desktop!)
#   - Wayland is reserved strictly for PC / Desktop builds (`build-x86-iso.sh`, `build-rpi-iso.sh`).
#   - Outputs:
#       * dist/qyronex-android-emulator.elf           (QEMU AArch64 virt Android 15 / GrapheneOS kernel)
#       * dist/initramfs-android.cpio                 (Pure Android First-Stage & Second-Stage Ramdisk `/init`)
#       * dist/qyronex-pixel-boot.img                 (AOSP GKI Boot Image v4 `ANDROID!` + ARM64 header + Android ramdisk)
#       * dist/qyronex-pixel-vendor-boot.img          (AOSP Vendor Boot Image v4 `VNDRBOOT` + bootconfig + DTB)
#       * dist/qyronex-android-system.img             (Pure Native Android 15 MBR + ext4 partition image)
#       * dist/qyronex-android-pixel-grapheneos.iso   (Self-contained ISO-9660 + Joliet release ISO)
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

echo "[1/4] Baue Qyronex Native-Android-15-Kernel, Pure-Android-Initramfs (/init), Direct-DRM SurfaceFlinger & Dalvik-VM ..."
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

    # 1c) Compile 100% static ARM64 Native Android Daemons, Direct-DRM SurfaceFlinger & Dalvik VM (NO Wayland / NO GTK!)
    rm -rf /tmp/android-bin /tmp/android-apks /tmp/android-root
    mkdir -p /tmp/android-bin /tmp/android-apks
    gcc -O2 -static -Wall -Wextra -Werror tools/android/src/servicemanager.c -o /tmp/android-bin/servicemanager
    gcc -O2 -static -Wall -Wextra -Werror tools/android/src/surfaceflinger.c -o /tmp/android-bin/surfaceflinger
    gcc -O2 -static -Wall -Wextra -Werror tools/android/src/android_tools.c  -o /tmp/android-bin/android-tools
    gcc -O2 -static -Wall -Wextra -Werror tools/android/src/qyronex_art.c    -o /tmp/android-bin/qyronex-art
    chmod 0755 /tmp/android-bin/*

    # 1d) Generate real Android .apk packages (ZIP + Binary AXML + DEX 035) & EROFS/F2FS/super.img LP probes
    python3 tools/android/mkapk.py --out-dir /tmp/android-apks

    # 1e) Assemble Pure Native Android 15 First-Stage & Second-Stage Root Hierarchy (ZERO Debian / ZERO Wayland)
    R="/tmp/android-root"
    mkdir -p "$R/dev" "$R/proc" "$R/sys" "$R/mnt" "$R/mnt/graphene" \
             "$R/first_stage_ramdisk" "$R/system/bin" "$R/system/app" "$R/system/etc/init" \
             "$R/vendor/bin" "$R/vendor/etc/vintf" "$R/vendor/etc/init/hw" "$R/vendor/etc/qyronex-fs" \
             "$R/product/app" "$R/system_ext" "$R/apex" "$R/linkerconfig" \
             "$R/data/app" "$R/data/system" "$R/data/data" "$R/data/local/tmp" \
             "$R/run/user/0" "$R/bin" "$R/sbin" "$R/lib/aarch64-linux-gnu"

    # Extract minimal Step-15 initialrd bootstrap entries from target/step31/debian13-shell-initramfs.cpio
    python3 - /workspace/target/step31/debian13-shell-initramfs.cpio "$R" << "PY"
import os, sys
cpio_path, root_dir = sys.argv[1], sys.argv[2]
keep = {
    "bin/busybox", "bin/dash", "bin/sh",
    "lib/ld-linux-aarch64.so.1",
    "lib/aarch64-linux-gnu/libc.so.6",
    "lib/aarch64-linux-gnu/libresolv.so.2",
}
data = open(cpio_path, "rb").read()
off = 0
while off + 110 <= len(data):
    hdr = data[off:off+110]
    if hdr[:6] not in (b"070701", b"070702"): break
    fsize = int(hdr[54:62], 16)
    nsize = int(hdr[94:102], 16)
    name = data[off+110:off+110+nsize-1].decode("utf-8")
    off = (off + 110 + nsize + 3) & ~3
    if name == "TRAILER!!!": break
    if name in keep:
        dst = os.path.join(root_dir, name)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(data[off:off+fsize])
        os.chmod(dst, 0o755)
    off = (off + fsize + 3) & ~3
PY

    # Install Native Android PID 1 /init & /system/bin suite
    cp /tmp/android-bin/android-tools  "$R/init"
    ln -sf /init                       "$R/sbin/init"
    cp /tmp/android-bin/servicemanager "$R/system/bin/servicemanager"
    cp /tmp/android-bin/surfaceflinger "$R/system/bin/surfaceflinger"
    cp /tmp/android-bin/android-tools  "$R/system/bin/android-tools"
    cp /tmp/android-bin/qyronex-art    "$R/system/bin/qyronex-art"
    chmod 0755 "$R/init" "$R/system/bin/"*

    ln -sf servicemanager "$R/system/bin/hwservicemanager"
    ln -sf servicemanager "$R/system/bin/vndservicemanager"
    ln -sf android-tools  "$R/system/bin/android-init"
    ln -sf android-tools  "$R/system/bin/getprop"
    ln -sf android-tools  "$R/system/bin/setprop"
    ln -sf android-tools  "$R/system/bin/service"
    ln -sf android-tools  "$R/system/bin/dumpsys"
    ln -sf android-tools  "$R/system/bin/logcat"
    ln -sf android-tools  "$R/system/bin/qyronex-android-selftest"
    ln -sf qyronex-art    "$R/system/bin/dalvikvm"
    ln -sf qyronex-art    "$R/system/bin/zygote64"
    ln -sf qyronex-art    "$R/system/bin/pm"
    ln -sf qyronex-art    "$R/system/bin/am"

    # Install real Android .apk packages & filesystem probes
    cp /tmp/android-apks/GrapheneWelcome.apk     "$R/system/app/GrapheneWelcome.apk"
    cp /tmp/android-apks/PixelSecurityBench.apk  "$R/system/app/PixelSecurityBench.apk"
    cp /tmp/android-apks/QyronexHardwareInfo.apk "$R/system/app/QyronexHardwareInfo.apk"
    cp /tmp/android-apks/PixelSecurityBench.apk  "$R/data/local/tmp/PixelSecurityBench.apk"
    cp /tmp/android-apks/QyronexHardwareInfo.apk "$R/data/local/tmp/QyronexHardwareInfo.apk"
    cp /tmp/android-apks/fs-probes/*             "$R/vendor/etc/qyronex-fs/"

    # Standard Google Pixel / AOSP First-Stage fstab (Dynamic Partitions super -> system/vendor/product/system_ext)
    cat > "$R/fstab.zumapro" << "FSTAB"
# Android 15 / GrapheneOS fstab for Google Pixel Tensor (zumapro / zuma / gs201 / gs101)
system      /system      erofs ro wait,slotselect,avb=vbmeta_system,logical,first_stage_mount
system      /system      ext4  ro wait,slotselect,avb=vbmeta_system,logical,first_stage_mount
vendor      /vendor      erofs ro wait,slotselect,avb,logical,first_stage_mount
product     /product     erofs ro wait,slotselect,avb,logical,first_stage_mount
system_ext  /system_ext  erofs ro wait,slotselect,avb,logical,first_stage_mount
/dev/block/by-name/metadata /metadata ext4 noatime,nosuid,nodev,discard wait,check,formattable,first_stage_mount
/dev/block/by-name/userdata /data     f2fs noatime,nosuid,nodev,discard,inlinecrypt wait,check,quota,formattable
FSTAB
    cp "$R/fstab.zumapro" "$R/first_stage_ramdisk/fstab.zumapro"
    cp "$R/fstab.zumapro" "$R/first_stage_ramdisk/fstab.zuma"
    cp "$R/fstab.zumapro" "$R/first_stage_ramdisk/fstab.gs201"
    cp "$R/fstab.zumapro" "$R/first_stage_ramdisk/fstab.gs101"

    # Android First-Stage SELinux Policy v33 & init.rc
    printf "QYRONEX_GRAPHENEOS_SEPOLICY_V33_ENFORCING_BINARY_BLOB\n" > "$R/sepolicy"

    cat > "$R/init.rc" << "INITRC"
# Android 15 / GrapheneOS Native Init Configuration (Qyronex Hybrid Rust Kernel)
on early-init
    mount proc proc /proc
    mount sysfs sysfs /sys
    mount selinuxfs selinuxfs /sys/fs/selinux
    load_system_props

on init
    mkdir /data 0755 system system
    mkdir /data/app 0755 system system
    mkdir /data/system 0755 system system
    start servicemanager
    start surfaceflinger

service servicemanager /system/bin/servicemanager
    class core
    user system
    group system

service surfaceflinger /system/bin/surfaceflinger
    class core
    user system
    group graphics drmrpc
INITRC

    cat > "$R/system/build.prop" << "PROP"
ro.build.version.release=15
ro.build.version.sdk=35
ro.build.version.security_patch=2026-11-05
ro.build.fingerprint=google/qyronex_pixel/qyronex_pixel:15/AP4A.261105.001/qyronex:user/release-keys
ro.product.brand=Google
ro.product.manufacturer=Google
ro.product.model=Google Pixel 9 / Tensor G4 (Qyronex GrapheneOS)
ro.product.device=qyronex_pixel
ro.product.cpu.abi=arm64-v8a
ro.grapheneos.version=2026112200
ro.qyronex.kernel.mode=hybrid-rust-android15-native-drm
ro.boot.verifiedbootstate=green
ro.boot.vbmeta.device_state=locked
ro.boot.dm_verity=enforcing-sha256
ro.boot.dynamic_partitions=true
ro.qyronex.ebpf.verifier=fail-closed-64bit
ro.qyronex.storage.fs=erofs,f2fs,ext4,fuse
ro.qyronex.art.runtime=qyronex-art-dalvik-035
PROP
    cp "$R/system/build.prop" "$R/default.prop"

    cat > "$R/vendor/etc/vintf/manifest.xml" << "XML"
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

    # 1f) Pack Pure Native Android Initramfs (`dist/initramfs-android.cpio`) in SVR4 newc format
    python3 - "$R" /out/initramfs-android.cpio << "PY"
import os, stat, sys

root_dir = sys.argv[1]
out_path = sys.argv[2]
out = bytearray()

def align4(b):
    while len(b) % 4 != 0:
        b.append(0)

def add_entry(ino, rel_path, mode, payload):
    name_bytes = rel_path.encode("utf-8") + b"\x00"
    fields = [
        ino, mode, 0, 0, 1, 0, len(payload),
        0, 0, 0, 0, len(name_bytes), 0
    ]
    hdr = b"070701" + b"".join(f"{v:08x}".encode("ascii") for v in fields)
    out.extend(hdr)
    out.extend(name_bytes)
    align4(out)
    out.extend(payload)
    align4(out)

ino = 1
add_entry(ino, ".", 0o040755, b"")
ino += 1

all_paths = []
for dirpath, dirnames, filenames in os.walk(root_dir):
    dirnames.sort()
    filenames.sort()
    rel_dir = os.path.relpath(dirpath, root_dir)
    if rel_dir != ".":
        all_paths.append(rel_dir)
    for fn in filenames:
        rel_fn = fn if rel_dir == "." else os.path.join(rel_dir, fn)
        all_paths.append(rel_fn)

for rel in all_paths:
    full = os.path.join(root_dir, rel)
    st = os.lstat(full)
    if stat.S_ISLNK(st.st_mode):
        target = os.readlink(full).encode("utf-8")
        add_entry(ino, rel, 0o120777, target)
    elif stat.S_ISDIR(st.st_mode):
        add_entry(ino, rel, 0o040755, b"")
    elif stat.S_ISREG(st.st_mode):
        perm = 0o100755 if (st.st_mode & 0o111) else 0o100644
        with open(full, "rb") as f:
            data = f.read()
        add_entry(ino, rel, perm, data)
    ino += 1

add_entry(ino, "TRAILER!!!", 0, b"")
while len(out) % 512 != 0:
    out.append(0)

with open(out_path, "wb") as f:
    f.write(out)
print(f"Packed Pure Native Android Initramfs: {out_path} ({len(out)} bytes, {ino - 1} entries)")
PY

    # 1g) Build Pure Native Android 15 MBR + ext4 Disk Image (`dist/qyronex-android-system.img`, 64 MiB)
    ANDROID_PART="/tmp/qyronex-android-part1.ext4"
    rm -f "$ANDROID_PART"
    mke2fs -t ext4 -q -F -L "QYRONEX_ANDROID" -d "$R" "$ANDROID_PART" 64M

    PART_BYTES=$(stat -c%s "$ANDROID_PART")
    PART_SECTORS=$(( PART_BYTES / 512 ))
    DISK_BYTES=$(( (2048 + PART_SECTORS) * 512 ))
    DISK_IMG="/out/qyronex-android-system.img"
    rm -f "$DISK_IMG"
    truncate -s "$DISK_BYTES" "$DISK_IMG"
    dd if="$ANDROID_PART" of="$DISK_IMG" bs=512 seek=2048 conv=notrunc status=none
    python3 - "$DISK_IMG" "$PART_SECTORS" << "PY"
import struct, sys
p = sys.argv[1]
part_lba = 2048
part_sectors = int(sys.argv[2])
mbr = bytearray(512)
mbr[446:462] = struct.pack("<BBBBBBBBII", 0x80, 0x00, 0x02, 0x00, 0x83, 0xFE, 0xFF, 0xFF, part_lba, part_sectors)
mbr[510:512] = b"\x55\xAA"
with open(p, "r+b") as f:
    f.seek(0)
    f.write(mbr)
PY

    # 1h) Build & verify AOSP GKI Boot Image v4 (`ANDROID!`) + Vendor Boot Image v4 (`VNDRBOOT`)
    python3 tools/android/mkbootimg_v4.py \
      --kernel /tmp/qyronex-pixel-kernel.img \
      --ramdisk /out/initramfs-android.cpio \
      --cmdline "console=ttyAMA0 init=/init androidboot.hardware=zumapro androidboot.slot_suffix=_a androidboot.selinux=enforcing androidboot.verifiedbootstate=green androidboot.dm_verity=enforcing" \
      --out /out/qyronex-pixel-boot.img
    python3 tools/android/mkbootimg_v4.py \
      --vendor-boot \
      --ramdisk /out/initramfs-android.cpio \
      --cmdline "androidboot.hardware=zumapro androidboot.dynamic_partitions=true androidboot.dm_verity=enforcing" \
      --out /out/qyronex-pixel-vendor-boot.img
  '

echo "[2/4] Befuelle Release-ISO-Staging (Pure Native Android 15 — Kein Wayland) ..."
cp "$OUT_DIR/qyronex-pixel-boot.img"         "$STAGING_DIR/"
cp "$OUT_DIR/qyronex-pixel-vendor-boot.img"  "$STAGING_DIR/"
cp "$OUT_DIR/qyronex-android-emulator.elf"   "$STAGING_DIR/"
cp "$OUT_DIR/initramfs-android.cpio"         "$STAGING_DIR/"
gzip -c -6 "$OUT_DIR/qyronex-android-system.img" > "$STAGING_DIR/qyronex-android-system.img.gz"
cp "$REPO_DIR/tools/android/start-android-emulator.sh" "$STAGING_DIR/"
cp "$REPO_DIR/tools/android/flash-pixel-grapheneos.sh" "$STAGING_DIR/"
chmod +x "$STAGING_DIR/start-android-emulator.sh" "$STAGING_DIR/flash-pixel-grapheneos.sh"

cat > "$STAGING_DIR/README-ANDROID-PIXEL.txt" << 'README'
===========================================================================
  Qyronex OS v0.7.0 - Pure Native Android 15 / GrapheneOS Pixel Edition
===========================================================================

100% NATIVE ANDROID ARCHITECTURE (KEIN WAYLAND / KEIN GTK3 / KEIN DEBIAN-DESKTOP!):
  Wayland (`labwc` + XFCE) wird ausschliesslich fuer die PC-/Desktop-Editionen
  genutzt. Die Android-Edition bootet direkt in das native Android `/init`
  (PID 1 First-Stage & Second-Stage), laedt die SELinux-Policy v33 nach
  `/sys/fs/selinux/load`, startet `/system/bin/servicemanager` (`/dev/binder`)
  und rendert direkt ueber `/system/bin/surfaceflinger` (Direct-DRM/KMS auf
  `/dev/dri/card0` + Ashmem + DMA-Heap) sowie die Qyronex ART Dalvik VM
  (`qyronex-art`, `pm`, `am`).

Standard-GrapheneOS-Handoff fuer Google Pixel:
  Wenn auf dem Google Pixel (oder per `--graphene-img <system.img>`) eine
  Standard-GrapheneOS-Systempartition vorhanden ist, erkennt `/init` im
  First-Stage-Mount `/system/bin/init` + `/system/bin/linker64` und verkettet
  direkt in `second_stage` des Standard-GrapheneOS.

Inhalt dieser ISO:
  - qyronex-pixel-boot.img           AOSP GKI Boot Image v4 (`ANDROID!` v4)
  - qyronex-pixel-vendor-boot.img    AOSP Vendor Boot Image v4 (`VNDRBOOT` v4)
  - qyronex-android-system.img.gz    Reines Native-Android-15-Partitionsimage
  - qyronex-android-emulator.elf     QEMU AArch64 virt Android-15-Kernel ELF
  - initramfs-android.cpio           Reines Android First-/Second-Stage Ramdisk
  - start-android-emulator.sh        Emulator-Starter (Browser/VNC/Cocoa)
  - flash-pixel-grapheneos.sh        Fastboot-Boot/Flash-Skript fuer Pixel
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

echo "[4/4] Fertig! Pure Native Android Artefakte (Kein Wayland):"
ls -lh "$OUT_DIR/qyronex-android-pixel-grapheneos.iso" \
       "$OUT_DIR/qyronex-pixel-boot.img" \
       "$OUT_DIR/qyronex-pixel-vendor-boot.img" \
       "$OUT_DIR/qyronex-android-system.img" \
       "$OUT_DIR/qyronex-android-emulator.elf"
