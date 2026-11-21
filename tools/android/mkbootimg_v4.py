#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
"""Build and verify AOSP GKI Boot Image v4 (`ANDROID!`) for Google Pixel / GrapheneOS."""

import argparse
import struct
import sys
from pathlib import Path

BOOT_MAGIC = b"ANDROID!"
PAGE_SIZE = 4096
BOOT_HEADER_VERSION_4 = 4
BOOT_HEADER_SIZE_V4 = 1580


def pack_os_version(major: int, minor: int, patch: int, year: int, month: int) -> int:
    ver = ((major & 0x7F) << 14) | ((minor & 0x7F) << 7) | (patch & 0x7F)
    pl = (((year - 2000) & 0x7F) << 4) | (month & 0x0F)
    return (ver << 11) | pl


def align_page(data: bytes) -> bytes:
    rem = len(data) % PAGE_SIZE
    if rem == 0:
        return data
    return data + b"\x00" * (PAGE_SIZE - rem)


def build_boot_img_v4(kernel_path: Path, ramdisk_path: Path, cmdline: str, out_path: Path) -> None:
    kernel = kernel_path.read_bytes()
    ramdisk = ramdisk_path.read_bytes()
    os_ver = pack_os_version(15, 0, 0, 2026, 11)

    cmd_bytes = cmdline.encode("utf-8")[:1535]
    cmd_padded = cmd_bytes + b"\x00" * (1536 - len(cmd_bytes))

    # Exact AOSP `boot_img_hdr_v4` binary layout (1580 bytes inside page 0):
    #   0..8:     magic ("ANDROID!")
    #   8..12:    kernel_size
    #   12..16:   ramdisk_size
    #   16..20:   os_version
    #   20..24:   header_size (1580)
    #   24..40:   reserved[4]
    #   40..44:   header_version (4)
    #   44..1580: cmdline[1536]
    #   1580..1584: signature_size (0)
    header = struct.pack(
        "<8sIIII4II",
        BOOT_MAGIC,
        len(kernel),
        len(ramdisk),
        os_ver,
        BOOT_HEADER_SIZE_V4,
        0,
        0,
        0,
        0,
        BOOT_HEADER_VERSION_4,
    ) + cmd_padded + struct.pack("<I", 0)
    assert len(header) == 1584, f"unexpected header size {len(header)}"

    image = align_page(header) + align_page(kernel) + align_page(ramdisk)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(image)
    print(
        f"Built Android Boot Image v4: {out_path} ({len(image)} bytes, "
        f"kernel={len(kernel)} B, ramdisk={len(ramdisk)} B, os=Android 15 / 2026-11)"
    )


def verify_boot_img_v4(img_path: Path) -> None:
    data = img_path.read_bytes()
    if len(data) < PAGE_SIZE or data[:8] != BOOT_MAGIC:
        sys.exit(f"ERROR: {img_path} missing ANDROID! magic")
    ksize, rsize, os_ver, hdr_size = struct.unpack_from("<IIII", data, 8)
    hdr_ver = struct.unpack_from("<I", data, 40)[0]
    if hdr_ver != BOOT_HEADER_VERSION_4 or hdr_size != BOOT_HEADER_SIZE_V4:
        sys.exit(f"ERROR: expected v4 header (1580), got v{hdr_ver} ({hdr_size})")
    expected_len = PAGE_SIZE + ((ksize + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE + (
        (rsize + PAGE_SIZE - 1) // PAGE_SIZE
    ) * PAGE_SIZE
    if len(data) < expected_len:
        sys.exit(f"ERROR: truncated boot image ({len(data)} < {expected_len})")
    cmdline = data[44:1580].split(b"\x00", 1)[0].decode("utf-8", "replace")
    arm64_magic = data[PAGE_SIZE + 56 : PAGE_SIZE + 60]
    print(
        f"VERIFIED Boot Image v4: magic=ANDROID! v{hdr_ver} hdr={hdr_size}B "
        f"kernel={ksize}B ramdisk={rsize}B arm64_hdr={arm64_magic!r} os_ver=0x{os_ver:08x}"
    )
    print(f"  cmdline: {cmdline}")


def main() -> None:
    p = argparse.ArgumentParser(description="Build/verify AOSP Boot Image v4 for Qyronex Pixel")
    p.add_argument("--kernel", type=Path)
    p.add_argument("--ramdisk", type=Path)
    p.add_argument(
        "--cmdline",
        default="console=ttyAMA0 androidboot.hardware=zumapro androidboot.selinux=enforcing androidboot.verifiedbootstate=green",
    )
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--verify-only", action="store_true")
    args = p.parse_args()
    if args.verify_only:
        verify_boot_img_v4(args.out)
        return
    if not args.kernel or not args.ramdisk:
        sys.exit("ERROR: --kernel and --ramdisk are required when building")
    build_boot_img_v4(args.kernel, args.ramdisk, args.cmdline, args.out)
    verify_boot_img_v4(args.out)


if __name__ == "__main__":
    main()
