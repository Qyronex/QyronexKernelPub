#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
"""Build an unmodified pinned Debian 13 (trixie) arm64 dynamic initramfs for Kernal."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import struct
import tempfile
import urllib.request
from pathlib import Path

MAX_INITRAMFS_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_BYTES = 8 * 1024 * 1024
STEP28_BUILDER = Path("tools/step28/build-busybox-initramfs.py")
DEFAULT_MANIFEST = Path("tests/step31/debian13-userspace-arm64.json")
DEFAULT_OUTPUT = Path("target/step31/debian13-initramfs.cpio")
CPIO_TRAILER = "TRAILER!!!"
EM_AARCH64 = 183


def fail(message: str) -> "NoReturn":
    raise RuntimeError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_step28_helpers(root: Path):
    path = root / STEP28_BUILDER
    if not path.is_file():
        fail(f"Step-28 helper module missing: {path}")
    spec = importlib.util.spec_from_file_location("kernal_step28_builder", path)
    if spec is None or spec.loader is None:
        fail(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fetch_verified_package(cache_dir: Path, pkg: dict[str, object]) -> bytes:
    artifact = str(pkg["artifact"])
    expected_size = int(pkg["size_bytes"])
    expected_sha = str(pkg["sha256"])
    url = str(pkg["immutable_url"])
    if not url.startswith("https://snapshot.debian.org/archive/debian/20260712T000000Z/"):
        fail(f"URL must point to pinned 20260712T000000Z snapshot: {url}")

    def verify(raw: bytes) -> None:
        if len(raw) != expected_size:
            fail(f"{artifact}: size mismatch ({len(raw)} != {expected_size})")
        digest = sha256_bytes(raw)
        if digest != expected_sha:
            fail(f"{artifact}: sha256 mismatch ({digest} != {expected_sha})")

    cache_dir.mkdir(parents=True, exist_ok=True)
    cached = cache_dir / artifact
    if cached.is_file():
        data = cached.read_bytes()
        verify(data)
        return data

    req = urllib.request.Request(url, headers={"User-Agent": "kernal-step31/1"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read(MAX_PACKAGE_BYTES + 1)
    if len(data) > MAX_PACKAGE_BYTES:
        fail(f"{artifact}: exceeds package bound")
    verify(data)

    with tempfile.NamedTemporaryFile(dir=cache_dir, delete=False) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)
    tmp_path.replace(cached)
    return data


def validate_aarch64_elf(data: bytes, name: str) -> None:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        fail(f"{name}: not an ELF binary")
    if data[4] != 2 or data[5] != 1 or data[6] != 1:
        fail(f"{name}: must be ELF64 little-endian v1")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != EM_AARCH64:
        fail(f"{name}: unexpected machine {machine}, expected {EM_AARCH64}")


def build_smoke_script() -> bytes:
    return (
        b"#!/bin/dash\n"
        b"echo KERNAL/DEBIAN13: dash pid=$$ booted\n"
        b"/bin/busybox cat /etc/os-release\n"
        b"UNAME_OUT=$(/bin/busybox uname -s -m)\n"
        b"echo KERNAL/DEBIAN13: uname=$UNAME_OUT\n"
        b"PIPE_OUT=$(echo hello-debian13-pipe | /bin/busybox cat)\n"
        b"echo KERNAL/DEBIAN13: pipe=$PIPE_OUT\n"
        b"EXE_OUT=$(/bin/busybox readlink /proc/self/exe)\n"
        b"echo KERNAL/DEBIAN13: exe=$EXE_OUT\n"
        b"/bin/busybox ls /proc /sys /sys/.. /proc/self/fd/..\n"
        b"/bin/busybox ps\n"
        b"/bin/busybox sleep 0.05\n"
        b"echo KERNAL/DEBIAN13: sleep_ok=$?\n"
        b"mkdir -p /tmp/d13 && echo ok > /tmp/d13/file && /bin/busybox cat /tmp/d13/file\n"
        b"ls /bin\n"
        b"echo KERNAL/DEBIAN13: SMOKE PASS\n"
    )


def build_initramfs(manifest: dict[str, object], cache_dir: Path, helpers, mode: str) -> bytes:
    pkgs = manifest["packages"]
    libc6_deb = fetch_verified_package(cache_dir, pkgs["libc6"])
    dash_deb = fetch_verified_package(cache_dir, pkgs["dash"])
    busybox_deb = fetch_verified_package(cache_dir, pkgs["busybox"])

    ld_so = helpers.extract_member(libc6_deb, "usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1")
    libc_so = helpers.extract_member(libc6_deb, "usr/lib/aarch64-linux-gnu/libc.so.6")
    libresolv_so = helpers.extract_member(libc6_deb, "usr/lib/aarch64-linux-gnu/libresolv.so.2")
    dash_bin = helpers.extract_member(dash_deb, "usr/bin/dash")
    busybox_bin = helpers.extract_member(busybox_deb, "usr/bin/busybox")

    for name, payload in [
        ("ld-linux-aarch64.so.1", ld_so),
        ("libc.so.6", libc_so),
        ("libresolv.so.2", libresolv_so),
        ("dash", dash_bin),
        ("busybox", busybox_bin),
    ]:
        validate_aarch64_elf(payload, name)

    dirs = [
        "bin",
        "dev",
        "dev/pts",
        "etc",
        "lib",
        "lib/aarch64-linux-gnu",
        "proc",
        "root",
        "run",
        "sys",
        "tmp",
        "usr",
        "usr/bin",
        "usr/lib",
        "usr/lib/aarch64-linux-gnu",
        "var",
        "var/tmp",
    ]

    files: list[tuple[str, int, bytes]] = [
        ("bin/dash", 0o100755, dash_bin),
        ("bin/sh", 0o100755, dash_bin),
        ("usr/bin/dash", 0o100755, dash_bin),
        ("bin/busybox", 0o100755, busybox_bin),
        ("usr/bin/busybox", 0o100755, busybox_bin),
        ("bin/ls", 0o100755, busybox_bin),
        ("bin/cat", 0o100755, busybox_bin),
        ("bin/uname", 0o100755, busybox_bin),
        ("bin/echo", 0o100755, busybox_bin),
        ("bin/mkdir", 0o100755, busybox_bin),
        ("bin/ps", 0o100755, busybox_bin),
        ("bin/id", 0o100755, busybox_bin),
        ("bin/sleep", 0o100755, busybox_bin),
        ("bin/readlink", 0o100755, busybox_bin),
        ("bin/kill", 0o100755, busybox_bin),
        ("bin/grep", 0o100755, busybox_bin),
        ("bin/true", 0o100755, busybox_bin),
        ("lib/ld-linux-aarch64.so.1", 0o100755, ld_so),
        ("usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1", 0o100755, ld_so),
        ("lib/aarch64-linux-gnu/libc.so.6", 0o100755, libc_so),
        ("lib/aarch64-linux-gnu/libresolv.so.2", 0o100755, libresolv_so),
        (
            "etc/os-release",
            0o100644,
            b'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n'
            b'NAME="Debian GNU/Linux"\n'
            b'VERSION_ID="13"\n'
            b'VERSION="13 (trixie)"\n'
            b'ID=debian\n',
        ),
        ("etc/hostname", 0o100644, b"kernal-debian13\n"),
        ("etc/passwd", 0o100644, b"root:x:0:0:root:/root:/bin/dash\n"),
        ("etc/group", 0o100644, b"root:x:0:\n"),
    ]
    if mode == "smoke":
        files.append(("etc/kernal-init", 0o100755, build_smoke_script()))

    output = bytearray()
    ino = 1
    helpers.newc_entry(output, ino, ".", 0o040755, b"")
    ino += 1
    for d in dirs:
        helpers.newc_entry(output, ino, d, 0o040755, b"")
        ino += 1
    for path, fmode, data in files:
        helpers.newc_entry(output, ino, path, fmode, data)
        ino += 1
    helpers.newc_entry(output, ino, CPIO_TRAILER, 0, b"")
    while len(output) % 512:
        output.append(0)

    if len(output) > MAX_INITRAMFS_BYTES:
        fail(f"initramfs size {len(output)} exceeds {MAX_INITRAMFS_BYTES}")
    return bytes(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--cache",
        type=Path,
        default=Path(os.environ.get("KERNAL_DEBIAN13_CACHE", "~/.cache/kernal/debian13")).expanduser(),
    )
    parser.add_argument("--mode", choices=("smoke", "shell"), default="smoke")
    args = parser.parse_args()

    root = Path.cwd()
    helpers = load_step28_helpers(root)
    manifest = json.loads((root / args.manifest).read_text(encoding="utf-8"))
    archive = build_initramfs(manifest, args.cache, helpers, args.mode)

    out_path = root / args.output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(archive)
    print(
        f"built {out_path} ({len(archive)} bytes, mode={args.mode}, sha256={sha256_bytes(archive)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
