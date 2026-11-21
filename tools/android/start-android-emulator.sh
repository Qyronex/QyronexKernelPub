#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
# Launch the Qyronex OS Android 15 / GrapheneOS Pixel Emulator (QEMU AArch64 + VirtIO-GPU).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="${DIST_DIR:-$REPO_DIR/dist}"

MODE="vnc"
SMP="1"
MEM="1G"
SOC="zumapro"
OPEN_UI="auto"
BUILD_FIRST=0
VNC_PORT="${VNC_PORT:-5902}"
WEB_PORT="${WEB_PORT:-6082}"
WS_PORT="${WS_PORT:-6083}"
HTTP_PID=""

cleanup() {
  if [ -n "$HTTP_PID" ] && kill -0 "$HTTP_PID" 2>/dev/null; then
    kill "$HTTP_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
Verwendung: start-android-emulator.sh [Optionen]
  --vnc             Grafische GrapheneOS / Android-15-UI im Browser & VNC (Standard)
  --cocoa           Natives macOS QEMU-Cocoa-Fenster (benoetigt lokales qemu-system-aarch64)
  --headless        Nur serielle Android-Konsole (-display none)
  --open            Browser-Viewer automatisch oeffnen (Standard bei --vnc)
  --no-open         Browser nicht automatisch oeffnen
  --soc NAME        Pixel-Tensor-Profil: gs101 | gs201 | zuma | zumapro | virt (Standard: zumapro)
  --smp N           vCPU-Anzahl (Standard: 1)
  --build           Android-Kernel & System-Image vor dem Start neu bauen
  -h, --help        Diese Hilfe anzeigen
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --vnc) MODE="vnc"; shift ;;
    --cocoa) MODE="cocoa"; OPEN_UI="0"; shift ;;
    --headless) MODE="headless"; OPEN_UI="0"; shift ;;
    --open) MODE="vnc"; OPEN_UI="1"; shift ;;
    --no-open) OPEN_UI="0"; shift ;;
    --soc) SOC="${2:?Fehlender SoC-Name}"; shift 2 ;;
    --smp) SMP="${2:?Fehlende vCPU-Anzahl}"; shift 2 ;;
    --build) BUILD_FIRST=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unbekannte Option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$OPEN_UI" = "auto" ]; then
  if [ "$MODE" = "vnc" ]; then OPEN_UI="1"; else OPEN_UI="0"; fi
fi

KERNEL_ELF="$DIST_DIR/qyronex-android-emulator.elf"
INITRD="$DIST_DIR/initramfs-android.cpio"
SYSTEM_IMG="$DIST_DIR/qyronex-android-system.img"

if [ "$BUILD_FIRST" = "1" ] || [ ! -f "$KERNEL_ELF" ] || [ ! -f "$SYSTEM_IMG" ] || [ ! -f "$INITRD" ]; then
  if [ -x "$REPO_DIR/tools/build-android-iso.sh" ]; then
    echo "Baue Qyronex Android 15 / GrapheneOS Emulator-Artefakte ..."
    "$REPO_DIR/tools/build-android-iso.sh"
  else
    echo "Fehler: Android-Emulator-Artefakte fehlen in $DIST_DIR." >&2
    exit 1
  fi
fi

APPEND_LINE="console=ttyAMA0 root=/dev/vda1 rw init=/system/bin/android-init androidboot.hardware=${SOC} androidboot.selinux=enforcing androidboot.verifiedbootstate=green"

echo "==================================================================="
echo "  Qyronex OS - Android 15 / GrapheneOS Pixel Emulator"
echo "  Kernel : $KERNEL_ELF"
echo "  System : $SYSTEM_IMG"
echo "  Profil : Google Pixel ($SOC) | SELinux: enforcing | Binder v8"
echo "  Modus  : $MODE (SMP=$SMP, RAM=$MEM)"
echo "==================================================================="

if [ "$MODE" = "cocoa" ]; then
  if ! command -v qemu-system-aarch64 >/dev/null 2>&1; then
    echo "Fehler: lokales qemu-system-aarch64 nicht installiert. Nutze --vnc." >&2
    exit 1
  fi
  exec qemu-system-aarch64 \
    -machine virt,gic-version=3 -cpu max -smp "$SMP" -m "$MEM" \
    -kernel "$KERNEL_ELF" \
    -device "guest-loader,addr=0x48000000,initrd=$INITRD" \
    -append "$APPEND_LINE" \
    -drive "file=$SYSTEM_IMG,format=raw,if=none,id=hd0" \
    -device virtio-blk-device,drive=hd0 \
    -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
    -device virtio-gpu-device \
    -device virtio-keyboard-device \
    -device virtio-tablet-device \
    -display cocoa -serial mon:stdio
fi

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "Fehler: Docker laeuft nicht. Bitte Docker Desktop starten." >&2
  exit 1
fi

DOCKER_PORTS=()
QEMU_DISPLAY_ARGS=(-display none)
VNC_PASS="${VNC_PASS:-qyronex}"
if [ "$MODE" = "vnc" ]; then
  VNC_DISPLAY=$((VNC_PORT - 5900))
  WS_DISPLAY=$((VNC_DISPLAY + 1))
  DOCKER_PORTS=(-p "127.0.0.1:${VNC_PORT}:${VNC_PORT}" -p "127.0.0.1:${WS_PORT}:${WS_PORT}")
  QEMU_DISPLAY_ARGS=(
    -object "secret,id=vncsec,data=${VNC_PASS}"
    -vnc ":${VNC_DISPLAY},password-secret=vncsec"
    -vnc ":${WS_DISPLAY},websocket=${WS_PORT}"
    -display none
  )

  WEB_HTML="$REPO_DIR/tools/debian13/web_vnc.html"
  if [ -f "$WEB_HTML" ]; then
    python3 -m http.server "$WEB_PORT" --bind 127.0.0.1 --directory "$REPO_DIR/tools/debian13" >/dev/null 2>&1 &
    HTTP_PID=$!
    echo "  Browser-Viewer : http://127.0.0.1:${WEB_PORT}/web_vnc.html?ws=${WS_PORT}"
    echo "  VNC direkt     : vnc://:${VNC_PASS}@127.0.0.1:${VNC_PORT} (Passwort: ${VNC_PASS})"
    if [ "$OPEN_UI" = "1" ] && command -v open >/dev/null 2>&1; then
      (sleep 2 && open "http://127.0.0.1:${WEB_PORT}/web_vnc.html?ws=${WS_PORT}") >/dev/null 2>&1 &
    fi
  fi
fi

TTY_FLAGS=(-i)
if [ -t 0 ] && [ -t 1 ]; then
  TTY_FLAGS=(-it)
fi

docker run --rm "${TTY_FLAGS[@]}" \
  ${DOCKER_PORTS[@]+"${DOCKER_PORTS[@]}"} \
  -v "$DIST_DIR:/dist" \
  kernal-dev:bookworm-arm64 \
  qemu-system-aarch64 \
    -machine virt,gic-version=3 -cpu max -smp "$SMP" -m "$MEM" \
    -kernel /dist/qyronex-android-emulator.elf \
    -device guest-loader,addr=0x48000000,initrd=/dist/initramfs-android.cpio \
    -append "$APPEND_LINE" \
    -drive file=/dist/qyronex-android-system.img,format=raw,if=none,id=hd0 \
    -device virtio-blk-device,drive=hd0 \
    -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
    -device virtio-gpu-device \
    -device virtio-keyboard-device \
    -device virtio-tablet-device \
    "${QEMU_DISPLAY_ARGS[@]}" \
    -no-reboot \
    -serial mon:stdio
