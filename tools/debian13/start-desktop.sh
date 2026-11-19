#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
SMP="1"
MODE="vnc"
IMAGE_KIND="desktop"
MEM="2G"
OPEN_UI="auto"
BUILD_KERNEL=0
VNC_PORT="${VNC_PORT:-5900}"
WEB_PORT="${WEB_PORT:-6080}"
WS_PORT="${WS_PORT:-6081}"
VNC_PASS="${VNC_PASS:-qyronex}"
HTTP_PID=""

cleanup() {
  if [ -n "$HTTP_PID" ] && kill -0 "$HTTP_PID" 2>/dev/null; then
    kill "$HTTP_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
Verwendung: qyronex [SMP] [Optionen]
  SMP               Anzahl vCPUs (1, 2, 4 oder 8; Standard: 1)
  --smp N           Anzahl vCPUs festlegen
  --open            Browser-Viewer nach dem Start automatisch oeffnen (Standard bei --vnc)
  --no-open         Browser nicht automatisch oeffnen
  --vnc             Grafischer Desktop via Web-Viewer & VNC (Standard)
  --cocoa           Natives macOS QEMU-Cocoa-Fenster nutzen (benoetigt lokales `qemu`)
  --headless        Nur serielle Konsole (-display none)
  --build           AArch64-Kernel vor dem Start neu kompilieren
  --etappe5         Aelteres Etappe-5-Weston-Desktop-Image statt XFCE-Desktop booten
  --etappe4         Debian-13-systemd-CLI-Image (Etappe 4) booten
  -h, --help        Diese Hilfe anzeigen
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    1|2|4|8)
      SMP="$1"
      shift
      ;;
    --smp)
      SMP="${2:?Fehlender Wert fuer --smp}"
      shift 2
      ;;
    --vnc)
      MODE="vnc"
      shift
      ;;
    --open)
      MODE="vnc"
      OPEN_UI="1"
      shift
      ;;
    --no-open)
      OPEN_UI="0"
      shift
      ;;
    --cocoa)
      MODE="cocoa"
      OPEN_UI="0"
      shift
      ;;
    --headless)
      MODE="headless"
      OPEN_UI="0"
      shift
      ;;
    --build)
      BUILD_KERNEL=1
      shift
      ;;
    --etappe5)
      IMAGE_KIND="etappe5"
      MEM="512M"
      shift
      ;;
    --etappe4)
      IMAGE_KIND="etappe4"
      MEM="512M"
      MODE="headless"
      OPEN_UI="0"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unbekannte Option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ "$OPEN_UI" = "auto" ]; then
  if [ "$MODE" = "vnc" ]; then
    OPEN_UI="1"
  else
    OPEN_UI="0"
  fi
fi

if [ "$IMAGE_KIND" = "etappe4" ]; then
  DISK_IN_CONTAINER="/root/.cache/kernal/debian13/etappe4/etappe4-disk.img"
  APPEND_LINE="console=ttyAMA0 root=/dev/vda1 rw init=/sbin/init systemd.unit=multi-user.target"
elif [ "$IMAGE_KIND" = "etappe5" ]; then
  DISK_IN_CONTAINER="/root/.cache/kernal/debian13/etappe5/etappe5-disk.img"
  APPEND_LINE="console=ttyAMA0 root=/dev/vda1 rw init=/sbin/init udev.children_max=2 systemd.unit=multi-user.target"
else
  DISK_IN_CONTAINER="/root/.cache/kernal/debian13/etappe6-desktop/desktop-disk.img"
  APPEND_LINE="console=ttyAMA0 root=/dev/vda1 rw init=/sbin/init udev.children_max=2 systemd.unit=multi-user.target"
fi

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "Docker laeuft nicht. Bitte zuerst Docker Desktop starten." >&2
  exit 1
fi

set +e
docker run --rm \
  -v kernal-docker-target:/mnt/target:ro \
  -v kernal-docker-cache:/root/.cache/kernal:ro \
  -e CHECK_DISK="$DISK_IN_CONTAINER" \
  kernal-dev:bookworm-arm64 \
  bash -c '
    [ -f "$CHECK_DISK" ] || exit 42
    [ -f /mnt/target/aarch64-unknown-none-softfloat/debug/kernal-core-aarch64 ] && [ -f /mnt/target/step31/debian13-shell-initramfs.cpio ] || exit 43
  '
CHECK_RC=$?
set -e

if [ "$CHECK_RC" = "42" ]; then
  echo "Fehlendes Disk-Image im Volume kernal-docker-cache: ${DISK_IN_CONTAINER}" >&2
  exit 1
elif [ "$CHECK_RC" = "43" ]; then
  BUILD_KERNEL=1
elif [ "$CHECK_RC" != "0" ]; then
  echo "Fehler beim Pruefen der Docker-Volumes (Exit-Code $CHECK_RC)." >&2
  exit "$CHECK_RC"
fi

if [ "$BUILD_KERNEL" = "1" ]; then
  echo "Baue AArch64-Debian-Kernel (step31-debian-shell) ..."
  docker run --rm \
    -v "$REPO_DIR:/workspace" \
    -v kernal-docker-target:/workspace/target \
    -v kernal-docker-cargo-registry:/usr/local/cargo/registry \
    -w /workspace \
    kernal-dev:bookworm-arm64 \
    cargo build -p kernal-core-aarch64 --target aarch64-unknown-none-softfloat --features step31-debian-shell
fi

if [ "$MODE" = "cocoa" ]; then
  if ! command -v qemu-system-aarch64 >/dev/null 2>&1; then
    echo "qemu-system-aarch64 ist nicht lokal auf macOS installiert (z. B. per 'brew install qemu')." >&2
    echo "Starte stattdessen ohne --cocoa im Standard-Browser/VNC-Modus." >&2
    exit 1
  fi
  HOST_EXPORT="/tmp/qyronex-debian13-cocoa"
  COCOA_DISK="$HOST_EXPORT/disk-${IMAGE_KIND}.img"
  mkdir -p "$HOST_EXPORT"
  echo "Synchronisiere Kernel, Initramfs und Disk-Image aus den Docker-Volumes nach $HOST_EXPORT ..."
  docker run --rm \
    -v kernal-docker-target:/mnt/target:ro \
    -v kernal-docker-cache:/root/.cache/kernal:ro \
    -v "$HOST_EXPORT:/out" \
    -e SRC_DISK="$DISK_IN_CONTAINER" \
    -e SRC_NAME="disk-${IMAGE_KIND}.img" \
    kernal-dev:bookworm-arm64 \
    bash -c 'set -euo pipefail
      cp /mnt/target/aarch64-unknown-none-softfloat/debug/kernal-core-aarch64 /out/kernal-core-aarch64
      cp /mnt/target/step31/debian13-shell-initramfs.cpio /out/debian13-shell-initramfs.cpio
      [ -f "/out/$SRC_NAME" ] || cp "$SRC_DISK" "/out/$SRC_NAME"'
  EXTRA_DEV=()
  if [ "$IMAGE_KIND" != "etappe4" ]; then
    EXTRA_DEV=(
      -device virtio-gpu-device
      -device virtio-keyboard-device
      -device virtio-tablet-device
    )
  fi
  if [ "$IMAGE_KIND" = "etappe5" ]; then
    echo "Login: 'root' (ohne Passwort), danach im Serial/Terminal fuer Weston: /usr/local/bin/start-weston-desktop.sh"
  else
    echo "Desktop (labwc + XFCE 4.20) startet automatisch ueber qyronex-desktop.service; Serial-Login: 'root' (ohne Passwort)"
  fi
  exec qemu-system-aarch64 \
    -machine virt,gic-version=3 \
    -cpu max \
    -m "$MEM" \
    -smp "$SMP" \
    -display cocoa \
    -serial mon:stdio \
    -no-reboot \
    -kernel "$HOST_EXPORT/kernal-core-aarch64" \
    -device "guest-loader,addr=0x48000000,initrd=$HOST_EXPORT/debian13-shell-initramfs.cpio" \
    -drive "if=none,format=raw,file=${COCOA_DISK},id=vd0" \
    -device virtio-blk-device,drive=vd0 \
    -netdev user,id=net0 \
    -device virtio-net-device,netdev=net0 \
    ${EXTRA_DEV[@]+"${EXTRA_DEV[@]}"} \
    -append "$APPEND_LINE"
fi

DOCKER_TTY_FLAGS=(-i)
if [ -t 0 ]; then
  DOCKER_TTY_FLAGS=(-it)
fi

DOCKER_PORTS=()
DISPLAY_ARGS=(-display none)
EXTRA_DEV=()

if [ "$IMAGE_KIND" != "etappe4" ]; then
  EXTRA_DEV=(
    -device virtio-gpu-device
    -device virtio-keyboard-device
    -device virtio-tablet-device
  )
fi

if [ "$MODE" = "vnc" ]; then
  VNC_DISPLAY=$((VNC_PORT - 5900))
  WS_DISPLAY=$((VNC_DISPLAY + 1))
  DOCKER_PORTS=(
    -p "127.0.0.1:${VNC_PORT}:${VNC_PORT}"
    -p "127.0.0.1:${WS_PORT}:${WS_PORT}"
  )
  DISPLAY_ARGS=(
    -object "secret,id=vncsec,data=${VNC_PASS}"
    -vnc ":${VNC_DISPLAY},password-secret=vncsec"
    -vnc ":${WS_DISPLAY},websocket=${WS_PORT}"
  )
  if command -v python3 >/dev/null 2>&1 && [ -f "${SCRIPT_DIR}/web_vnc.html" ]; then
    python3 -m http.server "$WEB_PORT" --bind 127.0.0.1 --directory "$SCRIPT_DIR" >/dev/null 2>&1 &
    HTTP_PID=$!
  fi
  echo "=================================================================="
  if [ "$IMAGE_KIND" = "etappe5" ]; then
    echo " Qyronex OS + Debian 13 (ARM64) Weston Desktop wird gestartet (smp=$SMP, mem=$MEM)"
  else
    echo " Qyronex OS + Debian 13 (ARM64) XFCE Wayland Desktop wird gestartet (smp=$SMP, mem=$MEM)"
  fi
  echo " Browser-Desktop:  http://127.0.0.1:${WEB_PORT}/web_vnc.html?ws=${WS_PORT}"
  echo " VNC-Client/macOS: vnc://:${VNC_PASS}@127.0.0.1:${VNC_PORT} (Passwort: ${VNC_PASS})"
  echo " 1. Login hier:    Benutzer 'root' (kein Passwort)"
  if [ "$IMAGE_KIND" = "etappe5" ]; then
    echo " 2. Desktop start: /usr/local/bin/start-weston-desktop.sh"
  else
    echo " 2. Desktop:       startet automatisch (qyronex-desktop.service)"
  fi
  echo "    Beenden: Strg+A, dann x"
  echo "=================================================================="
  if [ "$OPEN_UI" = "1" ] && command -v open >/dev/null 2>&1; then
    (sleep 2 && open "http://127.0.0.1:${WEB_PORT}/web_vnc.html?ws=${WS_PORT}") >/dev/null 2>&1 &
  fi
fi

docker run "${DOCKER_TTY_FLAGS[@]}" --rm \
  ${DOCKER_PORTS[@]+"${DOCKER_PORTS[@]}"} \
  -v "$REPO_DIR:/workspace" \
  -v kernal-docker-cache:/root/.cache/kernal \
  -v kernal-docker-target:/workspace/target \
  -v kernal-docker-cargo-registry:/usr/local/cargo/registry \
  -w /workspace \
  kernal-dev:bookworm-arm64 \
  qemu-system-aarch64 \
    -machine virt,gic-version=3 \
    -cpu max \
    -m "$MEM" \
    -smp "$SMP" \
    "${DISPLAY_ARGS[@]}" \
    -serial mon:stdio \
    -no-reboot \
    -kernel /workspace/target/aarch64-unknown-none-softfloat/debug/kernal-core-aarch64 \
    -device guest-loader,addr=0x48000000,initrd=/workspace/target/step31/debian13-shell-initramfs.cpio \
    -drive "if=none,format=raw,file=${DISK_IN_CONTAINER},id=vd0" \
    -device virtio-blk-device,drive=vd0 \
    -netdev user,id=net0 \
    -device virtio-net-device,netdev=net0 \
    ${EXTRA_DEV[@]+"${EXTRA_DEV[@]}"} \
    -append "$APPEND_LINE"
