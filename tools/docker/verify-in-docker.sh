#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE="${KERNAL_DOCKER_IMAGE:-kernal-dev:bookworm-arm64}"
MODE="${1:-all}"

usage() {
  cat >&2 <<'EOF'
Usage: tools/docker/verify-in-docker.sh [all|doctor|arm-qemu|verify|test|shell]
  all       Run fmt-check, strict clippy, workspace tests, xtask doctor, arm-build, arm-qemu, and Python oracle/prep checks
  doctor    Run cargo xtask doctor inside the container
  arm-qemu  Build AArch64 kernel/user fixtures and run all QEMU acceptance proofs (Step 29 + Step 30)
  verify    Run full cargo xtask verify (host + x86_64 QEMU + AArch64 QEMU)
  test      Run rustfmt, clippy, and cargo test --workspace
  shell     Open an interactive bash shell inside the container
EOF
  exit 64
}

command -v docker >/dev/null 2>&1 || {
  printf 'docker CLI not found in PATH\n' >&2
  exit 1
}

docker build -t "$IMAGE" -f "$ROOT/tools/docker/Dockerfile" "$ROOT"

run_container() {
  docker run --rm \
    -v "$ROOT:/workspace" \
    -v kernal-docker-target:/workspace/target \
    -v kernal-docker-cargo-registry:/usr/local/cargo/registry \
    -v kernal-docker-cache:/root/.cache/kernal \
    "$IMAGE" \
    bash -c "$1"
}

case "$MODE" in
  doctor)
    run_container "cargo xtask doctor"
    ;;
  arm-qemu)
    run_container "cargo xtask doctor && cargo xtask arm-build && cargo xtask arm-qemu"
    ;;
  verify)
    run_container "cargo xtask verify"
    ;;
  test)
    run_container 'set -euo pipefail
      cargo fmt --all --check
      cargo clippy --workspace --lib --tests -- -D warnings
      cargo clippy -p xtask --bin xtask -- -D warnings
      if [ "$(uname -m)" = "aarch64" ]; then
        echo "Note: excluding kernal-percpu-x86-64 in Linux aarch64 container (48-bit PIE ASLR user addresses >= 0x0000_8000_0000_0000 fail x86_64 is_canonical_48; verify on x86_64 or macOS host)"
        cargo test --workspace --exclude kernal-percpu-x86-64
      else
        cargo test --workspace
      fi'
    ;;
  all)
    run_container 'set -euo pipefail
      cargo xtask doctor
      cargo fmt --all --check
      cargo clippy --workspace --lib --tests -- -D warnings
      cargo clippy -p xtask --bin xtask -- -D warnings
      if [ "$(uname -m)" = "aarch64" ]; then
        echo "Note: excluding kernal-percpu-x86-64 in Linux aarch64 container (48-bit PIE ASLR user addresses >= 0x0000_8000_0000_0000 fail x86_64 is_canonical_48; verify on x86_64 or macOS host)"
        cargo test --workspace --exclude kernal-percpu-x86-64
      else
        cargo test --workspace
      fi
      cargo xtask qemu
      cargo xtask qemu-smp
      cargo xtask arm-build
      cargo xtask arm-qemu
      python3 tools/debian13/oracle.py validate
      python3 -m unittest tests/debian13/test_oracle.py
      python3 tools/prep/step20/validate_virtio_block_contract.py
      python3 tools/prep/step21/validate_virtio_net_contract.py'
    ;;
  shell)
    exec docker run --rm -it \
      -v "$ROOT:/workspace" \
      -v kernal-docker-target:/workspace/target \
      -v kernal-docker-cargo-registry:/usr/local/cargo/registry \
      -v kernal-docker-cache:/root/.cache/kernal \
      "$IMAGE" bash
    ;;
  *)
    usage
    ;;
esac
