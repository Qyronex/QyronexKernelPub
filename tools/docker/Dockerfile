# SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    KERNAL_TOOLCHAIN_CACHE=/opt/kernal/toolchains \
    KERNAL_AARCH64_MUSL_CC=/usr/local/bin/aarch64-linux-musl-gcc \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    ca-certificates \
    curl \
    dosfstools \
    git \
    mtools \
    ovmf \
    pkg-config \
    python3 \
    qemu-efi-aarch64 \
    qemu-system-arm \
    qemu-system-x86 \
    qemu-utils \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

COPY rust-toolchain.toml /opt/kernal/rust-toolchain.toml
COPY tools/bootstrap-step15-zig.sh /opt/kernal/tools/bootstrap-step15-zig.sh

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --profile minimal --default-toolchain 1.98.0 \
    && rustup component add --toolchain 1.98.0 rust-src rustfmt clippy llvm-tools-preview \
    && rustup target add --toolchain 1.98.0 \
        aarch64-unknown-none-softfloat \
        x86_64-unknown-none \
        x86_64-unknown-uefi \
    && chmod -R a+rX /usr/local/rustup /usr/local/cargo

RUN bash /opt/kernal/tools/bootstrap-step15-zig.sh >/opt/kernal/zig-path.txt \
    && ZIG_BIN="$(cat /opt/kernal/zig-path.txt)" \
    && printf '#!/bin/bash\nset -eu\nif [ "${1:-}" = "-dumpmachine" ]; then\n  printf "%%s\\n" "aarch64-linux-musl"\n  exit 0\nfi\nexec "%s" cc -target aarch64-linux-musl "$@"\n' "$ZIG_BIN" > /usr/local/bin/aarch64-linux-musl-gcc \
    && chmod 0755 /usr/local/bin/aarch64-linux-musl-gcc \
    && /usr/local/bin/aarch64-linux-musl-gcc -dumpmachine \
    && printf 'export PATH="/usr/local/cargo/bin:%s"\nexport RUSTUP_HOME=/usr/local/rustup\nexport CARGO_HOME=/usr/local/cargo\nexport KERNAL_AARCH64_MUSL_CC=/usr/local/bin/aarch64-linux-musl-gcc\nexport KERNAL_TOOLCHAIN_CACHE=/opt/kernal/toolchains\n' "$PATH" > /etc/profile.d/kernal-env.sh \
    && git config --system --add safe.directory /workspace

WORKDIR /workspace
