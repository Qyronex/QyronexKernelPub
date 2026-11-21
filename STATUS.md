# Qyronex Kernal — Status

Last updated: 2026-11-21 (source head `2129339`). German version: [docs/de/STATUS.md](docs/de/STATUS.md).

> Research kernel. Not production-ready, not a security boundary. Claims below are limited to what the commit history and the observed QEMU/verification runs show; they are not a completed conformance or audit result.

## What Qyronex is

- A **standalone Rust hybrid kernel** (about 163k lines across `kernel/` & `drivers/`), **not Linux and not a Linux fork**.
- Own architecture: capabilities, W^X, null-page and guard-stack invariants, IOMMU/IRQ fail-closed design, own scheduler and memory management.
- Provides the **Linux userspace ABI** (syscalls, VFS, `/proc`, `/sys`, devices, netlink) so unmodified Linux binaries can run. Linux kernel modules (`.ko`) are not supported.
- **Multi-architecture targets:**
  - **AArch64 / ARM64:** QEMU `virt` (GICv3) **and** Raspberry Pi 3B+ (`BCM2837B0`), Raspberry Pi 4B (`BCM2711`), and Raspberry Pi 5 (`BCM2712` + `RP1`) hybrid driver HAL (`drivers/rpi3b-plus`, `firmware/fdt-aarch64`).
  - **x86_64:** UEFI + ACPI + APIC/IOAPIC SMP (1/2/4 vCPUs), Intel (`GenuineIntel`) & AMD (`AuthenticAMD`) CPUID profile/feature drivers (`kernel/arch-x86_64`), PCIe ECAM + x86 legacy port I/O (`0xCF8`/`0xCFC`) (`drivers/pci`).

## Current state (observed)

| Area | State | Notes |
|---|---|---|
| Protected boot, EL0/EL1, PAN, W^X, TTBR0/TTBR1 | Working in QEMU | Boot log proves each step (S7–S15) |
| x86_64 UEFI boot, SMP (1/2/4 vCPUs), Intel & AMD CPUID | Working in QEMU | `cargo xtask qemu` & `cargo xtask qemu-smp` exit 0 |
| PCIe (ECAM + `0xCF8`/`0xCFC`, MSI/MSI-X) & NIC/Internet stack | Implemented & tested | `e1000`, `e1000e`, `I225-V`, `pcnet32`, `RTL8168`, `virtio-net`, DHCP/IPv4/ICMP |
| Raspberry Pi 3B+ / 4B / 5 hybrid driver layer | Implemented & tested | `BCM2837B0` + `LAN7515`, `BCM2711` + `GENET v5` + `VL805`, `BCM2712` + `RP1` |
| Installable Raspberry Pi ISO & SD-card image | Built & verified | `tools/build-rpi-iso.sh` -> `qyronex-rpi-installer.iso` & `qyronex-rpi-sdcard.img` |
| Linux syscall personality (arm64) | Working | Unchanged static and dynamic ELF programs run |
| VFS: initramfs, memfs (tmpfs), ext4 on virtio-blk (GPT) | Working | |
| Networking: virtio-net, DHCP, AF_UNIX, TCP/UDP, netlink | Working | DHCP lease `10.0.2.15` in QEMU user networking |
| **Debian 13 (trixie/arm64) with systemd 257 as PID 1** | **Boots to `multi-user.target`** | Unchanged Debian userspace; udevd, journald, dbus, serial getty run |
| Graphics/input: virtio-gpu (KMS/mmap), virtio-input evdev (keyboard, tablet) | Implemented | `drivers/virtio`, `kernel/linux-desktop` |
| **Desktop: labwc (Wayland) + XFCE 4.20 + NetSurf Browser** | **Starts via `qyronex-desktop.service`** | Single-click desktop icons via `qyronex-filemanager`, noVNC viewer |
| SMP | `smp=1` default (AArch64), 1/2/4 vCPUs tested | Both `x86_64` and `AArch64` 1/2/4-vCPU matrices pass |

## Wayland and XFCE: how it works

Wayland and XFCE are **not built into the kernel**. They are ordinary **Debian 13 userspace programs** (labwc as Wayland compositor, XFCE on top) that run on Qyronex through the Linux ABI layer and the DRM/KMS, evdev, seat and udev interfaces in `kernel/linux-desktop` and `drivers/virtio`.

## Known gaps (verified honestly)

- **Native Raspberry Pi userspace mount:** `kernel8.img` (`--features rpi-native`, `0x0008_0000`, `ARM\x64` header) boots natively in TTBR1 high-half, parses the official Pi 3B+/4B/5 DTBs, queries the live VideoCore IV hardware mailbox (`0x3F00_B880`), initializes QA7/GIC-400, and delivers live hardware timer IRQs (verified on `qemu-system-aarch64 -M raspi3b`). Switching rootfs block/network/display I/O from VirtIO to live SDHCI/EMMC2, GENET/RP1 and HDMI framebuffer userspace execution on physical silicon is the next integration milestone.
- **x86_64 userspace:** `kernal-core` (`x86_64`) boots via UEFI (`BOOTX64.EFI`), brings up ACPI/IOAPIC SMP (1/2/4 vCPUs), detects Intel/AMD CPUID profiles, scans PCI Bus 0 (`0xCF8`/`0xCFC`), and probes real Intel `e1000`/`e1000e` MMIO registers (`link=up`, `1000Mbps`, real hardware MAC). The Linux userspace ABI (`systemd`/`ext4`/`XFCE`) is currently wired on AArch64 only.
- **Debian 13 / systemd in QEMU:** systemd notes missing kernel features (`autofs4`, BPF LSM / cgroup BPF firewalling, `fs.file-max`, `fs.nr_open`, `kbrequest` ioctl), detects virtualization as `container-other`, and `modprobe@*` units terminate with `SIGKILL` (kernel modules are intentionally unsupported).
- **Desktop rendering:** Software-rendered in QEMU (`smp=4` recommended over `smp=1`).

## How to run (macOS)

The launcher is `tools/debian13/start-desktop.sh` (a user-level wrapper named `qyronex` may point to it). QEMU runs inside a Docker image (`kernal-dev:bookworm-arm64`), so **Docker Desktop must be running**.

```bash
tools/debian13/start-desktop.sh            # XFCE + labwc desktop via web VNC (default)
tools/debian13/start-desktop.sh 4          # 4 vCPUs
tools/debian13/start-desktop.sh --headless # serial console only
tools/debian13/start-desktop.sh --cocoa    # native QEMU window (needs local qemu)
tools/debian13/start-desktop.sh --build    # rebuild the AArch64 kernel first
tools/debian13/start-desktop.sh --etappe5  # older Weston desktop image
tools/debian13/start-desktop.sh --etappe4  # systemd CLI image
```

- Browser desktop: `http://127.0.0.1:6080/web_vnc.html?ws=6081`
- VNC: `vnc://:qyronex@127.0.0.1:5900` (override with `VNC_PORT`, `WEB_PORT`, `WS_PORT`, `VNC_PASS`)
- Login: `root`, no password. Quit: `Ctrl+A`, then `x`.
- The default VNC password and empty root password are for local development only. Do not expose these ports.

The disk images live in Docker volumes (`kernal-docker-cache`, `kernal-docker-target`), not in Git.

## Milestone history

| Milestone | Commit | Date |
|---|---|---|
| Etappes 1–3: pty, virtio-blk ext4, virtio-net/apt | `2d4f2d7` | — |
| Etappe 4: systemd PID 1, udevd, cgroups v2, login, SMP | `b6aa145` | 2026-11-18 |
| Etappe 5: virtio-gpu KMS, virtio-input, Weston | `8c67bfe` | 2026-11-18 |
| Full XFCE + labwc desktop, VM/TTY/PTY hardening | `d81aab8` | 2026-11-19 |
| `qyronex` desktop launcher, web VNC viewer | `a130154` | 2026-11-19 |
| epoll aliasing fix, virtio-tablet udev tags | `b0cc59c` | 2026-11-19 |
