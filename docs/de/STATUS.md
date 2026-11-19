# Qyronex Kernal — Status

Stand: 19.11.2026 (Quellcode-Head `b0cc59c`). Englische Version: [../../STATUS.md](../../STATUS.md).

> Forschungskernel. Nicht produktionsreif, keine Sicherheitsgrenze. Die Aussagen beruhen auf der Commit-Historie und dem beobachteten QEMU-Bootlog. Sie sind kein abgeschlossenes Konformitäts- oder Audit-Ergebnis.

## Was Qyronex ist

- Ein **eigenständiger Kernel in Rust** (rund 157.000 Zeilen unter `kernel/`), **kein Linux und kein Linux-Fork**.
- Eigene Architektur: Capabilities, W^X, Null-Page- und Guard-Stack-Invarianten, fail-closed IOMMU/IRQ, eigener Scheduler und eigene Speicherverwaltung.
- Stellt das **Linux-Userspace-ABI** bereit (Syscalls, VFS, `/proc`, `/sys`, Geräte, Netlink), damit unveränderte Linux-Programme laufen. Linux-Kernelmodule (`.ko`) werden nicht unterstützt.
- Hauptziel: **AArch64 / ARM64 in QEMU** (`virt`, GICv3). x86_64-Komponenten existieren, sind aber nicht das aktive Laufzeitziel.

## Aktueller Stand (beobachtet)

| Bereich | Stand | Hinweise |
|---|---|---|
| Geschützter Boot, EL0/EL1, PAN, W^X, TTBR0/TTBR1 | Läuft in QEMU | Bootlog belegt jeden Schritt (S7–S15) |
| Linux-Syscall-Persönlichkeit (arm64) | Läuft | Unveränderte statische und dynamische ELF-Programme |
| VFS: initramfs, memfs (tmpfs), ext4 auf virtio-blk (GPT) | Läuft | |
| Netzwerk: virtio-net, DHCP, AF_UNIX, TCP/UDP, Netlink | Läuft | DHCP-Adresse `10.0.2.15` im QEMU-User-Netz |
| Events/cgroups: epoll, eventfd, timerfd, signalfd, inotify, memfd, cgroups v2 | Implementiert | |
| **Debian 13 (trixie/arm64) mit systemd 257 als PID 1** | **Bootet bis `multi-user.target`** | Unverändertes Debian-Userspace; udevd, journald, dbus, serieller getty laufen |
| Grafik/Eingabe: virtio-gpu (KMS/mmap), virtio-input evdev (Tastatur, Tablet) | Implementiert | `drivers/virtio`, `kernel/linux-desktop` |
| **Desktop: labwc (Wayland-Compositor) + XFCE 4.20** | **Startet über `qyronex-desktop.service`** | Visuell geprüft: XFCE-Leiste, Terminal, Dateimanager über noVNC |
| SMP | Standard `smp=1`; 1/2/4/8 wählbar | Höhere Werte weniger getestet |

## Wayland und XFCE: wie es funktioniert

Wayland und XFCE sind **nicht im Kernel eingebaut**. Es sind normale **Debian-13-Userspace-Programme** (labwc als Wayland-Compositor, XFCE darüber). Sie laufen auf Qyronex über die Linux-ABI-Schicht und die Schnittstellen DRM/KMS, evdev, Seat und udev in `kernel/linux-desktop` und `drivers/virtio`.

## Bekannte Lücken (aus dem Bootlog)

- systemd meldet fehlende Kernel-Funktionen: `autofs4`, BPF-LSM / cgroup-BPF-Firewall, `fs.file-max`, `fs.nr_open`, kbrequest-ioctl.
- systemd erkennt die Virtualisierung als `container-other`.
- `modprobe@*`-Dienste werden mit `SIGKILL` beendet (Module werden nicht unterstützt, die Units sind praktisch wirkungslos).
- Der Desktop wird in QEMU per Software gerendert und ist mit 1 vCPU / 2 GB vermutlich langsam.
- Es gibt kein dokumentiertes Real-Hardware-Profil. QEMU ist die einzige Nachweisplattform.
- Roadmap-Schritte 27–39 und 43 sind vom Maintainer als DONE markiert (nur AArch64/QEMU), Schritt 40 ist PARTIAL, die Schritte 41, 42 und 44 sind offen. Die DONE-Markierungen wurden nicht durch einen automatischen Abnahmelauf geprüft.

## Starten (macOS)

Der Launcher ist `tools/debian13/start-desktop.sh` (ein Wrapper namens `qyronex` kann darauf zeigen). QEMU läuft in einem Docker-Image (`kernal-dev:bookworm-arm64`), **Docker Desktop muss also laufen**.

```bash
tools/debian13/start-desktop.sh            # XFCE + labwc Desktop über Web-VNC (Standard)
tools/debian13/start-desktop.sh 4          # 4 vCPUs
tools/debian13/start-desktop.sh --headless # nur serielle Konsole
tools/debian13/start-desktop.sh --cocoa    # natives QEMU-Fenster (lokales qemu nötig)
tools/debian13/start-desktop.sh --build    # AArch64-Kernel vorher neu bauen
tools/debian13/start-desktop.sh --etappe5  # älteres Weston-Desktop-Image
tools/debian13/start-desktop.sh --etappe4  # systemd-CLI-Image
```

- Browser-Desktop: `http://127.0.0.1:6080/web_vnc.html?ws=6081`
- VNC: `vnc://:qyronex@127.0.0.1:5900` (änderbar über `VNC_PORT`, `WEB_PORT`, `WS_PORT`, `VNC_PASS`)
- Login: `root`, kein Passwort. Beenden: `Strg+A`, dann `x`.
- Das Standard-VNC-Passwort und das leere root-Passwort sind nur für lokale Entwicklung gedacht. Die Ports nicht nach außen freigeben.

Die Disk-Images liegen in Docker-Volumes (`kernal-docker-cache`, `kernal-docker-target`), nicht in Git.

## Meilensteine

| Meilenstein | Commit | Datum |
|---|---|---|
| Etappen 1–3: pty, virtio-blk ext4, virtio-net/apt | `2d4f2d7` | — |
| Etappe 4: systemd PID 1, udevd, cgroups v2, Login, SMP | `b6aa145` | 18.11.2026 |
| Etappe 5: virtio-gpu KMS, virtio-input, Weston | `8c67bfe` | 18.11.2026 |
| Voller XFCE + labwc Desktop, VM/TTY/PTY-Härtung | `d81aab8` | 19.11.2026 |
| `qyronex`-Desktop-Launcher, Web-VNC-Viewer | `a130154` | 19.11.2026 |
| epoll-Aliasing-Fix, virtio-tablet udev-Tags | `b0cc59c` | 19.11.2026 |
