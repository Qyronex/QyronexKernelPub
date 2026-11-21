# Qyronex OS — Android 15 / GrapheneOS Google Pixel Edition (v0.5.1)

Die **Qyronex Android 15 / GrapheneOS Pixel Edition** erweitert den AArch64-Hybrid-Kernel um eine speichersichere Android-15-Kernel-ABI (`#![forbid(unsafe_code)]` im Subsystem- & Pixel-Treiber-Crate), GrapheneOS-Kernel-Härtung, eine Google-Pixel-Tensor-/Titan-M2-Treiberschicht sowie eine **vollständig per Maus und Tastatur bedienbare, klickbare GrapheneOS-15-Wayland-Oberfläche** (`labwc` + natives ARM64 GTK3 `gtk-layer-shell`) mit 10 echten lauffähigen Apps — verpackt als eigenständige Release-ISO (`dist/qyronex-android-pixel-grapheneos.iso`) plus AOSP GKI Boot Image v4 (`dist/qyronex-pixel-boot.img`).

![Qyronex GrapheneOS 15 Home Launcher (Wayland / GTK3)](assets/qyronex_android_grapheneos_emulator.png)

## Vollständig bedienbare GrapheneOS-15-App-Suite (Live-Screenshots)

Alle Elemente der Top-Statusleiste (`SELINUX: ENFORCING`, `Binder v8 · tx · FD`, `5G · IP`, `Quick Settings`), der unteren Android-15-Navigations- & Dock-Leiste (`< Back`, `O Home`, `[] Apps`), der Web-Suchleiste, der 4 Telemetrie-Karten sowie aller **10 Apps** sind live klickbar und öffnen ohne Einfrieren oder Verzögerung:

| App | Funktion |
|---|---|
| **Vanadium** | Eingebauter gehärteter Webbrowser mit Adressleiste, Lesezeichen, Live-HTTP/HTTPS-Abruf über VirtIO-Net (`curl` via `qyronex-appd`) **und** `Full NetSurf`-Button für vollständiges grafisches HTML/CSS-Rendering (`netsurf-gtk`) |
| **Settings** | 5-Tab-Systemeinstellungen: Live-**SELinux-Enforcing-Lockdown-Test** (versucht Downgrade auf Permissive -> Kernel blockiert mit `-EPERM`), Live-`getprop`/`setprop`, persistente App-Berechtigungen (`/data/system/permissions.conf`), Live-Netzwerk-/POSIX-TCP-Test & Pixel-Hardware-Info |
| **Auditor** | Live-**10/10-Hardware-, Kernel-, Binder-FD-Passing- & Titan-M2-Attestierung** mit direkter Live-Auswertung im Fenster |
| **Terminal** | Interaktive Android-15-/Linux-Shell (`getprop`, `service list`, `dumpsys`, `qyronex-android-selftest`, `uname -a`, `ip addr`, beliebige Shell-Befehle über `qyronex-appd`) |
| **Files** | Echter POSIX-ext4-/sysfs-/binderfs-Dateimanager (`/data`, `/system`, `/sys/kernel/qyronex/android`, `/dev/binderfs`, `/`) mit Dateivorschau und direktem Öffnen in Notes |
| **Apps & Binder** | App-Launcher & Live-`/dev/binder`-ServiceManager-Explorer (alle registrierten Services + neue Services live registrieren + Kernel-Binder-Audit-Zähler) |
| **Logcat** | Live-Stream aus `/dev/log/main` (Auto-Refresh + eigene Log-Events schreiben) |
| **Notes** | Persistenter Texteditor auf `/data` (ext4) mit `Reload` und `Save to Disk` |
| **Calculator** | Klickbarer Dezimal- & Hex-Rechner |
| **Gallery** | Echter `GdkPixbuf`-Bildbetrachter für `/data/pictures` mit Vor/Zurück-Navigation |

| GrapheneOS Settings & Live SELinux `-EPERM`-Test | GrapheneOS Auditor (10/10 Attestation GREEN) |
|---|---|
| ![Settings](assets/qyronex_grapheneos_settings_selinux.png) | ![Auditor](assets/qyronex_grapheneos_auditor_10_10.png) |

| Interaktive Android-15-Shell (`service list`, `getprop`) | Vanadium Web Browser (Live HTTP/HTTPS + NetSurf) |
|---|---|
| ![Terminal](assets/qyronex_grapheneos_terminal_binder.png) | ![Vanadium](assets/qyronex_grapheneos_vanadium_browser.png) |

## Architektur & Qyronex-Vorteile gegenüber Standard-Linux/Android

| Komponente | Implementierung in Qyronex | Sicherheits- & Architekturvorteil |
|---|---|---|
| **64-Bit Android Binder v8 + Cross-Process FD Passing** | [`kernel/linux-android`](../kernel/linux-android/src/lib.rs) + [`step45_android.rs`](../kernel/core-aarch64/src/step45_android.rs) | Treble-Domain-Trennung (`/dev/binder`, `/dev/hwbinder`, `/dev/vndbinder`), **echtes `flat_binder_object`-Objekt- & FD-Passing (`BINDER_TYPE_FD`, `BINDER_TYPE_BINDER`, `BINDER_TYPE_HANDLE`)** mit prozessübergreifender FD-Übertragung, **Qyronex `CapRights`-Prüfung** auf jeder Transaktion & Audit-Zähler `total_fd_transfers` |
| **`binderfs`, `FUSE`, `userfaultfd` & `membarrier`** | `/dev/binderfs/binder-control` (`BINDER_CTL_ADD`), `/dev/fuse`, Syscalls `282` (`UFFDIO_API`) & `283` (`MEMBARRIER_*`) | Dynamische Binder-Device-Erzeugung für Android-Container/APEX, ART-GC-Grundlagen (`userfaultfd` & `membarrier`) |
| **Android Shared Memory & DMA-Heap** | `/dev/ashmem`, `/dev/dma_heap/system` | Echtes `mmap(MAP_SHARED)` mit Dirty-Writeback, Pin/Unpin und **GrapheneOS Zero-on-Free Sanitization** beim Schließen |
| **GrapheneOS Kernel-Lockdown** | `/sys/fs/selinux/{enforce,checkreqprot,deny_unknown}`, `/sys/kernel/qyronex/grapheneos/status` | **SELinux Enforcing nicht herabstufbar** (`write("0")` -> `-EPERM`), unveränderliche `ro.*`-System-Properties, W^X TTBR1-Isolation, HW PAN & ARMv8.5 MTE-Telemetrie |
| **Google Pixel Tensor & Titan M2** | [`drivers/google-pixel`](../drivers/google-pixel/src/lib.rs) | Tensor G1–G4 (`gs101`, `gs201`, `zuma`, `zumapro`), Titan M2 StrongBox KeyMint 3.0 & 64 Weaver-Slots, UFS A/B-Slot-Management, **IOMMU-gesandboxter Shannon-5G-Modem-DMA-Pfad** |
| **Android GKI Boot Image v4** | [`tools/android/mkbootimg_v4.py`](../tools/android/mkbootimg_v4.py) | Spezifikationskonformes AOSP `ANDROID!` v4-Boot-Image (`dist/qyronex-pixel-boot.img`) mit ARM64-Image-Header (`ARM\x64`) & Initramfs |
| **Wayland-Compositor & GrapheneOS-15-Shell** | [`tools/android/ui/qyronex_graphene_ui.c`](../tools/android/ui/qyronex_graphene_ui.c) + [`qyronex_appd.c`](../tools/android/src/qyronex_appd.c) | `labwc` Wayland + Zero-Fork Single-Process GTK3 `gtk-layer-shell` + nativer C-App-Daemon `qyronex-appd`, plus `/system/bin/servicemanager`, `getprop`, `setprop`, `service`, `dumpsys`, `logcat`, `qyronex-android-selftest` |

## Bauen & Im Emulator starten

```bash
# 1. Android-15-/GrapheneOS-ISO, GKI Boot Image v4 & System-Image bauen
./tools/build-android-iso.sh

# 2. Im grafischen Qyronex Android-Emulator (Browser-VNC auf http://127.0.0.1:6082) starten
./tools/android/start-android-emulator.sh --vnc

# Optional: SoC-Profil waehlen (gs101 | gs201 | zuma | zumapro | virt)
./tools/android/start-android-emulator.sh --soc zumapro --vnc
```

## Live-Verifikation im Emulator (10/10 Kernel-Selbsttest)

Beim Systemstart startet `qyronex-desktop.service` automatisch `/system/bin/servicemanager`, führt `qyronex-android-selftest` (10/10 Tests) aus und startet anschließend die `labwc`-Wayland-Sitzung mit `qyronex-appd` und `qyronex-graphene-ui shell`:

1. `SELINUX_ENFORCING_LOCKDOWN` — Verifiziert `1` und lehnt Downgrade auf `0` mit `-EPERM` ab.
2. `BINDER_V8_IPC_SERVICEMANAGER` — Echter prozessübergreifender Binder-v8-RPC (`PING`, `ADD_SERVICE`, `GET_SERVICE`, `LIST_SERVICES`).
3. `ASHMEM_MMAP_PIN_ZERO_ON_FREE` — `mmap(MAP_SHARED)` Writeback, `ASHMEM_UNPIN`/`ASHMEM_PIN` & Zero-on-Free.
4. `DMA_HEAP_SYSTEM_ALLOC` — `DMA_HEAP_IOCTL_ALLOC` über `/dev/dma_heap/system`.
5. `RO_PROPERTIES_IMMUTABLE` — Blockiert Überschreiben von `ro.*` (`-EPERM`), erlaubt mutable Properties.
6. `POWER_WAKELOCK_AND_PSI` — `/sys/power/wake_lock`, `wake_unlock`, `/proc/pressure/memory`.
7. `GRAPHENEOS_HARDENING_STATUS` — Live-Prüfung der GrapheneOS-/Qyronex-Härtungsparameter.
8. `PIXEL_TITAN_M2_MODEM_IOMMU` — Live-Telemetrie für Titan M2 StrongBox & Shannon-Modem-IOMMU-Sandbox.
9. `BINDER_FD_PASSING_CROSS_PROC` — Echte prozessübergreifende Übergabe eines Ashmem-FDs via `BINDER_TYPE_FD` (`SM_CMD_ECHO_FD`) inkl. Daten-Verifikation im Zielprozess.
10. `BINDERFS_USERFAULTFD_MEMBARRIER` — Dynamisches `BINDER_CTL_ADD` auf `/dev/binderfs/binder-control`, `sys_userfaultfd` (`UFFDIO_API`) und `sys_membarrier`.

## Transparenz: Emulator vs. physisches Google Pixel (Stock-GrapheneOS Daily Driver)

- **Sofort live & vollständig klickbar im QEMU-AArch64-Emulator:** Der komplette Qyronex Android-15-Kernel (10/10 Tests inkl. Binder-v8-FD-Passing, `binderfs`, `userfaultfd`, `membarrier`, Ashmem, DMA-Heap, SELinux-Lockdown), die komplette klickbare Wayland-/GTK3-GrapheneOS-15-Oberfläche mit allen 10 Apps, `servicemanager`, Android-CLI-Suite und das AOSP GKI Boot Image v4 (`qyronex-pixel-boot.img`).
- **Was für das Booten eines unveränderten signierten Google-Pixel-AOSP/GrapheneOS-`super.img` (Daily Driver auf echter Pixel-Hardware) noch zusätzlich erforderlich bleibt:** Die vollständige **Android-ART-/Java-Runtime (`system_server`, APK-Installation & Zygote)**, zusätzliche Dateisystem-/Sicherheits-Subsysteme (`erofs`, `f2fs`, `dm-verity`, `eBPF`) sowie die proprietären **Google-Tensor-Vendor-Komponenten** (`vendor_boot`, `vendor_dlkm`, Mali-GPU-Treiber, geschlossene GXP/TPU/Kamera- und Shannon-5G-Modem-Firmware-Blobs).
