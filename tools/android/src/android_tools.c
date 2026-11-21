/* SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0 */
/* Multi-call native ARM64 Android CLI & init suite for Qyronex OS (Android 15 / GrapheneOS):
 *   android-init, getprop, setprop, service, dumpsys, logcat, qyronex-android-selftest
 */

#include "binder_abi.h"
#include <sys/stat.h>
#include <sys/wait.h>

static int read_entire_file(const char *path, char *buf, size_t cap) {
    memset(buf, 0, cap);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t total = 0;
    while ((size_t)total + 1 < cap) {
        ssize_t n = read(fd, buf + total, cap - 1 - (size_t)total);
        if (n <= 0) break;
        total += n;
    }
    close(fd);
    buf[total] = '\0';
    return (int)total;
}

static int write_text_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = write(fd, text, strlen(text));
    int saved = errno;
    close(fd);
    errno = saved;
    return n < 0 ? -1 : 0;
}

static int cmd_getprop(int argc, char **argv) {
    char buf[4096];
    if (read_entire_file("/sys/kernel/qyronex/android/properties", buf, sizeof(buf)) < 0) {
        fprintf(stderr, "getprop: cannot read /sys/kernel/qyronex/android/properties\n");
        return 1;
    }
    const char *want = (argc >= 2) ? argv[1] : NULL;
    char *p = buf;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        char *eq = strchr(p, '=');
        if (eq) {
            *eq = '\0';
            const char *k = p;
            const char *v = eq + 1;
            if (want) {
                if (strcmp(k, want) == 0) {
                    printf("%s\n", v);
                    return 0;
                }
            } else {
                printf("[%s]: [%s]\n", k, v);
            }
        }
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

static int cmd_setprop(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: setprop <key> <value>\n");
        return 2;
    }
    char line[384];
    snprintf(line, sizeof(line), "%s=%s\n", argv[1], argv[2]);
    if (write_text_file("/sys/kernel/qyronex/android/properties", line) < 0) {
        fprintf(stderr, "setprop: failed to set '%s': %s\n", argv[1], strerror(errno));
        return 1;
    }
    return 0;
}

static int cmd_service(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: service <list|check <name>|add <name>|ping>\n");
        return 2;
    }
    struct binder_client bc;
    if (binder_client_open(&bc, "/dev/binder") < 0) {
        fprintf(stderr, "service: failed to open /dev/binder: %s\n", strerror(errno));
        return 1;
    }
    char reply[1536];
    memset(reply, 0, sizeof(reply));
    int rc = -1;
    if (strcmp(argv[1], "list") == 0) {
        rc = binder_rpc(&bc, 0, SM_CMD_LIST_SERVICES, "", 0, reply, sizeof(reply));
        if (rc >= 0) {
            printf("Found services on Qyronex Binder v8:\n%s", reply);
        }
    } else if (strcmp(argv[1], "check") == 0 && argc >= 3) {
        rc = binder_rpc(&bc, 0, SM_CMD_GET_SERVICE, argv[2], strlen(argv[2]), reply, sizeof(reply));
        if (rc >= 0) printf("Service %s: %s\n", argv[2], reply);
    } else if (strcmp(argv[1], "add") == 0 && argc >= 3) {
        rc = binder_rpc(&bc, 0, SM_CMD_ADD_SERVICE, argv[2], strlen(argv[2]), reply, sizeof(reply));
        if (rc >= 0) printf("%s\n", reply);
    } else if (strcmp(argv[1], "ping") == 0) {
        rc = binder_rpc(&bc, 0, SM_CMD_PING, "", 0, reply, sizeof(reply));
        if (rc >= 0) printf("%s\n", reply);
    } else {
        fprintf(stderr, "service: unknown subcommand '%s'\n", argv[1]);
        binder_client_close(&bc);
        return 2;
    }
    binder_client_close(&bc);
    if (rc < 0) {
        fprintf(stderr, "service: binder RPC failed (is servicemanager running?)\n");
        return 1;
    }
    return 0;
}

static int cmd_dumpsys(int argc, char **argv) {
    const char *topic = (argc >= 2) ? argv[1] : "all";
    char buf[4096];

    if (strcmp(topic, "all") == 0 || strcmp(topic, "security") == 0) {
        printf("=== GRAPHENEOS & QYRONEX HARDENING ===\n");
        if (read_entire_file("/sys/kernel/qyronex/grapheneos/status", buf, sizeof(buf)) >= 0) {
            printf("%s\n", buf);
        }
    }
    if (strcmp(topic, "all") == 0 || strcmp(topic, "pixel") == 0) {
        printf("=== GOOGLE PIXEL HARDWARE & TITAN M2 ===\n");
        if (read_entire_file("/sys/bus/platform/drivers/google_pixel/status", buf, sizeof(buf)) >= 0) {
            printf("%s\n", buf);
        }
    }
    if (strcmp(topic, "all") == 0 || strcmp(topic, "binder") == 0) {
        printf("=== ANDROID BINDER v8 STATS ===\n");
        if (read_entire_file("/sys/kernel/qyronex/android/binder_stats", buf, sizeof(buf)) >= 0) {
            printf("%s\n", buf);
        }
    }
    if (strcmp(topic, "all") == 0 || strcmp(topic, "services") == 0 || strcmp(topic, "SurfaceFlinger") == 0) {
        printf("=== SERVICEMANAGER REGISTRY ===\n");
        char *fake_argv[] = { "service", "list" };
        (void)cmd_service(2, fake_argv);
    }
    return 0;
}

static int cmd_logcat(void) {
    char buf[16384];
    if (read_entire_file("/dev/log/main", buf, sizeof(buf)) < 0) {
        fprintf(stderr, "logcat: cannot read /dev/log/main\n");
        return 1;
    }
    fputs(buf, stdout);
    return 0;
}

static int cmd_selftest(void) {
    int passed = 0;
    int total = 8;
    char buf[2048];

    printf("\n============================================================\n");
    printf(" Qyronex OS - Android 15 / GrapheneOS Kernel Self-Test Suite\n");
    printf("============================================================\n");

    /* 1. SELinux Enforcing Lockdown */
    int ok1 = 0;
    if (read_entire_file("/sys/fs/selinux/enforce", buf, sizeof(buf)) > 0 && buf[0] == '1') {
        errno = 0;
        int wr = write_text_file("/sys/fs/selinux/enforce", "0");
        if (wr < 0 && errno == EPERM) {
            if (read_entire_file("/sys/fs/selinux/enforce", buf, sizeof(buf)) > 0 && buf[0] == '1') {
                ok1 = 1;
            }
        }
    }
    printf("[TEST 1/8] SELINUX_ENFORCING_LOCKDOWN ....... %s\n", ok1 ? "PASS" : "FAIL");
    passed += ok1;

    /* 2. Cross-Process Binder v8 IPC with servicemanager */
    int ok2 = 0;
    struct binder_client bc;
    if (binder_client_open(&bc, "/dev/binder") == 0) {
        char r1[256] = {0}, r2[256] = {0}, r3[512] = {0};
        int a = binder_rpc(&bc, 0, SM_CMD_PING, "", 0, r1, sizeof(r1));
        int b = binder_rpc(&bc, 0, SM_CMD_ADD_SERVICE, "qyronex.selftest", 16, r2, sizeof(r2));
        int c = binder_rpc(&bc, 0, SM_CMD_GET_SERVICE, "qyronex.selftest", 16, r3, sizeof(r3));
        if (a > 0 && strstr(r1, "PONG") && b > 0 && strstr(r2, "OK") && c > 0 && strstr(r3, "FOUND")) {
            ok2 = 1;
        }
        binder_client_close(&bc);
    }
    printf("[TEST 2/8] BINDER_V8_IPC_SERVICEMANAGER ..... %s\n", ok2 ? "PASS" : "FAIL");
    passed += ok2;

    /* 3. Ashmem mmap(MAP_SHARED) writeback + pin/unpin */
    int ok3 = 0;
    int afd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
    if (afd >= 0) {
        char aname[256] = "selftest.ashmem";
        char got_name[256] = {0};
        if (ioctl(afd, ASHMEM_SET_NAME, aname) == 0 &&
            ioctl(afd, ASHMEM_SET_SIZE, (unsigned long)8192) == 0 &&
            ioctl(afd, ASHMEM_GET_NAME, got_name) == 0 &&
            strcmp(got_name, "selftest.ashmem") == 0) {
            void *p = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, afd, 0);
            if (p != MAP_FAILED && p != NULL) {
                memcpy(p, "QYRONEX_ASHMEM_OK", 18);
                munmap(p, 8192);
                char check[32] = {0};
                if (pread(afd, check, 18, 0) == 18 && strcmp(check, "QYRONEX_ASHMEM_OK") == 0) {
                    if (ioctl(afd, ASHMEM_UNPIN, 0UL) == 0 &&
                        ioctl(afd, ASHMEM_GET_PIN_STATUS, 0UL) == ASHMEM_IS_UNPINNED &&
                        ioctl(afd, ASHMEM_PIN, 0UL) == ASHMEM_NOT_PURGED &&
                        ioctl(afd, ASHMEM_GET_PIN_STATUS, 0UL) == ASHMEM_IS_PINNED) {
                        ok3 = 1;
                    }
                }
            }
        }
        close(afd);
    }
    printf("[TEST 3/8] ASHMEM_MMAP_PIN_ZERO_ON_FREE ..... %s\n", ok3 ? "PASS" : "FAIL");
    passed += ok3;

    /* 4. DMA-Heap /dev/dma_heap/system allocation */
    int ok4 = 0;
    int dfd = open("/dev/dma_heap/system", O_RDWR | O_CLOEXEC);
    if (dfd >= 0) {
        struct dma_heap_allocation_data alloc;
        memset(&alloc, 0, sizeof(alloc));
        alloc.len = 4096;
        if (ioctl(dfd, DMA_HEAP_IOCTL_ALLOC, &alloc) == 0 && (int)alloc.fd >= 0) {
            const char *sig = "DMA_BUF_OK";
            char rd[16] = {0};
            if (pwrite((int)alloc.fd, sig, 10, 0) == 10 &&
                pread((int)alloc.fd, rd, 10, 0) == 10 &&
                memcmp(rd, sig, 10) == 0) {
                ok4 = 1;
            }
            close((int)alloc.fd);
        }
        close(dfd);
    }
    printf("[TEST 4/8] DMA_HEAP_SYSTEM_ALLOC ............ %s\n", ok4 ? "PASS" : "FAIL");
    passed += ok4;

    /* 5. Immutable ro.* System Properties + Mutable Property Write */
    int ok5 = 0;
    if (read_entire_file("/sys/kernel/qyronex/android/properties", buf, sizeof(buf)) > 0 &&
        strstr(buf, "ro.build.version.release=15") != NULL) {
        errno = 0;
        int wr_ro = write_text_file("/sys/kernel/qyronex/android/properties", "ro.build.version.release=99\n");
        if (wr_ro < 0 && errno == EPERM) {
            if (write_text_file("/sys/kernel/qyronex/android/properties", "sys.qyronex.selftest=passed\n") == 0 &&
                read_entire_file("/sys/kernel/qyronex/android/properties", buf, sizeof(buf)) > 0 &&
                strstr(buf, "sys.qyronex.selftest=passed") != NULL) {
                ok5 = 1;
            }
        }
    }
    printf("[TEST 5/8] RO_PROPERTIES_IMMUTABLE .......... %s\n", ok5 ? "PASS" : "FAIL");
    passed += ok5;

    /* 6. Power Wakelocks & PSI */
    int ok6 = 0;
    if (write_text_file("/sys/power/wake_lock", "qyronex_test_wl\n") == 0 &&
        read_entire_file("/sys/power/wake_lock", buf, sizeof(buf)) > 0 &&
        strstr(buf, "qyronex_test_wl") != NULL &&
        write_text_file("/sys/power/wake_unlock", "qyronex_test_wl\n") == 0 &&
        read_entire_file("/proc/pressure/memory", buf, sizeof(buf)) > 0 &&
        strstr(buf, "some avg10=") != NULL) {
        ok6 = 1;
    }
    printf("[TEST 6/8] POWER_WAKELOCK_AND_PSI ........... %s\n", ok6 ? "PASS" : "FAIL");
    passed += ok6;

    /* 7. GrapheneOS Hardening Status */
    int ok7 = 0;
    if (read_entire_file("/sys/kernel/qyronex/grapheneos/status", buf, sizeof(buf)) > 0 &&
        strstr(buf, "selinux=enforcing") != NULL &&
        strstr(buf, "wx_ttbr1_isolated=active") != NULL &&
        strstr(buf, "capability_binder=enforced") != NULL &&
        strstr(buf, "zero_on_free=1") != NULL) {
        ok7 = 1;
    }
    printf("[TEST 7/8] GRAPHENEOS_HARDENING_STATUS ...... %s\n", ok7 ? "PASS" : "FAIL");
    passed += ok7;

    /* 8. Google Pixel Titan M2 + Shannon Modem IOMMU Telemetry */
    int ok8 = 0;
    if (read_entire_file("/sys/bus/platform/drivers/google_pixel/status", buf, sizeof(buf)) > 0 &&
        strstr(buf, "titan_m2=online-strongbox") != NULL &&
        strstr(buf, "keymint_version=300") != NULL &&
        strstr(buf, "modem_iommu_sandbox=enforced") != NULL) {
        ok8 = 1;
    }
    printf("[TEST 8/8] PIXEL_TITAN_M2_MODEM_IOMMU ....... %s\n", ok8 ? "PASS" : "FAIL");
    passed += ok8;

    printf("------------------------------------------------------------\n");
    if (passed == total) {
        printf("QYRONEX_ANDROID_SELFTEST: ALL %d/%d PASSED\n", passed, total);
        android_log_write("I/QyronexSelftest: ALL 8/8 Android 15 / GrapheneOS kernel checks PASSED");
        return 0;
    } else {
        printf("QYRONEX_ANDROID_SELFTEST: FAILED (%d/%d passed)\n", passed, total);
        return 1;
    }
}

static pid_t spawn_daemon(const char *path) {
    pid_t pid = fork();
    if (pid == 0) {
        char *const argv[] = { (char *)path, NULL };
        execv(path, argv);
        _exit(127);
    }
    return pid;
}

static int cmd_android_init(void) {
    printf("\n");
    printf("===================================================================\n");
    printf("  Qyronex OS - Android 15 / GrapheneOS Native Kernel Edition v0.5.0\n");
    printf("  Target: Google Pixel (Tensor G1-G4) & QEMU AArch64 Emulator\n");
    printf("===================================================================\n");
    fflush(stdout);

    (void)mkdir("/data", 0755);
    (void)mkdir("/data/local", 0755);
    (void)mkdir("/data/local/tmp", 0777);

    /* 1. Start Android ServiceManager on /dev/binder */
    printf("[android-init] Starting /system/bin/servicemanager ...\n");
    fflush(stdout);
    pid_t sm_pid = spawn_daemon("/system/bin/servicemanager");
    printf("[android-init] servicemanager spawned (pid=%d)\n", (int)sm_pid);

    /* Wait up to ~3 seconds for servicemanager to answer SM_CMD_PING over Binder */
    int sm_ready = 0;
    for (int i = 0; i < 60; i++) {
        struct binder_client bc;
        if (binder_client_open(&bc, "/dev/binder") == 0) {
            char pong[128] = {0};
            if (binder_rpc(&bc, 0, SM_CMD_PING, "", 0, pong, sizeof(pong)) > 0 &&
                strstr(pong, "PONG") != NULL) {
                printf("[android-init] Binder v8 context manager ready: %s\n", pong);
                binder_client_close(&bc);
                sm_ready = 1;
                break;
            }
            binder_client_close(&bc);
        }
        usleep(50000);
    }
    if (!sm_ready) {
        printf("[android-init] WARN: servicemanager ping timeout\n");
    }

    /* 2. Start SurfaceFlinger (registers core services & presents GrapheneOS UI on VirtIO-GPU) */
    printf("[android-init] Starting /system/bin/surfaceflinger (VirtIO-GPU 1280x800) ...\n");
    fflush(stdout);
    pid_t sf_pid = spawn_daemon("/system/bin/surfaceflinger");
    printf("[android-init] surfaceflinger spawned (pid=%d)\n", (int)sf_pid);
    usleep(350000);

    /* 3. Mark Android boot completed */
    (void)write_text_file("/sys/kernel/qyronex/android/properties", "sys.boot_completed=1\n");
    android_log_write("I/init: sys.boot_completed=1 (GrapheneOS / Qyronex Hybrid Kernel)");

    /* 4. Run full self-test suite */
    (void)cmd_selftest();

    /* 5. Print live services & drop into interactive Android shell */
    printf("\n[android-init] Launching interactive Android shell (type 'dumpsys', 'getprop', 'service list', 'logcat'):\n");
    fflush(stdout);
    setenv("PATH", "/system/bin:/system/xbin:/vendor/bin:/usr/bin:/bin:/sbin", 1);
    setenv("PS1", "qyronex_pixel:/ # ", 1);
    setenv("HOME", "/data/local/tmp", 1);
    setenv("TERM", "vt100", 1);

    char *const sh_argv[] = { "/bin/dash", "-i", NULL };
    execv("/bin/dash", sh_argv);
    char *const bb_argv[] = { "/bin/sh", "-i", NULL };
    execv("/bin/sh", bb_argv);

    /* Keep PID 1 alive if no shell is present */
    while (1) {
        int st = 0;
        (void)waitpid(-1, &st, WNOHANG);
        usleep(200000);
    }
    return 0;
}

static const char *base_name(const char *s) {
    const char *sl = strrchr(s, '/');
    return sl ? sl + 1 : s;
}

int main(int argc, char **argv) {
    const char *prog = base_name(argv[0]);
    if (strcmp(prog, "android-tools") == 0 && argc >= 2) {
        prog = argv[1];
        argc--;
        argv++;
    }

    if (strcmp(prog, "android-init") == 0 || strcmp(prog, "init") == 0) {
        return cmd_android_init();
    }
    if (strcmp(prog, "getprop") == 0) {
        return cmd_getprop(argc, argv);
    }
    if (strcmp(prog, "setprop") == 0) {
        return cmd_setprop(argc, argv);
    }
    if (strcmp(prog, "service") == 0) {
        return cmd_service(argc, argv);
    }
    if (strcmp(prog, "dumpsys") == 0) {
        return cmd_dumpsys(argc, argv);
    }
    if (strcmp(prog, "logcat") == 0) {
        return cmd_logcat();
    }
    if (strcmp(prog, "qyronex-android-selftest") == 0 || strcmp(prog, "selftest") == 0) {
        return cmd_selftest();
    }

    fprintf(stderr, "Qyronex Android Tools: unknown applet '%s'\n", prog);
    fprintf(stderr, "Applets: android-init, getprop, setprop, service, dumpsys, logcat, qyronex-android-selftest\n");
    return 2;
}
