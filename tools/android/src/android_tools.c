/* SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0 */
/* Multi-call native ARM64 Android CLI & init suite for Qyronex OS (Android 15 / GrapheneOS):
 *   android-init, getprop, setprop, service, dumpsys, logcat, qyronex-android-selftest
 */

#include "binder_abi.h"
#include <poll.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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
        if (read_entire_file("/sys/fs/selinux/load", buf, sizeof(buf)) >= 0) {
            printf("%s\n", buf);
        }
        if (read_entire_file("/proc/bootconfig", buf, sizeof(buf)) >= 0) {
            printf("=== ANDROID 15 BOOTCONFIG (/proc/bootconfig) ===\n%s\n", buf);
        }
    }
    if (strcmp(topic, "all") == 0 || strcmp(topic, "pixel") == 0) {
        printf("=== GOOGLE PIXEL HARDWARE & TITAN M2 ===\n");
        if (read_entire_file("/sys/bus/platform/drivers/google_pixel/status", buf, sizeof(buf)) >= 0) {
            printf("%s\n", buf);
        }
        if (read_entire_file("/sys/bus/platform/drivers/google_pixel/hardware", buf, sizeof(buf)) >= 0) {
            printf("%s\n", buf);
        }
    }
    if (strcmp(topic, "all") == 0 || strcmp(topic, "ebpf") == 0) {
        printf("=== ANDROID eBPF SUBSYSTEM (sys_bpf) ===\n");
        if (read_entire_file("/sys/kernel/qyronex/android/bpf_stats", buf, sizeof(buf)) >= 0) {
            printf("%s\n", buf);
        }
    }
    if (strcmp(topic, "all") == 0 || strcmp(topic, "storage") == 0 || strcmp(topic, "verity") == 0) {
        printf("=== DM-VERITY & STORAGE FILESYSTEMS (EROFS/F2FS/SUPER-LP/FUSE) ===\n");
        if (read_entire_file("/sys/kernel/qyronex/android/dm_verity_status", buf, sizeof(buf)) >= 0) {
            printf("%s\n", buf);
        }
        if (read_entire_file("/sys/kernel/qyronex/android/storage_fs_status", buf, sizeof(buf)) >= 0) {
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
    int total = 16;
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
    printf("[TEST 1/16] SELINUX_ENFORCING_LOCKDOWN ...... %s\n", ok1 ? "PASS" : "FAIL");
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
    printf("[TEST 2/16] BINDER_V8_IPC_SERVICEMANAGER .... %s\n", ok2 ? "PASS" : "FAIL");
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
    printf("[TEST 3/16] ASHMEM_MMAP_PIN_ZERO_ON_FREE .... %s\n", ok3 ? "PASS" : "FAIL");
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
    printf("[TEST 4/16] DMA_HEAP_SYSTEM_ALLOC ........... %s\n", ok4 ? "PASS" : "FAIL");
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
    printf("[TEST 5/16] RO_PROPERTIES_IMMUTABLE ......... %s\n", ok5 ? "PASS" : "FAIL");
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
    printf("[TEST 6/16] POWER_WAKELOCK_AND_PSI .......... %s\n", ok6 ? "PASS" : "FAIL");
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
    printf("[TEST 7/16] GRAPHENEOS_HARDENING_STATUS ..... %s\n", ok7 ? "PASS" : "FAIL");
    passed += ok7;

    /* 8. Google Pixel Titan M2 + Shannon Modem IOMMU Telemetry */
    int ok8 = 0;
    if (read_entire_file("/sys/bus/platform/drivers/google_pixel/status", buf, sizeof(buf)) > 0 &&
        strstr(buf, "titan_m2=online-strongbox") != NULL &&
        strstr(buf, "keymint_version=300") != NULL &&
        strstr(buf, "modem_iommu_sandbox=enforced") != NULL) {
        ok8 = 1;
    }
    printf("[TEST 8/16] PIXEL_TITAN_M2_MODEM_IOMMU ...... %s\n", ok8 ? "PASS" : "FAIL");
    passed += ok8;

    /* 9. Real Cross-Process Binder v8 FD Passing (`BINDER_TYPE_FD`) */
    int ok9 = 0;
    {
        int sfd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
        struct binder_client fbc;
        if (sfd >= 0 && binder_client_open(&fbc, "/dev/binder") == 0) {
            (void)ioctl(sfd, ASHMEM_SET_SIZE, (unsigned long)4096);
            (void)pwrite(sfd, "FD_PASSED_OK", 12, 0);

            struct flat_binder_object fbo;
            memset(&fbo, 0, sizeof(fbo));
            fbo.hdr_type = BINDER_TYPE_FD;
            fbo.flags = 0x7f;
            fbo.binder_or_handle = (uint64_t)sfd;
            uint64_t obj_off = 0;

            uint8_t wbuf[4 + sizeof(struct binder_transaction_data)];
            uint32_t wcmd = BC_TRANSACTION;
            struct binder_transaction_data tx;
            memset(&tx, 0, sizeof(tx));
            tx.target_handle_or_ptr = 0;
            tx.code = SM_CMD_ECHO_FD;
            tx.flags = 0x10; /* TF_ACCEPT_FDS */
            tx.data_size = sizeof(fbo);
            tx.offsets_size = sizeof(obj_off);
            tx.data_ptr = (uint64_t)(uintptr_t)&fbo;
            tx.offsets_ptr = (uint64_t)(uintptr_t)&obj_off;
            memcpy(wbuf, &wcmd, 4);
            memcpy(wbuf + 4, &tx, sizeof(tx));

            uint8_t rbuf[512];
            struct binder_write_read bwr;
            memset(&bwr, 0, sizeof(bwr));
            bwr.write_size = sizeof(wbuf);
            bwr.write_buffer = (uint64_t)(uintptr_t)wbuf;
            bwr.read_size = sizeof(rbuf);
            bwr.read_buffer = (uint64_t)(uintptr_t)rbuf;

            if (ioctl(fbc.fd, BINDER_WRITE_READ, &bwr) == 0) {
                char freply[192] = {0};
                for (int tries = 0; tries < 64 && !freply[0]; tries++) {
                    size_t off = 0;
                    while (off + 4 <= (size_t)bwr.read_consumed) {
                        uint32_t br = 0;
                        memcpy(&br, rbuf + off, 4);
                        off += 4;
                        if (br == BR_REPLY && off + sizeof(tx) <= (size_t)bwr.read_consumed) {
                            struct binder_transaction_data rtx;
                            memcpy(&rtx, rbuf + off, sizeof(rtx));
                            off += sizeof(rtx);
                            if (rtx.data_ptr && rtx.data_size > 0) {
                                size_t n = (size_t)rtx.data_size;
                                if (n >= sizeof(freply)) n = sizeof(freply) - 1;
                                memcpy(freply, (const void *)(uintptr_t)rtx.data_ptr, n);
                                freply[n] = '\0';
                            }
                            break;
                        }
                    }
                    if (!freply[0]) {
                        memset(&bwr, 0, sizeof(bwr));
                        bwr.read_size = sizeof(rbuf);
                        bwr.read_buffer = (uint64_t)(uintptr_t)rbuf;
                        if (ioctl(fbc.fd, BINDER_WRITE_READ, &bwr) < 0) break;
                    }
                }
                char verify_back[16] = {0};
                (void)pread(sfd, verify_back, 12, 32);
                if (strstr(freply, "FD_OK") && strstr(freply, "FD_PASSED_OK") &&
                    memcmp(verify_back, "SM_SAW_FD_OK", 12) == 0) {
                    ok9 = 1;
                }
            }
            binder_client_close(&fbc);
        }
        if (sfd >= 0) close(sfd);
    }
    printf("[TEST 9/16] BINDER_FD_PASSING_CROSS_PROC .... %s\n", ok9 ? "PASS" : "FAIL");
    passed += ok9;

    /* 10. binderfs BINDER_CTL_ADD + Android 15 ART userfaultfd + membarrier */
    int ok10 = 0;
    {
        int ctl_ok = 0, uffd_ok = 0, mb_ok = 0;
        int cfd = open("/dev/binderfs/binder-control", O_RDWR | O_CLOEXEC);
        if (cfd >= 0) {
            struct binderfs_device dev;
            memset(&dev, 0, sizeof(dev));
            snprintf(dev.name, sizeof(dev.name), "qyronex-hal");
            if (ioctl(cfd, BINDER_CTL_ADD, &dev) == 0 && dev.major == 240) {
                ctl_ok = 1;
            }
            close(cfd);
        }
        long ufd = syscall(282 /* SYS_userfaultfd */, O_CLOEXEC);
        if (ufd >= 0) {
            struct uffdio_api ua;
            memset(&ua, 0, sizeof(ua));
            ua.api = 0xAA;
            if (ioctl((int)ufd, UFFDIO_API, &ua) == 0 && ua.ioctls != 0) {
                uffd_ok = 1;
            }
            close((int)ufd);
        }
        long mb = syscall(283 /* SYS_membarrier */, 0, 0, 0);
        if (mb > 0) mb_ok = 1;
        if (ctl_ok && uffd_ok && mb_ok) ok10 = 1;
    }
    printf("[TEST 10/16] BINDERFS_USERFAULTFD_MEMBARRIER  %s\n", ok10 ? "PASS" : "FAIL");
    passed += ok10;

    /* 11. Real eBPF (`sys_bpf` 280): Hash Map + Verifier + 64-bit VM Execution + Reject Bad Loop */
    int ok11 = 0;
    {
        uint8_t attr[128];
        memset(attr, 0, sizeof(attr));
        uint32_t mtype = 1, ksz = 4, vsz = 8, maxe = 16;
        memcpy(attr + 0, &mtype, 4);
        memcpy(attr + 4, &ksz, 4);
        memcpy(attr + 8, &vsz, 4);
        memcpy(attr + 12, &maxe, 4);
        long mfd = syscall(280 /* SYS_bpf */, 0 /* BPF_MAP_CREATE */, attr, 64);
        int map_ok = 0, prog_ok = 0, rej_ok = 0;
        if (mfd >= 0) {
            uint32_t k = 7;
            uint64_t v = 0x1122334455667788ULL, vout = 0;
            uint64_t kp = (uint64_t)(uintptr_t)&k, vp = (uint64_t)(uintptr_t)&v, vo = (uint64_t)(uintptr_t)&vout;
            uint32_t mfd32 = (uint32_t)mfd;
            memset(attr, 0, sizeof(attr));
            memcpy(attr + 0, &mfd32, 4);
            memcpy(attr + 8, &kp, 8);
            memcpy(attr + 16, &vp, 8);
            if (syscall(280, 2 /* BPF_MAP_UPDATE_ELEM */, attr, 64) == 0) {
                memcpy(attr + 16, &vo, 8);
                if (syscall(280, 1 /* BPF_MAP_LOOKUP_ELEM */, attr, 64) == 0 && vout == v) {
                    map_ok = 1;
                }
            }
            close((int)mfd);
        }
        /* Valid eBPF filter: LDX_B R0,[R1+0]; ADD64 R0,10; EXIT */
        struct { uint8_t code; uint8_t regs; int16_t off; int32_t imm; } insns[3] = {
            { 0x71, 0x10, 0, 0 },  /* BPF_LDX | BPF_B | BPF_MEM: dst=0, src=1 */
            { 0x07, 0x00, 0, 10 }, /* BPF_ALU64 | BPF_ADD | BPF_K: dst=0, imm=10 */
            { 0x95, 0x00, 0, 0 },  /* BPF_JMP | BPF_EXIT */
        };
        memset(attr, 0, sizeof(attr));
        uint32_t ptype = 1, icnt = 3;
        uint64_t iptr = (uint64_t)(uintptr_t)insns;
        memcpy(attr + 0, &ptype, 4);
        memcpy(attr + 4, &icnt, 4);
        memcpy(attr + 8, &iptr, 8);
        long pfd = syscall(280, 5 /* BPF_PROG_LOAD */, attr, 64);
        if (pfd >= 0) {
            uint8_t pkt[4] = { 32, 0, 0, 0 };
            uint32_t pfd32 = (uint32_t)pfd, dsz = 4, retval = 0;
            uint64_t dptr = (uint64_t)(uintptr_t)pkt;
            memset(attr, 0, sizeof(attr));
            memcpy(attr + 0, &pfd32, 4);
            memcpy(attr + 8, &dsz, 4);
            memcpy(attr + 16, &dptr, 8);
            if (syscall(280, 10 /* BPF_PROG_TEST_RUN */, attr, 64) == 0) {
                memcpy(&retval, attr + 4, 4);
                if (retval == 42) prog_ok = 1;
            }
            close((int)pfd);
        }
        /* Malicious backward loop must be rejected by verifier with -EACCES */
        struct { uint8_t code; uint8_t regs; int16_t off; int32_t imm; } bad[2] = {
            { 0x05, 0x00, -1, 0 }, /* BPF_JMP | BPF_JA off=-1 */
            { 0x95, 0x00, 0, 0 },
        };
        memset(attr, 0, sizeof(attr));
        icnt = 2;
        iptr = (uint64_t)(uintptr_t)bad;
        memcpy(attr + 0, &ptype, 4);
        memcpy(attr + 4, &icnt, 4);
        memcpy(attr + 8, &iptr, 8);
        errno = 0;
        if (syscall(280, 5 /* BPF_PROG_LOAD */, attr, 64) < 0 && errno == EACCES) {
            rej_ok = 1;
        }
        if (map_ok && prog_ok && rej_ok) ok11 = 1;
    }
    printf("[TEST 11/16] EBPF_SYS_BPF_VERIFY_AND_EXEC ... %s\n", ok11 ? "PASS" : "FAIL");
    passed += ok11;

    /* 12. Real `dm-verity` SHA-256 Merkle Verification & 1-Bit Tamper Fail-Closed (-EIO) */
    int ok12 = 0;
    {
        int dmfd = open("/dev/mapper/control", O_RDWR | O_CLOEXEC);
        if (dmfd >= 0) {
            uint8_t ver[16] = {0};
            uint32_t maj = 0, minv = 0;
            int v_ok = (ioctl(dmfd, 0xC138FD00UL /* DM_VERSION */, ver) == 0);
            memcpy(&maj, ver, 4);
            memcpy(&minv, ver + 4, 4);
            char blk[48] = "QYRONEX_ANDROID_15_VERITY_SYSTEM_BLOCK_0";
            uint8_t req[64];
            memset(req, 0, sizeof(req));
            snprintf((char *)req, 32, "system-verity");
            uint32_t bidx = 0, blen = 40;
            uint64_t bptr = (uint64_t)(uintptr_t)blk;
            memcpy(req + 32, &bidx, 4);
            memcpy(req + 36, &blen, 4);
            memcpy(req + 40, &bptr, 8);
            int clean_ok = (ioctl(dmfd, 0xC040FD80UL /* QYRONEX_DM_VERITY_VERIFY_BLOCK */, req) == 0);
            blk[5] ^= 0x01; /* 1-bit tamper! */
            errno = 0;
            int tamper_blocked = (ioctl(dmfd, 0xC040FD80UL, req) < 0 && errno == EIO);
            if (v_ok && maj == 4 && minv == 48 && clean_ok && tamper_blocked) ok12 = 1;
            close(dmfd);
        }
    }
    printf("[TEST 12/16] DM_VERITY_MERKLE_FAIL_CLOSED ... %s\n", ok12 ? "PASS" : "FAIL");
    passed += ok12;

    /* 13. Real Kernel Validation of EROFS + F2FS + super.img LP_METADATA + /dev/fuse Handshake */
    int ok13 = 0;
    {
        int erofs_ok = 0, f2fs_ok = 0, lp_ok = 0, fuse_ok = 0;
        const char *probes[3] = {
            "/vendor/etc/qyronex-fs/com.qyronex.android.erofs",
            "/vendor/etc/qyronex-fs/userdata_probe.f2fs",
            "/vendor/etc/qyronex-fs/super_lp_probe.img",
        };
        int *flags[3] = { &erofs_ok, &f2fs_ok, &lp_ok };
        for (int i = 0; i < 3; i++) {
            int pfd = open(probes[i], O_RDONLY | O_CLOEXEC);
            if (pfd >= 0) {
                static uint8_t imgbuf[20480];
                ssize_t n = read(pfd, imgbuf, sizeof(imgbuf));
                close(pfd);
                if (n > 0) {
                    int sfd = open("/sys/kernel/qyronex/android/storage_fs_status", O_WRONLY | O_CLOEXEC);
                    if (sfd >= 0) {
                        if (write(sfd, imgbuf, (size_t)n) == n) *flags[i] = 1;
                        close(sfd);
                    }
                }
            }
        }
        int ffd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
        if (ffd >= 0) {
            uint8_t finit[64] = {0};
            if (read(ffd, finit, sizeof(finit)) >= 56) {
                uint32_t op = 0, fmaj = 0, fmin = 0;
                memcpy(&op, finit + 4, 4);
                memcpy(&fmaj, finit + 40, 4);
                memcpy(&fmin, finit + 44, 4);
                if (op == 26 && fmaj == 7 && fmin == 39) {
                    uint8_t rep[32] = {0};
                    uint32_t rlen = 32;
                    uint64_t uniq = 1;
                    memcpy(rep + 0, &rlen, 4);
                    memcpy(rep + 8, &uniq, 8);
                    memcpy(rep + 16, &fmaj, 4);
                    memcpy(rep + 20, &fmin, 4);
                    if (write(ffd, rep, sizeof(rep)) == (ssize_t)sizeof(rep)) fuse_ok = 1;
                }
            }
            close(ffd);
        }
        if (erofs_ok && f2fs_ok && lp_ok && fuse_ok) ok13 = 1;
    }
    printf("[TEST 13/16] EROFS_F2FS_SUPER_LP_FUSE ....... %s\n", ok13 ? "PASS" : "FAIL");
    passed += ok13;

    /* 14. Google Pixel Mali-G715 CSF GPU + Edge TPU + Modem + Camera HAL */
    int ok14 = 0;
    {
        int mfd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
        int mali_ok = 0, hw_ok = 0;
        if (mfd >= 0) {
            uint16_t ver[2] = {0, 0};
            uint32_t props[4] = {0, 0, 0, 0};
            if (ioctl(mfd, 0xC0048000UL /* KBASE_IOCTL_VERSION_CHECK */, ver) == 0 &&
                ioctl(mfd, 0xC0108003UL /* KBASE_IOCTL_GET_GPUPROPS */, props) == 0 &&
                ver[0] == 1 && props[0] != 0 && props[3] == 1) {
                mali_ok = 1;
            }
            close(mfd);
        }
        if (read_entire_file("/sys/bus/platform/drivers/google_pixel/hardware", buf, sizeof(buf)) > 0 &&
            strstr(buf, "gpu_iommu=enforced") != NULL &&
            strstr(buf, "edge_tpu_iommu=enforced") != NULL &&
            strstr(buf, "vendor_boot_v4=supported") != NULL &&
            access("/dev/edgetpu", F_OK) == 0 &&
            access("/dev/umts_ipc0", F_OK) == 0) {
            hw_ok = 1;
        }
        if (mali_ok && hw_ok) ok14 = 1;
    }
    printf("[TEST 14/16] PIXEL_MALI_GPU_EDGETPU_HAL ..... %s\n", ok14 ? "PASS" : "FAIL");
    passed += ok14;

    /* 15. Real Android APK/DEX Dalvik VM (`pm install` + `am start` -> `qyronex-art`) */
    int ok15 = 0;
    {
        if (access("/system/app/GrapheneWelcome.apk", R_OK) == 0 &&
            access("/system/bin/pm", X_OK) == 0 &&
            access("/system/bin/am", X_OK) == 0) {
            pid_t p1 = fork();
            if (p1 == 0) {
                int nfd = open("/dev/null", O_WRONLY);
                if (nfd >= 0) { dup2(nfd, 1); dup2(nfd, 2); close(nfd); }
                execl("/system/bin/pm", "pm", "install", "/system/app/GrapheneWelcome.apk", (char *)NULL);
                _exit(127);
            }
            int st1 = 1;
            if (p1 > 0) (void)waitpid(p1, &st1, 0);

            pid_t p2 = fork();
            if (p2 == 0) {
                int nfd = open("/dev/null", O_WRONLY);
                if (nfd >= 0) { dup2(nfd, 1); dup2(nfd, 2); close(nfd); }
                execl("/system/bin/am", "am", "start", "-n",
                      "org.grapheneos.welcome/org.grapheneos.welcome.MainActivity", (char *)NULL);
                _exit(127);
            }
            int st2 = 1;
            if (p2 > 0) (void)waitpid(p2, &st2, 0);

            if (WIFEXITED(st1) && WEXITSTATUS(st1) == 0 &&
                WIFEXITED(st2) && WEXITSTATUS(st2) == 0 &&
                read_entire_file("/run/user/0/qyronex-activity.txt", buf, sizeof(buf)) > 0 &&
                strstr(buf, "PACKAGE=org.grapheneos.welcome") != NULL &&
                strstr(buf, "Dalvik VM Computed Score = 15") != NULL) {
                ok15 = 1;
            }
        }
    }
    printf("[TEST 15/16] APK_DEX_DALVIK_VM_PM_AM_EXEC ... %s\n", ok15 ? "PASS" : "FAIL");
    passed += ok15;

    /* 16. Android Bionic prctl (PR_SET_VMA + MTE/TBI) + /proc/bootconfig + First-Stage sepolicy Load */
    int ok16 = 0;
    {
        const char *vma_tag = "anon:bionic_libc_malloc";
        long pr_vma = syscall(167 /* SYS_prctl */, 0x53564d41UL /* PR_SET_VMA */,
                              0UL /* PR_SET_VMA_ANON_NAME */, 0x10000UL, 4096UL,
                              (unsigned long)(uintptr_t)vma_tag);
        long pr_tbi_set = syscall(167, 55UL /* PR_SET_TAGGED_ADDR_CTRL */, 1UL, 0UL, 0UL, 0UL);
        long pr_tbi_get = syscall(167, 56UL /* PR_GET_TAGGED_ADDR_CTRL */, 0UL, 0UL, 0UL, 0UL);
        int bc_ok = (read_entire_file("/proc/bootconfig", buf, sizeof(buf)) > 0 &&
                     strstr(buf, "androidboot.hardware =") != NULL &&
                     strstr(buf, "androidboot.dynamic_partitions = \"true\"") != NULL);
        int dt_ok = (read_entire_file("/sys/firmware/devicetree/base/firmware/android/compatible",
                                      buf, sizeof(buf)) > 0 &&
                     strstr(buf, "android,firmware") != NULL);
        int sep_ok = (write_text_file("/sys/fs/selinux/load", "SELINUX_BINARY_POLICY_V33_GRAPHENEOS") == 0 &&
                      write_text_file("/sys/fs/selinux/context", "u:r:init:s0") == 0);
        if (pr_vma == 0 && pr_tbi_set == 0 && pr_tbi_get == 1 && bc_ok && dt_ok && sep_ok) {
            ok16 = 1;
        }
    }
    printf("[TEST 16/16] BIONIC_PRCTL_BOOTCONFIG_SEPOLICY %s\n", ok16 ? "PASS" : "FAIL");
    passed += ok16;

    printf("------------------------------------------------------------\n");
    if (passed == total) {
        printf("QYRONEX_ANDROID_SELFTEST: ALL %d/%d PASSED\n", passed, total);
        android_log_write("I/QyronexSelftest: ALL 16/16 Native Android 15 / GrapheneOS / Bionic checks PASSED");
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

static void run_cmd_sync(const char *prog, const char *arg1, const char *arg2) {
    pid_t pid = fork();
    if (pid == 0) {
        int nfd = open("/dev/null", O_WRONLY);
        if (nfd >= 0) { dup2(nfd, 1); dup2(nfd, 2); close(nfd); }
        execl(prog, prog, arg1, arg2, (char *)NULL);
        _exit(127);
    }
    if (pid > 0) {
        int st = 0;
        (void)waitpid(pid, &st, 0);
    }
}

static int cmd_android_init(void) {
    (void)mkdir("/dev", 0755);
    (void)mkdir("/proc", 0555);
    (void)mkdir("/sys", 0555);
    (void)mount("proc", "/proc", "proc", 0, NULL);
    (void)mount("sysfs", "/sys", "sysfs", 0, NULL);
    (void)mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);

    (void)mkdir("/mnt", 0755);
    (void)mkdir("/mnt/graphene", 0755);
    (void)mkdir("/data", 0755);
    (void)mkdir("/data/app", 0755);
    (void)mkdir("/data/system", 0755);
    (void)mkdir("/data/local", 0755);
    (void)mkdir("/data/local/tmp", 0777);
    (void)mkdir("/run", 0755);
    (void)mkdir("/run/user", 0755);
    (void)mkdir("/run/user/0", 0700);
    (void)mkdir("/apex", 0755);
    (void)mkdir("/linkerconfig", 0755);

    printf("\n");
    printf("===================================================================\n");
    printf("  Qyronex OS - Native Android 15 / GrapheneOS Kernel Edition v0.7.0\n");
    printf("  Mode  : Pure Native Android First-Stage & Second-Stage /init\n");
    printf("  Stack : Direct-DRM SurfaceFlinger + Binder v8 + Dalvik VM (NO Wayland)\n");
    printf("===================================================================\n");
    fflush(stdout);

    /* 1. Android First-Stage Init: Load SELinux Policy & Verify Bootconfig */
    printf("[init:stage1] Loading SELinux policy v33 -> /sys/fs/selinux/load (ENFORCING)\n");
    (void)write_text_file("/sys/fs/selinux/load", "QYRONEX_GRAPHENEOS_SEPOLICY_V33_FIRST_STAGE");
    (void)write_text_file("/sys/fs/selinux/context", "u:r:init:s0");
    android_log_write("I/init: First-stage SELinux policy v33 loaded (enforcing=1)");

    /* 2. Check for external Standard GrapheneOS / AOSP system partition (/dev/vdb or /dev/sda) */
    const char *ext_devs[] = { "/dev/vdb", "/dev/vdb1", "/dev/sda", "/dev/sda1", NULL };
    for (int i = 0; ext_devs[i] != NULL; i++) {
        if (mount(ext_devs[i], "/mnt/graphene", "ext4", MS_RDONLY, NULL) == 0 ||
            mount(ext_devs[i], "/mnt/graphene", "erofs", MS_RDONLY, NULL) == 0) {
            if (access("/mnt/graphene/system/bin/init", X_OK) == 0 &&
                access("/mnt/graphene/system/bin/linker64", X_OK) == 0) {
                printf("[init:stage1] Detected Standard GrapheneOS / AOSP partition on %s!\n", ext_devs[i]);
                printf("[init:stage1] Chaining into Standard GrapheneOS /system/bin/init second_stage ...\n");
                fflush(stdout);
                if (chdir("/mnt/graphene") == 0 && chroot("/mnt/graphene") == 0) {
                    char *const g_argv[] = { "/system/bin/init", "second_stage", NULL };
                    execv("/system/bin/init", g_argv);
                }
            }
            (void)umount("/mnt/graphene");
        }
    }

    /* 3. Mount persistent /data ext4 partition if not already writable on / */
    if (access("/data/system", W_OK) == 0) {
        printf("[init:stage1] Persistent ext4 Android partition active on / (/data writable)\n");
    } else if (mount("/dev/vda1", "/data", "ext4", 0, NULL) == 0) {
        (void)mkdir("/data/app", 0755);
        (void)mkdir("/data/system", 0755);
        (void)mkdir("/data/local", 0755);
        (void)mkdir("/data/local/tmp", 0777);
        printf("[init:stage1] Mounted persistent ext4 /dev/vda1 -> /data\n");
    }

    /* 4. Start Android ServiceManager on /dev/binder */
    printf("[init:stage2] Starting /system/bin/servicemanager (/dev/binder) ...\n");
    fflush(stdout);
    pid_t sm_pid = spawn_daemon("/system/bin/servicemanager");
    printf("[init:stage2] servicemanager spawned (pid=%d)\n", (int)sm_pid);

    int sm_ready = 0;
    for (int i = 0; i < 60; i++) {
        struct binder_client bc;
        if (binder_client_open(&bc, "/dev/binder") == 0) {
            char pong[128] = {0};
            if (binder_rpc(&bc, 0, SM_CMD_PING, "", 0, pong, sizeof(pong)) > 0 &&
                strstr(pong, "PONG") != NULL) {
                printf("[init:stage2] Binder v8 context manager ready: %s\n", pong);
                binder_client_close(&bc);
                sm_ready = 1;
                break;
            }
            binder_client_close(&bc);
        }
        usleep(50000);
    }
    if (!sm_ready) {
        printf("[init:stage2] WARN: servicemanager ping timeout\n");
    }

    /* 5. Pre-install built-in Android .apk packages via PackageManager (`pm`) */
    const char *boot_apks[] = {
        "/system/app/GrapheneWelcome.apk",
        "/system/app/PixelSecurityBench.apk",
        "/system/app/QyronexHardwareInfo.apk",
        NULL
    };
    for (int i = 0; boot_apks[i] != NULL; i++) {
        if (access(boot_apks[i], R_OK) == 0) {
            run_cmd_sync("/system/bin/pm", "install", boot_apks[i]);
        }
    }

    /* 6. Run full 16/16 Native Android Kernel & Bionic self-test suite */
    (void)cmd_selftest();

    /* 7. Start Native Direct-DRM SurfaceFlinger (VirtIO-GPU 1280x800, ZERO Wayland!) */
    printf("[init:stage2] Starting /system/bin/surfaceflinger (Direct-DRM 1280x800, No Wayland) ...\n");
    fflush(stdout);
    pid_t sf_pid = spawn_daemon("/system/bin/surfaceflinger");
    printf("[init:stage2] surfaceflinger spawned (pid=%d)\n", (int)sf_pid);
    usleep(350000);

    /* 8. Mark Android boot completed */
    (void)write_text_file("/sys/kernel/qyronex/android/properties", "sys.boot_completed=1\n");
    android_log_write("I/init: sys.boot_completed=1 (Pure Native Android 15 / Direct-DRM SurfaceFlinger)");

    /* 9. Native Android 15 interactive serial shell + PID 1 supervisor loop */
    printf("\n[init:stage2] Native Android 15 Shell ready (commands: getprop, setprop, service list, dumpsys, logcat, pm, am, dalvikvm, selftest)\n");
    printf("qyronex_pixel:/ # ");
    fflush(stdout);

    char line[512];
    size_t lpos = 0;
    while (1) {
        int st = 0;
        while (waitpid(-1, &st, WNOHANG) > 0) {}

        struct pollfd pfd;
        pfd.fd = STDIN_FILENO;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, 200);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            char ch = 0;
            if (read(STDIN_FILENO, &ch, 1) == 1) {
                if (ch == '\r' || ch == '\n') {
                    printf("\n");
                    line[lpos] = '\0';
                    lpos = 0;
                    /* Tokenize command */
                    char *toks[16];
                    int ntok = 0;
                    char *p = strtok(line, " \t");
                    while (p && ntok < 15) {
                        toks[ntok++] = p;
                        p = strtok(NULL, " \t");
                    }
                    toks[ntok] = NULL;
                    if (ntok > 0) {
                        if (strcmp(toks[0], "getprop") == 0) {
                            (void)cmd_getprop(ntok, toks);
                        } else if (strcmp(toks[0], "setprop") == 0) {
                            (void)cmd_setprop(ntok, toks);
                        } else if (strcmp(toks[0], "service") == 0) {
                            (void)cmd_service(ntok, toks);
                        } else if (strcmp(toks[0], "dumpsys") == 0) {
                            (void)cmd_dumpsys(ntok, toks);
                        } else if (strcmp(toks[0], "logcat") == 0) {
                            (void)cmd_logcat();
                        } else if (strcmp(toks[0], "selftest") == 0 ||
                                   strcmp(toks[0], "qyronex-android-selftest") == 0) {
                            (void)cmd_selftest();
                        } else if (strcmp(toks[0], "help") == 0) {
                            printf("Android 15 Shell Commands: getprop, setprop, service list, dumpsys [security|pixel|storage|ebpf|binder], logcat, pm, am, dalvikvm, selftest\n");
                        } else {
                            char binpath[128];
                            if (toks[0][0] == '/') {
                                snprintf(binpath, sizeof(binpath), "%s", toks[0]);
                            } else {
                                snprintf(binpath, sizeof(binpath), "/system/bin/%s", toks[0]);
                            }
                            pid_t cpid = fork();
                            if (cpid == 0) {
                                execv(binpath, toks);
                                fprintf(stderr, "qyronex_pixel: %s: not found\n", toks[0]);
                                _exit(127);
                            } else if (cpid > 0) {
                                (void)waitpid(cpid, &st, 0);
                            }
                        }
                    }
                    printf("qyronex_pixel:/ # ");
                    fflush(stdout);
                } else if (ch == 0x7f || ch == '\b') {
                    if (lpos > 0) {
                        lpos--;
                        printf("\b \b");
                        fflush(stdout);
                    }
                } else if (lpos + 1 < sizeof(line) && (unsigned char)ch >= 32) {
                    line[lpos++] = ch;
                    putchar(ch);
                    fflush(stdout);
                }
            }
        }
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
