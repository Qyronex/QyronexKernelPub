/* SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0 */
/* Shared 64-bit Android Binder v8 + Ashmem + DMA-Heap + ServiceManager ABI header. */
#ifndef QYRONEX_BINDER_ABI_H
#define QYRONEX_BINDER_ABI_H

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

/* 64-bit AArch64 Android Binder ioctls (exact Linux UAPI encoding). */
#define BINDER_WRITE_READ           0xc0306201UL
#define BINDER_SET_IDLE_TIMEOUT     0x40086203UL
#define BINDER_SET_MAX_THREADS      0x40046205UL
#define BINDER_SET_IDLE_PRIORITY    0x40046206UL
#define BINDER_SET_CONTEXT_MGR      0x40046207UL
#define BINDER_THREAD_EXIT          0x40046208UL
#define BINDER_VERSION              0xc0046209UL
#define BINDER_CURRENT_VERSION      8

/* Binder driver commands (BC_*) and return codes (BR_*). */
#define BC_TRANSACTION              0x40406300U
#define BC_REPLY                    0x40406301U
#define BC_FREE_BUFFER              0x40086303U
#define BC_INCREFS                  0x40046304U
#define BC_ACQUIRE                  0x40046305U
#define BC_RELEASE                  0x40046306U
#define BC_DECREFS                  0x40046307U
#define BC_REGISTER_LOOPER          0x0000630bU
#define BC_ENTER_LOOPER             0x0000630cU
#define BC_EXIT_LOOPER              0x0000630dU

#define BR_ERROR                    0x80047200U
#define BR_OK                       0x00007201U
#define BR_TRANSACTION              0x80407202U
#define BR_REPLY                    0x80407203U
#define BR_TRANSACTION_COMPLETE     0x00007206U
#define BR_NOOP                     0x0000720cU
#define BR_FAILED_REPLY             0x00007211U

#define TF_ONE_WAY                  0x01U

/* Android Ashmem + DMA-Heap ioctls. */
#define ASHMEM_SET_NAME             0x41007701UL
#define ASHMEM_GET_NAME             0x81007702UL
#define ASHMEM_SET_SIZE             0x40087703UL
#define ASHMEM_GET_SIZE             0x00007704UL
#define ASHMEM_SET_PROT_MASK        0x40087705UL
#define ASHMEM_GET_PROT_MASK        0x00007706UL
#define ASHMEM_PIN                  0x40087707UL
#define ASHMEM_UNPIN                0x40087708UL
#define ASHMEM_GET_PIN_STATUS       0x00007709UL
#define ASHMEM_PURGE_ALL_CACHES     0x0000770aUL

#define ASHMEM_NOT_PURGED           0
#define ASHMEM_IS_UNPINNED          0
#define ASHMEM_IS_PINNED            1

#define DMA_HEAP_IOCTL_ALLOC        0xc0184800UL
#define BINDER_CTL_ADD              0xc1086201UL
#define UFFDIO_API                  0xc018aa3fUL

/* 64-bit flat_binder_object types (Linux UAPI). */
#define BINDER_TYPE_BINDER          0x73622a85U
#define BINDER_TYPE_HANDLE          0x73682a85U
#define BINDER_TYPE_FD              0x66642a85U

/* Qyronex Android ServiceManager RPC codes (target handle = 0). */
#define SM_CMD_ADD_SERVICE          1U
#define SM_CMD_GET_SERVICE          2U
#define SM_CMD_LIST_SERVICES        3U
#define SM_CMD_PING                 4U
#define SM_CMD_ECHO_FD              5U

struct flat_binder_object {
    uint32_t hdr_type;
    uint32_t flags;
    uint64_t binder_or_handle;
    uint64_t cookie;
};

struct binderfs_device {
    char name[256];
    uint32_t major;
    uint32_t minor;
};

struct uffdio_api {
    uint64_t api;
    uint64_t features;
    uint64_t ioctls;
};

struct binder_write_read {
    uint64_t write_size;
    uint64_t write_consumed;
    uint64_t write_buffer;
    uint64_t read_size;
    uint64_t read_consumed;
    uint64_t read_buffer;
};

struct binder_transaction_data {
    uint64_t target_handle_or_ptr;
    uint64_t cookie;
    uint32_t code;
    uint32_t flags;
    int32_t  sender_pid;
    uint32_t sender_euid;
    uint64_t data_size;
    uint64_t offsets_size;
    uint64_t data_ptr;
    uint64_t offsets_ptr;
};

struct dma_heap_allocation_data {
    uint64_t len;
    uint32_t fd;
    uint32_t fd_flags;
    uint64_t heap_flags;
};

struct binder_client {
    int fd;
    void *map;
    size_t map_size;
};

static inline int binder_client_open(struct binder_client *c, const char *dev) {
    memset(c, 0, sizeof(*c));
    c->fd = open(dev ? dev : "/dev/binder", O_RDWR | O_CLOEXEC);
    if (c->fd < 0) return -1;
    int ver = 0;
    if (ioctl(c->fd, BINDER_VERSION, &ver) < 0 || ver != BINDER_CURRENT_VERSION) {
        close(c->fd);
        c->fd = -1;
        return -1;
    }
    uint32_t max_threads = 4;
    (void)ioctl(c->fd, BINDER_SET_MAX_THREADS, &max_threads);
    c->map_size = 128 * 1024;
    c->map = mmap(NULL, c->map_size, PROT_READ | PROT_WRITE, MAP_SHARED, c->fd, 0);
    if (c->map == MAP_FAILED) {
        c->map = NULL;
        close(c->fd);
        c->fd = -1;
        return -1;
    }
    return 0;
}

static inline void binder_client_close(struct binder_client *c) {
    if (c->map && c->map != MAP_FAILED) {
        munmap(c->map, c->map_size);
        c->map = NULL;
    }
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}

/* Synchronous Binder RPC to target handle (0 = servicemanager). Returns reply length or -1. */
static inline int binder_rpc(
    struct binder_client *c,
    uint32_t target_handle,
    uint32_t code,
    const void *req_data,
    size_t req_len,
    void *reply_buf,
    size_t reply_cap
) {
    uint8_t wbuf[4 + sizeof(struct binder_transaction_data)];
    uint32_t cmd = BC_TRANSACTION;
    struct binder_transaction_data tx;
    memset(&tx, 0, sizeof(tx));
    tx.target_handle_or_ptr = (uint64_t)target_handle;
    tx.code = code;
    tx.flags = 0;
    tx.data_size = (uint64_t)req_len;
    tx.data_ptr = (uint64_t)(uintptr_t)req_data;
    memcpy(wbuf, &cmd, 4);
    memcpy(wbuf + 4, &tx, sizeof(tx));

    uint8_t rbuf[512];
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(wbuf);
    bwr.write_buffer = (uint64_t)(uintptr_t)wbuf;
    bwr.read_size = sizeof(rbuf);
    bwr.read_buffer = (uint64_t)(uintptr_t)rbuf;

    if (ioctl(c->fd, BINDER_WRITE_READ, &bwr) < 0) {
        return -1;
    }

    /* Poll/read until BR_REPLY arrives (up to 64 driver roundtrips). */
    for (int attempt = 0; attempt < 64; attempt++) {
        size_t off = 0;
        while (off + 4 <= (size_t)bwr.read_consumed) {
            uint32_t br = 0;
            memcpy(&br, rbuf + off, 4);
            off += 4;
            if (br == BR_NOOP || br == BR_TRANSACTION_COMPLETE || br == BR_OK) {
                continue;
            }
            if (br == BR_FAILED_REPLY) {
                return -1;
            }
            if (br == BR_ERROR) {
                if (off + 4 <= (size_t)bwr.read_consumed) off += 4;
                return -1;
            }
            if (br == BR_REPLY) {
                if (off + sizeof(struct binder_transaction_data) > (size_t)bwr.read_consumed) {
                    return -1;
                }
                struct binder_transaction_data rtx;
                memcpy(&rtx, rbuf + off, sizeof(rtx));
                off += sizeof(rtx);
                size_t copy_n = (size_t)rtx.data_size;
                if (reply_buf && reply_cap > 0 && rtx.data_ptr != 0) {
                    if (copy_n >= reply_cap) copy_n = reply_cap - 1;
                    memcpy(reply_buf, (const void *)(uintptr_t)rtx.data_ptr, copy_n);
                    ((char *)reply_buf)[copy_n] = '\0';
                }
                if (rtx.data_ptr != 0) {
                    uint8_t fbuf[12];
                    uint32_t fcmd = BC_FREE_BUFFER;
                    memcpy(fbuf, &fcmd, 4);
                    memcpy(fbuf + 4, &rtx.data_ptr, 8);
                    struct binder_write_read fbwr;
                    memset(&fbwr, 0, sizeof(fbwr));
                    fbwr.write_size = sizeof(fbuf);
                    fbwr.write_buffer = (uint64_t)(uintptr_t)fbuf;
                    (void)ioctl(c->fd, BINDER_WRITE_READ, &fbwr);
                }
                return (int)rtx.data_size;
            }
            if (br == BR_TRANSACTION) {
                off += sizeof(struct binder_transaction_data);
            }
        }

        memset(&bwr, 0, sizeof(bwr));
        bwr.read_size = sizeof(rbuf);
        bwr.read_buffer = (uint64_t)(uintptr_t)rbuf;
        if (ioctl(c->fd, BINDER_WRITE_READ, &bwr) < 0) {
            return -1;
        }
    }
    return -1;
}

static inline void android_log_write(const char *msg) {
    int fd = open("/dev/log/main", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        size_t n = strlen(msg);
        (void)write(fd, msg, n);
        if (n == 0 || msg[n - 1] != '\n') (void)write(fd, "\n", 1);
        close(fd);
    }
}

#endif /* QYRONEX_BINDER_ABI_H */
