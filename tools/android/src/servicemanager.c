/* SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0 */
/* Native ARM64 Android ServiceManager daemon running on Qyronex /dev/binder (v8). */

#include "binder_abi.h"
#include <signal.h>

#define MAX_SERVICES 32

struct service_entry {
    int active;
    char name[96];
    int32_t owner_pid;
    uint32_t owner_uid;
    uint32_t handle;
};

static struct service_entry g_services[MAX_SERVICES];
static uint32_t g_next_handle = 100;
static volatile sig_atomic_t g_running = 1;

static void on_sigterm(int sig) {
    (void)sig;
    g_running = 0;
}

static int find_service(const char *name) {
    for (int i = 0; i < MAX_SERVICES; i++) {
        if (g_services[i].active && strcmp(g_services[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

static int add_service(const char *name, int32_t pid, uint32_t uid) {
    if (!name || !name[0]) return -1;
    int idx = find_service(name);
    if (idx < 0) {
        for (int i = 0; i < MAX_SERVICES; i++) {
            if (!g_services[i].active) {
                idx = i;
                break;
            }
        }
    }
    if (idx < 0) return -1;
    g_services[idx].active = 1;
    snprintf(g_services[idx].name, sizeof(g_services[idx].name), "%s", name);
    g_services[idx].owner_pid = pid;
    g_services[idx].owner_uid = uid;
    if (g_services[idx].handle == 0) {
        g_services[idx].handle = g_next_handle++;
    }
    return idx;
}

static void send_reply(int fd, const char *payload) {
    size_t len = strlen(payload);
    uint8_t wbuf[4 + sizeof(struct binder_transaction_data)];
    uint32_t cmd = BC_REPLY;
    struct binder_transaction_data tx;
    memset(&tx, 0, sizeof(tx));
    tx.data_size = (uint64_t)len;
    tx.data_ptr = (uint64_t)(uintptr_t)payload;
    memcpy(wbuf, &cmd, 4);
    memcpy(wbuf + 4, &tx, sizeof(tx));

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(wbuf);
    bwr.write_buffer = (uint64_t)(uintptr_t)wbuf;
    (void)ioctl(fd, BINDER_WRITE_READ, &bwr);
}

static void handle_transaction(int fd, const struct binder_transaction_data *tx) {
    char req[256];
    memset(req, 0, sizeof(req));
    if (tx->data_ptr != 0 && tx->data_size > 0) {
        size_t n = (size_t)tx->data_size;
        if (n >= sizeof(req)) n = sizeof(req) - 1;
        memcpy(req, (const void *)(uintptr_t)tx->data_ptr, n);
        /* Trim trailing newline/space */
        while (n > 0 && (req[n - 1] == '\n' || req[n - 1] == '\r' || req[n - 1] == ' ')) {
            req[--n] = '\0';
        }
    }

    char reply[1536];
    memset(reply, 0, sizeof(reply));

    switch (tx->code) {
        case SM_CMD_PING:
            snprintf(reply, sizeof(reply), "PONG qyronex-servicemanager pid=%d proto=8", (int)getpid());
            break;

        case SM_CMD_ADD_SERVICE: {
            int idx = add_service(req, tx->sender_pid, tx->sender_euid);
            if (idx >= 0) {
                snprintf(reply, sizeof(reply), "OK handle=%u name=%s",
                         g_services[idx].handle, g_services[idx].name);
                char logline[192];
                snprintf(logline, sizeof(logline),
                         "I/ServiceManager: +service '%s' handle=%u pid=%d uid=%u",
                         g_services[idx].name, g_services[idx].handle,
                         tx->sender_pid, tx->sender_euid);
                android_log_write(logline);
            } else {
                snprintf(reply, sizeof(reply), "ERR table_full");
            }
            break;
        }

        case SM_CMD_GET_SERVICE: {
            int idx = find_service(req);
            if (idx >= 0) {
                snprintf(reply, sizeof(reply), "FOUND handle=%u pid=%d uid=%u name=%s",
                         g_services[idx].handle, g_services[idx].owner_pid,
                         g_services[idx].owner_uid, g_services[idx].name);
            } else {
                snprintf(reply, sizeof(reply), "NOT_FOUND %s", req);
            }
            break;
        }

        case SM_CMD_LIST_SERVICES: {
            size_t pos = 0;
            int count = 0;
            for (int i = 0; i < MAX_SERVICES; i++) {
                if (g_services[i].active) {
                    int w = snprintf(reply + pos, sizeof(reply) - pos,
                                     "%d\t%s\t[handle=%u pid=%d]\n",
                                     count, g_services[i].name,
                                     g_services[i].handle, g_services[i].owner_pid);
                    if (w > 0 && pos + (size_t)w < sizeof(reply)) {
                        pos += (size_t)w;
                    }
                    count++;
                }
            }
            if (count == 0) {
                snprintf(reply, sizeof(reply), "(no services registered)\n");
            }
            break;
        }

        default:
            snprintf(reply, sizeof(reply), "ERR unknown_code=%u", tx->code);
            break;
    }

    if ((tx->flags & TF_ONE_WAY) == 0) {
        send_reply(fd, reply);
    }

    if (tx->data_ptr != 0) {
        uint8_t fbuf[12];
        uint32_t fcmd = BC_FREE_BUFFER;
        memcpy(fbuf, &fcmd, 4);
        memcpy(fbuf + 4, &tx->data_ptr, 8);
        struct binder_write_read fbwr;
        memset(&fbwr, 0, sizeof(fbwr));
        fbwr.write_size = sizeof(fbuf);
        fbwr.write_buffer = (uint64_t)(uintptr_t)fbuf;
        (void)ioctl(fd, BINDER_WRITE_READ, &fbwr);
    }
}

int main(void) {
    signal(SIGTERM, on_sigterm);
    signal(SIGINT, on_sigterm);

    struct binder_client bc;
    if (binder_client_open(&bc, "/dev/binder") < 0) {
        fprintf(stderr, "servicemanager: failed to open /dev/binder: %s\n", strerror(errno));
        return 1;
    }

    int dummy = 0;
    if (ioctl(bc.fd, BINDER_SET_CONTEXT_MGR, &dummy) < 0) {
        fprintf(stderr, "servicemanager: BINDER_SET_CONTEXT_MGR failed: %s\n", strerror(errno));
        binder_client_close(&bc);
        return 1;
    }

    /* Enter Binder looper. */
    uint32_t enter = BC_ENTER_LOOPER;
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(enter);
    bwr.write_buffer = (uint64_t)(uintptr_t)&enter;
    (void)ioctl(bc.fd, BINDER_WRITE_READ, &bwr);

    /* Register self as default context manager entry. */
    add_service("manager", (int32_t)getpid(), (uint32_t)geteuid());
    android_log_write("I/ServiceManager: Binder v8 context manager online (Qyronex CapRights enforced)");

    uint8_t rbuf[512];
    while (g_running) {
        memset(&bwr, 0, sizeof(bwr));
        bwr.read_size = sizeof(rbuf);
        bwr.read_buffer = (uint64_t)(uintptr_t)rbuf;
        if (ioctl(bc.fd, BINDER_WRITE_READ, &bwr) < 0) {
            if (errno == EINTR) continue;
            usleep(10000);
            continue;
        }
        size_t off = 0;
        while (off + 4 <= (size_t)bwr.read_consumed) {
            uint32_t br = 0;
            memcpy(&br, rbuf + off, 4);
            off += 4;
            if (br == BR_TRANSACTION) {
                if (off + sizeof(struct binder_transaction_data) <= (size_t)bwr.read_consumed) {
                    struct binder_transaction_data tx;
                    memcpy(&tx, rbuf + off, sizeof(tx));
                    off += sizeof(tx);
                    handle_transaction(bc.fd, &tx);
                }
            } else if (br == BR_REPLY) {
                off += sizeof(struct binder_transaction_data);
            } else if (br == BR_ERROR) {
                off += 4;
            }
        }
    }

    binder_client_close(&bc);
    return 0;
}
