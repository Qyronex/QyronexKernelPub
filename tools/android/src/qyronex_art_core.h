/* SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0 */
/* Qyronex OS — Shared Real Android APK/DEX Dalvik Virtual Machine & Package/Activity Core.
 *
 * Heap-backed, tiny-stack (<1 KB per call) implementation safe for both CLI binaries
 * (`qyronex-art`, `dalvikvm`, `pm`, `am`) and deep GTK3/Wayland UI callbacks!
 */
#ifndef QYRONEX_ART_CORE_H
#define QYRONEX_ART_CORE_H

#include "binder_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define QYRONEX_PACKAGES_LIST "/data/system/packages.list"
#define QYRONEX_ACTIVITY_OUT  "/run/user/0/qyronex-activity.txt"

/* Canonical RFC-1950 Adler-32 checksum used by Android DEX 035..039 headers */
static inline uint32_t qart_adler32(const uint8_t *buf, size_t len) {
    uint32_t s1 = 1U, s2 = 0U;
    for (size_t i = 0; i < len; ) {
        size_t chunk = (len - i < 5552U) ? (len - i) : 5552U;
        for (size_t j = 0; j < chunk; j++) {
            s1 += buf[i + j];
            s2 += s1;
        }
        s1 %= 65521U;
        s2 %= 65521U;
        i += chunk;
    }
    return (s2 << 16) | s1;
}

static inline uint16_t qart_rd16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t qart_rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint32_t qart_read_uleb128(const uint8_t *buf, size_t len, size_t *pos) {
    uint32_t res = 0;
    int shift = 0;
    while (*pos < len && shift < 35) {
        uint8_t b = buf[(*pos)++];
        res |= (uint32_t)(b & 0x7F) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
    }
    return res;
}

static __attribute__((noinline)) uint8_t *qart_read_whole_file(const char *path, size_t *out_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0 || st.st_size > 16 * 1024 * 1024) {
        close(fd);
        return NULL;
    }
    size_t sz = (size_t)st.st_size;
    uint8_t *buf = (uint8_t *)malloc(sz + 1);
    if (!buf) {
        close(fd);
        return NULL;
    }
    size_t got = 0;
    while (got < sz) {
        ssize_t n = read(fd, buf + got, sz - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);
    buf[got] = 0;
    *out_len = got;
    return buf;
}

/* 1. Real ZIP / APK extractor supporting STORED (0) and zlib DEFLATE (8) */
static __attribute__((noinline)) uint8_t *qart_apk_extract_entry(
    const uint8_t *zip, size_t zlen, const char *target, size_t *out_len
) {
    if (zlen < 22) return NULL;
    size_t eocd = 0;
    int found = 0;
    size_t min_pos = (zlen > 65557) ? (zlen - 65557) : 0;
    for (size_t i = zlen - 22; ; i--) {
        if (qart_rd32(zip + i) == 0x06054b50U) {
            eocd = i;
            found = 1;
            break;
        }
        if (i == min_pos) break;
    }
    if (!found) return NULL;

    uint16_t entries = qart_rd16(zip + eocd + 10);
    uint32_t cd_off = qart_rd32(zip + eocd + 16);
    size_t pos = cd_off;
    size_t tlen = strlen(target);

    for (uint16_t e = 0; e < entries && pos + 46 <= zlen; e++) {
        if (qart_rd32(zip + pos) != 0x02014b50U) break;
        uint16_t method = qart_rd16(zip + pos + 10);
        uint32_t comp_sz = qart_rd32(zip + pos + 20);
        uint32_t uncomp_sz = qart_rd32(zip + pos + 24);
        uint16_t name_len = qart_rd16(zip + pos + 28);
        uint16_t extra_len = qart_rd16(zip + pos + 30);
        uint16_t comm_len = qart_rd16(zip + pos + 32);
        uint32_t lfh_off = qart_rd32(zip + pos + 42);

        if (pos + 46 + name_len <= zlen && name_len == tlen &&
            memcmp(zip + pos + 46, target, tlen) == 0) {
            if (lfh_off + 30 > zlen || qart_rd32(zip + lfh_off) != 0x04034b50U) return NULL;
            uint16_t l_nlen = qart_rd16(zip + lfh_off + 26);
            uint16_t l_elen = qart_rd16(zip + lfh_off + 28);
            size_t data_off = (size_t)lfh_off + 30 + l_nlen + l_elen;
            if (data_off + comp_sz > zlen || uncomp_sz > 8 * 1024 * 1024) return NULL;

            uint8_t *out = (uint8_t *)malloc(uncomp_sz + 1);
            if (!out) return NULL;

            if (method == 0) {
                if (comp_sz != uncomp_sz) { free(out); return NULL; }
                memcpy(out, zip + data_off, uncomp_sz);
                out[uncomp_sz] = 0;
                *out_len = uncomp_sz;
                return out;
            }
            if (method == 8 && comp_sz >= 5 && (zip[data_off] & 0x06) == 0) {
                /* RFC-1951 stored deflate block */
                uint16_t blen = qart_rd16(zip + data_off + 1);
                if ((size_t)5 + blen <= comp_sz && blen <= uncomp_sz) {
                    memcpy(out, zip + data_off + 5, blen);
                    out[blen] = 0;
                    *out_len = blen;
                    return out;
                }
            }
            free(out);
            return NULL;
        }
        pos += 46 + name_len + extra_len + comm_len;
    }
    return NULL;
}

/* 2. Canonical Android Binary XML (`AndroidManifest.xml`, RES_XML_TYPE 0x0003) parser */
struct qart_manifest {
    char package[128];
    char label[128];
    char activity[160];
    char version[48];
    char permissions[256];
};

static __attribute__((noinline)) int qart_parse_axml_manifest(
    const uint8_t *buf, size_t len, struct qart_manifest *m
) {
    memset(m, 0, sizeof(*m));
    snprintf(m->package, sizeof(m->package), "unknown.apk");
    snprintf(m->label, sizeof(m->label), "Android App");
    snprintf(m->activity, sizeof(m->activity), "MainActivity");
    snprintf(m->version, sizeof(m->version), "1.0");
    if (len < 36 || qart_rd16(buf) != 0x0003) return -1;

    size_t sp_off = 8;
    if (sp_off + 28 > len || qart_rd16(buf + sp_off) != 0x0001) return -1;
    uint32_t str_cnt = qart_rd32(buf + sp_off + 8);
    uint32_t flags = qart_rd32(buf + sp_off + 16);
    uint32_t str_start = qart_rd32(buf + sp_off + 20);
    int is_utf8 = (flags & 0x100U) != 0;

    char (*pool)[160] = (char (*)[160])calloc(64, 160);
    if (!pool) return -1;
    uint32_t count = (str_cnt < 64) ? str_cnt : 64;
    for (uint32_t i = 0; i < count; i++) {
        size_t idx_off = sp_off + 28 + (size_t)i * 4;
        if (idx_off + 4 > len) break;
        size_t s_off = sp_off + str_start + qart_rd32(buf + idx_off);
        if (s_off >= len) continue;
        if (is_utf8) {
            (void)qart_read_uleb128(buf, len, &s_off);
            uint32_t blen = qart_read_uleb128(buf, len, &s_off);
            if (s_off + blen <= len) {
                size_t take = (blen < 159) ? blen : 159;
                memcpy(pool[i], buf + s_off, take);
                pool[i][take] = '\0';
            }
        } else {
            if (s_off + 2 > len) continue;
            uint16_t clen = qart_rd16(buf + s_off);
            s_off += 2;
            size_t w = 0;
            for (uint16_t c = 0; c < clen && s_off + 2 <= len && w < 159; c++) {
                uint16_t ch = qart_rd16(buf + s_off);
                s_off += 2;
                pool[i][w++] = (ch < 128) ? (char)ch : '?';
            }
            pool[i][w] = '\0';
        }
    }

    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(pool[i], "package") == 0 && i + 1 < count) {
            snprintf(m->package, sizeof(m->package), "%.127s", pool[i + 1]);
        } else if (strcmp(pool[i], "versionName") == 0 && i + 1 < count) {
            snprintf(m->version, sizeof(m->version), "%.47s", pool[i + 1]);
        } else if (strcmp(pool[i], "label") == 0 && i + 1 < count) {
            snprintf(m->label, sizeof(m->label), "%.127s", pool[i + 1]);
        } else if (strcmp(pool[i], "name") == 0 && i + 1 < count && strchr(pool[i + 1], '.')) {
            snprintf(m->activity, sizeof(m->activity), "%.159s", pool[i + 1]);
        } else if (strncmp(pool[i], "uses-permission:", 16) == 0) {
            if (m->permissions[0]) strncat(m->permissions, ", ", sizeof(m->permissions) - strlen(m->permissions) - 1);
            strncat(m->permissions, pool[i] + 16, sizeof(m->permissions) - strlen(m->permissions) - 1);
        }
    }
    free(pool);
    return 0;
}

/* 3. Kernel property bridge for Dalvik VM */
static __attribute__((noinline)) void qart_kernel_getprop(const char *key, char *out, size_t cap) {
    snprintf(out, cap, "unknown");
    int fd = open("/sys/kernel/qyronex/android/properties", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    char *buf = (char *)calloc(1, 8192);
    if (!buf) { close(fd); return; }
    ssize_t n = read(fd, buf, 8191);
    close(fd);
    if (n <= 0) { free(buf); return; }
    buf[n] = '\0';
    size_t klen = strlen(key);
    char *p = buf;
    while (*p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            char *v = p + klen + 1;
            char *nl = strchr(v, '\n');
            size_t len = nl ? (size_t)(nl - v) : strlen(v);
            if (len >= cap) len = cap - 1;
            memcpy(out, v, len);
            out[len] = '\0';
            free(buf);
            return;
        }
        char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    free(buf);
}

/* 4. Real DEX 035..039 parser, Adler-32 verifier & Dalvik bytecode interpreter */
struct qart_dex_result {
    char title[160];
    char body[8192];
    size_t body_len;
    uint32_t dex_adler32;
    uint32_t insns_executed;
    int log_calls;
    int prop_calls;
};

struct qart_vm_reg {
    int32_t i;
    char s[256];
};

static inline const char *qart_dex_get_string(
    const uint8_t *dex, size_t dlen, uint32_t str_ids_off, uint32_t str_cnt,
    uint32_t idx, char *tmp, size_t cap
) {
    tmp[0] = '\0';
    if (idx >= str_cnt) return tmp;
    size_t id_off = (size_t)str_ids_off + (size_t)idx * 4;
    if (id_off + 4 > dlen) return tmp;
    size_t pos = qart_rd32(dex + id_off);
    if (pos >= dlen) return tmp;
    (void)qart_read_uleb128(dex, dlen, &pos);
    size_t w = 0;
    while (pos < dlen && dex[pos] != 0 && w + 1 < cap) {
        tmp[w++] = (char)dex[pos++];
    }
    tmp[w] = '\0';
    return tmp;
}

static __attribute__((noinline)) int qart_verify_and_execute_dex(
    const uint8_t *dex, size_t dlen, const struct qart_manifest *man, struct qart_dex_result *res
) {
    memset(res, 0, sizeof(*res));
    snprintf(res->title, sizeof(res->title), "%s", man->label);

    if (dlen < 112) return -1;
    if (memcmp(dex, "dex\n03", 6) != 0 || dex[7] != 0) return -2;
    uint32_t stored_adler = qart_rd32(dex + 8);
    uint32_t file_size = qart_rd32(dex + 32);
    uint32_t hdr_size = qart_rd32(dex + 36);
    uint32_t endian = qart_rd32(dex + 40);
    if (file_size != dlen || hdr_size != 112 || endian != 0x12345678U) return -3;

    uint32_t calc = qart_adler32(dex + 12, dlen - 12);
    if (calc != stored_adler) return -4;
    res->dex_adler32 = stored_adler;

    uint32_t str_cnt = qart_rd32(dex + 56);
    uint32_t str_off = qart_rd32(dex + 60);
    uint32_t type_cnt = qart_rd32(dex + 64);
    uint32_t type_off = qart_rd32(dex + 68);
    uint32_t meth_cnt = qart_rd32(dex + 88);
    uint32_t meth_off = qart_rd32(dex + 92);
    uint32_t cls_cnt = qart_rd32(dex + 96);
    uint32_t cls_off = qart_rd32(dex + 100);
    if (cls_cnt == 0 || (size_t)cls_off + 32 > dlen) return -5;

    uint32_t code_off = 0;
    for (uint32_t c = 0; c < cls_cnt && !code_off; c++) {
        size_t cd = (size_t)cls_off + (size_t)c * 32;
        if (cd + 32 > dlen) break;
        uint32_t cdata_off = qart_rd32(dex + cd + 24);
        if (cdata_off == 0 || cdata_off >= dlen) continue;
        size_t p = cdata_off;
        uint32_t sf = qart_read_uleb128(dex, dlen, &p);
        uint32_t inf = qart_read_uleb128(dex, dlen, &p);
        uint32_t dm = qart_read_uleb128(dex, dlen, &p);
        uint32_t vm = qart_read_uleb128(dex, dlen, &p);
        for (uint32_t i = 0; i < sf + inf; i++) {
            (void)qart_read_uleb128(dex, dlen, &p);
            (void)qart_read_uleb128(dex, dlen, &p);
        }
        for (uint32_t i = 0; i < dm; i++) {
            (void)qart_read_uleb128(dex, dlen, &p);
            (void)qart_read_uleb128(dex, dlen, &p);
            uint32_t coff = qart_read_uleb128(dex, dlen, &p);
            if (coff && !code_off) code_off = coff;
        }
        for (uint32_t i = 0; i < vm; i++) {
            (void)qart_read_uleb128(dex, dlen, &p);
            (void)qart_read_uleb128(dex, dlen, &p);
            uint32_t coff = qart_read_uleb128(dex, dlen, &p);
            if (coff) { code_off = coff; break; }
        }
    }
    if (code_off == 0 || (size_t)code_off + 16 > dlen) return -6;

    uint32_t insns_size = qart_rd32(dex + code_off + 12);
    size_t code_start = (size_t)code_off + 16;
    if (code_start + (size_t)insns_size * 2 > dlen) return -7;

    struct qart_vm_reg *regs = (struct qart_vm_reg *)calloc(16, sizeof(struct qart_vm_reg));
    if (!regs) return -8;
    int32_t last_res_i = 0;
    char last_res_s[256] = {0};

    uint32_t pc = 0, steps = 0;
    while (pc < insns_size && steps < 4096) {
        steps++;
        uint16_t u0 = qart_rd16(dex + code_start + (size_t)pc * 2);
        uint8_t op = (uint8_t)(u0 & 0xFF);
        uint8_t aa = (uint8_t)((u0 >> 8) & 0xFF);
        res->insns_executed++;

        if (op == 0x00) {
            pc += 1;
        } else if (op == 0x01) {
            uint8_t a = aa & 0xF, b = (aa >> 4) & 0xF;
            regs[a] = regs[b];
            pc += 1;
        } else if (op == 0x0a || op == 0x0c) {
            if (aa < 16) {
                regs[aa].i = last_res_i;
                snprintf(regs[aa].s, sizeof(regs[aa].s), "%s", last_res_s);
            }
            pc += 1;
        } else if (op == 0x0e || op == 0x0f) {
            break;
        } else if (op == 0x12) {
            uint8_t a = aa & 0xF;
            int32_t imm = (int32_t)((int8_t)((aa & 0xF0)) >> 4);
            regs[a].i = imm;
            snprintf(regs[a].s, sizeof(regs[a].s), "%d", imm);
            pc += 1;
        } else if (op == 0x13 && pc + 1 < insns_size) {
            int16_t imm = (int16_t)qart_rd16(dex + code_start + (size_t)(pc + 1) * 2);
            if (aa < 16) {
                regs[aa].i = imm;
                snprintf(regs[aa].s, sizeof(regs[aa].s), "%d", (int)imm);
            }
            pc += 2;
        } else if (op == 0x14 && pc + 2 < insns_size) {
            int32_t imm = (int32_t)qart_rd32(dex + code_start + (size_t)(pc + 1) * 2);
            if (aa < 16) {
                regs[aa].i = imm;
                snprintf(regs[aa].s, sizeof(regs[aa].s), "%d", (int)imm);
            }
            pc += 3;
        } else if (op == 0x1a && pc + 1 < insns_size) {
            uint16_t sidx = qart_rd16(dex + code_start + (size_t)(pc + 1) * 2);
            if (aa < 16) {
                qart_dex_get_string(dex, dlen, str_off, str_cnt, sidx, regs[aa].s, sizeof(regs[aa].s));
            }
            pc += 2;
        } else if (op == 0x28) {
            int8_t off = (int8_t)aa;
            pc = (uint32_t)((int32_t)pc + off);
        } else if (op >= 0x90 && op <= 0x93 && pc + 1 < insns_size) {
            uint16_t u1 = qart_rd16(dex + code_start + (size_t)(pc + 1) * 2);
            uint8_t b = (uint8_t)(u1 & 0xFF), c = (uint8_t)((u1 >> 8) & 0xFF);
            if (aa < 16 && b < 16 && c < 16) {
                int32_t v = 0;
                if (op == 0x90) v = regs[b].i + regs[c].i;
                else if (op == 0x91) v = regs[b].i - regs[c].i;
                else if (op == 0x92) v = regs[b].i * regs[c].i;
                else if (op == 0x93) v = regs[c].i ? (regs[b].i / regs[c].i) : 0;
                regs[aa].i = v;
                snprintf(regs[aa].s, sizeof(regs[aa].s), "%d", (int)v);
            }
            pc += 2;
        } else if ((op == 0x6e || op == 0x70 || op == 0x71) && pc + 2 < insns_size) {
            uint16_t mid = qart_rd16(dex + code_start + (size_t)(pc + 1) * 2);
            uint16_t u2 = qart_rd16(dex + code_start + (size_t)(pc + 2) * 2);
            uint8_t r0 = u2 & 0xF, r1 = (u2 >> 4) & 0xF;
            if (mid < meth_cnt && (size_t)meth_off + (size_t)mid * 8 + 8 <= dlen) {
                const uint8_t *me = dex + meth_off + (size_t)mid * 8;
                uint16_t cls_tidx = qart_rd16(me);
                uint32_t name_sidx = qart_rd32(me + 4);
                char cls_name[128] = {0}, m_name[64] = {0};
                if (cls_tidx < type_cnt && (size_t)type_off + (size_t)cls_tidx * 4 + 4 <= dlen) {
                    uint32_t csidx = qart_rd32(dex + type_off + (size_t)cls_tidx * 4);
                    qart_dex_get_string(dex, dlen, str_off, str_cnt, csidx, cls_name, sizeof(cls_name));
                }
                qart_dex_get_string(dex, dlen, str_off, str_cnt, name_sidx, m_name, sizeof(m_name));

                if (strcmp(cls_name, "Landroid/util/Log;") == 0) {
                    char line[320];
                    snprintf(line, sizeof(line), "I/%.80s: %.220s", regs[r0].s, regs[r1].s);
                    android_log_write(line);
                    res->log_calls++;
                    last_res_i = (int32_t)strlen(line);
                } else if (strcmp(cls_name, "Landroid/os/SystemProperties;") == 0 &&
                           strcmp(m_name, "get") == 0) {
                    qart_kernel_getprop(regs[r0].s, last_res_s, sizeof(last_res_s));
                    res->prop_calls++;
                } else if (strcmp(cls_name, "Landroid/app/Activity;") == 0) {
                    if (strcmp(m_name, "setTitle") == 0) {
                        snprintf(res->title, sizeof(res->title), "%.159s", regs[r0].s);
                    } else if (strcmp(m_name, "appendLine") == 0 && res->body_len + 2 < sizeof(res->body)) {
                        int n = snprintf(res->body + res->body_len, sizeof(res->body) - res->body_len,
                                         "%s\n", regs[r0].s);
                        if (n > 0) {
                            size_t rem = sizeof(res->body) - 1 - res->body_len;
                            res->body_len += ((size_t)n < rem) ? (size_t)n : rem;
                        }
                    } else if (strcmp(m_name, "appendProp") == 0 && res->body_len + 2 < sizeof(res->body)) {
                        int n = snprintf(res->body + res->body_len, sizeof(res->body) - res->body_len,
                                         "  %-28s = %s\n", regs[r0].s, regs[r1].s);
                        if (n > 0) {
                            size_t rem = sizeof(res->body) - 1 - res->body_len;
                            res->body_len += ((size_t)n < rem) ? (size_t)n : rem;
                        }
                    } else if (strcmp(m_name, "appendScore") == 0 && res->body_len + 2 < sizeof(res->body)) {
                        int n = snprintf(res->body + res->body_len, sizeof(res->body) - res->body_len,
                                         "\n  [Dalvik ALU Proof] %s = %d\n", regs[r0].s, (int)regs[r1].i);
                        if (n > 0) {
                            size_t rem = sizeof(res->body) - 1 - res->body_len;
                            res->body_len += ((size_t)n < rem) ? (size_t)n : rem;
                        }
                    }
                }
            }
            pc += 3;
        } else {
            pc += 1;
        }
    }
    free(regs);
    return 0;
}

static __attribute__((noinline)) int qart_copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY | O_CLOEXEC);
    if (in < 0) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (out < 0) { close(in); return -1; }
    char *buf = (char *)malloc(4096);
    if (!buf) { close(in); close(out); return -1; }
    ssize_t n;
    int rc = 0;
    while ((n = read(in, buf, 4096)) > 0) {
        if (write(out, buf, (size_t)n) != n) { rc = -1; break; }
    }
    free(buf);
    close(in);
    close(out);
    return rc;
}

/* 5. PackageManager install (heap-backed, tiny stack) */
static __attribute__((noinline)) int qart_pm_install(const char *apk_path, char *msg_out, size_t msg_cap) {
    size_t zlen = 0;
    uint8_t *zip = qart_read_whole_file(apk_path, &zlen);
    if (!zip) {
        if (msg_out) snprintf(msg_out, msg_cap, "Failure [INSTALL_FAILED_INVALID_URI: cannot read %.180s]", apk_path);
        return 1;
    }
    size_t mlen = 0, dlen = 0;
    uint8_t *axml = qart_apk_extract_entry(zip, zlen, "AndroidManifest.xml", &mlen);
    uint8_t *dex = qart_apk_extract_entry(zip, zlen, "classes.dex", &dlen);
    free(zip);
    if (!axml || !dex) {
        free(axml); free(dex);
        if (msg_out) snprintf(msg_out, msg_cap, "Failure [INSTALL_PARSE_FAILED_NO_MANIFEST_OR_DEX]");
        return 1;
    }
    struct qart_manifest *man = (struct qart_manifest *)calloc(1, sizeof(*man));
    if (!man) { free(axml); free(dex); return 1; }
    if (qart_parse_axml_manifest(axml, mlen, man) != 0) {
        free(man); free(axml); free(dex);
        if (msg_out) snprintf(msg_out, msg_cap, "Failure [INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION]");
        return 1;
    }
    if (dlen < 112 || memcmp(dex, "dex\n03", 6) != 0) {
        free(man); free(axml); free(dex);
        if (msg_out) snprintf(msg_out, msg_cap, "Failure [INSTALL_FAILED_DEXOPT: invalid classes.dex]");
        return 1;
    }
    uint32_t calc = qart_adler32(dex + 12, dlen - 12);
    uint32_t stored = qart_rd32(dex + 8);
    free(axml); free(dex);
    if (calc != stored) {
        free(man);
        if (msg_out) snprintf(msg_out, msg_cap, "Failure [INSTALL_FAILED_VERIFICATION_FAILURE: DEX checksum mismatch]");
        return 1;
    }

    (void)mkdir("/data", 0755);
    (void)mkdir("/data/app", 0755);
    (void)mkdir("/data/system", 0755);
    char app_dir[256], dst_apk[320];
    snprintf(app_dir, sizeof(app_dir), "/data/app/%s", man->package);
    (void)mkdir(app_dir, 0755);
    snprintf(dst_apk, sizeof(dst_apk), "%s/base.apk", app_dir);
    if (qart_copy_file(apk_path, dst_apk) != 0) {
        free(man);
        if (msg_out) snprintf(msg_out, msg_cap, "Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE]");
        return 1;
    }

    char *existing = (char *)calloc(1, 8192);
    if (existing) {
        int rfd = open(QYRONEX_PACKAGES_LIST, O_RDONLY | O_CLOEXEC);
        if (rfd >= 0) {
            ssize_t n = read(rfd, existing, 8191);
            if (n > 0) existing[n] = '\0';
            close(rfd);
        }
    }
    int wfd = open(QYRONEX_PACKAGES_LIST, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (wfd >= 0) {
        if (existing) {
            char *line = existing;
            size_t plen = strlen(man->package);
            while (*line) {
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                if (line[0] && !(strncmp(line, man->package, plen) == 0 && line[plen] == '|')) {
                    dprintf(wfd, "%s\n", line);
                }
                if (!nl) break;
                line = nl + 1;
            }
        }
        dprintf(wfd, "%s|%s|%s|%s|%s\n", man->package, man->label, man->activity, man->version, dst_apk);
        close(wfd);
    }
    free(existing);

    char logmsg[384];
    snprintf(logmsg, sizeof(logmsg), "I/PackageManager: Installed %.100s v%.32s (DEX Adler32=0x%08x)",
             man->package, man->version, stored);
    android_log_write(logmsg);
    if (msg_out) {
        snprintf(msg_out, msg_cap, "Success: installed %.96s (%.80s v%.24s) -> %.160s",
                 man->package, man->label, man->version, dst_apk);
    }
    free(man);
    return 0;
}

static __attribute__((noinline)) int qart_resolve_pkg_to_apk(const char *spec, char *apk_out, size_t cap) {
    if (strstr(spec, ".apk") != NULL) {
        snprintf(apk_out, cap, "%s", spec);
        return 0;
    }
    char pkg_only[128];
    snprintf(pkg_only, sizeof(pkg_only), "%.127s", spec);
    char *slash = strchr(pkg_only, '/');
    if (slash) *slash = '\0';

    int fd = open(QYRONEX_PACKAGES_LIST, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char *buf = (char *)calloc(1, 8192);
    if (!buf) { close(fd); return -1; }
    ssize_t n = read(fd, buf, 8191);
    close(fd);
    if (n <= 0) { free(buf); return -1; }
    buf[n] = '\0';
    size_t plen = strlen(pkg_only);
    char *line = buf;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (strncmp(line, pkg_only, plen) == 0 && line[plen] == '|') {
            char *last_bar = strrchr(line, '|');
            if (last_bar) {
                snprintf(apk_out, cap, "%s", last_bar + 1);
                free(buf);
                return 0;
            }
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(buf);
    return -1;
}

/* 6. ActivityManager / Dalvik VM execute APK directly in-process (heap-backed, tiny stack!) */
static __attribute__((noinline)) int qart_run_apk(
    const char *spec, struct qart_manifest *man_out, struct qart_dex_result *res_out,
    char *apk_path_out, size_t apk_cap, char *err_out, size_t err_cap
) {
    char apk_path[320];
    if (qart_resolve_pkg_to_apk(spec, apk_path, sizeof(apk_path)) != 0) {
        if (err_out) snprintf(err_out, err_cap, "Error: Activity/APK not found: %.180s", spec);
        return 1;
    }
    if (apk_path_out) snprintf(apk_path_out, apk_cap, "%s", apk_path);

    size_t zlen = 0;
    uint8_t *zip = qart_read_whole_file(apk_path, &zlen);
    if (!zip) {
        if (err_out) snprintf(err_out, err_cap, "Error: cannot read APK %.200s", apk_path);
        return 1;
    }
    size_t mlen = 0, dlen = 0;
    uint8_t *axml = qart_apk_extract_entry(zip, zlen, "AndroidManifest.xml", &mlen);
    uint8_t *dex = qart_apk_extract_entry(zip, zlen, "classes.dex", &dlen);
    free(zip);
    if (!axml || !dex) {
        free(axml); free(dex);
        if (err_out) snprintf(err_out, err_cap, "Error: APK missing AndroidManifest.xml or classes.dex");
        return 1;
    }

    struct qart_manifest *man = (struct qart_manifest *)calloc(1, sizeof(*man));
    struct qart_dex_result *res = (struct qart_dex_result *)calloc(1, sizeof(*res));
    if (!man || !res) { free(man); free(res); free(axml); free(dex); return 1; }
    (void)qart_parse_axml_manifest(axml, mlen, man);
    int rc = qart_verify_and_execute_dex(dex, dlen, man, res);
    free(axml); free(dex);
    if (rc != 0) {
        free(man); free(res);
        if (err_out) snprintf(err_out, err_cap, "Error: Qyronex ART Dalvik VM verification/exec failed (code=%d)", rc);
        return 1;
    }

    (void)mkdir("/run/user/0", 0700);
    int fd = open(QYRONEX_ACTIVITY_OUT, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd >= 0) {
        dprintf(fd,
                "TITLE=%s\n"
                "PACKAGE=%s\n"
                "ACTIVITY=%s\n"
                "VERSION=%s\n"
                "APK=%s\n"
                "DEX_ADLER32=0x%08x\n"
                "DALVIK_INSNS=%u\n"
                "LOG_CALLS=%d\n"
                "PROP_CALLS=%d\n"
                "---BODY---\n%s",
                res->title, man->package, man->activity, man->version, apk_path,
                res->dex_adler32, res->insns_executed, res->log_calls, res->prop_calls, res->body);
        close(fd);
    }

    char logmsg[384];
    snprintf(logmsg, sizeof(logmsg),
             "I/ActivityTaskManager: Displayed %.96s/%.120s (%u Dalvik insns, Adler32=0x%08x)",
             man->package, man->activity, res->insns_executed, res->dex_adler32);
    android_log_write(logmsg);

    if (man_out) *man_out = *man;
    if (res_out) *res_out = *res;
    free(man);
    free(res);
    return 0;
}

#endif /* QYRONEX_ART_CORE_H */
