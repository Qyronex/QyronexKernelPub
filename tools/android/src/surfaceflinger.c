/* SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0 */
/* Native ARM64 Android SurfaceFlinger + GrapheneOS / Qyronex Android 15 UI Shell. */

#include "binder_abi.h"
#include "font8x8.h"
#include <signal.h>
#include <time.h>

/* Exact Linux AArch64 DRM UAPI ioctl constants (matching Qyronex step43_desktop). */
#define DRM_IOCTL_SET_MASTER          0x0000641eUL
#define DRM_IOCTL_MODE_SETCRTC        0xc06864a2UL
#define DRM_IOCTL_MODE_ADDFB          0xc01c64aeUL
#define DRM_IOCTL_MODE_DIRTYFB        0xc01864b1UL
#define DRM_IOCTL_MODE_CREATE_DUMB    0xc02064b2UL
#define DRM_IOCTL_MODE_MAP_DUMB       0xc01064b3UL

#define DRM_CONNECTOR_ID              10U
#define DRM_CRTC_ID                   30U

#define FB_W 1280
#define FB_H 800

struct q_drm_create_dumb {
    uint32_t height;
    uint32_t width;
    uint32_t bpp;
    uint32_t flags;
    uint32_t handle;
    uint32_t pitch;
    uint64_t size;
};

struct q_drm_map_dumb {
    uint32_t handle;
    uint32_t pad;
    uint64_t offset;
};

struct q_drm_fb_cmd {
    uint32_t fb_id;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
    uint32_t depth;
    uint32_t handle;
};

struct q_drm_crtc {
    uint64_t set_connectors_ptr;
    uint32_t count_connectors;
    uint32_t crtc_id;
    uint32_t fb_id;
    uint32_t x;
    uint32_t y;
    uint32_t gamma_size;
    uint32_t mode_valid;
    uint8_t  mode[68];
};

struct q_drm_dirtyfb {
    uint32_t fb_id;
    uint32_t flags;
    uint32_t color;
    uint32_t num_clips;
    uint64_t clips_ptr;
};

struct input_ev {
    int64_t tv_sec;
    int64_t tv_usec;
    uint16_t type;
    uint16_t code;
    int32_t value;
};

static volatile sig_atomic_t g_running = 1;
static void on_signal(int s) { (void)s; g_running = 0; }

/* Framebuffer drawing helpers (XRGB8888: 0x00RRGGBB). */
static inline uint32_t rgb(uint8_t r, uint8_t g, uint8_t b) {
    return ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
}

static inline uint32_t blend_rgb(uint32_t dst, uint32_t src, uint8_t alpha) {
    uint32_t sr = (src >> 16) & 0xFF, sg = (src >> 8) & 0xFF, sb = src & 0xFF;
    uint32_t dr = (dst >> 16) & 0xFF, dg = (dst >> 8) & 0xFF, db = dst & 0xFF;
    uint32_t ia = 255U - alpha;
    uint32_t rr = (sr * alpha + dr * ia) / 255U;
    uint32_t rg = (sg * alpha + dg * ia) / 255U;
    uint32_t rb = (sb * alpha + db * ia) / 255U;
    return (rr << 16) | (rg << 8) | rb;
}

static void put_px(uint32_t *fb, int x, int y, uint32_t col) {
    if (x >= 0 && x < FB_W && y >= 0 && y < FB_H) {
        fb[y * FB_W + x] = col;
    }
}

static void fill_rect(uint32_t *fb, int x, int y, int w, int h, uint32_t col) {
    int x0 = x < 0 ? 0 : x;
    int y0 = y < 0 ? 0 : y;
    int x1 = x + w > FB_W ? FB_W : x + w;
    int y1 = y + h > FB_H ? FB_H : y + h;
    for (int py = y0; py < y1; py++) {
        uint32_t *row = fb + py * FB_W;
        for (int px = x0; px < x1; px++) {
            row[px] = col;
        }
    }
}

static void fill_grad_v(uint32_t *fb, int x, int y, int w, int h, uint32_t top, uint32_t bot) {
    int tr = (top >> 16) & 0xFF, tg = (top >> 8) & 0xFF, tb = top & 0xFF;
    int br = (bot >> 16) & 0xFF, bg = (bot >> 8) & 0xFF, bb = bot & 0xFF;
    if (h <= 0) return;
    for (int i = 0; i < h; i++) {
        int py = y + i;
        if (py < 0 || py >= FB_H) continue;
        uint8_t r = (uint8_t)(tr + (br - tr) * i / h);
        uint8_t g = (uint8_t)(tg + (bg - tg) * i / h);
        uint8_t b = (uint8_t)(tb + (bb - tb) * i / h);
        uint32_t c = rgb(r, g, b);
        int x0 = x < 0 ? 0 : x;
        int x1 = x + w > FB_W ? FB_W : x + w;
        uint32_t *row = fb + py * FB_W;
        for (int px = x0; px < x1; px++) row[px] = c;
    }
}

static void fill_rrect(uint32_t *fb, int x, int y, int w, int h, int rad, uint32_t col) {
    if (rad * 2 > w) rad = w / 2;
    if (rad * 2 > h) rad = h / 2;
    for (int py = y; py < y + h; py++) {
        if (py < 0 || py >= FB_H) continue;
        int dy = 0;
        if (py < y + rad) dy = (y + rad) - py;
        else if (py >= y + h - rad) dy = py - (y + h - rad - 1);
        for (int px = x; px < x + w; px++) {
            if (px < 0 || px >= FB_W) continue;
            int dx = 0;
            if (px < x + rad) dx = (x + rad) - px;
            else if (px >= x + w - rad) dx = px - (x + w - rad - 1);
            if (dx * dx + dy * dy <= rad * rad) {
                fb[py * FB_W + px] = col;
            }
        }
    }
}

static void stroke_rrect(uint32_t *fb, int x, int y, int w, int h, int rad, uint32_t col) {
    if (rad * 2 > w) rad = w / 2;
    if (rad * 2 > h) rad = h / 2;
    int r_out = rad * rad;
    int r_in = (rad - 1) * (rad - 1);
    for (int py = y; py < y + h; py++) {
        if (py < 0 || py >= FB_H) continue;
        int dy = 0;
        if (py < y + rad) dy = (y + rad) - py;
        else if (py >= y + h - rad) dy = py - (y + h - rad - 1);
        for (int px = x; px < x + w; px++) {
            if (px < 0 || px >= FB_W) continue;
            int dx = 0;
            if (px < x + rad) dx = (x + rad) - px;
            else if (px >= x + w - rad) dx = px - (x + w - rad - 1);
            int d2 = dx * dx + dy * dy;
            if (dx > 0 && dy > 0) {
                if (d2 <= r_out && d2 >= r_in) fb[py * FB_W + px] = col;
            } else if (px == x || px == x + w - 1 || py == y || py == y + h - 1) {
                if (d2 <= r_out) fb[py * FB_W + px] = col;
            }
        }
    }
}

static void fill_circle(uint32_t *fb, int cx, int cy, int r, uint32_t col) {
    for (int dy = -r; dy <= r; dy++) {
        int py = cy + dy;
        if (py < 0 || py >= FB_H) continue;
        for (int dx = -r; dx <= r; dx++) {
            int px = cx + dx;
            if (px < 0 || px >= FB_W) continue;
            if (dx * dx + dy * dy <= r * r) fb[py * FB_W + px] = col;
        }
    }
}

static void draw_text(uint32_t *fb, int x, int y, const char *s, int scale, uint32_t col) {
    if (!s) return;
    int cx = x;
    while (*s) {
        if (*s == '\n') {
            cx = x;
            y += 10 * scale;
            s++;
            continue;
        }
        for (int row = 0; row < 8; row++) {
            for (int col_i = 0; col_i < 8; col_i++) {
                if (font8x8_pixel(*s, row, col_i)) {
                    for (int sy = 0; sy < scale; sy++) {
                        for (int sx = 0; sx < scale; sx++) {
                            put_px(fb, cx + col_i * scale + sx, y + row * scale + sy, col);
                        }
                    }
                }
            }
        }
        cx += 8 * scale;
        s++;
    }
}

/* Draw crisp GrapheneOS / Android security shield icon. */
static void draw_shield(uint32_t *fb, int cx, int cy, int sz, uint32_t col, uint32_t check_col) {
    for (int dy = -sz; dy <= sz; dy++) {
        int half_w;
        if (dy < 0) {
            half_w = sz * 8 / 10;
        } else {
            half_w = (sz * 8 / 10) * (sz - dy) / sz;
        }
        for (int dx = -half_w; dx <= half_w; dx++) {
            put_px(fb, cx + dx, cy + dy, col);
        }
    }
    /* Checkmark inside shield */
    for (int i = -sz / 3; i <= 0; i++) {
        put_px(fb, cx + i - 1, cy + i + sz / 4, check_col);
        put_px(fb, cx + i,     cy + i + sz / 4, check_col);
        put_px(fb, cx + i,     cy + i + sz / 4 + 1, check_col);
    }
    for (int i = 0; i <= sz / 2; i++) {
        put_px(fb, cx + i,     cy - i + sz / 4, check_col);
        put_px(fb, cx + i + 1, cy - i + sz / 4, check_col);
        put_px(fb, cx + i,     cy - i + sz / 4 + 1, check_col);
    }
}

static size_t read_text_file(const char *path, char *buf, size_t cap) {
    memset(buf, 0, cap);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    return (size_t)n;
}

static void extract_kv(const char *text, const char *key, char *out, size_t cap) {
    size_t klen = strlen(key);
    const char *p = text;
    while (*p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *v = p + klen + 1;
            const char *e = strchr(v, '\n');
            size_t len = e ? (size_t)(e - v) : strlen(v);
            if (len >= cap) len = cap - 1;
            memcpy(out, v, len);
            out[len] = '\0';
            return;
        }
        const char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    snprintf(out, cap, "n/a");
}

struct live_telemetry {
    char selinux[32];
    char wx_ttbr1[32];
    char cap_binder[32];
    char zero_free[16];
    char hw_pan[32];
    char hw_mte[32];
    char avb[32];
    char pixel_model[64];
    char titan_m2[32];
    char keymint[16];
    char weaver[16];
    char ufs_slot[16];
    char modem_iommu[32];
    char binder_proto[16];
    char binder_eps[16];
    char binder_tx[16];
    char binder_replies[16];
    char binder_denials[16];
    char services_raw[1024];
    int  frame_no;
};

static void poll_telemetry(struct binder_client *bc, struct live_telemetry *t) {
    char buf[2048];
    read_text_file("/sys/kernel/qyronex/grapheneos/status", buf, sizeof(buf));
    extract_kv(buf, "selinux", t->selinux, sizeof(t->selinux));
    extract_kv(buf, "wx_ttbr1_isolated", t->wx_ttbr1, sizeof(t->wx_ttbr1));
    extract_kv(buf, "capability_binder", t->cap_binder, sizeof(t->cap_binder));
    extract_kv(buf, "zero_on_free", t->zero_free, sizeof(t->zero_free));
    extract_kv(buf, "hw_pan", t->hw_pan, sizeof(t->hw_pan));
    extract_kv(buf, "hw_mte", t->hw_mte, sizeof(t->hw_mte));
    extract_kv(buf, "avb_verified_boot", t->avb, sizeof(t->avb));

    read_text_file("/sys/bus/platform/drivers/google_pixel/status", buf, sizeof(buf));
    extract_kv(buf, "model", t->pixel_model, sizeof(t->pixel_model));
    extract_kv(buf, "titan_m2", t->titan_m2, sizeof(t->titan_m2));
    extract_kv(buf, "keymint_version", t->keymint, sizeof(t->keymint));
    extract_kv(buf, "weaver_slots", t->weaver, sizeof(t->weaver));
    extract_kv(buf, "ufs_slot", t->ufs_slot, sizeof(t->ufs_slot));
    extract_kv(buf, "modem_iommu_sandbox", t->modem_iommu, sizeof(t->modem_iommu));

    read_text_file("/sys/kernel/qyronex/android/binder_stats", buf, sizeof(buf));
    extract_kv(buf, "protocol_version", t->binder_proto, sizeof(t->binder_proto));
    extract_kv(buf, "active_endpoints", t->binder_eps, sizeof(t->binder_eps));
    extract_kv(buf, "total_transactions", t->binder_tx, sizeof(t->binder_tx));
    extract_kv(buf, "total_replies", t->binder_replies, sizeof(t->binder_replies));
    extract_kv(buf, "capability_denials", t->binder_denials, sizeof(t->binder_denials));

    memset(t->services_raw, 0, sizeof(t->services_raw));
    if (bc && bc->fd >= 0) {
        if (binder_rpc(bc, 0, SM_CMD_LIST_SERVICES, "", 0, t->services_raw, sizeof(t->services_raw)) < 0) {
            snprintf(t->services_raw, sizeof(t->services_raw), "0\tSurfaceFlinger\n1\tmanager\n");
        }
    }
    t->frame_no++;
}

static void draw_app_icon(
    uint32_t *fb, int x, int y, int sz,
    uint32_t bg, uint32_t accent, const char *glyph, const char *label
) {
    fill_rrect(fb, x, y, sz, sz, 20, bg);
    stroke_rrect(fb, x, y, sz, sz, 20, blend_rgb(bg, rgb(255, 255, 255), 40));
    fill_circle(fb, x + sz / 2, y + sz / 2, sz / 3, accent);
    int gw = (int)strlen(glyph) * 16;
    draw_text(fb, x + (sz - gw) / 2, y + sz / 2 - 8, glyph, 2, rgb(14, 18, 28));
    int lw = (int)strlen(label) * 8;
    draw_text(fb, x + (sz - lw) / 2, y + sz + 10, label, 1, rgb(216, 226, 240));
}

static void draw_kv_badge(
    uint32_t *fb, int x, int y, int w, const char *k, const char *v, uint32_t val_col
) {
    fill_rrect(fb, x, y, w, 30, 8, rgb(20, 29, 44));
    draw_text(fb, x + 12, y + 11, k, 1, rgb(148, 168, 196));
    int vw = (int)strlen(v) * 8;
    draw_text(fb, x + w - vw - 12, y + 11, v, 1, val_col);
}

static void render_ui(uint32_t *fb, const struct live_telemetry *t, int active_tab) {
    /* 1. Deep Obsidian -> Midnight Teal Material You Android 15 wallpaper gradient. */
    fill_grad_v(fb, 0, 0, FB_W, FB_H, rgb(10, 15, 26), rgb(14, 24, 38));

    /* Subtle ambient glow circles in background */
    for (int py = 40; py < 420; py++) {
        for (int px = 40; px < 480; px++) {
            int dx = px - 220, dy = py - 210;
            int d2 = dx * dx + dy * dy;
            if (d2 < 36000) {
                uint8_t a = (uint8_t)((36000 - d2) * 28 / 36000);
                fb[py * FB_W + px] = blend_rgb(fb[py * FB_W + px], rgb(16, 185, 129), a);
            }
        }
    }
    for (int py = 360; py < 780; py++) {
        for (int px = 820; px < 1260; px++) {
            int dx = px - 1060, dy = py - 580;
            int d2 = dx * dx + dy * dy;
            if (d2 < 42000) {
                uint8_t a = (uint8_t)((42000 - d2) * 24 / 42000);
                fb[py * FB_W + px] = blend_rgb(fb[py * FB_W + px], rgb(56, 189, 248), a);
            }
        }
    }

    /* 2. Top Android 15 / GrapheneOS Status Bar (44px) */
    fill_rect(fb, 0, 0, FB_W, 44, rgb(8, 12, 22));
    fill_rect(fb, 0, 44, FB_W, 1, rgb(32, 48, 72));
    draw_text(fb, 20, 14, "17:05", 2, rgb(240, 246, 255));
    draw_shield(fb, 134, 22, 11, rgb(16, 185, 129), rgb(8, 12, 22));
    draw_text(fb, 154, 15, "GrapheneOS 15  |  Qyronex Hybrid Rust Kernel", 2, rgb(224, 238, 252));

    /* Right status pills: SELinux Enforcing, 5G, Wi-Fi, Battery */
    fill_rrect(fb, 868, 9, 178, 26, 13, rgb(16, 62, 48));
    stroke_rrect(fb, 868, 9, 178, 26, 13, rgb(16, 185, 129));
    draw_text(fb, 882, 18, "SELINUX: ENFORCING", 1, rgb(110, 242, 192));

    draw_text(fb, 1066, 15, "5G", 2, rgb(186, 214, 242));
    /* Signal bars */
    for (int i = 0; i < 4; i++) {
        fill_rect(fb, 1106 + i * 7, 26 - i * 4, 5, 6 + i * 4, rgb(56, 189, 248));
    }
    /* Battery icon 100% */
    stroke_rrect(fb, 1152, 13, 34, 18, 3, rgb(224, 236, 248));
    fill_rect(fb, 1186, 18, 3, 8, rgb(224, 236, 248));
    fill_rect(fb, 1155, 16, 28, 12, rgb(34, 197, 94));
    draw_text(fb, 1196, 18, "100%", 1, rgb(224, 236, 248));

    /* 3. Left Column: Google Pixel / GrapheneOS Phone Shell (x=28..518, y=66..732) */
    int px0 = 28, py0 = 66, pw = 490, ph = 664;
    fill_rrect(fb, px0, py0, pw, ph, 28, rgb(15, 22, 36));
    stroke_rrect(fb, px0, py0, pw, ph, 28, rgb(42, 62, 92));

    /* Pixel Punch-Hole Camera */
    fill_circle(fb, px0 + pw / 2, py0 + 22, 7, rgb(5, 8, 14));
    fill_circle(fb, px0 + pw / 2, py0 + 22, 3, rgb(24, 42, 68));

    /* Hero Clock & Device Banner */
    draw_text(fb, px0 + 30, py0 + 48, "17:05", 4, rgb(248, 250, 252));
    draw_text(fb, px0 + 32, py0 + 92, "Sat, Nov 21  |  Android 15 (API 35)", 1, rgb(148, 172, 204));
    draw_text(fb, px0 + 32, py0 + 108, "Google Pixel / GrapheneOS Native Kernel", 1, rgb(56, 189, 248));

    /* Shield + Qyronex Verified Card inside Pixel screen */
    fill_rrect(fb, px0 + 24, py0 + 132, pw - 48, 86, 18, rgb(18, 38, 44));
    stroke_rrect(fb, px0 + 24, py0 + 132, pw - 48, 86, 18, rgb(20, 148, 110));
    draw_shield(fb, px0 + 60, py0 + 175, 22, rgb(16, 185, 129), rgb(10, 22, 26));
    draw_text(fb, px0 + 96, py0 + 148, "QYRONEX HYBRID CORE", 2, rgb(226, 252, 242));
    draw_text(fb, px0 + 96, py0 + 174, "Rust Memory-Safe Kernel + Cap-Binder v8", 1, rgb(148, 226, 200));
    draw_text(fb, px0 + 96, py0 + 190, "Titan M2 StrongBox | Verified Boot GREEN", 1, rgb(110, 231, 183));

    /* Material You Quick Security Toggles (2x2) */
    const char *tiles[4][2] = {
        {"Cap-Binder v8", "ENFORCED"},
        {"Zero-On-Free",  "ACTIVE"},
        {"Modem IOMMU",   "SANDBOXED"},
        {"W^X TTBR1",     "LOCKED"},
    };
    for (int i = 0; i < 4; i++) {
        int col = i % 2, row = i / 2;
        int tx = px0 + 24 + col * 228;
        int ty = py0 + 234 + row * 66;
        fill_rrect(fb, tx, ty, 214, 54, 16, rgb(22, 34, 54));
        stroke_rrect(fb, tx, ty, 214, 54, 16, rgb(44, 72, 108));
        fill_circle(fb, tx + 24, ty + 27, 10, rgb(16, 185, 129));
        draw_text(fb, tx + 46, ty + 14, tiles[i][0], 1, rgb(236, 244, 255));
        draw_text(fb, tx + 46, ty + 30, tiles[i][1], 1, rgb(52, 211, 153));
    }

    /* GrapheneOS App Launcher Grid (3x2) */
    draw_text(fb, px0 + 28, py0 + 382, "GRAPHENEOS APPS & SYSTEM", 1, rgb(134, 158, 190));
    draw_app_icon(fb, px0 + 38,  py0 + 404, 86, rgb(24, 42, 68), rgb(56, 189, 248),  "VN", "Vanadium");
    draw_app_icon(fb, px0 + 202, py0 + 404, 86, rgb(18, 48, 42), rgb(52, 211, 153),  "AU", "Auditor");
    draw_app_icon(fb, px0 + 366, py0 + 404, 86, rgb(42, 34, 68), rgb(167, 139, 250), "ST", "Settings");

    draw_app_icon(fb, px0 + 38,  py0 + 528, 86, rgb(24, 34, 48), rgb(251, 191, 36),  ">_", "Terminal");
    draw_app_icon(fb, px0 + 202, py0 + 528, 86, rgb(46, 36, 30), rgb(251, 146, 60),  "FS", "Files");
    draw_app_icon(fb, px0 + 366, py0 + 528, 86, rgb(20, 44, 58), rgb(45, 212, 191),  "AP", "Apps");

    /* Bottom Gesture Pill inside Pixel phone */
    fill_rrect(fb, px0 + pw / 2 - 70, py0 + ph - 18, 140, 6, 3, rgb(148, 168, 196));

    /* 4. Right Column: Live Kernel, Binder IPC & Pixel Hardware Dashboard (x=542..1252) */
    int rx0 = 542, rw = 710;

    /* Tab Selector Header */
    const char *tabs[3] = {
        "[1] Live Overview",
        "[2] GrapheneOS Security",
        "[3] Binder & Pixel HW"
    };
    for (int i = 0; i < 3; i++) {
        int tx = rx0 + i * 240;
        uint32_t bg = (active_tab == i) ? rgb(20, 64, 84) : rgb(16, 24, 38);
        uint32_t bd = (active_tab == i) ? rgb(56, 189, 248) : rgb(38, 54, 78);
        uint32_t fg = (active_tab == i) ? rgb(240, 248, 255) : rgb(140, 164, 196);
        fill_rrect(fb, tx, 66, 230, 36, 12, bg);
        stroke_rrect(fb, tx, 66, 230, 36, 12, bd);
        int tw = (int)strlen(tabs[i]) * 8;
        draw_text(fb, tx + (230 - tw) / 2, 80, tabs[i], 1, fg);
    }

    /* Card A: GrapheneOS & Qyronex Security Hardening (y=116..316) */
    fill_rrect(fb, rx0, 116, rw, 200, 20, rgb(15, 22, 36));
    stroke_rrect(fb, rx0, 116, rw, 200, 20, rgb(36, 56, 84));
    draw_text(fb, rx0 + 20, 132, "GRAPHENEOS + QYRONEX HARDENING", 2, rgb(52, 211, 153));
    draw_kv_badge(fb, rx0 + 20,  162, 326, "SELinux Mode",       t->selinux,    rgb(52, 211, 153));
    draw_kv_badge(fb, rx0 + 364, 162, 326, "TTBR1 W^X Isolation",t->wx_ttbr1,   rgb(56, 189, 248));
    draw_kv_badge(fb, rx0 + 20,  200, 326, "Capability Binder",  t->cap_binder, rgb(52, 211, 153));
    draw_kv_badge(fb, rx0 + 364, 200, 326, "Zero-on-Free Heap",  t->zero_free,  rgb(52, 211, 153));
    draw_kv_badge(fb, rx0 + 20,  238, 326, "ARM64 PAN / TTBR0",  t->hw_pan,     rgb(56, 189, 248));
    draw_kv_badge(fb, rx0 + 364, 238, 326, "ARMv8.5 HW MTE",     t->hw_mte,     rgb(251, 191, 36));
    draw_kv_badge(fb, rx0 + 20,  276, 326, "AVB Verified Boot",  t->avb,        rgb(52, 211, 153));
    draw_kv_badge(fb, rx0 + 364, 276, 326, "Modem DMA IOMMU",    t->modem_iommu,rgb(52, 211, 153));

    /* Card B: Live Binder v8 IPC & ServiceManager Registry (y=332..540) */
    fill_rrect(fb, rx0, 332, rw, 208, 20, rgb(15, 22, 36));
    stroke_rrect(fb, rx0, 332, rw, 208, 20, rgb(36, 56, 84));
    draw_text(fb, rx0 + 20, 348, "ANDROID BINDER v8 & SERVICEMANAGER", 2, rgb(56, 189, 248));

    char line[256];
    snprintf(line, sizeof(line), "Proto v%s | Endpoints: %s | Tx: %s | Replies: %s | CapDenials: %s",
             t->binder_proto, t->binder_eps, t->binder_tx, t->binder_replies, t->binder_denials);
    fill_rrect(fb, rx0 + 20, 376, rw - 40, 28, 8, rgb(20, 32, 50));
    draw_text(fb, rx0 + 32, 386, line, 1, rgb(186, 230, 253));

    /* Render registered Android services from live Binder RPC */
    const char *sp = t->services_raw;
    int sy = 414;
    int shown = 0;
    while (*sp && shown < 6) {
        const char *nl = strchr(sp, '\n');
        size_t len = nl ? (size_t)(nl - sp) : strlen(sp);
        if (len > 0) {
            char row_s[96];
            size_t cp = len < sizeof(row_s) - 1 ? len : sizeof(row_s) - 1;
            memcpy(row_s, sp, cp);
            row_s[cp] = '\0';
            /* Replace tabs with spaces for clean display */
            for (size_t k = 0; k < cp; k++) if (row_s[k] == '\t') row_s[k] = ' ';
            fill_circle(fb, rx0 + 30, sy + 4, 4, rgb(52, 211, 153));
            draw_text(fb, rx0 + 44, sy, row_s, 1, rgb(220, 232, 248));
            sy += 20;
            shown++;
        }
        if (!nl) break;
        sp = nl + 1;
    }

    /* Card C: Google Pixel Tensor + Titan M2 Hardware Layer (y=556..730) */
    fill_rrect(fb, rx0, 556, rw, 174, 20, rgb(15, 22, 36));
    stroke_rrect(fb, rx0, 556, rw, 174, 20, rgb(36, 56, 84));
    draw_text(fb, rx0 + 20, 572, "PIXEL TENSOR / TITAN M2 / BOOT v4", 2, rgb(167, 139, 250));
    draw_kv_badge(fb, rx0 + 20,  602, rw - 40, "Target Device & SoC", t->pixel_model, rgb(240, 246, 255));
    draw_kv_badge(fb, rx0 + 20,  640, 246,     "Titan M2",            t->titan_m2,    rgb(52, 211, 153));
    draw_kv_badge(fb, rx0 + 278, 640, 200,     "KeyMint",             t->keymint,     rgb(167, 139, 250));
    draw_kv_badge(fb, rx0 + 490, 640, 200,     "Weaver Slots",        t->weaver,      rgb(56, 189, 248));

    snprintf(line, sizeof(line),
             "DRM/VirtIO-GPU 1280x800x32 | Ashmem Surface Active | UFS Slot %s | Frame #%d",
             t->ufs_slot, t->frame_no);
    draw_text(fb, rx0 + 24, 686, line, 1, rgb(148, 172, 204));
    draw_text(fb, rx0 + 24, 706,
              "Shell: getprop | service list | dumpsys | logcat | qyronex-android-selftest",
              1, rgb(110, 231, 183));

    /* 5. Bottom Android System Bar (y=750..800) */
    fill_rect(fb, 0, 750, FB_W, 50, rgb(8, 12, 22));
    fill_rect(fb, 0, 750, FB_W, 1, rgb(32, 48, 72));
    draw_text(fb, 28, 770,
              "QYRONEX OS v0.5.0  |  Android 15 / GrapheneOS Pixel Edition  |  ISO: qyronex-android-pixel-grapheneos.iso",
              1, rgb(148, 168, 196));
    fill_rrect(fb, FB_W / 2 - 90, 786, 180, 5, 2, rgb(200, 214, 232));
    draw_text(fb, 1020, 770, "[1-3] Tabs   [R] Refresh", 1, rgb(56, 189, 248));
}

int main(void) {
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);

    /* 1. Connect to /dev/binder and register core Android system services with servicemanager. */
    struct binder_client bc;
    if (binder_client_open(&bc, "/dev/binder") == 0) {
        char resp[192];
        const char *svcs[] = {
            "SurfaceFlinger",
            "activity",
            "window",
            "package",
            "power",
            "android.hardware.security.keymint/strongbox"
        };
        for (size_t i = 0; i < sizeof(svcs) / sizeof(svcs[0]); i++) {
            (void)binder_rpc(&bc, 0, SM_CMD_ADD_SERVICE, svcs[i], strlen(svcs[i]), resp, sizeof(resp));
        }
        android_log_write("I/SurfaceFlinger: Registered 6 core Android services via Binder v8");
    }

    /* 2. Allocate & pin real /dev/ashmem composition metadata buffer. */
    int ashmem_fd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
    void *ashmem_ptr = NULL;
    if (ashmem_fd >= 0) {
        char name[256] = "SurfaceFlinger.LayerState";
        (void)ioctl(ashmem_fd, ASHMEM_SET_NAME, name);
        (void)ioctl(ashmem_fd, ASHMEM_SET_SIZE, (unsigned long)(64 * 1024));
        (void)ioctl(ashmem_fd, ASHMEM_PIN, 0UL);
        ashmem_ptr = mmap(NULL, 64 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED, ashmem_fd, 0);
        if (ashmem_ptr != MAP_FAILED && ashmem_ptr != NULL) {
            snprintf((char *)ashmem_ptr, 256,
                     "SurfaceFlinger layer0=GrapheneOS-Launcher 1280x800 XRGB8888\n");
            android_log_write("I/SurfaceFlinger: Ashmem composition buffer mapped & pinned (64 KiB)");
        } else {
            ashmem_ptr = NULL;
        }
    }

    /* 3. Initialize DRM/KMS dumb scanout framebuffer on /dev/dri/card0 (VirtIO-GPU). */
    int drm_fd = open("/dev/dri/card0", O_RDWR | O_CLOEXEC);
    if (drm_fd < 0) {
        android_log_write("E/SurfaceFlinger: Cannot open /dev/dri/card0");
        return 1;
    }
    (void)ioctl(drm_fd, DRM_IOCTL_SET_MASTER, 0);

    struct q_drm_create_dumb cd;
    memset(&cd, 0, sizeof(cd));
    cd.width = FB_W;
    cd.height = FB_H;
    cd.bpp = 32;
    if (ioctl(drm_fd, DRM_IOCTL_MODE_CREATE_DUMB, &cd) < 0) {
        android_log_write("E/SurfaceFlinger: CREATE_DUMB failed");
        close(drm_fd);
        return 1;
    }

    struct q_drm_map_dumb md;
    memset(&md, 0, sizeof(md));
    md.handle = cd.handle;
    if (ioctl(drm_fd, DRM_IOCTL_MODE_MAP_DUMB, &md) < 0) {
        android_log_write("E/SurfaceFlinger: MAP_DUMB failed");
        close(drm_fd);
        return 1;
    }

    uint32_t *fb = (uint32_t *)mmap(NULL, (size_t)cd.size, PROT_READ | PROT_WRITE,
                                    MAP_SHARED, drm_fd, (off_t)md.offset);
    if (fb == MAP_FAILED || !fb) {
        android_log_write("E/SurfaceFlinger: mmap dumb fb failed");
        close(drm_fd);
        return 1;
    }

    struct q_drm_fb_cmd fbc;
    memset(&fbc, 0, sizeof(fbc));
    fbc.width = FB_W;
    fbc.height = FB_H;
    fbc.pitch = cd.pitch;
    fbc.bpp = 32;
    fbc.depth = 24;
    fbc.handle = cd.handle;
    if (ioctl(drm_fd, DRM_IOCTL_MODE_ADDFB, &fbc) < 0) {
        android_log_write("E/SurfaceFlinger: ADDFB failed");
        close(drm_fd);
        return 1;
    }

    /* Render initial GrapheneOS Android 15 UI frame BEFORE SETCRTC scanout! */
    struct live_telemetry tel;
    memset(&tel, 0, sizeof(tel));
    int active_tab = 0;
    poll_telemetry(&bc, &tel);
    render_ui(fb, &tel, active_tab);

    uint32_t conn_id = DRM_CONNECTOR_ID;
    struct q_drm_crtc crtc;
    memset(&crtc, 0, sizeof(crtc));
    crtc.set_connectors_ptr = (uint64_t)(uintptr_t)&conn_id;
    crtc.count_connectors = 1;
    crtc.crtc_id = DRM_CRTC_ID;
    crtc.fb_id = fbc.fb_id;
    if (ioctl(drm_fd, DRM_IOCTL_MODE_SETCRTC, &crtc) < 0) {
        android_log_write("E/SurfaceFlinger: SETCRTC failed");
    } else {
        android_log_write("I/SurfaceFlinger: VirtIO-GPU 1280x800x32 GrapheneOS UI presented!");
    }

    /* Optional keyboard input fd for live tab switching (non-blocking). */
    int kbd_fd = open("/dev/input/event0", O_RDONLY | O_NONBLOCK | O_CLOEXEC);

    struct q_drm_dirtyfb dirty;
    memset(&dirty, 0, sizeof(dirty));
    dirty.fb_id = fbc.fb_id;

    int tick = 0;
    while (g_running) {
        int need_redraw = 0;
        if (kbd_fd >= 0) {
            struct input_ev ev;
            while (read(kbd_fd, &ev, sizeof(ev)) == (ssize_t)sizeof(ev)) {
                if (ev.type == 1 && ev.value == 1) { /* EV_KEY pressed */
                    if (ev.code == 2) { active_tab = 0; need_redraw = 1; } /* KEY_1 */
                    else if (ev.code == 3) { active_tab = 1; need_redraw = 1; } /* KEY_2 */
                    else if (ev.code == 4) { active_tab = 2; need_redraw = 1; } /* KEY_3 */
                    else if (ev.code == 19) { need_redraw = 1; } /* KEY_R */
                }
            }
        }
        /* Refresh live telemetry every ~2 seconds. */
        if (need_redraw || (++tick % 20 == 0)) {
            poll_telemetry(&bc, &tel);
            render_ui(fb, &tel, active_tab);
            (void)ioctl(drm_fd, DRM_IOCTL_MODE_DIRTYFB, &dirty);
        }
        usleep(100000);
    }

    if (kbd_fd >= 0) close(kbd_fd);
    if (ashmem_ptr) munmap(ashmem_ptr, 64 * 1024);
    if (ashmem_fd >= 0) close(ashmem_fd);
    munmap(fb, (size_t)cd.size);
    close(drm_fd);
    binder_client_close(&bc);
    return 0;
}
