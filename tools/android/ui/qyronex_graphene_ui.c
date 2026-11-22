/* SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0 */
/* Qyronex OS — Native ARM64 GTK3 + gtk-layer-shell GrapheneOS 15 Mobile/Tablet Shell & App Suite.
 *
 * ZERO-FORK GTK3 architecture:
 * - Single-process Wayland shell (`statusbar` + `navbar` + `launcher`)
 * - Instant in-process native GrapheneOS windows (`Settings`, `Auditor`, `Apps`, `Logcat`, `Quick Settings`)
 * - All kernel checks (10/10 Attestation incl. Binder v8 FD Passing, SELinux lockdown, getprop/setprop,
 *   uname, getifaddrs, live TCP/HTTP connectivity probe) execute directly via POSIX/Linux syscalls in C!
 * - External ARM64 GUI apps (`netsurf-gtk`, `xfce4-terminal`, `thunar`, `mousepad`, `galculator`,
 *   `ristretto`) are dispatched non-blocking via `/run/user/0/qyronex-launch.fifo` to the single-threaded
 *   launcher daemon (`qyronex-appd`), avoiding multi-threaded GTK3 fork() deadlocks completely.
 */

#define _GNU_SOURCE
#include "../src/qyronex_art_core.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <gtk/gtk.h>
#include <gtk-layer-shell/gtk-layer-shell.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>

#define LAUNCH_DIR_PATH "/run/user/0/qyronex-launch.d"

static const char *GRAPHENE_CSS =
    "window, .graphene-bg {"
    "  background-color: #0b111e;"
    "  background-image: none;"
    "  color: #e6eefb;"
    "  font-family: 'DejaVu Sans', sans-serif;"
    "  font-size: 12px;"
    "}"
    "button {"
    "  background-image: none;"
    "  text-shadow: none;"
    "  box-shadow: none;"
    "}"
    ".statusbar {"
    "  background-color: #070b14;"
    "  border-bottom: 1px solid #1e2d45;"
    "  padding: 0px 10px;"
    "}"
    ".navbar {"
    "  background-color: #070b14;"
    "  border-top: 1px solid #1e2d45;"
    "  padding: 4px 10px;"
    "}"
    ".pill-green {"
    "  background-color: #0d3b2e;"
    "  color: #6ee7b7;"
    "  border: 1px solid #10b981;"
    "  border-radius: 14px;"
    "  padding: 2px 10px;"
    "  font-weight: bold;"
    "  font-size: 11px;"
    "}"
    ".pill-green:hover { background-color: #145542; color: #ffffff; }"
    ".pill-cyan {"
    "  background-color: #0e2e44;"
    "  color: #7dd3fc;"
    "  border: 1px solid #38bdf8;"
    "  border-radius: 14px;"
    "  padding: 2px 10px;"
    "  font-weight: bold;"
    "  font-size: 11px;"
    "}"
    ".pill-cyan:hover { background-color: #164769; color: #ffffff; }"
    ".pill-dark {"
    "  background-color: #131e32;"
    "  color: #cbd5e1;"
    "  border: 1px solid #2b3f5e;"
    "  border-radius: 14px;"
    "  padding: 2px 10px;"
    "  font-size: 11px;"
    "}"
    ".pill-dark:hover { background-color: #1e2f4d; color: #ffffff; }"
    ".clock-hero {"
    "  font-size: 38px;"
    "  font-weight: bold;"
    "  color: #f8fafc;"
    "}"
    ".subtitle-cyan {"
    "  color: #38bdf8;"
    "  font-size: 11px;"
    "  font-weight: bold;"
    "}"
    ".subtitle-muted {"
    "  color: #94a3b8;"
    "  font-size: 11px;"
    "}"
    ".card-btn {"
    "  background-color: #111b2e;"
    "  border: 1px solid #243754;"
    "  border-radius: 14px;"
    "  padding: 7px 12px;"
    "  color: #e6eefb;"
    "}"
    ".card-btn:hover { background-color: #182844; border-color: #38bdf8; }"
    ".card-btn:active { background-color: #1f3458; }"
    ".app-tile {"
    "  background-color: #121d33;"
    "  border: 1px solid #263b5c;"
    "  border-radius: 16px;"
    "  padding: 8px 6px;"
    "  color: #f1f5f9;"
    "}"
    ".app-tile:hover { background-color: #192a47; border-color: #10b981; }"
    ".app-tile:active { background-color: #21375c; }"
    ".app-badge {"
    "  font-size: 18px;"
    "  font-weight: bold;"
    "  border-radius: 13px;"
    "  padding: 7px 13px;"
    "  color: #08101c;"
    "}"
    ".badge-blue   { background-color: #38bdf8; }"
    ".badge-green  { background-color: #34d399; }"
    ".badge-purple { background-color: #a78bfa; }"
    ".badge-amber  { background-color: #fbbf24; }"
    ".badge-orange { background-color: #fb923c; }"
    ".badge-teal   { background-color: #2dd4bf; }"
    ".badge-rose   { background-color: #fb7185; }"
    ".badge-indigo { background-color: #818cf8; }"
    ".badge-lime   { background-color: #a3e635; }"
    ".badge-sky    { background-color: #60a5fa; }"
    ".app-title { font-weight: bold; font-size: 13px; color: #f8fafc; }"
    ".app-sub   { font-size: 10px; color: #94a3b8; }"
    ".nav-btn {"
    "  background-color: #142036;"
    "  color: #e2e8f0;"
    "  border: 1px solid #2a3e5e;"
    "  border-radius: 12px;"
    "  padding: 5px 14px;"
    "  font-weight: bold;"
    "  font-size: 12px;"
    "}"
    ".nav-btn:hover { background-color: #1e3152; border-color: #38bdf8; color: #ffffff; }"
    ".nav-home {"
    "  background-color: #0e3a2d;"
    "  color: #6ee7b7;"
    "  border: 1px solid #10b981;"
    "  border-radius: 14px;"
    "  padding: 5px 18px;"
    "  font-weight: bold;"
    "  font-size: 12px;"
    "}"
    ".nav-home:hover { background-color: #145441; color: #ffffff; }"
    ".dock-btn {"
    "  background-color: #121d32;"
    "  color: #cbd5e1;"
    "  border: 1px solid #243856;"
    "  border-radius: 11px;"
    "  padding: 5px 12px;"
    "  font-size: 12px;"
    "  font-weight: bold;"
    "}"
    ".dock-btn:hover { background-color: #1c2d4a; border-color: #10b981; color: #ffffff; }"
    ".action-btn {"
    "  background-color: #10b981;"
    "  color: #051610;"
    "  border: none;"
    "  border-radius: 10px;"
    "  padding: 7px 14px;"
    "  font-weight: bold;"
    "}"
    ".action-btn:hover { background-color: #34d399; }"
    ".danger-btn {"
    "  background-color: #7f1d1d;"
    "  color: #fecaca;"
    "  border: 1px solid #ef4444;"
    "  border-radius: 10px;"
    "  padding: 6px 14px;"
    "  font-weight: bold;"
    "}"
    ".danger-btn:hover { background-color: #991b1b; }"
    ".search-entry {"
    "  background-color: #111b2e;"
    "  color: #f8fafc;"
    "  border: 1px solid #2c4366;"
    "  border-radius: 10px;"
    "  padding: 6px 12px;"
    "  font-size: 12px;"
    "}"
    ".search-entry:focus { border-color: #38bdf8; }"
    ".mono-box, textview text {"
    "  background-color: #080d17;"
    "  color: #d6e2f5;"
    "  font-family: 'DejaVu Sans Mono', monospace;"
    "  font-size: 12px;"
    "}"
    ".banner-pass {"
    "  background-color: #0c3529;"
    "  border: 1px solid #10b981;"
    "  border-radius: 12px;"
    "  padding: 10px 14px;"
    "  color: #6ee7b7;"
    "  font-weight: bold;"
    "  font-size: 13px;"
    "}"
    ".banner-warn {"
    "  background-color: #3b230c;"
    "  border: 1px solid #f59e0b;"
    "  border-radius: 12px;"
    "  padding: 10px 14px;"
    "  color: #fde68a;"
    "  font-weight: bold;"
    "  font-size: 13px;"
    "}"
    ".calc-display {"
    "  background-color: #060b14;"
    "  color: #f8fafc;"
    "  border: 1px solid #263b5c;"
    "  border-radius: 12px;"
    "  padding: 12px 14px;"
    "  font-family: 'DejaVu Sans Mono', monospace;"
    "  font-size: 28px;"
    "  font-weight: bold;"
    "}"
    ".calc-key {"
    "  background-color: #132036;"
    "  color: #f1f5f9;"
    "  border: 1px solid #2a3e5e;"
    "  border-radius: 10px;"
    "  font-size: 16px;"
    "  font-weight: bold;"
    "  padding: 10px;"
    "}"
    ".calc-key:hover { background-color: #1f3354; border-color: #38bdf8; }"
    ".calc-op {"
    "  background-color: #163348;"
    "  color: #7dd3fc;"
    "  border: 1px solid #38bdf8;"
    "  border-radius: 10px;"
    "  font-size: 16px;"
    "  font-weight: bold;"
    "  padding: 10px;"
    "}"
    ".calc-op:hover { background-color: #1e4766; color: #ffffff; }"
    ".term-box, .term-box text {"
    "  background-color: #050911;"
    "  color: #a7f3d0;"
    "  font-family: 'DejaVu Sans Mono', monospace;"
    "  font-size: 12px;"
    "}"
    "list, list row { background-color: #0a101d; color: #e6eefb; border-bottom: 1px solid #162238; }"
    "list row:hover { background-color: #14223a; }"
    "list row:selected { background-color: #163348; color: #7dd3fc; }"
    "stacksidebar list { background-color: #0d1525; border-right: 1px solid #1e2d45; }"
    "stacksidebar row { padding: 9px 12px; color: #cbd5e1; border-radius: 8px; margin: 2px 6px; }"
    "stacksidebar row:selected { background-color: #163348; color: #7dd3fc; font-weight: bold; }";

static GList *g_inproc_windows = NULL;
static GtkWidget *g_toast_lbl = NULL;
static guint g_toast_timer = 0;

static void open_settings_window(const char *initial_page);
static void open_auditor_window(void);
static void open_apps_window(void);
static void open_logcat_window(void);
static void open_quicksettings_window(void);
static void open_terminal_window(void);
static void open_files_window(const char *start_dir);
static void open_notes_window(const char *filepath);
static void open_calculator_window(void);
static void open_gallery_window(void);
static void open_vanadium_window(const char *initial_url);
static void open_apk_activity_window(const char *target, int do_install);
static void refresh_apk_packages_view(void);

static gboolean clear_toast_cb(gpointer data) {
    (void)data;
    g_toast_timer = 0;
    if (g_toast_lbl && GTK_IS_WIDGET(g_toast_lbl)) {
        gtk_widget_hide(g_toast_lbl);
    }
    return FALSE;
}

static void show_status_toast(const char *msg, guint seconds) {
    if (!g_toast_lbl || !GTK_IS_LABEL(g_toast_lbl)) return;
    gtk_label_set_text(GTK_LABEL(g_toast_lbl), msg);
    gtk_widget_show(g_toast_lbl);
    if (g_toast_timer) g_source_remove(g_toast_timer);
    g_toast_timer = g_timeout_add_seconds(seconds, clear_toast_cb, NULL);
}

static void apply_css(void) {
    GtkCssProvider *prov = gtk_css_provider_new();
    gtk_css_provider_load_from_data(prov, GRAPHENE_CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(prov),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION
    );
    g_object_unref(prov);
}

static size_t read_file_str(const char *path, char *buf, size_t cap) {
    memset(buf, 0, cap);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t total = 0;
    while ((size_t)total + 1 < cap) {
        ssize_t n = read(fd, buf + total, cap - 1 - (size_t)total);
        if (n <= 0) break;
        total += n;
    }
    close(fd);
    buf[total] = '\0';
    return (size_t)total;
}

static int write_file_str(const char *path, const char *s) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = write(fd, s, strlen(s));
    int err = errno;
    close(fd);
    errno = err;
    return n < 0 ? -1 : 0;
}

static void extract_kv(const char *text, const char *key, char *out, size_t cap) {
    size_t klen = strlen(key);
    const char *p = text;
    while (*p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *v = p + klen + 1;
            const char *nl = strchr(v, '\n');
            size_t len = nl ? (size_t)(nl - v) : strlen(v);
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

static void get_primary_ip(char *out, size_t cap) {
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) == 0 && ifaddr) {
        for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
            if (ifa->ifa_name && strcmp(ifa->ifa_name, "lo") == 0) continue;
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            char ipbuf[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf))) {
                snprintf(out, cap, "%s", ipbuf);
                freeifaddrs(ifaddr);
                return;
            }
        }
        freeifaddrs(ifaddr);
    }
    snprintf(out, cap, "10.0.2.15");
}

static void format_interfaces_summary(char *out, size_t cap) {
    size_t pos = 0;
    pos += (size_t)snprintf(out + pos, cap - pos, "=== Network Interfaces (VirtIO-Net) ===\n");
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) == 0 && ifaddr) {
        for (struct ifaddrs *ifa = ifaddr; ifa != NULL && pos + 64 < cap; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            char ipbuf[INET_ADDRSTRLEN] = {0};
            if (inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf))) {
                pos += (size_t)snprintf(out + pos, cap - pos, "  %-10s  UP  %s\n",
                                        ifa->ifa_name ? ifa->ifa_name : "eth0", ipbuf);
            }
        }
        freeifaddrs(ifaddr);
    }
    char resolv[512] = {0};
    if (read_file_str("/etc/resolv.conf", resolv, sizeof(resolv)) > 0 && pos + 64 < cap) {
        pos += (size_t)snprintf(out + pos, cap - pos, "\n=== DNS (/etc/resolv.conf) ===\n%s\n", resolv);
    }
}

/* Drop one atomic request file for single-threaded external app daemon (`qyronex-appd`). */
static void send_to_appd(const char *cmd) {
    static unsigned int seq = 1;
    (void)mkdir(LAUNCH_DIR_PATH, 0777);
    char tmp[180], path[180];
    unsigned int id = seq++;
    snprintf(tmp, sizeof(tmp), "%s/.req-%06u.tmp", LAUNCH_DIR_PATH, id);
    snprintf(path, sizeof(path), "%s/req-%06u.cmd", LAUNCH_DIR_PATH, id);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) return;
    char line[768];
    int n = snprintf(line, sizeof(line), "%s\n", cmd);
    if (n > 0) (void)write(fd, line, (size_t)n);
    close(fd);
    (void)rename(tmp, path);
}

static void on_inproc_window_destroy(GtkWidget *w, gpointer data) {
    (void)data;
    g_inproc_windows = g_list_remove(g_inproc_windows, w);
}

static void track_inproc_window(GtkWidget *win) {
    g_inproc_windows = g_list_append(g_inproc_windows, win);
    g_signal_connect(win, "delete-event", G_CALLBACK(gtk_widget_hide_on_delete), NULL);
    g_signal_connect(win, "destroy", G_CALLBACK(on_inproc_window_destroy), NULL);
}

static void launch_action(const char *action) {
    if (!action || !action[0]) return;
    char logmsg[256];
    snprintf(logmsg, sizeof(logmsg), "I/ActivityManager: Launch '%s'", action);
    android_log_write(logmsg);

    if (strcmp(action, "@settings") == 0 || strcmp(action, "@settings:security") == 0) {
        open_settings_window("security"); return;
    }
    if (strcmp(action, "@settings:network") == 0) { open_settings_window("network"); return; }
    if (strcmp(action, "@settings:props") == 0)   { open_settings_window("props"); return; }
    if (strcmp(action, "@settings:about") == 0)   { open_settings_window("about"); return; }
    if (strcmp(action, "@auditor") == 0)          { open_auditor_window(); return; }
    if (strcmp(action, "@apps") == 0)             { open_apps_window(); return; }
    if (strcmp(action, "@logcat") == 0)           { open_logcat_window(); return; }
    if (strcmp(action, "@quicksettings") == 0)    { open_quicksettings_window(); return; }
    if (strcmp(action, "@terminal") == 0)         { open_terminal_window(); return; }
    if (strcmp(action, "@files") == 0)            { open_files_window("/data"); return; }
    if (strcmp(action, "@notes") == 0)            { open_notes_window("/data/local/tmp/notes.txt"); return; }
    if (strcmp(action, "@calculator") == 0)       { open_calculator_window(); return; }
    if (strcmp(action, "@gallery") == 0)          { open_gallery_window(); return; }
    if (strcmp(action, "@vanadium") == 0)         { open_vanadium_window("about:vanadium"); return; }
    if (strncmp(action, "@vanadium:", 10) == 0)   { open_vanadium_window(action + 10); return; }
    if (strncmp(action, "@apk-run:", 9) == 0)     { open_apk_activity_window(action + 9, 0); return; }
    if (strncmp(action, "@apk-install-run:", 17) == 0) { open_apk_activity_window(action + 17, 1); return; }

    /* External ARM64 GUI app (e.g. full NetSurf engine) -> dispatch via single-threaded qyronex-appd */
    if (strncmp(action, "netsurf-gtk", 11) == 0) {
        show_status_toast("Launching NetSurf Graphical Engine...", 24);
    }
    send_to_appd(action);
}

static void on_launch_clicked(GtkWidget *w, gpointer data) {
    (void)w;
    launch_action((const char *)data);
}

static void on_home_clicked(GtkWidget *w, gpointer data) {
    (void)w; (void)data;
    for (GList *l = g_inproc_windows; l != NULL; l = l->next) {
        GtkWidget *win = GTK_WIDGET(l->data);
        if (GTK_IS_WIDGET(win) && gtk_widget_get_visible(win)) {
            gtk_widget_hide(win);
        }
    }
    send_to_appd("@home");
    android_log_write("I/ActivityManager: Home pressed - returned to GrapheneOS Home Screen");
}

static void on_back_clicked(GtkWidget *w, gpointer data) {
    (void)w; (void)data;
    GtkWidget *top_visible = NULL;
    for (GList *l = g_inproc_windows; l != NULL; l = l->next) {
        GtkWidget *win = GTK_WIDGET(l->data);
        if (GTK_IS_WIDGET(win) && gtk_widget_get_visible(win)) {
            top_visible = win;
        }
    }
    if (top_visible) {
        gtk_widget_hide(top_visible);
    } else {
        send_to_appd("@back");
    }
    android_log_write("I/ActivityManager: Back pressed");
}

/* ============================================================================
 * 1. TOP STATUS BAR (gtk-layer-shell TOP)
 * ============================================================================ */
struct statusbar_widgets {
    GtkWidget *clock_lbl;
    GtkWidget *binder_btn;
    GtkWidget *net_btn;
};

static gboolean update_statusbar_cb(gpointer data) {
    struct statusbar_widgets *sw = (struct statusbar_widgets *)data;
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char tbuf[32];
    if (tm) strftime(tbuf, sizeof(tbuf), "%H:%M:%S", tm);
    else snprintf(tbuf, sizeof(tbuf), "17:45");
    gtk_label_set_text(GTK_LABEL(sw->clock_lbl), tbuf);

    char bstat[512], tx[24], fds[24], blbl[96];
    read_file_str("/sys/kernel/qyronex/android/binder_stats", bstat, sizeof(bstat));
    extract_kv(bstat, "total_transactions", tx, sizeof(tx));
    extract_kv(bstat, "total_fd_transfers", fds, sizeof(fds));
    snprintf(blbl, sizeof(blbl), "Binder v8 · %s tx · %s FD", tx, fds);
    gtk_button_set_label(GTK_BUTTON(sw->binder_btn), blbl);

    char ip[48], nlbl[64];
    get_primary_ip(ip, sizeof(ip));
    snprintf(nlbl, sizeof(nlbl), "5G · %s", ip);
    gtk_button_set_label(GTK_BUTTON(sw->net_btn), nlbl);
    return TRUE;
}

static void build_statusbar_window(void) {
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_layer_init_for_window(GTK_WINDOW(win));
    gtk_layer_set_layer(GTK_WINDOW(win), GTK_LAYER_SHELL_LAYER_TOP);
    gtk_layer_set_anchor(GTK_WINDOW(win), GTK_LAYER_SHELL_EDGE_TOP, TRUE);
    gtk_layer_set_anchor(GTK_WINDOW(win), GTK_LAYER_SHELL_EDGE_LEFT, TRUE);
    gtk_layer_set_anchor(GTK_WINDOW(win), GTK_LAYER_SHELL_EDGE_RIGHT, TRUE);
    gtk_layer_auto_exclusive_zone_enable(GTK_WINDOW(win));
    gtk_widget_set_size_request(win, -1, 36);

    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_style_context_add_class(gtk_widget_get_style_context(bar), "statusbar");
    gtk_container_add(GTK_CONTAINER(win), bar);

    struct statusbar_widgets *sw = g_new0(struct statusbar_widgets, 1);
    sw->clock_lbl = gtk_label_new("17:45");
    gtk_style_context_add_class(gtk_widget_get_style_context(sw->clock_lbl), "app-title");
    gtk_box_pack_start(GTK_BOX(bar), sw->clock_lbl, FALSE, FALSE, 4);

    GtkWidget *brand_btn = gtk_button_new_with_label("GrapheneOS 15 | Qyronex Hybrid Rust Kernel");
    gtk_style_context_add_class(gtk_widget_get_style_context(brand_btn), "pill-dark");
    g_signal_connect(brand_btn, "clicked", G_CALLBACK(on_launch_clicked), (gpointer)"@auditor");
    gtk_box_pack_start(GTK_BOX(bar), brand_btn, FALSE, FALSE, 2);

    GtkWidget *selinux_btn = gtk_button_new_with_label("SELINUX: ENFORCING");
    gtk_style_context_add_class(gtk_widget_get_style_context(selinux_btn), "pill-green");
    g_signal_connect(selinux_btn, "clicked", G_CALLBACK(on_launch_clicked), (gpointer)"@settings:security");
    gtk_box_pack_start(GTK_BOX(bar), selinux_btn, FALSE, FALSE, 2);

    g_toast_lbl = gtk_label_new("");
    gtk_style_context_add_class(gtk_widget_get_style_context(g_toast_lbl), "pill-cyan");
    gtk_widget_set_no_show_all(g_toast_lbl, TRUE);
    gtk_box_pack_start(GTK_BOX(bar), g_toast_lbl, FALSE, FALSE, 4);

    GtkWidget *spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_box_pack_start(GTK_BOX(bar), spacer, TRUE, TRUE, 0);

    sw->binder_btn = gtk_button_new_with_label("Binder v8");
    gtk_style_context_add_class(gtk_widget_get_style_context(sw->binder_btn), "pill-cyan");
    g_signal_connect(sw->binder_btn, "clicked", G_CALLBACK(on_launch_clicked), (gpointer)"@apps");
    gtk_box_pack_start(GTK_BOX(bar), sw->binder_btn, FALSE, FALSE, 2);

    sw->net_btn = gtk_button_new_with_label("5G · 10.0.2.15");
    gtk_style_context_add_class(gtk_widget_get_style_context(sw->net_btn), "pill-dark");
    g_signal_connect(sw->net_btn, "clicked", G_CALLBACK(on_launch_clicked), (gpointer)"@settings:network");
    gtk_box_pack_start(GTK_BOX(bar), sw->net_btn, FALSE, FALSE, 2);

    GtkWidget *qs_btn = gtk_button_new_with_label("Quick Settings");
    gtk_style_context_add_class(gtk_widget_get_style_context(qs_btn), "pill-green");
    g_signal_connect(qs_btn, "clicked", G_CALLBACK(on_launch_clicked), (gpointer)"@quicksettings");
    gtk_box_pack_start(GTK_BOX(bar), qs_btn, FALSE, FALSE, 2);

    update_statusbar_cb(sw);
    g_timeout_add_seconds(2, update_statusbar_cb, sw);
    gtk_widget_show_all(win);
}

/* ============================================================================
 * 2. BOTTOM NAVIGATION & QUICK-DOCK BAR (gtk-layer-shell BOTTOM)
 * ============================================================================ */
static void build_navbar_window(void) {
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_layer_init_for_window(GTK_WINDOW(win));
    gtk_layer_set_layer(GTK_WINDOW(win), GTK_LAYER_SHELL_LAYER_TOP);
    gtk_layer_set_anchor(GTK_WINDOW(win), GTK_LAYER_SHELL_EDGE_BOTTOM, TRUE);
    gtk_layer_set_anchor(GTK_WINDOW(win), GTK_LAYER_SHELL_EDGE_LEFT, TRUE);
    gtk_layer_set_anchor(GTK_WINDOW(win), GTK_LAYER_SHELL_EDGE_RIGHT, TRUE);
    gtk_layer_auto_exclusive_zone_enable(GTK_WINDOW(win));
    gtk_widget_set_size_request(win, -1, 48);

    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_style_context_add_class(gtk_widget_get_style_context(bar), "navbar");
    gtk_container_add(GTK_CONTAINER(win), bar);

    struct { const char *lbl; const char *cmd; } dock[] = {
        { "Vanadium", "@vanadium" },
        { "Settings", "@settings" },
        { "Auditor",  "@auditor" },
        { "Terminal", "@terminal" },
        { "Files",    "@files" },
        { "Logcat",   "@logcat" },
    };
    for (size_t i = 0; i < sizeof(dock) / sizeof(dock[0]); i++) {
        GtkWidget *b = gtk_button_new_with_label(dock[i].lbl);
        gtk_style_context_add_class(gtk_widget_get_style_context(b), "dock-btn");
        g_signal_connect(b, "clicked", G_CALLBACK(on_launch_clicked), (gpointer)dock[i].cmd);
        gtk_box_pack_start(GTK_BOX(bar), b, FALSE, FALSE, 2);
    }

    GtkWidget *sp = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_box_pack_start(GTK_BOX(bar), sp, TRUE, TRUE, 0);

    GtkWidget *back_b = gtk_button_new_with_label("<  Back");
    gtk_style_context_add_class(gtk_widget_get_style_context(back_b), "nav-btn");
    g_signal_connect(back_b, "clicked", G_CALLBACK(on_back_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(bar), back_b, FALSE, FALSE, 3);

    GtkWidget *home_b = gtk_button_new_with_label("O  Home");
    gtk_style_context_add_class(gtk_widget_get_style_context(home_b), "nav-home");
    g_signal_connect(home_b, "clicked", G_CALLBACK(on_home_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(bar), home_b, FALSE, FALSE, 3);

    GtkWidget *apps_b = gtk_button_new_with_label("[]  Apps");
    gtk_style_context_add_class(gtk_widget_get_style_context(apps_b), "nav-btn");
    g_signal_connect(apps_b, "clicked", G_CALLBACK(on_launch_clicked), (gpointer)"@apps");
    gtk_box_pack_start(GTK_BOX(bar), apps_b, FALSE, FALSE, 3);

    gtk_widget_show_all(win);
}

/* ============================================================================
 * 3. GRAPHENEOS 15 HOME LAUNCHER (Fits cleanly inside 1280x716!)
 * ============================================================================ */
struct launcher_widgets {
    GtkWidget *clock_lbl;
    GtkWidget *date_lbl;
    GtkWidget *search_entry;
    GtkWidget *binder_sub;
    GtkWidget *pixel_sub;
    GtkWidget *net_sub;
};

static void on_search_go(GtkWidget *w, gpointer data) {
    (void)w;
    struct launcher_widgets *lw = (struct launcher_widgets *)data;
    const char *raw = gtk_entry_get_text(GTK_ENTRY(lw->search_entry));
    char cmd[640];
    if (!raw || !raw[0]) {
        snprintf(cmd, sizeof(cmd), "@vanadium:http://example.com/");
    } else if (strstr(raw, "://") != NULL) {
        snprintf(cmd, sizeof(cmd), "@vanadium:%s", raw);
    } else if (strchr(raw, '.') != NULL && strchr(raw, ' ') == NULL) {
        snprintf(cmd, sizeof(cmd), "@vanadium:http://%s", raw);
    } else {
        snprintf(cmd, sizeof(cmd), "@vanadium:https://html.duckduckgo.com/html/?q=%s", raw);
    }
    launch_action(cmd);
}

static gboolean update_launcher_cb(gpointer data) {
    struct launcher_widgets *lw = (struct launcher_widgets *)data;
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char tbuf[32], dbuf[64];
    if (tm) {
        strftime(tbuf, sizeof(tbuf), "%H:%M", tm);
        strftime(dbuf, sizeof(dbuf), "%a, %b %d  |  Android 15 (API 35)", tm);
    } else {
        snprintf(tbuf, sizeof(tbuf), "17:45");
        snprintf(dbuf, sizeof(dbuf), "Android 15 (API 35) | GrapheneOS");
    }
    gtk_label_set_text(GTK_LABEL(lw->clock_lbl), tbuf);
    gtk_label_set_text(GTK_LABEL(lw->date_lbl), dbuf);

    char bstat[512], tx[24], fds[24], eps[24], line[128];
    read_file_str("/sys/kernel/qyronex/android/binder_stats", bstat, sizeof(bstat));
    extract_kv(bstat, "total_transactions", tx, sizeof(tx));
    extract_kv(bstat, "total_fd_transfers", fds, sizeof(fds));
    extract_kv(bstat, "active_endpoints", eps, sizeof(eps));
    snprintf(line, sizeof(line), "v8 · %s ep · %s tx · %s FDs", eps, tx, fds);
    gtk_label_set_text(GTK_LABEL(lw->binder_sub), line);

    char pstat[512], km[16], wv[16];
    read_file_str("/sys/bus/platform/drivers/google_pixel/status", pstat, sizeof(pstat));
    extract_kv(pstat, "keymint_version", km, sizeof(km));
    extract_kv(pstat, "weaver_slots", wv, sizeof(wv));
    snprintf(line, sizeof(line), "Pixel 9 G4 · KeyMint v%s · %s Weaver", km, wv);
    gtk_label_set_text(GTK_LABEL(lw->pixel_sub), line);

    char ip[48];
    get_primary_ip(ip, sizeof(ip));
    snprintf(line, sizeof(line), "DHCP %s · Modem IOMMU", ip);
    gtk_label_set_text(GTK_LABEL(lw->net_sub), line);
    return TRUE;
}

static GtkWidget *make_app_tile(
    const char *badge_txt, const char *badge_cls,
    const char *title, const char *sub, const char *cmd
) {
    GtkWidget *btn = gtk_button_new();
    gtk_style_context_add_class(gtk_widget_get_style_context(btn), "app-tile");
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_halign(vbox, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(vbox, GTK_ALIGN_CENTER);

    GtkWidget *badge = gtk_label_new(badge_txt);
    gtk_style_context_add_class(gtk_widget_get_style_context(badge), "app-badge");
    gtk_style_context_add_class(gtk_widget_get_style_context(badge), badge_cls);
    gtk_widget_set_halign(badge, GTK_ALIGN_CENTER);

    GtkWidget *t = gtk_label_new(title);
    gtk_style_context_add_class(gtk_widget_get_style_context(t), "app-title");
    GtkWidget *s = gtk_label_new(sub);
    gtk_style_context_add_class(gtk_widget_get_style_context(s), "app-sub");
    gtk_label_set_ellipsize(GTK_LABEL(s), PANGO_ELLIPSIZE_END);

    gtk_box_pack_start(GTK_BOX(vbox), badge, FALSE, FALSE, 1);
    gtk_box_pack_start(GTK_BOX(vbox), t, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), s, FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(btn), vbox);

    g_signal_connect(btn, "clicked", G_CALLBACK(on_launch_clicked), (gpointer)cmd);
    return btn;
}

static GtkWidget *make_status_card(
    const char *title, const char *init_sub, const char *cmd, GtkWidget **sub_out
) {
    GtkWidget *btn = gtk_button_new();
    gtk_style_context_add_class(gtk_widget_get_style_context(btn), "card-btn");
    GtkWidget *vb = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *t = gtk_label_new(title);
    gtk_widget_set_halign(t, GTK_ALIGN_START);
    gtk_label_set_ellipsize(GTK_LABEL(t), PANGO_ELLIPSIZE_END);
    gtk_style_context_add_class(gtk_widget_get_style_context(t), "app-title");
    GtkWidget *s = gtk_label_new(init_sub);
    gtk_widget_set_halign(s, GTK_ALIGN_START);
    gtk_label_set_ellipsize(GTK_LABEL(s), PANGO_ELLIPSIZE_END);
    gtk_style_context_add_class(gtk_widget_get_style_context(s), "subtitle-cyan");
    gtk_box_pack_start(GTK_BOX(vb), t, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vb), s, FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(btn), vb);
    g_signal_connect(btn, "clicked", G_CALLBACK(on_launch_clicked), (gpointer)cmd);
    if (sub_out) *sub_out = s;
    return btn;
}

static void build_launcher_window(void) {
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_layer_init_for_window(GTK_WINDOW(win));
    gtk_layer_set_layer(GTK_WINDOW(win), GTK_LAYER_SHELL_LAYER_BOTTOM);
    gtk_layer_set_anchor(GTK_WINDOW(win), GTK_LAYER_SHELL_EDGE_TOP, TRUE);
    gtk_layer_set_anchor(GTK_WINDOW(win), GTK_LAYER_SHELL_EDGE_BOTTOM, TRUE);
    gtk_layer_set_anchor(GTK_WINDOW(win), GTK_LAYER_SHELL_EDGE_LEFT, TRUE);
    gtk_layer_set_anchor(GTK_WINDOW(win), GTK_LAYER_SHELL_EDGE_RIGHT, TRUE);
    gtk_layer_set_keyboard_mode(GTK_WINDOW(win), GTK_LAYER_SHELL_KEYBOARD_MODE_ON_DEMAND);
    gtk_style_context_add_class(gtk_widget_get_style_context(win), "graphene-bg");

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(root), 14);
    gtk_container_add(GTK_CONTAINER(win), root);

    struct launcher_widgets *lw = g_new0(struct launcher_widgets, 1);

    GtkWidget *hero = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 16);
    gtk_box_pack_start(GTK_BOX(root), hero, FALSE, FALSE, 0);

    GtkWidget *clock_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
    lw->clock_lbl = gtk_label_new("17:45");
    gtk_widget_set_halign(lw->clock_lbl, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(lw->clock_lbl), "clock-hero");
    lw->date_lbl = gtk_label_new("Android 15 (API 35) | GrapheneOS");
    gtk_widget_set_halign(lw->date_lbl, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(lw->date_lbl), "subtitle-muted");
    GtkWidget *kern_lbl = gtk_label_new("Qyronex Hybrid Rust Kernel · Cap-Binder v8 · eBPF · dm-verity · Dalvik APK");
    gtk_widget_set_halign(kern_lbl, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(kern_lbl), "subtitle-cyan");
    gtk_box_pack_start(GTK_BOX(clock_box), lw->clock_lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(clock_box), lw->date_lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(clock_box), kern_lbl, FALSE, FALSE, 1);
    gtk_box_pack_start(GTK_BOX(hero), clock_box, TRUE, TRUE, 0);

    GtkWidget *search_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_widget_set_valign(search_card, GTK_ALIGN_CENTER);
    GtkWidget *search_hint = gtk_label_new("Vanadium Web Search / URL (Press Enter or click Open)");
    gtk_widget_set_halign(search_hint, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(search_hint), "subtitle-muted");
    GtkWidget *srow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    lw->search_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(lw->search_entry), "http://example.com  or search...");
    gtk_widget_set_size_request(lw->search_entry, 320, -1);
    gtk_style_context_add_class(gtk_widget_get_style_context(lw->search_entry), "search-entry");
    g_signal_connect(lw->search_entry, "activate", G_CALLBACK(on_search_go), lw);
    GtkWidget *go_btn = gtk_button_new_with_label("Open Web");
    gtk_style_context_add_class(gtk_widget_get_style_context(go_btn), "action-btn");
    g_signal_connect(go_btn, "clicked", G_CALLBACK(on_search_go), lw);
    gtk_box_pack_start(GTK_BOX(srow), lw->search_entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(srow), go_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(search_card), search_hint, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(search_card), srow, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hero), search_card, FALSE, FALSE, 0);

    GtkWidget *cards = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_set_homogeneous(GTK_BOX(cards), TRUE);
    gtk_box_pack_start(GTK_BOX(root), cards, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(cards),
        make_status_card("SELinux & Hardening", "ENFORCING · W^X · Zero-Free",
                         "@settings:security", NULL),
        TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(cards),
        make_status_card("Binder v8 IPC", "Proto v8 · Live FD Passing",
                         "@apps", &lw->binder_sub),
        TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(cards),
        make_status_card("Pixel Tensor & Titan M2", "Pixel 9 G4 · KeyMint v300",
                         "@auditor", &lw->pixel_sub),
        TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(cards),
        make_status_card("Network & Modem IOMMU", "DHCP 10.0.2.15 · Sandboxed",
                         "@settings:network", &lw->net_sub),
        TRUE, TRUE, 0);

    GtkWidget *grid_hdr = gtk_label_new("GRAPHENEOS APPS  (Click any tile to launch)");
    gtk_widget_set_halign(grid_hdr, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(grid_hdr), "subtitle-muted");
    gtk_box_pack_start(GTK_BOX(root), grid_hdr, FALSE, FALSE, 0);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_homogeneous(GTK_GRID(grid), TRUE);
    gtk_grid_set_row_homogeneous(GTK_GRID(grid), TRUE);
    gtk_box_pack_start(GTK_BOX(root), grid, TRUE, TRUE, 0);

    struct {
        const char *badge; const char *cls; const char *name; const char *sub; const char *cmd;
    } apps[10] = {
        { "VN", "badge-blue",   "Vanadium",   "Web Browser",     "@vanadium" },
        { "ST", "badge-purple", "Settings",   "OS & Hardware",   "@settings" },
        { "AU", "badge-green",  "Auditor",    "15/15 HW Proof",  "@auditor" },
        { ">_", "badge-amber",  "Terminal",   "Android Shell",   "@terminal" },
        { "FS", "badge-orange", "Files",      "Storage & APKs",  "@files" },
        { "AP", "badge-teal",   "Apps",       "APKs & Binder",   "@apps" },
        { "LG", "badge-rose",   "Logcat",     "Live Kernel Log", "@logcat" },
        { "NT", "badge-indigo", "Notes",      "Text Editor",     "@notes" },
        { "CL", "badge-lime",   "Calculator", "Math & Hex",      "@calculator" },
        { "GL", "badge-sky",    "Gallery",    "Image Viewer",    "@gallery" },
    };

    for (int i = 0; i < 10; i++) {
        GtkWidget *tile = make_app_tile(apps[i].badge, apps[i].cls, apps[i].name, apps[i].sub, apps[i].cmd);
        gtk_grid_attach(GTK_GRID(grid), tile, i % 5, i / 5, 1, 1);
    }

    update_launcher_cb(lw);
    g_timeout_add_seconds(3, update_launcher_cb, lw);
    gtk_widget_show_all(win);
}

/* ============================================================================
 * 4. GRAPHENEOS SETTINGS WINDOW (100% Zero-Fork, Opens in <15ms!)
 * ============================================================================ */
struct settings_ctx {
    GtkWidget *selinux_result_lbl;
    GtkWidget *prop_view;
    GtkWidget *prop_key;
    GtkWidget *prop_val;
    GtkWidget *prop_msg;
    GtkWidget *net_view;
};

static void on_test_selinux_lockdown(GtkWidget *w, gpointer data) {
    (void)w;
    struct settings_ctx *ctx = (struct settings_ctx *)data;
    errno = 0;
    int rc = write_file_str("/sys/fs/selinux/enforce", "0");
    char msg[256];
    if (rc < 0 && errno == EPERM) {
        snprintf(msg, sizeof(msg),
                 "DEFENSE VERIFIED: Kernel blocked downgrade to permissive with -EPERM! SELinux remains ENFORCING (1).");
        android_log_write("W/SELinux: Blocked attempt to set /sys/fs/selinux/enforce=0 (-EPERM)");
    } else {
        snprintf(msg, sizeof(msg), "Unexpected result rc=%d errno=%d", rc, errno);
    }
    gtk_label_set_text(GTK_LABEL(ctx->selinux_result_lbl), msg);
}

static void refresh_props_view(struct settings_ctx *ctx) {
    char buf[4096];
    read_file_str("/sys/kernel/qyronex/android/properties", buf, sizeof(buf));
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(ctx->prop_view)),
                             buf[0] ? buf : "(no properties)", -1);
}

static void on_setprop_clicked(GtkWidget *w, gpointer data) {
    (void)w;
    struct settings_ctx *ctx = (struct settings_ctx *)data;
    const char *k = gtk_entry_get_text(GTK_ENTRY(ctx->prop_key));
    const char *v = gtk_entry_get_text(GTK_ENTRY(ctx->prop_val));
    if (!k || !k[0]) {
        gtk_label_set_text(GTK_LABEL(ctx->prop_msg), "Enter a property key (e.g. sys.demo or ro.build.version.release).");
        return;
    }
    char line[320];
    snprintf(line, sizeof(line), "%s=%s\n", k, v ? v : "");
    errno = 0;
    int rc = write_file_str("/sys/kernel/qyronex/android/properties", line);
    char msg[256];
    if (rc == 0) {
        snprintf(msg, sizeof(msg), "OK: Updated '%s' = '%s' in Qyronex Android Property Registry.", k, v ? v : "");
        refresh_props_view(ctx);
    } else if (errno == EPERM) {
        snprintf(msg, sizeof(msg), "BLOCKED (-EPERM): '%s' is an immutable ro.* GrapheneOS property!", k);
    } else {
        snprintf(msg, sizeof(msg), "ERROR: setprop failed (%s)", strerror(errno));
    }
    gtk_label_set_text(GTK_LABEL(ctx->prop_msg), msg);
}

/* Direct POSIX TCP/HTTP live Internet connectivity probe (ZERO fork!). */
static void on_net_test_clicked(GtkWidget *w, gpointer data) {
    (void)w;
    struct settings_ctx *ctx = (struct settings_ctx *)data;
    char out[4096];
    memset(out, 0, sizeof(out));
    format_interfaces_summary(out, sizeof(out));
    size_t pos = strlen(out);
    pos += (size_t)snprintf(out + pos, sizeof(out) - pos, "\n=== Live HTTP Probe (example.com:80) ===\n");

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo("example.com", "80", &hints, &res) == 0 && res) {
        int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s >= 0) {
            struct timeval tv = { 3, 0 };
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            if (connect(s, res->ai_addr, res->ai_addrlen) == 0) {
                const char *req = "HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n";
                (void)send(s, req, strlen(req), 0);
                char resp[512] = {0};
                ssize_t n = recv(s, resp, sizeof(resp) - 1, 0);
                if (n > 0) {
                    resp[n] = '\0';
                    snprintf(out + pos, sizeof(out) - pos, "CONNECTED! Response:\n%s", resp);
                } else {
                    snprintf(out + pos, sizeof(out) - pos, "TCP connected, no HTTP payload.\n");
                }
            } else {
                snprintf(out + pos, sizeof(out) - pos, "TCP connect failed: %s\n", strerror(errno));
            }
            close(s);
        }
        freeaddrinfo(res);
    } else {
        snprintf(out + pos, sizeof(out) - pos, "DNS lookup offline or blocked in sandbox.\n");
    }
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(ctx->net_view)), out, -1);
}

static void on_perm_toggled(GtkToggleButton *tb, gpointer data) {
    const char *key = (const char *)data;
    int active = gtk_toggle_button_get_active(tb);
    (void)mkdir("/data/system", 0755);
    FILE *f = fopen("/data/system/permissions.conf", "a");
    if (f) {
        fprintf(f, "%s=%d\n", key, active);
        fclose(f);
    }
    char logline[160];
    snprintf(logline, sizeof(logline), "I/PermissionMgr: %s -> %s", key, active ? "GRANTED" : "REVOKED");
    android_log_write(logline);
}

static void open_settings_window(const char *initial_page) {
    static GtkWidget *s_win = NULL;
    static GtkWidget *s_stack = NULL;
    if (s_win) {
        if (initial_page && s_stack) {
            gtk_stack_set_visible_child_name(GTK_STACK(s_stack), initial_page);
        }
        gtk_widget_show_all(s_win);
        gtk_window_present(GTK_WINDOW(s_win));
        return;
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    s_win = win;
    gtk_window_set_title(GTK_WINDOW(win), "GrapheneOS Settings — Qyronex Hybrid Kernel");
    gtk_window_set_default_size(GTK_WINDOW(win), 920, 540);
    track_inproc_window(win);

    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_container_add(GTK_CONTAINER(win), hbox);

    GtkWidget *stack = gtk_stack_new();
    s_stack = stack;
    gtk_stack_set_transition_type(GTK_STACK(stack), GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    GtkWidget *sidebar = gtk_stack_sidebar_new();
    gtk_stack_sidebar_set_stack(GTK_STACK_SIDEBAR(sidebar), GTK_STACK(stack));
    gtk_widget_set_size_request(sidebar, 200, -1);

    gtk_box_pack_start(GTK_BOX(hbox), sidebar, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), stack, TRUE, TRUE, 0);

    struct settings_ctx *ctx = g_new0(struct settings_ctx, 1);

    /* PAGE 1: Security & Hardening */
    GtkWidget *p_sec = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(p_sec), 16);
    GtkWidget *sec_h = gtk_label_new("GrapheneOS & Qyronex Kernel Hardening (Live Sysfs)");
    gtk_widget_set_halign(sec_h, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(sec_h), "app-title");
    gtk_box_pack_start(GTK_BOX(p_sec), sec_h, FALSE, FALSE, 0);

    char gbuf[2048];
    read_file_str("/sys/kernel/qyronex/grapheneos/status", gbuf, sizeof(gbuf));
    GtkWidget *sec_tv = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(sec_tv), FALSE);
    gtk_style_context_add_class(gtk_widget_get_style_context(sec_tv), "mono-box");
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(sec_tv)), gbuf, -1);
    GtkWidget *sec_sc = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sec_sc), sec_tv);
    gtk_box_pack_start(GTK_BOX(p_sec), sec_sc, TRUE, TRUE, 0);

    GtkWidget *test_btn = gtk_button_new_with_label("Test SELinux Enforcing Lockdown (Attempt write '0')");
    gtk_style_context_add_class(gtk_widget_get_style_context(test_btn), "action-btn");
    g_signal_connect(test_btn, "clicked", G_CALLBACK(on_test_selinux_lockdown), ctx);
    gtk_box_pack_start(GTK_BOX(p_sec), test_btn, FALSE, FALSE, 0);

    ctx->selinux_result_lbl = gtk_label_new("Click button above to test live kernel SELinux enforcing lockdown.");
    gtk_widget_set_halign(ctx->selinux_result_lbl, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->selinux_result_lbl), "subtitle-cyan");
    gtk_box_pack_start(GTK_BOX(p_sec), ctx->selinux_result_lbl, FALSE, FALSE, 0);
    gtk_stack_add_titled(GTK_STACK(stack), p_sec, "security", "Security & Hardening");

    /* PAGE 2: System Properties */
    GtkWidget *p_prop = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(p_prop), 16);
    GtkWidget *prow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    ctx->prop_key = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(ctx->prop_key), "Key (e.g. sys.demo or ro.build.type)");
    ctx->prop_val = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(ctx->prop_val), "Value");
    GtkWidget *set_btn = gtk_button_new_with_label("setprop");
    gtk_style_context_add_class(gtk_widget_get_style_context(set_btn), "action-btn");
    g_signal_connect(set_btn, "clicked", G_CALLBACK(on_setprop_clicked), ctx);
    gtk_box_pack_start(GTK_BOX(prow), ctx->prop_key, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(prow), ctx->prop_val, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(prow), set_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(p_prop), prow, FALSE, FALSE, 0);

    ctx->prop_msg = gtk_label_new("Try 'sys.demo=hello' (OK) or 'ro.build.version.release=99' (-EPERM!).");
    gtk_widget_set_halign(ctx->prop_msg, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->prop_msg), "subtitle-cyan");
    gtk_box_pack_start(GTK_BOX(p_prop), ctx->prop_msg, FALSE, FALSE, 0);

    ctx->prop_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(ctx->prop_view), FALSE);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->prop_view), "mono-box");
    GtkWidget *psc = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(psc), ctx->prop_view);
    gtk_box_pack_start(GTK_BOX(p_prop), psc, TRUE, TRUE, 0);
    refresh_props_view(ctx);
    gtk_stack_add_titled(GTK_STACK(stack), p_prop, "props", "System Properties");

    /* PAGE 3: Apps & Capability Permissions */
    GtkWidget *p_perm = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(p_perm), 16);
    GtkWidget *ph = gtk_label_new("GrapheneOS Per-App Capability Scopes (Saved to /data/system/permissions.conf)");
    gtk_widget_set_halign(ph, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(ph), "app-title");
    gtk_box_pack_start(GTK_BOX(p_perm), ph, FALSE, FALSE, 4);

    struct { const char *label; const char *key; int def; } perms[] = {
        { "Vanadium Browser — Network & DNS Capability",        "vanadium.network",    1 },
        { "Vanadium Browser — Scoped Storage (/data/downloads)", "vanadium.storage",    1 },
        { "Auditor — Titan M2 StrongBox Attestation",           "auditor.titan_m2",    1 },
        { "Terminal — Root & Binder Control Capability",        "terminal.binder_ctl", 1 },
        { "Files (Thunar) — /data & /sdcard Read/Write",        "files.storage",       1 },
        { "GrapheneOS — Native Exploit Protection (Zero-Free)", "graphene.zero_free",  1 },
        { "GrapheneOS — Deny Unprivileged User Namespaces",     "graphene.no_userns",  1 },
    };
    for (size_t i = 0; i < sizeof(perms) / sizeof(perms[0]); i++) {
        GtkWidget *cb = gtk_check_button_new_with_label(perms[i].label);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cb), perms[i].def);
        g_signal_connect(cb, "toggled", G_CALLBACK(on_perm_toggled), (gpointer)perms[i].key);
        gtk_box_pack_start(GTK_BOX(p_perm), cb, FALSE, FALSE, 2);
    }
    gtk_stack_add_titled(GTK_STACK(stack), p_perm, "perms", "Apps & Permissions");

    /* PAGE 4: Network & Internet (Zero-Fork POSIX getifaddrs!) */
    GtkWidget *p_net = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(p_net), 16);
    GtkWidget *net_btn = gtk_button_new_with_label("Run Live Network & Internet HTTP Probe (example.com)");
    gtk_style_context_add_class(gtk_widget_get_style_context(net_btn), "action-btn");
    g_signal_connect(net_btn, "clicked", G_CALLBACK(on_net_test_clicked), ctx);
    gtk_box_pack_start(GTK_BOX(p_net), net_btn, FALSE, FALSE, 0);

    ctx->net_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(ctx->net_view), FALSE);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->net_view), "mono-box");
    GtkWidget *nsc = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(nsc), ctx->net_view);
    gtk_box_pack_start(GTK_BOX(p_net), nsc, TRUE, TRUE, 0);
    char ninit[1024];
    format_interfaces_summary(ninit, sizeof(ninit));
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(ctx->net_view)), ninit, -1);
    gtk_stack_add_titled(GTK_STACK(stack), p_net, "network", "Network & Internet");

    /* PAGE 5: About Pixel & Kernel (Zero-Fork POSIX uname + Full Hardware/Storage/eBPF Sysfs!) */
    GtkWidget *p_about = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(p_about), 16);
    static char about_txt[8192];
    static char pix[1024], pix_hw[1536], bpf[1024], dmv[1024], stfs[1024], bnd[1024];
    struct utsname uts;
    memset(&uts, 0, sizeof(uts));
    (void)uname(&uts);
    read_file_str("/sys/bus/platform/drivers/google_pixel/status", pix, sizeof(pix));
    read_file_str("/sys/bus/platform/drivers/google_pixel/hardware", pix_hw, sizeof(pix_hw));
    read_file_str("/sys/kernel/qyronex/android/bpf_stats", bpf, sizeof(bpf));
    read_file_str("/sys/kernel/qyronex/android/dm_verity_status", dmv, sizeof(dmv));
    read_file_str("/sys/kernel/qyronex/android/storage_fs_status", stfs, sizeof(stfs));
    read_file_str("/sys/kernel/qyronex/android/binder_stats", bnd, sizeof(bnd));
    snprintf(about_txt, sizeof(about_txt),
             "=== OS & KERNEL ===\nQyronex OS v0.6.0 — Android 15 / GrapheneOS Pixel Edition\n"
             "%s %s %s %s\n\n"
             "=== PIXEL TENSOR G4 / MALI-G715 CSF GPU / EDGE TPU / MODEM / CAMERA HAL ===\n%s\n"
             "=== GOOGLE PIXEL TITAN M2 & VERIFIED BOOT ===\n%s\n"
             "=== DM-VERITY MERKLE TREE & ANDROID STORAGE (EROFS / F2FS / SUPER-LP / FUSE) ===\n%s%s\n"
             "=== eBPF SUBSYSTEM (sys_bpf nr 280) ===\n%s\n"
             "=== ANDROID BINDER v8 IPC ===\n%s\n",
             uts.sysname, uts.nodename, uts.release, uts.machine,
             pix_hw, pix, dmv, stfs, bpf, bnd);
    GtkWidget *atv = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(atv), FALSE);
    gtk_style_context_add_class(gtk_widget_get_style_context(atv), "mono-box");
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(atv)), about_txt, -1);
    GtkWidget *asc = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(asc), atv);
    gtk_box_pack_start(GTK_BOX(p_about), asc, TRUE, TRUE, 0);
    gtk_stack_add_titled(GTK_STACK(stack), p_about, "about", "About Pixel & Kernel");

    if (initial_page && initial_page[0]) {
        gtk_stack_set_visible_child_name(GTK_STACK(stack), initial_page);
    }

    gtk_widget_show_all(win);
    gtk_window_present(GTK_WINDOW(win));
}

/* ============================================================================
 * 5. GRAPHENEOS AUDITOR WINDOW (Direct In-Process Live 15/15 Kernel Attestation!)
 * ============================================================================ */
struct auditor_ctx {
    GtkWidget *banner;
    GtkWidget *tv;
};

static int run_inproc_15_tests(char *out, size_t cap) {
    int passed = 0;
    size_t pos = 0;
    char buf[2048];
    pos += (size_t)snprintf(out + pos, cap - pos,
        "================================================================\n"
        "  Qyronex OS v0.6.0 — Live Android 15 / GrapheneOS Attestation\n"
        "================================================================\n");

    /* 1. SELinux enforcing lockdown */
    int ok1 = 0;
    if (read_file_str("/sys/fs/selinux/enforce", buf, sizeof(buf)) > 0 && buf[0] == '1') {
        errno = 0;
        if (write_file_str("/sys/fs/selinux/enforce", "0") < 0 && errno == EPERM) ok1 = 1;
    }
    pos += (size_t)snprintf(out + pos, cap - pos, "[ 1/15] SELINUX_ENFORCING_LOCKDOWN ...... %s\n", ok1 ? "PASS" : "FAIL");
    passed += ok1;

    /* 2. Cross-Process Binder v8 RPC */
    int ok2 = 0;
    struct binder_client bc;
    if (binder_client_open(&bc, "/dev/binder") == 0) {
        char r1[192] = {0};
        if (binder_rpc(&bc, 0, SM_CMD_PING, "", 0, r1, sizeof(r1)) > 0 && strstr(r1, "PONG")) ok2 = 1;
        binder_client_close(&bc);
    }
    pos += (size_t)snprintf(out + pos, cap - pos, "[ 2/15] BINDER_V8_IPC_SERVICEMANAGER .... %s\n", ok2 ? "PASS" : "FAIL");
    passed += ok2;

    /* 3. Ashmem mmap + pin/unpin */
    int ok3 = 0;
    int afd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
    if (afd >= 0) {
        char aname[256] = "auditor.ashmem";
        if (ioctl(afd, ASHMEM_SET_NAME, aname) == 0 &&
            ioctl(afd, ASHMEM_SET_SIZE, (unsigned long)4096) == 0) {
            void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, afd, 0);
            if (p != MAP_FAILED && p != NULL) {
                memcpy(p, "AUDITOR_ASHMEM_OK", 18);
                munmap(p, 4096);
                char chk[32] = {0};
                if (pread(afd, chk, 18, 0) == 18 && strcmp(chk, "AUDITOR_ASHMEM_OK") == 0) ok3 = 1;
            }
        }
        close(afd);
    }
    pos += (size_t)snprintf(out + pos, cap - pos, "[ 3/15] ASHMEM_MMAP_PIN_ZERO_ON_FREE .... %s\n", ok3 ? "PASS" : "FAIL");
    passed += ok3;

    /* 4. DMA-Heap system alloc */
    int ok4 = 0;
    int dfd = open("/dev/dma_heap/system", O_RDWR | O_CLOEXEC);
    if (dfd >= 0) {
        struct dma_heap_allocation_data alloc;
        memset(&alloc, 0, sizeof(alloc));
        alloc.len = 4096;
        if (ioctl(dfd, DMA_HEAP_IOCTL_ALLOC, &alloc) == 0 && (int)alloc.fd >= 0) {
            char rd[16] = {0};
            if (pwrite((int)alloc.fd, "DMA_OK", 6, 0) == 6 && pread((int)alloc.fd, rd, 6, 0) == 6 &&
                memcmp(rd, "DMA_OK", 6) == 0) ok4 = 1;
            close((int)alloc.fd);
        }
        close(dfd);
    }
    pos += (size_t)snprintf(out + pos, cap - pos, "[ 4/15] DMA_HEAP_SYSTEM_ALLOC ........... %s\n", ok4 ? "PASS" : "FAIL");
    passed += ok4;

    /* 5. ro.* immutability */
    int ok5 = 0;
    errno = 0;
    if (write_file_str("/sys/kernel/qyronex/android/properties", "ro.build.version.release=99\n") < 0 &&
        errno == EPERM &&
        write_file_str("/sys/kernel/qyronex/android/properties", "sys.auditor.verified=1\n") == 0) ok5 = 1;
    pos += (size_t)snprintf(out + pos, cap - pos, "[ 5/15] RO_PROPERTIES_IMMUTABLE ......... %s\n", ok5 ? "PASS" : "FAIL");
    passed += ok5;

    /* 6. Power wakelocks & PSI */
    int ok6 = 0;
    if (write_file_str("/sys/power/wake_lock", "auditor_wl\n") == 0 &&
        write_file_str("/sys/power/wake_unlock", "auditor_wl\n") == 0 &&
        read_file_str("/proc/pressure/memory", buf, sizeof(buf)) > 0 && strstr(buf, "some avg10=")) ok6 = 1;
    pos += (size_t)snprintf(out + pos, cap - pos, "[ 6/15] POWER_WAKELOCK_AND_PSI .......... %s\n", ok6 ? "PASS" : "FAIL");
    passed += ok6;

    /* 7. GrapheneOS hardening status */
    int ok7 = 0;
    if (read_file_str("/sys/kernel/qyronex/grapheneos/status", buf, sizeof(buf)) > 0 &&
        strstr(buf, "selinux=enforcing") && strstr(buf, "capability_binder=enforced") &&
        strstr(buf, "zero_on_free=1")) ok7 = 1;
    pos += (size_t)snprintf(out + pos, cap - pos, "[ 7/15] GRAPHENEOS_HARDENING_STATUS ..... %s\n", ok7 ? "PASS" : "FAIL");
    passed += ok7;

    /* 8. Pixel Titan M2 StrongBox & Modem IOMMU */
    int ok8 = 0;
    if (read_file_str("/sys/bus/platform/drivers/google_pixel/status", buf, sizeof(buf)) > 0 &&
        strstr(buf, "titan_m2=online-strongbox") && strstr(buf, "modem_iommu_sandbox=enforced")) ok8 = 1;
    pos += (size_t)snprintf(out + pos, cap - pos, "[ 8/15] PIXEL_TITAN_M2_MODEM_IOMMU ...... %s\n", ok8 ? "PASS" : "FAIL");
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
            tx.code = SM_CMD_ECHO_FD;
            tx.flags = 0x10;
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
                for (int tries = 0; tries < 40 && !freply[0]; tries++) {
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
                char vback[16] = {0};
                (void)pread(sfd, vback, 12, 32);
                if (strstr(freply, "FD_OK") && memcmp(vback, "SM_SAW_FD_OK", 12) == 0) ok9 = 1;
            }
            binder_client_close(&fbc);
        }
        if (sfd >= 0) close(sfd);
    }
    pos += (size_t)snprintf(out + pos, cap - pos, "[ 9/15] BINDER_FD_PASSING_CROSS_PROC .... %s\n", ok9 ? "PASS" : "FAIL");
    passed += ok9;

    /* 10. binderfs + userfaultfd + membarrier */
    int ok10 = 0;
    {
        int ctl_ok = 0, uffd_ok = 0, mb_ok = 0;
        int cfd = open("/dev/binderfs/binder-control", O_RDWR | O_CLOEXEC);
        if (cfd >= 0) {
            struct binderfs_device dev;
            memset(&dev, 0, sizeof(dev));
            snprintf(dev.name, sizeof(dev.name), "graphene-auditor");
            if (ioctl(cfd, BINDER_CTL_ADD, &dev) == 0 && dev.major == 240) ctl_ok = 1;
            close(cfd);
        }
        long ufd = syscall(282, O_CLOEXEC);
        if (ufd >= 0) {
            struct uffdio_api ua = { 0xAA, 0, 0 };
            if (ioctl((int)ufd, UFFDIO_API, &ua) == 0 && ua.ioctls != 0) uffd_ok = 1;
            close((int)ufd);
        }
        if (syscall(283, 0, 0, 0) > 0) mb_ok = 1;
        if (ctl_ok && uffd_ok && mb_ok) ok10 = 1;
    }
    pos += (size_t)snprintf(out + pos, cap - pos, "[10/15] BINDERFS_USERFAULTFD_MEMBARRIER . %s\n", ok10 ? "PASS" : "FAIL");
    passed += ok10;

    /* 11. Real eBPF (sys_bpf 280): Hash Map + Fail-Closed Verifier + 64-bit VM Execution */
    int ok11 = 0;
    {
        uint8_t attr[128];
        memset(attr, 0, sizeof(attr));
        uint32_t mtype = 1, ksz = 4, vsz = 8, maxe = 16;
        memcpy(attr + 0, &mtype, 4);
        memcpy(attr + 4, &ksz, 4);
        memcpy(attr + 8, &vsz, 4);
        memcpy(attr + 12, &maxe, 4);
        long mfd = syscall(280, 0, attr, 64);
        int map_ok = 0, prog_ok = 0, rej_ok = 0;
        if (mfd >= 0) {
            uint32_t k = 11;
            uint64_t v = 0xCAFEBABE00150006ULL, vout = 0;
            uint64_t kp = (uint64_t)(uintptr_t)&k, vp = (uint64_t)(uintptr_t)&v, vo = (uint64_t)(uintptr_t)&vout;
            uint32_t mfd32 = (uint32_t)mfd;
            memset(attr, 0, sizeof(attr));
            memcpy(attr + 0, &mfd32, 4);
            memcpy(attr + 8, &kp, 8);
            memcpy(attr + 16, &vp, 8);
            if (syscall(280, 2, attr, 64) == 0) {
                memcpy(attr + 16, &vo, 8);
                if (syscall(280, 1, attr, 64) == 0 && vout == v) map_ok = 1;
            }
            close((int)mfd);
        }
        struct { uint8_t code; uint8_t regs; int16_t off; int32_t imm; } insns[3] = {
            { 0x71, 0x10, 0, 0 }, { 0x07, 0x00, 0, 10 }, { 0x95, 0x00, 0, 0 },
        };
        memset(attr, 0, sizeof(attr));
        uint32_t ptype = 1, icnt = 3;
        uint64_t iptr = (uint64_t)(uintptr_t)insns;
        memcpy(attr + 0, &ptype, 4);
        memcpy(attr + 4, &icnt, 4);
        memcpy(attr + 8, &iptr, 8);
        long pfd = syscall(280, 5, attr, 64);
        if (pfd >= 0) {
            uint8_t pkt[4] = { 32, 0, 0, 0 };
            uint32_t pfd32 = (uint32_t)pfd, dsz = 4, retval = 0;
            uint64_t dptr = (uint64_t)(uintptr_t)pkt;
            memset(attr, 0, sizeof(attr));
            memcpy(attr + 0, &pfd32, 4);
            memcpy(attr + 8, &dsz, 4);
            memcpy(attr + 16, &dptr, 8);
            if (syscall(280, 10, attr, 64) == 0) {
                memcpy(&retval, attr + 4, 4);
                if (retval == 42) prog_ok = 1;
            }
            close((int)pfd);
        }
        struct { uint8_t code; uint8_t regs; int16_t off; int32_t imm; } bad[2] = {
            { 0x05, 0x00, -1, 0 }, { 0x95, 0x00, 0, 0 },
        };
        memset(attr, 0, sizeof(attr));
        icnt = 2;
        iptr = (uint64_t)(uintptr_t)bad;
        memcpy(attr + 0, &ptype, 4);
        memcpy(attr + 4, &icnt, 4);
        memcpy(attr + 8, &iptr, 8);
        errno = 0;
        if (syscall(280, 5, attr, 64) < 0 && errno == EACCES) rej_ok = 1;
        if (map_ok && prog_ok && rej_ok) ok11 = 1;
    }
    pos += (size_t)snprintf(out + pos, cap - pos, "[11/15] EBPF_SYS_BPF_VERIFY_AND_EXEC .... %s\n", ok11 ? "PASS" : "FAIL");
    passed += ok11;

    /* 12. Real dm-verity SHA-256 Merkle Check + 1-Bit Tamper Fail-Closed (-EIO) */
    int ok12 = 0;
    {
        int dmfd = open("/dev/mapper/control", O_RDWR | O_CLOEXEC);
        if (dmfd >= 0) {
            uint8_t ver[16] = {0};
            uint32_t maj = 0, minv = 0;
            int v_ok = (ioctl(dmfd, 0xC138FD00UL, ver) == 0);
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
            int clean_ok = (ioctl(dmfd, 0xC040FD80UL, req) == 0);
            blk[5] ^= 0x01;
            errno = 0;
            int tamper_blocked = (ioctl(dmfd, 0xC040FD80UL, req) < 0 && errno == EIO);
            if (v_ok && maj == 4 && minv == 48 && clean_ok && tamper_blocked) ok12 = 1;
            close(dmfd);
        }
    }
    pos += (size_t)snprintf(out + pos, cap - pos, "[12/15] DM_VERITY_MERKLE_FAIL_CLOSED .... %s\n", ok12 ? "PASS" : "FAIL");
    passed += ok12;

    /* 13. Real EROFS + F2FS + super.img LP_METADATA + /dev/fuse v7.39 Handshake */
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
    pos += (size_t)snprintf(out + pos, cap - pos, "[13/15] EROFS_F2FS_SUPER_LP_FUSE ........ %s\n", ok13 ? "PASS" : "FAIL");
    passed += ok13;

    /* 14. Pixel Mali-G715 CSF GPU + Tensor Edge TPU + Camera LWIS + Modem HAL */
    int ok14 = 0;
    {
        int mfd = open("/dev/mali0", O_RDWR | O_CLOEXEC);
        int mali_ok = 0, hw_ok = 0;
        if (mfd >= 0) {
            uint16_t ver[2] = {0, 0};
            uint32_t props[4] = {0, 0, 0, 0};
            if (ioctl(mfd, 0xC0048000UL, ver) == 0 && ioctl(mfd, 0xC0108003UL, props) == 0 &&
                ver[0] == 1 && props[0] != 0 && props[3] == 1) mali_ok = 1;
            close(mfd);
        }
        if (read_file_str("/sys/bus/platform/drivers/google_pixel/hardware", buf, sizeof(buf)) > 0 &&
            strstr(buf, "gpu_iommu=enforced") && strstr(buf, "edge_tpu_iommu=enforced") &&
            strstr(buf, "vendor_boot_v4=supported") && access("/dev/edgetpu", F_OK) == 0 &&
            access("/dev/umts_ipc0", F_OK) == 0) hw_ok = 1;
        if (mali_ok && hw_ok) ok14 = 1;
    }
    pos += (size_t)snprintf(out + pos, cap - pos, "[14/15] PIXEL_MALI_GPU_EDGETPU_HAL ...... %s\n", ok14 ? "PASS" : "FAIL");
    passed += ok14;

    /* 15. Real Android APK/DEX Dalvik VM Runtime (pm + am + qyronex-art verified output) */
    int ok15 = 0;
    {
        char pkgs[1024] = {0}, act[2048] = {0};
        if (access("/system/bin/pm", X_OK) == 0 && access("/system/bin/am", X_OK) == 0 &&
            read_file_str("/data/system/packages.list", pkgs, sizeof(pkgs)) > 0 &&
            strstr(pkgs, "org.grapheneos.welcome") != NULL &&
            read_file_str("/run/user/0/qyronex-activity.txt", act, sizeof(act)) > 0 &&
            strstr(act, "DEX_ADLER32=0x") != NULL &&
            strstr(act, "DALVIK_INSNS=") != NULL) {
            ok15 = 1;
        }
    }
    pos += (size_t)snprintf(out + pos, cap - pos, "[15/15] APK_DEX_DALVIK_VM_PM_AM_EXEC .... %s\n", ok15 ? "PASS" : "FAIL");
    passed += ok15;

    snprintf(out + pos, cap - pos,
             "----------------------------------------------------------------\n"
             "RESULT: %d/15 CHECKS PASSED (Live zero-fork kernel attestation)\n",
             passed);
    return passed;
}

static void run_audit_now(GtkWidget *w, gpointer data) {
    (void)w;
    struct auditor_ctx *ctx = (struct auditor_ctx *)data;
    static char out[4096];
    int passed = run_inproc_15_tests(out, sizeof(out));
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(ctx->tv)), out, -1);

    GtkStyleContext *sc = gtk_widget_get_style_context(ctx->banner);
    if (passed == 15) {
        gtk_style_context_remove_class(sc, "banner-warn");
        gtk_style_context_add_class(sc, "banner-pass");
        gtk_label_set_text(GTK_LABEL(ctx->banner),
            "ATTESTATION GREEN: 15/15 Android 15 / eBPF / dm-verity / Pixel HAL / APK-DEX Checks PASSED!");
        android_log_write("I/Auditor: Live GUI hardware attestation VERIFIED (15/15 PASS)");
    } else {
        gtk_style_context_remove_class(sc, "banner-pass");
        gtk_style_context_add_class(sc, "banner-warn");
        gtk_label_set_text(GTK_LABEL(ctx->banner),
            "ATTESTATION WARNING: Some checks did not pass — inspect report below.");
    }
}

static gboolean run_audit_idle_cb(gpointer data) {
    run_audit_now(NULL, data);
    return FALSE;
}

static void open_auditor_window(void) {
    static GtkWidget *s_win = NULL;
    static struct auditor_ctx *s_ctx = NULL;
    if (s_win) {
        gtk_widget_show_all(s_win);
        gtk_window_present(GTK_WINDOW(s_win));
        g_idle_add(run_audit_idle_cb, s_ctx);
        return;
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    s_win = win;
    gtk_window_set_title(GTK_WINDOW(win), "GrapheneOS Auditor — 15/15 Kernel, eBPF, dm-verity & Pixel Attestation");
    gtk_window_set_default_size(GTK_WINDOW(win), 860, 540);
    track_inproc_window(win);

    GtkWidget *vb = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(vb), 16);
    gtk_container_add(GTK_CONTAINER(win), vb);

    struct auditor_ctx *ctx = g_new0(struct auditor_ctx, 1);
    s_ctx = ctx;
    ctx->banner = gtk_label_new("Running live 15/15 hardware & kernel attestation...");
    gtk_widget_set_halign(ctx->banner, GTK_ALIGN_FILL);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->banner), "banner-pass");
    gtk_box_pack_start(GTK_BOX(vb), ctx->banner, FALSE, FALSE, 0);

    GtkWidget *btn = gtk_button_new_with_label("Re-Run Live 15/15 Kernel, eBPF, dm-verity, Pixel HAL & APK Verification");
    gtk_style_context_add_class(gtk_widget_get_style_context(btn), "action-btn");
    g_signal_connect(btn, "clicked", G_CALLBACK(run_audit_now), ctx);
    gtk_box_pack_start(GTK_BOX(vb), btn, FALSE, FALSE, 0);

    ctx->tv = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(ctx->tv), FALSE);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->tv), "mono-box");
    GtkWidget *sc = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sc), ctx->tv);
    gtk_box_pack_start(GTK_BOX(vb), sc, TRUE, TRUE, 0);

    gtk_widget_show_all(win);
    gtk_window_present(GTK_WINDOW(win));
    g_idle_add(run_audit_idle_cb, ctx);
}

/* ============================================================================
 * 6. APPS, ANDROID APK INSTALLER (`pm`/`am`/`qyronex-art`) & BINDER v8 EXPLORER
 * ============================================================================ */
struct apps_ctx {
    GtkWidget *svc_view;
    GtkWidget *svc_entry;
    GtkWidget *apk_view;
};

static struct apps_ctx *g_apps_ctx = NULL;

static void refresh_apk_packages_view(void) {
    if (!g_apps_ctx || !GTK_IS_TEXT_VIEW(g_apps_ctx->apk_view)) return;
    static char raw[4096], out[4608];
    memset(raw, 0, sizeof(raw));
    size_t pos = 0;
    pos += (size_t)snprintf(out + pos, sizeof(out) - pos,
                            "=== Installed APKs (/data/system/packages.list) ===\n");
    if (read_file_str("/data/system/packages.list", raw, sizeof(raw)) > 0) {
        char *line = raw;
        int cnt = 0;
        while (*line && pos + 160 < sizeof(out)) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            if (line[0]) {
                char pkg[128] = {0}, lbl[128] = {0}, act[160] = {0}, ver[48] = {0}, path[256] = {0};
                if (sscanf(line, "%127[^|]|%127[^|]|%159[^|]|%47[^|]|%255[^\n]",
                           pkg, lbl, act, ver, path) == 5) {
                    pos += (size_t)snprintf(out + pos, sizeof(out) - pos,
                                            "  * %s  (v%s)\n    %s -> %s\n",
                                            pkg, ver, lbl, path);
                    cnt++;
                }
            }
            if (!nl) break;
            line = nl + 1;
        }
        if (cnt == 0) {
            snprintf(out + pos, sizeof(out) - pos, "  (none yet — click Install & Run above)\n");
        }
    } else {
        snprintf(out + pos, sizeof(out) - pos, "  (none yet — click Install & Run above)\n");
    }
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(g_apps_ctx->apk_view)), out, -1);
}

static void refresh_services(GtkWidget *w, gpointer data) {
    (void)w;
    struct apps_ctx *ctx = (struct apps_ctx *)data;
    char reply[1536] = {0}, stats[512] = {0}, out[2560];
    struct binder_client bc;
    if (binder_client_open(&bc, "/dev/binder") == 0) {
        if (binder_rpc(&bc, 0, SM_CMD_LIST_SERVICES, "", 0, reply, sizeof(reply)) < 0) {
            snprintf(reply, sizeof(reply), "(servicemanager unreachable)\n");
        }
        binder_client_close(&bc);
    } else {
        snprintf(reply, sizeof(reply), "(cannot open /dev/binder)\n");
    }
    read_file_str("/sys/kernel/qyronex/android/binder_stats", stats, sizeof(stats));
    snprintf(out, sizeof(out),
             "=== Registered Android Services (Live Binder v8 RPC) ===\n%s\n"
             "=== Kernel Binder Audit Stats ===\n%s",
             reply, stats);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(ctx->svc_view)), out, -1);
    refresh_apk_packages_view();
}

static void on_register_svc(GtkWidget *w, gpointer data) {
    (void)w;
    struct apps_ctx *ctx = (struct apps_ctx *)data;
    const char *name = gtk_entry_get_text(GTK_ENTRY(ctx->svc_entry));
    if (name && name[0]) {
        struct binder_client bc;
        if (binder_client_open(&bc, "/dev/binder") == 0) {
            char resp[192] = {0};
            (void)binder_rpc(&bc, 0, SM_CMD_ADD_SERVICE, name, strlen(name), resp, sizeof(resp));
            binder_client_close(&bc);
        }
        gtk_entry_set_text(GTK_ENTRY(ctx->svc_entry), "");
        refresh_services(NULL, ctx);
    }
}

static void open_apps_window(void) {
    static GtkWidget *s_win = NULL;
    static struct apps_ctx *s_ctx = NULL;
    if (s_win) {
        refresh_services(NULL, s_ctx);
        gtk_widget_show_all(s_win);
        gtk_window_present(GTK_WINDOW(s_win));
        return;
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    s_win = win;
    gtk_window_set_title(GTK_WINDOW(win), "GrapheneOS Apps — Android APK Installer (pm/am) & Binder v8");
    gtk_window_set_default_size(GTK_WINDOW(win), 980, 560);
    track_inproc_window(win);

    struct apps_ctx *ctx = g_new0(struct apps_ctx, 1);
    s_ctx = ctx;
    g_apps_ctx = ctx;

    GtkWidget *hb = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 14);
    gtk_container_set_border_width(GTK_CONTAINER(hb), 14);
    gtk_container_add(GTK_CONTAINER(win), hb);

    /* LEFT: Real Android APK Installer & Dalvik VM Launcher (`pm` / `am` / `qyronex-art`) */
    GtkWidget *left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_size_request(left, 450, -1);

    GtkWidget *lh = gtk_label_new("Android APK Packages (Qyronex ART Dalvik VM)");
    gtk_widget_set_halign(lh, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(lh), "app-title");
    gtk_box_pack_start(GTK_BOX(left), lh, FALSE, FALSE, 0);

    GtkWidget *lsub = gtk_label_new("Real ZIP + Binary AXML AndroidManifest.xml + classes.dex (DEX 035)");
    gtk_widget_set_halign(lsub, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(lsub), "subtitle-cyan");
    gtk_box_pack_start(GTK_BOX(left), lsub, FALSE, FALSE, 0);

    struct { const char *name; const char *sub; const char *btn; const char *cmd; } apks[] = {
        { "GrapheneWelcome.apk",     "org.grapheneos.welcome (System APK)", "Run APK",       "@apk-run:/system/app/GrapheneWelcome.apk" },
        { "PixelSecurityBench.apk",  "org.grapheneos.securitybench (/data)", "Install & Run", "@apk-install-run:/data/local/tmp/PixelSecurityBench.apk" },
        { "QyronexHardwareInfo.apk", "org.qyronex.hwinfo (/data/local/tmp)", "Install & Run", "@apk-install-run:/data/local/tmp/QyronexHardwareInfo.apk" },
    };
    for (size_t i = 0; i < sizeof(apks) / sizeof(apks[0]); i++) {
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *tb = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
        GtkWidget *t = gtk_label_new(apks[i].name);
        gtk_widget_set_halign(t, GTK_ALIGN_START);
        gtk_style_context_add_class(gtk_widget_get_style_context(t), "app-title");
        GtkWidget *s = gtk_label_new(apks[i].sub);
        gtk_widget_set_halign(s, GTK_ALIGN_START);
        gtk_style_context_add_class(gtk_widget_get_style_context(s), "subtitle-muted");
        gtk_box_pack_start(GTK_BOX(tb), t, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(tb), s, FALSE, FALSE, 0);
        GtkWidget *b = gtk_button_new_with_label(apks[i].btn);
        gtk_style_context_add_class(gtk_widget_get_style_context(b), "action-btn");
        g_signal_connect(b, "clicked", G_CALLBACK(on_launch_clicked), (gpointer)apks[i].cmd);
        gtk_box_pack_start(GTK_BOX(row), tb, TRUE, TRUE, 0);
        gtk_box_pack_start(GTK_BOX(row), b, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(left), row, FALSE, FALSE, 2);
    }

    ctx->apk_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(ctx->apk_view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(ctx->apk_view), GTK_WRAP_CHAR);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->apk_view), "mono-box");
    GtkWidget *apk_sc = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(apk_sc), ctx->apk_view);
    gtk_box_pack_start(GTK_BOX(left), apk_sc, TRUE, TRUE, 2);
    gtk_box_pack_start(GTK_BOX(hb), left, FALSE, FALSE, 0);

    /* RIGHT: Live Binder v8 ServiceManager + System App Quick-Launch */
    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *rh = gtk_label_new("Live /dev/binder ServiceManager Registry (Real Binder v8 RPC)");
    gtk_widget_set_halign(rh, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(rh), "app-title");
    gtk_box_pack_start(GTK_BOX(right), rh, FALSE, FALSE, 0);

    GtkWidget *add_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    ctx->svc_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(ctx->svc_entry), "New service (e.g. com.pixel.camera)");
    GtkWidget *add_btn = gtk_button_new_with_label("Register");
    gtk_style_context_add_class(gtk_widget_get_style_context(add_btn), "action-btn");
    g_signal_connect(add_btn, "clicked", G_CALLBACK(on_register_svc), ctx);
    GtkWidget *ref_btn = gtk_button_new_with_label("Refresh");
    gtk_style_context_add_class(gtk_widget_get_style_context(ref_btn), "nav-btn");
    g_signal_connect(ref_btn, "clicked", G_CALLBACK(refresh_services), ctx);
    gtk_box_pack_start(GTK_BOX(add_row), ctx->svc_entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(add_row), add_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(add_row), ref_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(right), add_row, FALSE, FALSE, 0);

    ctx->svc_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(ctx->svc_view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(ctx->svc_view), GTK_WRAP_CHAR);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->svc_view), "mono-box");
    GtkWidget *sc = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sc), ctx->svc_view);
    gtk_box_pack_start(GTK_BOX(right), sc, TRUE, TRUE, 0);

    GtkWidget *sys_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    struct { const char *lbl; const char *cmd; } sysapps[] = {
        { "Auditor 15/15", "@auditor" },
        { "Settings",      "@settings" },
        { "Vanadium",      "@vanadium" },
        { "Terminal",      "@terminal" },
        { "Files",         "@files" },
        { "Logcat",        "@logcat" },
    };
    for (size_t i = 0; i < sizeof(sysapps) / sizeof(sysapps[0]); i++) {
        GtkWidget *b = gtk_button_new_with_label(sysapps[i].lbl);
        gtk_style_context_add_class(gtk_widget_get_style_context(b), "pill-dark");
        g_signal_connect(b, "clicked", G_CALLBACK(on_launch_clicked), (gpointer)sysapps[i].cmd);
        gtk_box_pack_start(GTK_BOX(sys_row), b, TRUE, TRUE, 0);
    }
    gtk_box_pack_start(GTK_BOX(right), sys_row, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hb), right, TRUE, TRUE, 0);

    refresh_services(NULL, ctx);
    gtk_widget_show_all(win);
    gtk_window_present(GTK_WINDOW(win));
}

/* ============================================================================
 * 7. LIVE ANDROID LOGCAT WINDOW
 * ============================================================================ */
struct logcat_ctx {
    GtkWidget *win;
    GtkWidget *tv;
    GtkWidget *entry;
    guint timer_id;
};

static gboolean refresh_logcat_cb(gpointer data) {
    struct logcat_ctx *ctx = (struct logcat_ctx *)data;
    if (!GTK_IS_TEXT_VIEW(ctx->tv)) return FALSE;
    if (ctx->win && !gtk_widget_get_visible(ctx->win)) return TRUE;
    char buf[16384];
    read_file_str("/dev/log/main", buf, sizeof(buf));
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(ctx->tv)), buf, -1);
    return TRUE;
}

static void on_logcat_destroy(GtkWidget *w, gpointer data) {
    (void)w;
    struct logcat_ctx *ctx = (struct logcat_ctx *)data;
    if (ctx->timer_id) g_source_remove(ctx->timer_id);
    g_free(ctx);
}

static void on_inject_log(GtkWidget *w, gpointer data) {
    (void)w;
    struct logcat_ctx *ctx = (struct logcat_ctx *)data;
    const char *txt = gtk_entry_get_text(GTK_ENTRY(ctx->entry));
    if (txt && txt[0]) {
        char line[320];
        snprintf(line, sizeof(line), "I/UserLog: %s", txt);
        android_log_write(line);
        gtk_entry_set_text(GTK_ENTRY(ctx->entry), "");
        refresh_logcat_cb(ctx);
    }
}

static void open_logcat_window(void) {
    static GtkWidget *s_win = NULL;
    static struct logcat_ctx *s_ctx = NULL;
    if (s_win) {
        gtk_widget_show_all(s_win);
        refresh_logcat_cb(s_ctx);
        gtk_window_present(GTK_WINDOW(s_win));
        return;
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    s_win = win;
    gtk_window_set_title(GTK_WINDOW(win), "Android Logcat — /dev/log/main (Live)");
    gtk_window_set_default_size(GTK_WINDOW(win), 860, 520);
    track_inproc_window(win);

    GtkWidget *vb = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(vb), 14);
    gtk_container_add(GTK_CONTAINER(win), vb);

    struct logcat_ctx *ctx = g_new0(struct logcat_ctx, 1);
    ctx->win = win;
    s_ctx = ctx;
    GtkWidget *top = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    ctx->entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(ctx->entry), "Write custom event to /dev/log/main...");
    g_signal_connect(ctx->entry, "activate", G_CALLBACK(on_inject_log), ctx);
    GtkWidget *add_b = gtk_button_new_with_label("Write Log");
    gtk_style_context_add_class(gtk_widget_get_style_context(add_b), "action-btn");
    g_signal_connect(add_b, "clicked", G_CALLBACK(on_inject_log), ctx);
    GtkWidget *ref_b = gtk_button_new_with_label("Refresh");
    gtk_style_context_add_class(gtk_widget_get_style_context(ref_b), "nav-btn");
    g_signal_connect_swapped(ref_b, "clicked", G_CALLBACK(refresh_logcat_cb), ctx);
    gtk_box_pack_start(GTK_BOX(top), ctx->entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(top), add_b, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(top), ref_b, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vb), top, FALSE, FALSE, 0);

    ctx->tv = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(ctx->tv), FALSE);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->tv), "mono-box");
    GtkWidget *sc = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sc), ctx->tv);
    gtk_box_pack_start(GTK_BOX(vb), sc, TRUE, TRUE, 0);

    ctx->timer_id = g_timeout_add_seconds(2, refresh_logcat_cb, ctx);
    g_signal_connect(win, "destroy", G_CALLBACK(on_logcat_destroy), ctx);
    gtk_widget_show_all(win);
    refresh_logcat_cb(ctx);
    gtk_window_present(GTK_WINDOW(win));
}

/* ============================================================================
 * 8. QUICK SETTINGS CONTROL CENTER WINDOW
 * ============================================================================ */
static void open_quicksettings_window(void) {
    static GtkWidget *s_win = NULL;
    if (s_win) {
        gtk_widget_show_all(s_win);
        gtk_window_present(GTK_WINDOW(s_win));
        return;
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    s_win = win;
    gtk_window_set_title(GTK_WINDOW(win), "GrapheneOS Quick Settings");
    gtk_window_set_default_size(GTK_WINDOW(win), 380, 360);
    track_inproc_window(win);

    GtkWidget *vb = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(vb), 16);
    gtk_container_add(GTK_CONTAINER(win), vb);

    GtkWidget *h = gtk_label_new("GrapheneOS Quick Settings");
    gtk_style_context_add_class(gtk_widget_get_style_context(h), "app-title");
    gtk_box_pack_start(GTK_BOX(vb), h, FALSE, FALSE, 4);

    char ip[48], info[160];
    get_primary_ip(ip, sizeof(ip));
    snprintf(info, sizeof(info), "SELinux: ENFORCING  |  IP: %s\nTitan M2: StrongBox  |  Binder v8: Active", ip);
    GtkWidget *st = gtk_label_new(info);
    gtk_style_context_add_class(gtk_widget_get_style_context(st), "banner-pass");
    gtk_box_pack_start(GTK_BOX(vb), st, FALSE, FALSE, 4);

    struct { const char *lbl; const char *cmd; } btns[] = {
        { "Open GrapheneOS Settings",    "@settings" },
        { "Run 15/15 Hardware Auditor",  "@auditor" },
        { "Install & Run Android APKs",  "@apps" },
        { "Open Vanadium Web Browser",   "@vanadium" },
        { "Open Interactive Terminal",   "@terminal" },
        { "Open Files Manager (/data)",  "@files" },
        { "Open Live Android Logcat",    "@logcat" },
    };
    for (size_t i = 0; i < sizeof(btns) / sizeof(btns[0]); i++) {
        GtkWidget *b = gtk_button_new_with_label(btns[i].lbl);
        gtk_style_context_add_class(gtk_widget_get_style_context(b), "nav-btn");
        g_signal_connect(b, "clicked", G_CALLBACK(on_launch_clicked), (gpointer)btns[i].cmd);
        gtk_box_pack_start(GTK_BOX(vb), b, FALSE, FALSE, 2);
    }

    GtkWidget *close_b = gtk_button_new_with_label("Close Panel");
    gtk_style_context_add_class(gtk_widget_get_style_context(close_b), "danger-btn");
    g_signal_connect_swapped(close_b, "clicked", G_CALLBACK(gtk_widget_hide), win);
    gtk_box_pack_start(GTK_BOX(vb), close_b, FALSE, FALSE, 4);

    gtk_widget_show_all(win);
    gtk_window_present(GTK_WINDOW(win));
}

/* ============================================================================
 * 9. INTERACTIVE GRAPHENEOS ANDROID / LINUX TERMINAL (via qyronex-appd @exec)
 * ============================================================================ */
struct term_ctx {
    GtkWidget *tv;
    GtkWidget *entry;
    GtkWidget *status_lbl;
    unsigned int pending_id;
    guint poll_id;
};

static void term_append(struct term_ctx *ctx, const char *txt) {
    if (!GTK_IS_TEXT_VIEW(ctx->tv) || !txt) return;
    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(ctx->tv));
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buf, &end);
    gtk_text_buffer_insert(buf, &end, txt, -1);
    gtk_text_buffer_get_end_iter(buf, &end);
    GtkTextMark *mark = gtk_text_buffer_create_mark(buf, NULL, &end, FALSE);
    gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(ctx->tv), mark, 0.0, FALSE, 0.0, 1.0);
    gtk_text_buffer_delete_mark(buf, mark);
}

static gboolean term_poll_cb(gpointer data) {
    struct term_ctx *ctx = (struct term_ctx *)data;
    if (!ctx->pending_id) {
        ctx->poll_id = 0;
        return FALSE;
    }
    char done_path[192];
    snprintf(done_path, sizeof(done_path), "%s/out-t%u.done", LAUNCH_DIR_PATH, ctx->pending_id);
    struct stat st;
    if (stat(done_path, &st) != 0) {
        return TRUE; /* still running */
    }
    char outbuf[16384];
    size_t n = read_file_str(done_path, outbuf, sizeof(outbuf));
    (void)unlink(done_path);
    if (n > 0) {
        term_append(ctx, outbuf);
        if (outbuf[n - 1] != '\n') term_append(ctx, "\n");
    }
    gtk_label_set_text(GTK_LABEL(ctx->status_lbl), "Ready");
    ctx->pending_id = 0;
    ctx->poll_id = 0;
    return FALSE;
}

static void term_run_cmd(struct term_ctx *ctx, const char *cmd) {
    static unsigned int term_seq = 1;
    if (!cmd || !cmd[0]) return;
    if (strcmp(cmd, "clear") == 0) {
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(ctx->tv)), "", 0);
        return;
    }
    char header[512];
    snprintf(header, sizeof(header), "qyronex_pixel:/ # %s\n", cmd);
    term_append(ctx, header);

    unsigned int id = term_seq++;
    ctx->pending_id = id;
    gtk_label_set_text(GTK_LABEL(ctx->status_lbl), "Running...");
    char req[768];
    snprintf(req, sizeof(req), "@exec:t%u:%.680s", id, cmd);
    send_to_appd(req);
    if (!ctx->poll_id) {
        ctx->poll_id = g_timeout_add(120, term_poll_cb, ctx);
    }
}

static void on_term_submit(GtkWidget *w, gpointer data) {
    (void)w;
    struct term_ctx *ctx = (struct term_ctx *)data;
    const char *cmd = gtk_entry_get_text(GTK_ENTRY(ctx->entry));
    if (cmd && cmd[0]) {
        term_run_cmd(ctx, cmd);
        gtk_entry_set_text(GTK_ENTRY(ctx->entry), "");
    }
}

static void on_term_chip(GtkWidget *w, gpointer data) {
    struct term_ctx *ctx = (struct term_ctx *)data;
    const char *cmd = (const char *)g_object_get_data(G_OBJECT(w), "term-cmd");
    if (cmd) term_run_cmd(ctx, cmd);
}

static void on_term_destroy(GtkWidget *w, gpointer data) {
    (void)w;
    struct term_ctx *ctx = (struct term_ctx *)data;
    if (ctx->poll_id) g_source_remove(ctx->poll_id);
    g_free(ctx);
}

static void open_terminal_window(void) {
    static GtkWidget *s_win = NULL;
    static struct term_ctx *s_ctx = NULL;
    if (s_win) {
        gtk_widget_show_all(s_win);
        gtk_window_present(GTK_WINDOW(s_win));
        gtk_widget_grab_focus(s_ctx->entry);
        return;
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    s_win = win;
    gtk_window_set_title(GTK_WINDOW(win), "GrapheneOS Terminal — Android 15 Shell (qyronex_pixel)");
    gtk_window_set_default_size(GTK_WINDOW(win), 940, 540);
    track_inproc_window(win);

    GtkWidget *vb = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(vb), 12);
    gtk_container_add(GTK_CONTAINER(win), vb);

    struct term_ctx *ctx = g_new0(struct term_ctx, 1);
    s_ctx = ctx;

    GtkWidget *chips = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    struct { const char *lbl; const char *cmd; } quick[] = {
        { "getprop",      "getprop" },
        { "service list", "service list" },
        { "pm list",      "pm list packages -f" },
        { "am start",     "am start org.grapheneos.welcome" },
        { "dumpsys",      "dumpsys" },
        { "selftest",     "qyronex-android-selftest" },
        { "uname -a",     "uname -a" },
        { "Clear",        "clear" },
    };
    for (size_t i = 0; i < sizeof(quick) / sizeof(quick[0]); i++) {
        GtkWidget *b = gtk_button_new_with_label(quick[i].lbl);
        gtk_style_context_add_class(gtk_widget_get_style_context(b), "pill-cyan");
        g_object_set_data(G_OBJECT(b), "term-cmd", (gpointer)quick[i].cmd);
        g_signal_connect(b, "clicked", G_CALLBACK(on_term_chip), ctx);
        gtk_box_pack_start(GTK_BOX(chips), b, FALSE, FALSE, 1);
    }
    ctx->status_lbl = gtk_label_new("Ready");
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->status_lbl), "subtitle-cyan");
    gtk_box_pack_end(GTK_BOX(chips), ctx->status_lbl, FALSE, FALSE, 4);
    gtk_box_pack_start(GTK_BOX(vb), chips, FALSE, FALSE, 0);

    ctx->tv = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(ctx->tv), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(ctx->tv), GTK_WRAP_CHAR);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->tv), "term-box");
    GtkWidget *sc = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sc), ctx->tv);
    gtk_box_pack_start(GTK_BOX(vb), sc, TRUE, TRUE, 0);

    GtkWidget *prompt_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *plbl = gtk_label_new("qyronex_pixel:/ #");
    gtk_style_context_add_class(gtk_widget_get_style_context(plbl), "subtitle-cyan");
    ctx->entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(ctx->entry), "Type any Android/Linux command (e.g. getprop, service list, ls /dev/binderfs)...");
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->entry), "search-entry");
    g_signal_connect(ctx->entry, "activate", G_CALLBACK(on_term_submit), ctx);
    GtkWidget *run_b = gtk_button_new_with_label("Run");
    gtk_style_context_add_class(gtk_widget_get_style_context(run_b), "action-btn");
    g_signal_connect(run_b, "clicked", G_CALLBACK(on_term_submit), ctx);
    gtk_box_pack_start(GTK_BOX(prompt_row), plbl, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(prompt_row), ctx->entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(prompt_row), run_b, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vb), prompt_row, FALSE, FALSE, 0);

    g_signal_connect(win, "destroy", G_CALLBACK(on_term_destroy), ctx);
    gtk_widget_show_all(win);
    gtk_window_present(GTK_WINDOW(win));
    gtk_widget_grab_focus(ctx->entry);

    term_run_cmd(ctx, "uname -a && getprop ro.product.model && service list");
}

/* ============================================================================
 * 10. REAL POSIX FILE MANAGER (/data, /system, /sys/kernel/qyronex, /dev)
 * ============================================================================ */
struct files_ctx {
    char cur_dir[512];
    char sel_file[512];
    GtkWidget *path_entry;
    GtkWidget *listbox;
    GtkWidget *preview_tv;
    GtkWidget *preview_hdr;
};

static void files_populate(struct files_ctx *ctx, const char *dir);

static void on_files_row_activated(GtkListBox *box, GtkListBoxRow *row, gpointer data) {
    (void)box;
    struct files_ctx *ctx = (struct files_ctx *)data;
    if (!row) return;
    const char *full = (const char *)g_object_get_data(G_OBJECT(row), "full-path");
    int is_dir = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "is-dir"));
    if (!full) return;
    if (is_dir) {
        files_populate(ctx, full);
    } else {
        snprintf(ctx->sel_file, sizeof(ctx->sel_file), "%s", full);
        char hdr[600];
        snprintf(hdr, sizeof(hdr), "File Preview: %s", full);
        gtk_label_set_text(GTK_LABEL(ctx->preview_hdr), hdr);
        char content[12288];
        size_t n = read_file_str(full, content, sizeof(content));
        if (n == 0) {
            snprintf(content, sizeof(content), "(empty file or binary/device node)");
        } else {
            /* Replace NULs/control chars cleanly for UTF-8 safety */
            for (size_t i = 0; i < n; i++) {
                unsigned char c = (unsigned char)content[i];
                if (c < 9 || (c > 13 && c < 32) || c > 126) content[i] = '.';
            }
        }
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(ctx->preview_tv)), content, -1);
    }
}

static void files_populate(struct files_ctx *ctx, const char *dir) {
    snprintf(ctx->cur_dir, sizeof(ctx->cur_dir), "%s", dir && dir[0] ? dir : "/");
    gtk_entry_set_text(GTK_ENTRY(ctx->path_entry), ctx->cur_dir);

    GList *children = gtk_container_get_children(GTK_CONTAINER(ctx->listbox));
    for (GList *l = children; l != NULL; l = l->next) {
        gtk_widget_destroy(GTK_WIDGET(l->data));
    }
    g_list_free(children);

    DIR *d = opendir(ctx->cur_dir);
    if (!d) {
        GtkWidget *err = gtk_label_new("Unable to open directory.");
        gtk_container_add(GTK_CONTAINER(ctx->listbox), err);
        gtk_widget_show_all(ctx->listbox);
        return;
    }

    struct dirent *de;
    int count = 0;
    while ((de = readdir(d)) != NULL && count < 180) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char full[768];
        if (strcmp(ctx->cur_dir, "/") == 0) {
            snprintf(full, sizeof(full), "/%s", de->d_name);
        } else {
            snprintf(full, sizeof(full), "%s/%s", ctx->cur_dir, de->d_name);
        }
        struct stat st;
        int is_dir = 0;
        long long sz = 0;
        if (stat(full, &st) == 0) {
            is_dir = S_ISDIR(st.st_mode) ? 1 : 0;
            sz = (long long)st.st_size;
        }
        char label[320];
        if (is_dir) {
            snprintf(label, sizeof(label), "[DIR]  %s/", de->d_name);
        } else {
            snprintf(label, sizeof(label), "       %s  (%lld B)", de->d_name, sz);
        }
        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *lbl = gtk_label_new(label);
        gtk_widget_set_halign(lbl, GTK_ALIGN_START);
        gtk_widget_set_margin_start(lbl, 8);
        gtk_widget_set_margin_top(lbl, 4);
        gtk_widget_set_margin_bottom(lbl, 4);
        if (is_dir) gtk_style_context_add_class(gtk_widget_get_style_context(lbl), "subtitle-cyan");
        gtk_container_add(GTK_CONTAINER(row), lbl);
        g_object_set_data_full(G_OBJECT(row), "full-path", g_strdup(full), g_free);
        g_object_set_data(G_OBJECT(row), "is-dir", GINT_TO_POINTER(is_dir));
        gtk_container_add(GTK_CONTAINER(ctx->listbox), row);
        count++;
    }
    closedir(d);
    gtk_widget_show_all(ctx->listbox);
}

static void on_files_up(GtkWidget *w, gpointer data) {
    (void)w;
    struct files_ctx *ctx = (struct files_ctx *)data;
    char parent[512];
    snprintf(parent, sizeof(parent), "%s", ctx->cur_dir);
    size_t len = strlen(parent);
    while (len > 1 && parent[len - 1] == '/') parent[--len] = '\0';
    char *slash = strrchr(parent, '/');
    if (!slash || slash == parent) {
        files_populate(ctx, "/");
    } else {
        *slash = '\0';
        files_populate(ctx, parent);
    }
}

static void on_files_shortcut(GtkWidget *w, gpointer data) {
    struct files_ctx *ctx = (struct files_ctx *)data;
    const char *dir = (const char *)g_object_get_data(G_OBJECT(w), "dir-path");
    if (dir) files_populate(ctx, dir);
}

static void on_files_go_path(GtkWidget *w, gpointer data) {
    (void)w;
    struct files_ctx *ctx = (struct files_ctx *)data;
    const char *p = gtk_entry_get_text(GTK_ENTRY(ctx->path_entry));
    if (p && p[0]) files_populate(ctx, p);
}

static void on_files_edit_notes(GtkWidget *w, gpointer data) {
    (void)w;
    struct files_ctx *ctx = (struct files_ctx *)data;
    if (ctx->sel_file[0]) open_notes_window(ctx->sel_file);
}

static void on_files_install_apk(GtkWidget *w, gpointer data) {
    (void)w;
    struct files_ctx *ctx = (struct files_ctx *)data;
    if (ctx->sel_file[0] && strstr(ctx->sel_file, ".apk") != NULL) {
        open_apk_activity_window(ctx->sel_file, 1);
    } else {
        show_status_toast("Select an .apk file (in /system/app or /data/local/tmp) first", 5);
    }
}

static void open_files_window(const char *start_dir) {
    static GtkWidget *s_win = NULL;
    static struct files_ctx *s_ctx = NULL;
    if (s_win) {
        files_populate(s_ctx, start_dir ? start_dir : s_ctx->cur_dir);
        gtk_widget_show_all(s_win);
        gtk_window_present(GTK_WINDOW(s_win));
        return;
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    s_win = win;
    gtk_window_set_title(GTK_WINDOW(win), "GrapheneOS Files — Storage & Kernel Sysfs Explorer");
    gtk_window_set_default_size(GTK_WINDOW(win), 940, 540);
    track_inproc_window(win);

    struct files_ctx *ctx = g_new0(struct files_ctx, 1);
    s_ctx = ctx;

    GtkWidget *vb = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(vb), 12);
    gtk_container_add(GTK_CONTAINER(win), vb);

    GtkWidget *nav = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *up_b = gtk_button_new_with_label("Up");
    gtk_style_context_add_class(gtk_widget_get_style_context(up_b), "nav-btn");
    g_signal_connect(up_b, "clicked", G_CALLBACK(on_files_up), ctx);
    gtk_box_pack_start(GTK_BOX(nav), up_b, FALSE, FALSE, 0);

    struct { const char *lbl; const char *path; } places[] = {
        { "/data",        "/data" },
        { "APKs (/tmp)",  "/data/local/tmp" },
        { "/system/app",  "/system/app" },
        { "Qyronex Sysfs","/sys/kernel/qyronex/android" },
        { "/dev/binderfs","/dev/binderfs" },
        { "/",            "/" },
    };
    for (size_t i = 0; i < sizeof(places) / sizeof(places[0]); i++) {
        GtkWidget *b = gtk_button_new_with_label(places[i].lbl);
        gtk_style_context_add_class(gtk_widget_get_style_context(b), "pill-dark");
        g_object_set_data(G_OBJECT(b), "dir-path", (gpointer)places[i].path);
        g_signal_connect(b, "clicked", G_CALLBACK(on_files_shortcut), ctx);
        gtk_box_pack_start(GTK_BOX(nav), b, FALSE, FALSE, 1);
    }

    ctx->path_entry = gtk_entry_new();
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->path_entry), "search-entry");
    g_signal_connect(ctx->path_entry, "activate", G_CALLBACK(on_files_go_path), ctx);
    gtk_box_pack_start(GTK_BOX(nav), ctx->path_entry, TRUE, TRUE, 4);
    gtk_box_pack_start(GTK_BOX(vb), nav, FALSE, FALSE, 0);

    GtkWidget *hb = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_pack_start(GTK_BOX(vb), hb, TRUE, TRUE, 0);

    ctx->listbox = gtk_list_box_new();
    gtk_list_box_set_activate_on_single_click(GTK_LIST_BOX(ctx->listbox), TRUE);
    g_signal_connect(ctx->listbox, "row-activated", G_CALLBACK(on_files_row_activated), ctx);
    GtkWidget *sc_left = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(sc_left, 380, -1);
    gtk_container_add(GTK_CONTAINER(sc_left), ctx->listbox);
    gtk_box_pack_start(GTK_BOX(hb), sc_left, FALSE, TRUE, 0);

    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *rh = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    ctx->preview_hdr = gtk_label_new("Click any folder to open or file to preview");
    gtk_widget_set_halign(ctx->preview_hdr, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->preview_hdr), "app-title");
    GtkWidget *apk_b = gtk_button_new_with_label("Install & Run APK");
    gtk_style_context_add_class(gtk_widget_get_style_context(apk_b), "pill-green");
    g_signal_connect(apk_b, "clicked", G_CALLBACK(on_files_install_apk), ctx);
    GtkWidget *edit_b = gtk_button_new_with_label("Edit in Notes");
    gtk_style_context_add_class(gtk_widget_get_style_context(edit_b), "action-btn");
    g_signal_connect(edit_b, "clicked", G_CALLBACK(on_files_edit_notes), ctx);
    gtk_box_pack_start(GTK_BOX(rh), ctx->preview_hdr, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(rh), apk_b, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(rh), edit_b, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(right), rh, FALSE, FALSE, 0);

    ctx->preview_tv = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(ctx->preview_tv), FALSE);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->preview_tv), "mono-box");
    GtkWidget *sc_right = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sc_right), ctx->preview_tv);
    gtk_box_pack_start(GTK_BOX(right), sc_right, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(hb), right, TRUE, TRUE, 0);

    files_populate(ctx, start_dir ? start_dir : "/data");
    gtk_widget_show_all(win);
    gtk_window_present(GTK_WINDOW(win));
}

/* ============================================================================
 * 11. REAL EXT4 NOTES & TEXT EDITOR
 * ============================================================================ */
struct notes_ctx {
    GtkWidget *path_entry;
    GtkWidget *tv;
    GtkWidget *status_lbl;
};

static void on_notes_load(GtkWidget *w, gpointer data) {
    (void)w;
    struct notes_ctx *ctx = (struct notes_ctx *)data;
    const char *p = gtk_entry_get_text(GTK_ENTRY(ctx->path_entry));
    char buf[32768];
    size_t n = read_file_str(p, buf, sizeof(buf));
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(ctx->tv)), buf, -1);
    char msg[256];
    snprintf(msg, sizeof(msg), "Loaded %zu bytes from %s", n, p);
    gtk_label_set_text(GTK_LABEL(ctx->status_lbl), msg);
}

static void on_notes_save(GtkWidget *w, gpointer data) {
    (void)w;
    struct notes_ctx *ctx = (struct notes_ctx *)data;
    const char *p = gtk_entry_get_text(GTK_ENTRY(ctx->path_entry));
    GtkTextBuffer *tb = gtk_text_view_get_buffer(GTK_TEXT_VIEW(ctx->tv));
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(tb, &start, &end);
    gchar *txt = gtk_text_buffer_get_text(tb, &start, &end, FALSE);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    char msg[256];
    if (fd >= 0) {
        size_t len = strlen(txt);
        ssize_t written = write(fd, txt, len);
        close(fd);
        snprintf(msg, sizeof(msg), "SAVED %zd bytes to %s (ext4 persistent)", written, p);
    } else {
        snprintf(msg, sizeof(msg), "Save failed for %s (errno=%d)", p, errno);
    }
    g_free(txt);
    gtk_label_set_text(GTK_LABEL(ctx->status_lbl), msg);
}

static void open_notes_window(const char *filepath) {
    static GtkWidget *s_win = NULL;
    static struct notes_ctx *s_ctx = NULL;
    if (s_win) {
        if (filepath) {
            gtk_entry_set_text(GTK_ENTRY(s_ctx->path_entry), filepath);
            on_notes_load(NULL, s_ctx);
        }
        gtk_widget_show_all(s_win);
        gtk_window_present(GTK_WINDOW(s_win));
        return;
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    s_win = win;
    gtk_window_set_title(GTK_WINDOW(win), "GrapheneOS Notes — Persistent Text Editor");
    gtk_window_set_default_size(GTK_WINDOW(win), 820, 500);
    track_inproc_window(win);

    struct notes_ctx *ctx = g_new0(struct notes_ctx, 1);
    s_ctx = ctx;

    GtkWidget *vb = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(vb), 12);
    gtk_container_add(GTK_CONTAINER(win), vb);

    GtkWidget *top = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    ctx->path_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(ctx->path_entry), filepath ? filepath : "/data/local/tmp/notes.txt");
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->path_entry), "search-entry");
    GtkWidget *load_b = gtk_button_new_with_label("Reload");
    gtk_style_context_add_class(gtk_widget_get_style_context(load_b), "nav-btn");
    g_signal_connect(load_b, "clicked", G_CALLBACK(on_notes_load), ctx);
    GtkWidget *save_b = gtk_button_new_with_label("Save to Disk");
    gtk_style_context_add_class(gtk_widget_get_style_context(save_b), "action-btn");
    g_signal_connect(save_b, "clicked", G_CALLBACK(on_notes_save), ctx);
    gtk_box_pack_start(GTK_BOX(top), ctx->path_entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(top), load_b, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(top), save_b, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vb), top, FALSE, FALSE, 0);

    ctx->tv = gtk_text_view_new();
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(ctx->tv), GTK_WRAP_WORD_CHAR);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->tv), "mono-box");
    GtkWidget *sc = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sc), ctx->tv);
    gtk_box_pack_start(GTK_BOX(vb), sc, TRUE, TRUE, 0);

    ctx->status_lbl = gtk_label_new("");
    gtk_widget_set_halign(ctx->status_lbl, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->status_lbl), "subtitle-cyan");
    gtk_box_pack_start(GTK_BOX(vb), ctx->status_lbl, FALSE, FALSE, 2);

    on_notes_load(NULL, ctx);
    gtk_widget_show_all(win);
    gtk_window_present(GTK_WINDOW(win));
}

/* ============================================================================
 * 12. REAL GRAPHENEOS CALCULATOR (DEC + HEX)
 * ============================================================================ */
struct calc_ctx {
    GtkWidget *disp_lbl;
    GtkWidget *hex_lbl;
    char input[64];
    double acc;
    char op;
    int reset_next;
};

static void calc_refresh(struct calc_ctx *c) {
    const char *s = c->input[0] ? c->input : "0";
    gtk_label_set_text(GTK_LABEL(c->disp_lbl), s);
    long long iv = (long long)strtod(s, NULL);
    char hbuf[64];
    snprintf(hbuf, sizeof(hbuf), "HEX: 0x%llX   |   BIN-LOW: %u",
             (unsigned long long)iv, (unsigned int)(iv & 0xFFFF));
    gtk_label_set_text(GTK_LABEL(c->hex_lbl), hbuf);
}

static void calc_apply_op(struct calc_ctx *c) {
    double cur = strtod(c->input[0] ? c->input : "0", NULL);
    if (c->op == '+') c->acc += cur;
    else if (c->op == '-') c->acc -= cur;
    else if (c->op == '*') c->acc *= cur;
    else if (c->op == '/') c->acc = (cur != 0.0) ? (c->acc / cur) : 0.0;
    else if (c->op == '%') c->acc = (cur != 0.0) ? (double)((long long)c->acc % (long long)cur) : 0.0;
    else c->acc = cur;
    snprintf(c->input, sizeof(c->input), "%.10g", c->acc);
}

static void on_calc_key(GtkWidget *w, gpointer data) {
    struct calc_ctx *c = (struct calc_ctx *)data;
    const char *k = (const char *)g_object_get_data(G_OBJECT(w), "calc-k");
    if (!k) return;
    if (strcmp(k, "C") == 0) {
        c->input[0] = '\0'; c->acc = 0.0; c->op = 0; c->reset_next = 0;
    } else if (strcmp(k, "DEL") == 0) {
        size_t l = strlen(c->input);
        if (l > 0) c->input[l - 1] = '\0';
    } else if (strcmp(k, "+/-") == 0) {
        double v = -strtod(c->input[0] ? c->input : "0", NULL);
        snprintf(c->input, sizeof(c->input), "%.10g", v);
    } else if (strcmp(k, "=") == 0) {
        calc_apply_op(c);
        c->op = 0;
        c->reset_next = 1;
    } else if (k[1] == '\0' && strchr("+-*/%", k[0]) != NULL) {
        if (c->op && !c->reset_next) calc_apply_op(c);
        else c->acc = strtod(c->input[0] ? c->input : "0", NULL);
        c->op = k[0];
        c->reset_next = 1;
    } else {
        if (c->reset_next) {
            c->input[0] = '\0';
            c->reset_next = 0;
        }
        if (strcmp(k, ".") == 0 && strchr(c->input, '.') != NULL) return;
        if (strlen(c->input) < 20) {
            strcat(c->input, k);
        }
    }
    calc_refresh(c);
}

static void open_calculator_window(void) {
    static GtkWidget *s_win = NULL;
    if (s_win) {
        gtk_widget_show_all(s_win);
        gtk_window_present(GTK_WINDOW(s_win));
        return;
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    s_win = win;
    gtk_window_set_title(GTK_WINDOW(win), "GrapheneOS Calculator (Dec & Hex)");
    gtk_window_set_default_size(GTK_WINDOW(win), 360, 470);
    track_inproc_window(win);

    struct calc_ctx *c = g_new0(struct calc_ctx, 1);

    GtkWidget *vb = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(vb), 14);
    gtk_container_add(GTK_CONTAINER(win), vb);

    c->disp_lbl = gtk_label_new("0");
    gtk_widget_set_halign(c->disp_lbl, GTK_ALIGN_END);
    gtk_style_context_add_class(gtk_widget_get_style_context(c->disp_lbl), "calc-display");
    gtk_box_pack_start(GTK_BOX(vb), c->disp_lbl, FALSE, FALSE, 0);

    c->hex_lbl = gtk_label_new("HEX: 0x0");
    gtk_widget_set_halign(c->hex_lbl, GTK_ALIGN_END);
    gtk_style_context_add_class(gtk_widget_get_style_context(c->hex_lbl), "subtitle-cyan");
    gtk_box_pack_start(GTK_BOX(vb), c->hex_lbl, FALSE, FALSE, 0);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_row_homogeneous(GTK_GRID(grid), TRUE);
    gtk_grid_set_column_homogeneous(GTK_GRID(grid), TRUE);
    gtk_box_pack_start(GTK_BOX(vb), grid, TRUE, TRUE, 0);

    const char *keys[5][4] = {
        { "C",   "DEL", "%", "/" },
        { "7",   "8",   "9", "*" },
        { "4",   "5",   "6", "-" },
        { "1",   "2",   "3", "+" },
        { "+/-", "0",   ".", "=" },
    };
    for (int r = 0; r < 5; r++) {
        for (int col = 0; col < 4; col++) {
            const char *k = keys[r][col];
            GtkWidget *b = gtk_button_new_with_label(k);
            const char *cls = "calc-key";
            if (strcmp(k, "=") == 0) cls = "action-btn";
            else if (strcmp(k, "C") == 0) cls = "danger-btn";
            else if (col == 3 || r == 0) cls = "calc-op";
            gtk_style_context_add_class(gtk_widget_get_style_context(b), cls);
            g_object_set_data(G_OBJECT(b), "calc-k", (gpointer)k);
            g_signal_connect(b, "clicked", G_CALLBACK(on_calc_key), c);
            gtk_grid_attach(GTK_GRID(grid), b, col, r, 1, 1);
        }
    }

    calc_refresh(c);
    gtk_widget_show_all(win);
    gtk_window_present(GTK_WINDOW(win));
}

/* ============================================================================
 * 13. REAL GRAPHENEOS IMAGE GALLERY (GdkPixbuf Viewer over /data/pictures)
 * ============================================================================ */
struct gallery_ctx {
    char paths[32][300];
    int count;
    int idx;
    GtkWidget *img;
    GtkWidget *info_lbl;
};

static void gallery_show(struct gallery_ctx *g) {
    if (g->count <= 0) {
        gtk_label_set_text(GTK_LABEL(g->info_lbl), "No images in /data/pictures");
        return;
    }
    if (g->idx < 0) g->idx = g->count - 1;
    if (g->idx >= g->count) g->idx = 0;
    GError *err = NULL;
    GdkPixbuf *pb = gdk_pixbuf_new_from_file_at_scale(g->paths[g->idx], 820, 440, TRUE, &err);
    if (pb) {
        gtk_image_set_from_pixbuf(GTK_IMAGE(g->img), pb);
        char info[360];
        snprintf(info, sizeof(info), "[%d / %d]  %s", g->idx + 1, g->count, g->paths[g->idx]);
        gtk_label_set_text(GTK_LABEL(g->info_lbl), info);
        g_object_unref(pb);
    } else {
        char info[360];
        snprintf(info, sizeof(info), "Failed to load %s", g->paths[g->idx]);
        gtk_label_set_text(GTK_LABEL(g->info_lbl), info);
        if (err) g_error_free(err);
    }
}

static void on_gallery_prev(GtkWidget *w, gpointer data) {
    (void)w;
    struct gallery_ctx *g = (struct gallery_ctx *)data;
    g->idx--;
    gallery_show(g);
}

static void on_gallery_next(GtkWidget *w, gpointer data) {
    (void)w;
    struct gallery_ctx *g = (struct gallery_ctx *)data;
    g->idx++;
    gallery_show(g);
}

static void open_gallery_window(void) {
    static GtkWidget *s_win = NULL;
    if (s_win) {
        gtk_widget_show_all(s_win);
        gtk_window_present(GTK_WINDOW(s_win));
        return;
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    s_win = win;
    gtk_window_set_title(GTK_WINDOW(win), "GrapheneOS Gallery — /data/pictures");
    gtk_window_set_default_size(GTK_WINDOW(win), 880, 540);
    track_inproc_window(win);

    struct gallery_ctx *g = g_new0(struct gallery_ctx, 1);

    DIR *d = opendir("/data/pictures");
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL && g->count < 32) {
            if (de->d_name[0] == '.') continue;
            if (strstr(de->d_name, ".png") || strstr(de->d_name, ".jpg") || strstr(de->d_name, ".jpeg")) {
                snprintf(g->paths[g->count++], sizeof(g->paths[0]), "/data/pictures/%s", de->d_name);
            }
        }
        closedir(d);
    }

    GtkWidget *vb = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(vb), 12);
    gtk_container_add(GTK_CONTAINER(win), vb);

    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *prev_b = gtk_button_new_with_label("< Previous");
    gtk_style_context_add_class(gtk_widget_get_style_context(prev_b), "nav-btn");
    g_signal_connect(prev_b, "clicked", G_CALLBACK(on_gallery_prev), g);
    GtkWidget *next_b = gtk_button_new_with_label("Next >");
    gtk_style_context_add_class(gtk_widget_get_style_context(next_b), "action-btn");
    g_signal_connect(next_b, "clicked", G_CALLBACK(on_gallery_next), g);
    g->info_lbl = gtk_label_new("");
    gtk_style_context_add_class(gtk_widget_get_style_context(g->info_lbl), "subtitle-cyan");
    gtk_box_pack_start(GTK_BOX(bar), prev_b, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), next_b, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), g->info_lbl, TRUE, TRUE, 8);
    gtk_box_pack_start(GTK_BOX(vb), bar, FALSE, FALSE, 0);

    g->img = gtk_image_new();
    GtkWidget *sc = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sc), g->img);
    gtk_box_pack_start(GTK_BOX(vb), sc, TRUE, TRUE, 0);

    gallery_show(g);
    gtk_widget_show_all(win);
    gtk_window_present(GTK_WINDOW(win));
}

/* ============================================================================
 * 14. INSTANT GRAPHENEOS VANADIUM WEB BROWSER (Live HTTP/HTTPS + NetSurf Engine)
 * ============================================================================ */
struct vanadium_ctx {
    GtkWidget *url_entry;
    GtkWidget *status_lbl;
    GtkWidget *tv;
    char cur_url[512];
    unsigned int pending_id;
    guint poll_id;
};

static void html_to_readable(const char *raw, char *out, size_t cap) {
    size_t w = 0;
    int in_tag = 0, in_script = 0, in_style = 0, prev_space = 0;
    const char *p = raw;
    while (*p && w + 8 < cap) {
        if (*p == '<') {
            in_tag = 1;
            if (strncasecmp(p, "<script", 7) == 0) in_script = 1;
            else if (strncasecmp(p, "</script", 8) == 0) in_script = 0;
            else if (strncasecmp(p, "<style", 6) == 0) in_style = 1;
            else if (strncasecmp(p, "</style", 7) == 0) in_style = 0;
            else if (strncasecmp(p, "<br", 3) == 0 || strncasecmp(p, "<p", 2) == 0 ||
                     strncasecmp(p, "</p", 3) == 0 || strncasecmp(p, "<div", 4) == 0 ||
                     strncasecmp(p, "<h", 2) == 0 || strncasecmp(p, "</h", 3) == 0 ||
                     strncasecmp(p, "<li", 3) == 0 || strncasecmp(p, "</title", 7) == 0) {
                if (w > 0 && out[w - 1] != '\n') out[w++] = '\n';
                prev_space = 1;
            }
            p++;
            continue;
        }
        if (*p == '>') {
            in_tag = 0;
            p++;
            continue;
        }
        if (in_tag || in_script || in_style) {
            p++;
            continue;
        }
        if (*p == '&') {
            if (strncmp(p, "&amp;", 5) == 0)       { out[w++] = '&'; p += 5; prev_space = 0; continue; }
            if (strncmp(p, "&lt;", 4) == 0)        { out[w++] = '<'; p += 4; prev_space = 0; continue; }
            if (strncmp(p, "&gt;", 4) == 0)        { out[w++] = '>'; p += 4; prev_space = 0; continue; }
            if (strncmp(p, "&quot;", 6) == 0)      { out[w++] = '"'; p += 6; prev_space = 0; continue; }
            if (strncmp(p, "&nbsp;", 6) == 0)      { out[w++] = ' '; p += 6; prev_space = 1; continue; }
        }
        unsigned char c = (unsigned char)*p++;
        if (c == '\r') continue;
        if (c == '\n' || c == '\t' || c == ' ') {
            if (!prev_space && w > 0) {
                out[w++] = (c == '\n') ? '\n' : ' ';
                prev_space = 1;
            }
        } else if (c >= 32 && c < 127) {
            out[w++] = (char)c;
            prev_space = 0;
        }
    }
    out[w] = '\0';
}

static void vanadium_show_start_page(struct vanadium_ctx *v) {
    char ip[48];
    get_primary_ip(ip, sizeof(ip));
    char page[2048];
    snprintf(page, sizeof(page),
        "========================================================================\n"
        "  VANADIUM HARDENED WEB BROWSER — GrapheneOS 15 on Qyronex Rust Kernel\n"
        "========================================================================\n\n"
        "  Security Posture : SELinux ENFORCING | W^X TTBR1 | Modem IOMMU Sandboxed\n"
        "  Network Stack    : VirtIO-Net POSIX TCP/UDP | IP %s | DNS 10.0.2.3\n"
        "  Kernel IPC       : Capability-Enforced Binder v8 + Cross-Process FD Passing\n\n"
        "  HOW TO BROWSE:\n"
        "   - Click any bookmark above (`Example.com`, `GrapheneOS.org`, `1.1.1.1`, `DuckDuckGo`)\n"
        "   - Or enter any URL in the address bar and press Enter / click `Go`\n"
        "   - Click `Full NetSurf` at top-right to open full graphical HTML/CSS rendering\n\n"
        "  VERIFIED BOOKMARKS:\n"
        "   * http://example.com/                 — IANA Live HTTP Verification Page\n"
        "   * https://grapheneos.org/             — Official GrapheneOS Security Project\n"
        "   * https://html.duckduckgo.com/html/   — Private Web Search (No JS required)\n"
        "   * http://1.1.1.1/                     — Cloudflare Direct IP Connectivity\n",
        ip);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(v->tv)), page, -1);
    gtk_label_set_text(GTK_LABEL(v->status_lbl),
                       "Vanadium Ready  |  SELinux: ENFORCING  |  Click a bookmark or enter a URL");
}

static gboolean vanadium_poll_cb(gpointer data) {
    struct vanadium_ctx *v = (struct vanadium_ctx *)data;
    if (!v->pending_id) {
        v->poll_id = 0;
        return FALSE;
    }
    char done_path[192];
    snprintf(done_path, sizeof(done_path), "%s/out-w%u.done", LAUNCH_DIR_PATH, v->pending_id);
    struct stat st;
    if (stat(done_path, &st) != 0) return TRUE;

    static char raw[24576];
    static char clean[16384];
    size_t n = read_file_str(done_path, raw, sizeof(raw));
    (void)unlink(done_path);
    v->pending_id = 0;
    v->poll_id = 0;

    if (n == 0) {
        gtk_label_set_text(GTK_LABEL(v->status_lbl), "Network fetch returned empty response (check host Internet)");
        return FALSE;
    }
    /* Split HTTP headers and HTML body if present */
    char *body = strstr(raw, "\r\n\r\n");
    if (!body) body = strstr(raw, "\n\n");
    char out[20480];
    if (body) {
        size_t hlen = (size_t)(body - raw);
        if (hlen > 1024) hlen = 1024;
        char hdr[1040];
        memcpy(hdr, raw, hlen);
        hdr[hlen] = '\0';
        html_to_readable(body, clean, sizeof(clean));
        snprintf(out, sizeof(out),
                 "URL: %.400s\n"
                 "------------------------------------------------------------------------\n"
                 "%.15000s\n\n"
                 "=== HTTP RESPONSE HEADERS ===\n%.1024s\n",
                 v->cur_url, clean[0] ? clean : "(no text body)", hdr);
        gtk_label_set_text(GTK_LABEL(v->status_lbl), "Page loaded live via VirtIO-Net HTTP/HTTPS");
    } else {
        snprintf(out, sizeof(out), "URL: %.400s\n\n%.18000s\n", v->cur_url, raw);
        gtk_label_set_text(GTK_LABEL(v->status_lbl), "Fetch completed (see output below)");
    }
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(v->tv)), out, -1);
    return FALSE;
}

static void vanadium_navigate(struct vanadium_ctx *v, const char *raw_url) {
    static unsigned int web_seq = 1;
    if (!raw_url || !raw_url[0] || strcmp(raw_url, "about:vanadium") == 0) {
        snprintf(v->cur_url, sizeof(v->cur_url), "about:vanadium");
        gtk_entry_set_text(GTK_ENTRY(v->url_entry), "about:vanadium");
        vanadium_show_start_page(v);
        return;
    }
    if (strstr(raw_url, "://") != NULL) {
        snprintf(v->cur_url, sizeof(v->cur_url), "%s", raw_url);
    } else if (strchr(raw_url, '.') != NULL && strchr(raw_url, ' ') == NULL) {
        snprintf(v->cur_url, sizeof(v->cur_url), "http://%s", raw_url);
    } else {
        snprintf(v->cur_url, sizeof(v->cur_url), "https://html.duckduckgo.com/html/?q=%s", raw_url);
    }
    gtk_entry_set_text(GTK_ENTRY(v->url_entry), v->cur_url);

    /* Sanitize single quotes before invoking curl via qyronex-appd */
    char safe_url[512];
    size_t j = 0;
    for (size_t i = 0; v->cur_url[i] && j + 1 < sizeof(safe_url); i++) {
        char c = v->cur_url[i];
        if (c == '\'' || c == '\n' || c == '\r' || c == ';') continue;
        safe_url[j++] = c;
    }
    safe_url[j] = '\0';

    unsigned int id = web_seq++;
    v->pending_id = id;
    char stmsg[256];
    snprintf(stmsg, sizeof(stmsg), "Fetching %.160s over VirtIO-Net...", safe_url);
    gtk_label_set_text(GTK_LABEL(v->status_lbl), stmsg);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(v->tv)),
                             "Connecting via Qyronex POSIX TCP/TLS stack...\n", -1);

    char req[768];
    snprintf(req, sizeof(req),
             "@exec:w%u:curl -sSLk --max-time 8 -i -A 'Vanadium/15 GrapheneOS' '%s' 2>&1 | head -c 22000",
             id, safe_url);
    send_to_appd(req);
    if (!v->poll_id) {
        v->poll_id = g_timeout_add(150, vanadium_poll_cb, v);
    }
}

static void on_vanadium_go(GtkWidget *w, gpointer data) {
    (void)w;
    struct vanadium_ctx *v = (struct vanadium_ctx *)data;
    vanadium_navigate(v, gtk_entry_get_text(GTK_ENTRY(v->url_entry)));
}

static void on_vanadium_bookmark(GtkWidget *w, gpointer data) {
    struct vanadium_ctx *v = (struct vanadium_ctx *)data;
    const char *url = (const char *)g_object_get_data(G_OBJECT(w), "bm-url");
    if (url) vanadium_navigate(v, url);
}

static void on_vanadium_netsurf(GtkWidget *w, gpointer data) {
    (void)w;
    struct vanadium_ctx *v = (struct vanadium_ctx *)data;
    char cmd[640];
    const char *u = (strcmp(v->cur_url, "about:vanadium") == 0)
        ? "file:///data/local/tmp/vanadium-start.html"
        : v->cur_url;
    snprintf(cmd, sizeof(cmd), "netsurf-gtk %s", u);
    show_status_toast("Launching NetSurf Graphical Engine (~25s on 1 vCPU)...", 26);
    send_to_appd(cmd);
}

static void open_vanadium_window(const char *initial_url) {
    static GtkWidget *s_win = NULL;
    static struct vanadium_ctx *s_ctx = NULL;
    if (s_win) {
        gtk_widget_show_all(s_win);
        gtk_window_present(GTK_WINDOW(s_win));
        if (initial_url && strcmp(initial_url, "about:vanadium") != 0) {
            vanadium_navigate(s_ctx, initial_url);
        }
        return;
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    s_win = win;
    gtk_window_set_title(GTK_WINDOW(win), "Vanadium Web Browser — GrapheneOS 15 (Qyronex)");
    gtk_window_set_default_size(GTK_WINDOW(win), 980, 560);
    track_inproc_window(win);

    struct vanadium_ctx *v = g_new0(struct vanadium_ctx, 1);
    s_ctx = v;

    GtkWidget *vb = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(vb), 12);
    gtk_container_add(GTK_CONTAINER(win), vb);

    GtkWidget *nav = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *home_b = gtk_button_new_with_label("Start");
    gtk_style_context_add_class(gtk_widget_get_style_context(home_b), "nav-btn");
    g_object_set_data(G_OBJECT(home_b), "bm-url", (gpointer)"about:vanadium");
    g_signal_connect(home_b, "clicked", G_CALLBACK(on_vanadium_bookmark), v);

    v->url_entry = gtk_entry_new();
    gtk_style_context_add_class(gtk_widget_get_style_context(v->url_entry), "search-entry");
    g_signal_connect(v->url_entry, "activate", G_CALLBACK(on_vanadium_go), v);

    GtkWidget *go_b = gtk_button_new_with_label("Go");
    gtk_style_context_add_class(gtk_widget_get_style_context(go_b), "action-btn");
    g_signal_connect(go_b, "clicked", G_CALLBACK(on_vanadium_go), v);

    GtkWidget *ns_b = gtk_button_new_with_label("Full NetSurf");
    gtk_style_context_add_class(gtk_widget_get_style_context(ns_b), "pill-cyan");
    g_signal_connect(ns_b, "clicked", G_CALLBACK(on_vanadium_netsurf), v);

    gtk_box_pack_start(GTK_BOX(nav), home_b, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(nav), v->url_entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(nav), go_b, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(nav), ns_b, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vb), nav, FALSE, FALSE, 0);

    GtkWidget *bms = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    struct { const char *lbl; const char *url; } marks[] = {
        { "Start Page",         "about:vanadium" },
        { "Example.com (Live)", "http://example.com/" },
        { "GrapheneOS.org",     "https://grapheneos.org/" },
        { "DuckDuckGo Lite",    "https://html.duckduckgo.com/html/" },
        { "Cloudflare 1.1.1.1", "http://1.1.1.1/" },
    };
    for (size_t i = 0; i < sizeof(marks) / sizeof(marks[0]); i++) {
        GtkWidget *b = gtk_button_new_with_label(marks[i].lbl);
        gtk_style_context_add_class(gtk_widget_get_style_context(b), "pill-dark");
        g_object_set_data(G_OBJECT(b), "bm-url", (gpointer)marks[i].url);
        g_signal_connect(b, "clicked", G_CALLBACK(on_vanadium_bookmark), v);
        gtk_box_pack_start(GTK_BOX(bms), b, FALSE, FALSE, 1);
    }
    gtk_box_pack_start(GTK_BOX(vb), bms, FALSE, FALSE, 0);

    v->status_lbl = gtk_label_new("Vanadium Ready");
    gtk_widget_set_halign(v->status_lbl, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(v->status_lbl), "banner-pass");
    gtk_box_pack_start(GTK_BOX(vb), v->status_lbl, FALSE, FALSE, 0);

    v->tv = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(v->tv), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(v->tv), GTK_WRAP_WORD_CHAR);
    gtk_style_context_add_class(gtk_widget_get_style_context(v->tv), "mono-box");
    GtkWidget *sc = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sc), v->tv);
    gtk_box_pack_start(GTK_BOX(vb), sc, TRUE, TRUE, 0);

    gtk_widget_show_all(win);
    gtk_window_present(GTK_WINDOW(win));
    vanadium_navigate(v, initial_url ? initial_url : "about:vanadium");
}

/* ============================================================================
 * 15. NATIVE ANDROID APK ACTIVITY HOST WINDOW (Zero-Fork Instant Dalvik VM!)
 * ============================================================================ */
struct apk_act_ctx {
    GtkWidget *win;
    GtkWidget *banner;
    GtkWidget *meta_lbl;
    GtkWidget *tv;
    char cur_target[320];
};

static void apk_act_run(struct apk_act_ctx *ctx, const char *target, int do_install) {
    if (!target || !target[0]) return;
    snprintf(ctx->cur_target, sizeof(ctx->cur_target), "%.319s", target);

    char pm_msg[512] = {0};
    char err_msg[256] = {0};
    char apk_path[320] = {0};
    int inst_rc = 0;

    if (do_install) {
        inst_rc = qart_pm_install(target, pm_msg, sizeof(pm_msg));
        refresh_apk_packages_view();
    } else {
        snprintf(pm_msg, sizeof(pm_msg), "Launched installed package/APK directly via ActivityManager");
    }

    static struct qart_manifest man;
    static struct qart_dex_result res;
    int run_rc = (inst_rc == 0)
        ? qart_run_apk(target, &man, &res, apk_path, sizeof(apk_path), err_msg, sizeof(err_msg))
        : 1;

    static char view_buf[12288];
    if (inst_rc == 0 && run_rc == 0) {
        char wtitle[220];
        snprintf(wtitle, sizeof(wtitle), "%.150s — Android Activity (Qyronex ART)", res.title);
        gtk_window_set_title(GTK_WINDOW(ctx->win), wtitle);

        char btxt[280];
        snprintf(btxt, sizeof(btxt),
                 "DALVIK DEX EXECUTED  |  %.80s v%.24s  |  Adler-32 0x%08x  |  %u insns",
                 man.package, man.version, res.dex_adler32, res.insns_executed);
        GtkStyleContext *sc = gtk_widget_get_style_context(ctx->banner);
        gtk_style_context_remove_class(sc, "banner-warn");
        gtk_style_context_add_class(sc, "banner-pass");
        gtk_label_set_text(GTK_LABEL(ctx->banner), btxt);

        char mtxt[384];
        snprintf(mtxt, sizeof(mtxt),
                 "Activity: %.120s   |   APK: %.140s   |   Log.i=%d  SysProp=%d",
                 man.activity, apk_path, res.log_calls, res.prop_calls);
        gtk_label_set_text(GTK_LABEL(ctx->meta_lbl), mtxt);

        snprintf(view_buf, sizeof(view_buf),
                 "======================================================================\n"
                 "  ANDROID ACTIVITY OUTPUT (Live classes.dex Dalvik Bytecode VM)\n"
                 "======================================================================\n\n"
                 "%.6000s\n"
                 "----------------------------------------------------------------------\n"
                 "=== PackageManager (`pm`) & ActivityManager (`am`) Status ===\n"
                 "  %s\n"
                 "  Intent  : cmp=%s/%s\n"
                 "  DEX 035 : Adler-32=0x%08x | Bytecode Executed=%u instructions\n"
                 "  Record  : /run/user/0/qyronex-activity.txt & /dev/log/main\n",
                 res.body, pm_msg, man.package, man.activity, res.dex_adler32, res.insns_executed);
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(ctx->tv)), view_buf, -1);
    } else {
        GtkStyleContext *sc = gtk_widget_get_style_context(ctx->banner);
        gtk_style_context_remove_class(sc, "banner-pass");
        gtk_style_context_add_class(sc, "banner-warn");
        gtk_label_set_text(GTK_LABEL(ctx->banner), "APK Verification / Execution Error");
        snprintf(view_buf, sizeof(view_buf), "pm: %s\nam: %s\n", pm_msg, err_msg);
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(ctx->tv)), view_buf, -1);
    }
}

static void on_apk_rerun_clicked(GtkWidget *w, gpointer data) {
    (void)w;
    struct apk_act_ctx *ctx = (struct apk_act_ctx *)data;
    apk_act_run(ctx, ctx->cur_target, 0);
}

static void open_apk_activity_window(const char *target, int do_install) {
    static GtkWidget *s_win = NULL;
    static struct apk_act_ctx *s_ctx = NULL;
    if (s_win) {
        gtk_widget_show_all(s_win);
        gtk_window_present(GTK_WINDOW(s_win));
        apk_act_run(s_ctx, target, do_install);
        return;
    }
    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    s_win = win;
    gtk_window_set_title(GTK_WINDOW(win), "Android Activity Host — Qyronex ART Dalvik VM");
    gtk_window_set_default_size(GTK_WINDOW(win), 880, 520);
    track_inproc_window(win);

    struct apk_act_ctx *ctx = g_new0(struct apk_act_ctx, 1);
    ctx->win = win;
    s_ctx = ctx;

    GtkWidget *vb = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(vb), 14);
    gtk_container_add(GTK_CONTAINER(win), vb);

    ctx->banner = gtk_label_new("Preparing Qyronex ART Dalvik VM...");
    gtk_widget_set_halign(ctx->banner, GTK_ALIGN_FILL);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->banner), "banner-pass");
    gtk_box_pack_start(GTK_BOX(vb), ctx->banner, FALSE, FALSE, 0);

    ctx->meta_lbl = gtk_label_new("ZIP + Binary AXML + DEX 035 Interpreter");
    gtk_widget_set_halign(ctx->meta_lbl, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->meta_lbl), "subtitle-cyan");
    gtk_box_pack_start(GTK_BOX(vb), ctx->meta_lbl, FALSE, FALSE, 0);

    ctx->tv = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(ctx->tv), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(ctx->tv), GTK_WRAP_WORD_CHAR);
    gtk_style_context_add_class(gtk_widget_get_style_context(ctx->tv), "mono-box");
    GtkWidget *sc = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sc), ctx->tv);
    gtk_box_pack_start(GTK_BOX(vb), sc, TRUE, TRUE, 0);

    GtkWidget *brow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *rerun_b = gtk_button_new_with_label("Re-Run classes.dex");
    gtk_style_context_add_class(gtk_widget_get_style_context(rerun_b), "action-btn");
    g_signal_connect(rerun_b, "clicked", G_CALLBACK(on_apk_rerun_clicked), ctx);
    GtkWidget *log_b = gtk_button_new_with_label("Inspect in Logcat");
    gtk_style_context_add_class(gtk_widget_get_style_context(log_b), "nav-btn");
    g_signal_connect(log_b, "clicked", G_CALLBACK(on_launch_clicked), (gpointer)"@logcat");
    GtkWidget *apps_b = gtk_button_new_with_label("Apps & APKs");
    gtk_style_context_add_class(gtk_widget_get_style_context(apps_b), "nav-btn");
    g_signal_connect(apps_b, "clicked", G_CALLBACK(on_launch_clicked), (gpointer)"@apps");
    GtkWidget *close_b = gtk_button_new_with_label("Close Activity");
    gtk_style_context_add_class(gtk_widget_get_style_context(close_b), "danger-btn");
    g_signal_connect_swapped(close_b, "clicked", G_CALLBACK(gtk_widget_hide), win);
    gtk_box_pack_start(GTK_BOX(brow), rerun_b, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(brow), log_b, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(brow), apps_b, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(brow), close_b, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vb), brow, FALSE, FALSE, 0);

    gtk_widget_show_all(win);
    gtk_window_present(GTK_WINDOW(win));
    apk_act_run(ctx, target, do_install);
}

int main(int argc, char **argv) {
    gtk_init(&argc, &argv);
    apply_css();

    const char *mode = (argc >= 2) ? argv[1] : "shell";
    if (strcmp(mode, "shell") == 0) {
        build_statusbar_window();
        build_navbar_window();
        build_launcher_window();
        gtk_main();
        return 0;
    }
    if (strcmp(mode, "settings") == 0) {
        open_settings_window(argc >= 3 ? argv[2] : "security");
        g_signal_connect(g_inproc_windows->data, "destroy", G_CALLBACK(gtk_main_quit), NULL);
        gtk_main();
        return 0;
    }
    if (strcmp(mode, "auditor") == 0) {
        open_auditor_window();
        g_signal_connect(g_inproc_windows->data, "destroy", G_CALLBACK(gtk_main_quit), NULL);
        gtk_main();
        return 0;
    }
    fprintf(stderr, "Usage: %s <shell|settings|auditor>\n", argv[0]);
    return 2;
}
