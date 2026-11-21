/* SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0 */
/* Qyronex OS — Native Zero-Overhead External ARM64 App & Shell Daemon (`qyronex-appd`).
 *
 * Single-threaded static C daemon running inside the `labwc` Wayland session.
 * Watches `/run/user/0/qyronex-launch.d/` for `.cmd` files via pure `nanosleep()`
 * (0% idle CPU, zero subshell forks while idle):
 *   - `@exec:<id>:<shell_cmd>` : runs `/bin/sh -c <shell_cmd>` non-blocking and
 *     atomically writes stdout+stderr to `out-<id>.done` for the interactive
 *     GrapheneOS Terminal app (avoids multi-threaded GTK3 fork() deadlocks).
 *   - `@home` / `@back`        : closes tracked external GUI app windows cleanly.
 *   - `<gui_app_cmd>`          : forks and `execvp()`s external Wayland GUI apps
 *     such as `netsurf-gtk` (Vanadium Browser).
 */

#define _GNU_SOURCE
#include "binder_abi.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LAUNCH_DIR "/run/user/0/qyronex-launch.d"
#define APPD_LOG   "/tmp/graphene-appd.log"
#define APP_LOG    "/tmp/qyronex-last-app.log"
#define MAX_PIDS   64
#define MAX_ARGS   32

static pid_t g_pids[MAX_PIDS];
static int g_pid_count = 0;

static void appd_log(const char *msg) {
    int fd = open(APPD_LOG, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd >= 0) {
        (void)write(fd, msg, strlen(msg));
        (void)write(fd, "\n", 1);
        close(fd);
    }
    android_log_write(msg);
}

static void prune_pids(void) {
    int status = 0;
    pid_t dead;
    while ((dead = waitpid(-1, &status, WNOHANG)) > 0) {
        for (int i = 0; i < g_pid_count; i++) {
            if (g_pids[i] == dead) {
                for (int j = i; j + 1 < g_pid_count; j++) {
                    g_pids[j] = g_pids[j + 1];
                }
                g_pid_count--;
                break;
            }
        }
    }
    int w = 0;
    for (int i = 0; i < g_pid_count; i++) {
        if (g_pids[i] > 1 && kill(g_pids[i], 0) == 0) {
            g_pids[w++] = g_pids[i];
        }
    }
    g_pid_count = w;
}

static void track_pid(pid_t pid) {
    if (pid <= 1) return;
    if (g_pid_count < MAX_PIDS) {
        g_pids[g_pid_count++] = pid;
    } else {
        memmove(&g_pids[0], &g_pids[1], (MAX_PIDS - 1) * sizeof(pid_t));
        g_pids[MAX_PIDS - 1] = pid;
    }
}

static void kill_all_tracked(void) {
    for (int i = g_pid_count - 1; i >= 0; i--) {
        if (g_pids[i] > 1) {
            (void)kill(-g_pids[i], SIGTERM);
            (void)kill(g_pids[i], SIGTERM);
        }
    }
    g_pid_count = 0;
    appd_log("I/AppLauncher: @home closed all external app windows");
}

static void kill_last_tracked(void) {
    prune_pids();
    if (g_pid_count > 0) {
        pid_t p = g_pids[--g_pid_count];
        (void)kill(-p, SIGTERM);
        (void)kill(p, SIGTERM);
        char msg[128];
        snprintf(msg, sizeof(msg), "I/AppLauncher: @back closed pid=%d", (int)p);
        appd_log(msg);
    }
}

static void ensure_wayland_env(void) {
    const char *wd = getenv("WAYLAND_DISPLAY");
    if (!wd || !wd[0]) {
        DIR *d = opendir("/run/user/0");
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (strncmp(de->d_name, "wayland-", 8) == 0 &&
                    strstr(de->d_name, ".lock") == NULL) {
                    setenv("WAYLAND_DISPLAY", de->d_name, 1);
                    break;
                }
            }
            closedir(d);
        }
        if (!getenv("WAYLAND_DISPLAY")) {
            setenv("WAYLAND_DISPLAY", "wayland-0", 1);
        }
    }
    if (!getenv("XDG_RUNTIME_DIR")) setenv("XDG_RUNTIME_DIR", "/run/user/0", 1);
    if (!getenv("GDK_BACKEND"))     setenv("GDK_BACKEND", "wayland", 1);
    if (!getenv("GTK_THEME"))       setenv("GTK_THEME", "Adwaita:dark", 1);
    if (!getenv("HOME"))            setenv("HOME", "/root", 1);
    setenv("PATH", "/system/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
}

static int parse_argv(char *buf, char *argv[], int max_args) {
    int argc = 0;
    char *p = buf;
    while (*p && argc + 1 < max_args) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (!*p) break;
        char quote = 0;
        if (*p == '\'' || *p == '"') {
            quote = *p++;
        }
        argv[argc++] = p;
        char *dst = p;
        while (*p) {
            if (quote) {
                if (*p == quote) {
                    p++;
                    break;
                }
                *dst++ = *p++;
            } else {
                if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
                    p++;
                    break;
                }
                *dst++ = *p++;
            }
        }
        *dst = '\0';
    }
    argv[argc] = NULL;
    return argc;
}

/* Non-blocking interactive shell execution for GrapheneOS Terminal:
 * Format: "@exec:<id>:<shell_command>"
 * Runs `/bin/sh -c <shell_command>` in a dedicated helper process and atomically
 * renames `out-<id>.tmp` -> `out-<id>.done` on completion.
 */
static void run_exec_request(const char *spec) {
    const char *colon = strchr(spec, ':');
    if (!colon || colon == spec) return;
    char id[48];
    size_t idlen = (size_t)(colon - spec);
    if (idlen >= sizeof(id)) idlen = sizeof(id) - 1;
    memcpy(id, spec, idlen);
    id[idlen] = '\0';
    const char *shcmd = colon + 1;
    if (!shcmd[0]) return;

    ensure_wayland_env();
    pid_t helper = fork();
    if (helper != 0) return;

    /* Helper process: fork child running /bin/sh -c, wait, then atomically publish output */
    char tmp_path[180], done_path[180];
    snprintf(tmp_path, sizeof(tmp_path), "%s/out-%s.tmp", LAUNCH_DIR, id);
    snprintf(done_path, sizeof(done_path), "%s/out-%s.done", LAUNCH_DIR, id);

    int outfd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (outfd < 0) _exit(1);

    pid_t worker = fork();
    if (worker == 0) {
        int nullfd = open("/dev/null", O_RDONLY);
        if (nullfd >= 0) {
            dup2(nullfd, STDIN_FILENO);
            if (nullfd > 2) close(nullfd);
        }
        dup2(outfd, STDOUT_FILENO);
        dup2(outfd, STDERR_FILENO);
        if (outfd > 2) close(outfd);
        alarm(15);
        execl("/bin/sh", "sh", "-c", shcmd, (char *)NULL);
        _exit(127);
    }

    int status = 0;
    if (worker > 0) {
        (void)waitpid(worker, &status, 0);
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        dprintf(outfd, "[exit %d]\n", WEXITSTATUS(status));
    }
    close(outfd);
    (void)rename(tmp_path, done_path);
    _exit(0);
}

static void spawn_command(const char *raw_cmd) {
    char copy[768];
    snprintf(copy, sizeof(copy), "%s", raw_cmd);
    char *argv[MAX_ARGS];
    int argc = parse_argv(copy, argv, MAX_ARGS);
    if (argc <= 0) return;

    ensure_wayland_env();

    pid_t pid = fork();
    if (pid < 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "E/AppLauncher: fork() failed for '%.120s' (errno=%d)", raw_cmd, errno);
        appd_log(msg);
        return;
    }
    if (pid == 0) {
        (void)setsid();
        int nullfd = open("/dev/null", O_RDONLY);
        if (nullfd >= 0) {
            dup2(nullfd, STDIN_FILENO);
            if (nullfd > 2) close(nullfd);
        }
        int logfd = open(APP_LOG, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (logfd >= 0) {
            char hdr[256];
            int n = snprintf(hdr, sizeof(hdr), "\n--- [qyronex-appd] exec: %.140s (WAYLAND_DISPLAY=%.32s) ---\n",
                             raw_cmd, getenv("WAYLAND_DISPLAY") ? getenv("WAYLAND_DISPLAY") : "none");
            if (n > 0) (void)write(logfd, hdr, (size_t)n);
            dup2(logfd, STDOUT_FILENO);
            dup2(logfd, STDERR_FILENO);
            if (logfd > 2) close(logfd);
        }
        execvp(argv[0], argv);
        int err = errno;
        dprintf(STDERR_FILENO, "[qyronex-appd] execvp('%s') failed: errno=%d (%s)\n",
                argv[0], err, strerror(err));
        _exit(127);
    }

    track_pid(pid);
    char msg[256];
    snprintf(msg, sizeof(msg), "I/AppLauncher: Started pid=%d cmd='%.120s' (WAYLAND_DISPLAY=%.32s)",
             (int)pid, raw_cmd, getenv("WAYLAND_DISPLAY") ? getenv("WAYLAND_DISPLAY") : "none");
    appd_log(msg);
}

static void clean_launch_dir(void) {
    (void)mkdir("/run/user/0", 0700);
    (void)mkdir(LAUNCH_DIR, 0777);
    (void)chmod(LAUNCH_DIR, 0777);
    DIR *d = opendir(LAUNCH_DIR);
    if (!d) return;
    struct dirent *de;
    char path[320];
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "%s/%s", LAUNCH_DIR, de->d_name);
        (void)unlink(path);
    }
    closedir(d);
}

static void poll_requests(void) {
    DIR *d = opendir(LAUNCH_DIR);
    if (!d) {
        (void)mkdir(LAUNCH_DIR, 0777);
        (void)chmod(LAUNCH_DIR, 0777);
        return;
    }
    struct dirent *de;
    char path[320];
    while ((de = readdir(d)) != NULL) {
        size_t nlen = strlen(de->d_name);
        if (nlen < 5 || strcmp(de->d_name + nlen - 4, ".cmd") != 0) continue;
        snprintf(path, sizeof(path), "%s/%s", LAUNCH_DIR, de->d_name);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        char buf[768];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        (void)unlink(path);
        if (n <= 0) continue;
        buf[n] = '\0';
        while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' ')) {
            buf[--n] = '\0';
        }
        if (buf[0] == '\0') continue;

        if (strcmp(buf, "@home") == 0) {
            kill_all_tracked();
        } else if (strcmp(buf, "@back") == 0) {
            kill_last_tracked();
        } else if (strncmp(buf, "@exec:", 6) == 0) {
            run_exec_request(buf + 6);
        } else {
            spawn_command(buf);
        }
    }
    closedir(d);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    clean_launch_dir();
    ensure_wayland_env();

    char boot_msg[192];
    snprintf(boot_msg, sizeof(boot_msg),
             "I/AppLauncher: qyronex-appd online pid=%d WAYLAND_DISPLAY=%s DBUS=%s",
             (int)getpid(),
             getenv("WAYLAND_DISPLAY") ? getenv("WAYLAND_DISPLAY") : "unset",
             getenv("DBUS_SESSION_BUS_ADDRESS") ? "yes" : "no");
    appd_log(boot_msg);

    struct timespec ts = { .tv_sec = 0, .tv_nsec = 80000000L }; /* 80 ms */
    for (;;) {
        prune_pids();
        poll_requests();
        nanosleep(&ts, NULL);
    }
    return 0;
}
