/* SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0 */
/* Qyronex OS — Real ARM64 Android APK/DEX Dalvik Virtual Machine (`qyronex-art` / `dalvikvm`),
 * Android Package Manager (`pm`), and Activity Manager (`am`) CLI.
 */
#define _GNU_SOURCE
#include "qyronex_art_core.h"

static int pm_list(int show_files) {
    int fd = open(QYRONEX_PACKAGES_LIST, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char buf[8192];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    char *line = buf;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (line[0]) {
            char pkg[128] = {0}, lbl[128] = {0}, act[160] = {0}, ver[48] = {0}, path[256] = {0};
            if (sscanf(line, "%127[^|]|%127[^|]|%159[^|]|%47[^|]|%255[^\n]", pkg, lbl, act, ver, path) == 5) {
                if (show_files) printf("package:%s=%s (%s v%s)\n", path, pkg, lbl, ver);
                else printf("package:%s\n", pkg);
            }
        }
        if (!nl) break;
        line = nl + 1;
    }
    return 0;
}

static int pm_uninstall(const char *pkg) {
    char existing[8192] = {0};
    int rfd = open(QYRONEX_PACKAGES_LIST, O_RDONLY | O_CLOEXEC);
    if (rfd >= 0) {
        ssize_t n = read(rfd, existing, sizeof(existing) - 1);
        if (n > 0) existing[n] = '\0';
        close(rfd);
    }
    int found = 0;
    int wfd = open(QYRONEX_PACKAGES_LIST, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (wfd >= 0) {
        char *line = existing;
        size_t plen = strlen(pkg);
        while (*line) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            if (line[0]) {
                if (strncmp(line, pkg, plen) == 0 && line[plen] == '|') found = 1;
                else dprintf(wfd, "%s\n", line);
            }
            if (!nl) break;
            line = nl + 1;
        }
        close(wfd);
    }
    char apk[256];
    snprintf(apk, sizeof(apk), "/data/app/%s/base.apk", pkg);
    (void)unlink(apk);
    if (!found) {
        fprintf(stderr, "Failure [DELETE_FAILED_INTERNAL_ERROR: %s not installed]\n", pkg);
        return 1;
    }
    printf("Success\n");
    return 0;
}

static int cli_install(const char *apk_path) {
    char msg[512] = {0};
    int rc = qart_pm_install(apk_path, msg, sizeof(msg));
    fprintf(rc == 0 ? stdout : stderr, "%s\n", msg);
    return rc;
}

static int cli_run(const char *spec) {
    struct qart_manifest man;
    struct qart_dex_result res;
    char err[256] = {0};
    int rc = qart_run_apk(spec, &man, &res, NULL, 0, err, sizeof(err));
    if (rc != 0) {
        fprintf(stderr, "%s\n", err);
        return rc;
    }
    printf("Starting: Intent { cmp=%s/%s }\n", man.package, man.activity);
    printf("Title        : %s\n", res.title);
    printf("DEX Verified : magic=dex\\n035\\0 adler32=0x%08x insns_executed=%u\n",
           res.dex_adler32, res.insns_executed);
    printf("------------------------------------------------------------\n");
    printf("%s", res.body);
    return 0;
}

int main(int argc, char **argv) {
    const char *prog = strrchr(argv[0], '/');
    prog = prog ? prog + 1 : argv[0];

    if (strcmp(prog, "pm") == 0) {
        if (argc >= 3 && strcmp(argv[1], "install") == 0) return cli_install(argv[2]);
        if (argc >= 3 && strcmp(argv[1], "list") == 0 && strcmp(argv[2], "packages") == 0) {
            int show_f = (argc >= 4 && strcmp(argv[3], "-f") == 0);
            return pm_list(show_f);
        }
        if (argc >= 3 && strcmp(argv[1], "uninstall") == 0) return pm_uninstall(argv[2]);
        fprintf(stderr, "Usage: pm <install file.apk | list packages [-f] | uninstall pkg>\n");
        return 2;
    }

    if (strcmp(prog, "am") == 0) {
        if (argc >= 3 && strcmp(argv[1], "start") == 0) {
            const char *target = (argc >= 4 && strcmp(argv[2], "-n") == 0) ? argv[3] : argv[2];
            return cli_run(target);
        }
        fprintf(stderr, "Usage: am start [-n] <package/activity | file.apk>\n");
        return 2;
    }

    if (argc >= 3 && (strcmp(argv[1], "-cp") == 0 || strcmp(argv[1], "run") == 0)) return cli_run(argv[2]);
    if (argc >= 3 && strcmp(argv[1], "install") == 0) return cli_install(argv[2]);
    if (argc >= 2 && strcmp(argv[1], "list") == 0) return pm_list(1);
    fprintf(stderr, "Usage: qyronex-art <run file.apk | install file.apk | list>\n");
    return 2;
}
