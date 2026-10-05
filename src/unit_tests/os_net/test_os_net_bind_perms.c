/* Real-filesystem tests for OS_BindUnixDomainWithPerms(): they exercise the actual syscalls
 * (no mocks for the permission calls) so they cover the permission result, the private-directory
 * cleanup, an error path and the refusal to follow a path swapped right after bind(), which a
 * mock-based test cannot verify. bind() is wrapped only to play the local attacker. */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "shared.h"
#include "../../os_net/os_net.h"

#define TDIR  "/tmp/wz_os_net_bind_perms"
#define SPATH TDIR "/s.sock"
#define VPATH TDIR "/victim"
#define VDIR  TDIR "_victimdir"

int __real_bind(int fd, const struct sockaddr *addr, socklen_t len);
static int swap_after_bind;

/* Plays the local attacker who can rename entries in the socket directory: right after the real
 * bind(), move the entry the bound path goes through and leave a symlink to a victim in its place.
 * It targets the final path for the by-path base code and the private subdirectory for the fix. */
int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    int ret = __real_bind(fd, addr, len);

    if (ret == 0 && swap_after_bind) {
        const char *rest = ((const struct sockaddr_un *)addr)->sun_path + sizeof(TDIR);
        char entry[PATH_MAX];
        char moved[PATH_MAX + 8];

        snprintf(entry, sizeof(entry), TDIR "/%.*s", (int)strcspn(rest, "/"), rest);
        snprintf(moved, sizeof(moved), "%s.moved", entry);
        rename(entry, moved);
        symlink(strchr(rest, '/') ? VDIR : VPATH, entry);
    }
    return ret;
}

static int setup(void **state) {
    (void)state;
    system("rm -rf " TDIR " " VDIR);
    mkdir(TDIR, 0700);
    return 0;
}

static int teardown(void **state) {
    (void)state;
    system("rm -rf " TDIR " " VDIR);
    return 0;
}

static int leftover_temp_dirs(void) {
    DIR *d = opendir(TDIR);
    struct dirent *e;
    int n = 0;

    if (d == NULL) {
        return -1;
    }
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, ".w", 2) == 0) {
            n++;
        }
    }
    closedir(d);
    return n;
}

/* The socket is created with the requested mode and no private directory is left behind. */
static void test_bind_sets_mode_and_cleans_up(void **state) {
    (void)state;
    mode_t old = umask(022);
    int fd = OS_BindUnixDomain(SPATH, SOCK_STREAM, OS_MAXSTR);
    umask(old);

    assert_true(fd >= 0);

    struct stat st;
    assert_int_equal(lstat(SPATH, &st), 0);
    assert_true(S_ISSOCK(st.st_mode));
    assert_int_equal(st.st_mode & 0777, 0660);
    assert_int_equal(leftover_temp_dirs(), 0);

    OS_CloseSocket(fd);
}

/* A swap of the entry right after bind() must not redirect the permission change: the victim is
 * left untouched. This fails against the by-path code (victim ends 0660) and passes with the fix. */
static void test_bind_does_not_follow_swap_after_bind(void **state) {
    (void)state;
    FILE *f = fopen(VPATH, "w");
    assert_non_null(f);
    fclose(f);
    assert_int_equal(chmod(VPATH, 0600), 0);
    assert_int_equal(mkdir(VDIR, 0700), 0);
    assert_non_null(f = fopen(VDIR "/s", "w"));
    fclose(f);
    assert_int_equal(chmod(VDIR "/s", 0600), 0);

    struct stat before, before_dir;
    assert_int_equal(lstat(VPATH, &before), 0);
    assert_int_equal(lstat(VDIR "/s", &before_dir), 0);

    swap_after_bind = 1;
    int fd = OS_BindUnixDomain(SPATH, SOCK_STREAM, OS_MAXSTR);
    swap_after_bind = 0;

    struct stat after, after_dir;
    assert_int_equal(lstat(VPATH, &after), 0);
    assert_int_equal(lstat(VDIR "/s", &after_dir), 0);
    assert_int_equal(before.st_mode, after.st_mode);
    assert_int_equal(before_dir.st_mode, after_dir.st_mode);

    assert_true(fd >= 0);
    struct stat sock;
    assert_int_equal(lstat(SPATH, &sock), 0);
    assert_true(S_ISSOCK(sock.st_mode));

    OS_CloseSocket(fd);
}

/* An error after the socket is bound (here the final path is a directory, so the move fails) must
 * still remove the private directory and the socket it holds: nothing is left behind. */
static void test_bind_error_path_cleans_up(void **state) {
    (void)state;
    /* Final path is a directory, so moving the socket onto it fails and the error path runs. */
    assert_int_equal(mkdir(SPATH, 0700), 0);

    assert_int_equal(OS_BindUnixDomain(SPATH, SOCK_STREAM, OS_MAXSTR), OS_SOCKTERR);
    assert_int_equal(leftover_temp_dirs(), 0);

    struct stat st;
    assert_int_equal(lstat(SPATH, &st), 0);
    assert_true(S_ISDIR(st.st_mode));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_bind_sets_mode_and_cleans_up, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_does_not_follow_swap_after_bind, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_error_path_cleans_up, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
