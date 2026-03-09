/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/*
 * Unit tests for the ENOENT double-lstat fix in check_rc_sys.c (issue #32653).
 *
 * Since read_sys_file() is static, we test it indirectly through check_rc_sys(),
 * which calls read_sys_dir() -> read_sys_file(). We use rootcheck.scanall = 1
 * so that check_rc_sys() scans a single root directory instead of 19 subdirs.
 *
 * The key behavior under test:
 *   - When lstat fails with ENOENT twice -> no alert (fix works)
 *   - When lstat fails with EACCES -> alert fires (non-ENOENT still alerts)
 *   - When lstat fails with ENOENT then succeeds -> alert fires (suspicious)
 *   - When lstat succeeds -> no alert (normal file)
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#include "../wrappers/common.h"

#include "shared.h"
#include "rootcheck.h"

/*
 * Define rootcheck globals directly so the linker does not pull in rootcheck.o
 * (which would drag in dozens of unresolved dependencies like StartMQ,
 * ReadConfig, File_DateofChange, etc.).
 */
rkconfig rootcheck;
int rk_sys_count;
char **rk_sys_file;
char **rk_sys_name;

/* Sentinel arrays for rk_sys_file/rk_sys_name (avoid NULL dereference) */
static char *empty_rk_sys[] = {NULL};

/* Test mode flag used by some wrappers in libwazuh_test.a */
int test_mode = 1;

/*
 * Custom __wrap_lstat: sets errno from the mock queue.
 * The standard wrapper in libwazuh_test.a does not set errno, but the
 * ENOENT fix checks errno after lstat failure. This override takes
 * 3 will_return values: (struct stat *buf, int errno_val, int return_val).
 *
 * Because this symbol is defined in the test .o file, the linker uses it
 * instead of the one in the static library (libwazuh_test.a).
 */
int __wrap_lstat(const char *filename, struct stat *buf)
{
    check_expected(filename);
    const struct stat *mock_buf = mock_type(struct stat *);
    if (mock_buf != NULL) {
        memcpy(buf, mock_buf, sizeof(struct stat));
    }
    int mock_errno = mock_type(int);
    if (mock_errno != 0) {
        errno = mock_errno;
    }
    return mock_type(int);
}

/* Helper: queue lstat mock expectations (3 will_return values) */
static void expect_lstat(const char *path, struct stat *buf, int err, int ret)
{
    expect_string(__wrap_lstat, filename, path);
    will_return(__wrap_lstat, buf);
    will_return(__wrap_lstat, err);
    will_return(__wrap_lstat, ret);
}

/* Wrap notify_rk to track rootkit alerts */
int __wrap_notify_rk(int rk_type, const char *msg)
{
    check_expected(rk_type);
    check_expected(msg);
    return mock_type(int);
}

/* Wrap directory operations */
DIR *__wrap_wopendir(const char *name)
{
    check_expected(name);
    return mock_type(DIR *);
}

struct dirent *__wrap_readdir(DIR *dirp)
{
    return mock_type(struct dirent *);
}

int __wrap_closedir(DIR *dirp)
{
    return 0;
}

/* Wrap check_ignore */
int __wrap_check_ignore(const char *path_to_ignore)
{
    check_expected(path_to_ignore);
    return mock_type(int);
}

/* Wrap skipFS and IsNFS */
short __wrap_skipFS(const char *dir_name)
{
    return 0;
}

short __wrap_IsNFS(const char *dir_name)
{
    return 0;
}

/* ===================================================================
 * Setup / Teardown
 * =================================================================== */

static int setup(void **state)
{
    (void)state;
    memset(&rootcheck, 0, sizeof(rkconfig));
    rootcheck.notify = QUEUE;
    rootcheck.skip_nfs = 0;
    rootcheck.scanall = 1; /* scan single root dir, not 19 subdirs */
    rootcheck.readall = 0;
    rk_sys_count = 0;
    rk_sys_file = empty_rk_sys;
    rk_sys_name = empty_rk_sys;

    /* Allow any number of debug/log calls without failing the test */
    expect_any_always(__wrap__mtdebug1, tag);
    expect_any_always(__wrap__mtdebug1, formatted_msg);
    expect_any_always(__wrap__mtdebug2, tag);
    expect_any_always(__wrap__mtdebug2, formatted_msg);
    expect_any_always(__wrap__mterror, tag);
    expect_any_always(__wrap__mterror, formatted_msg);
    expect_any_always(__wrap__mtwarn, tag);
    expect_any_always(__wrap__mtwarn, formatted_msg);

    return 0;
}

/* ===================================================================
 * Test: File deleted between readdir and lstat (ENOENT + ENOENT)
 * Fix should skip the alert.
 * =================================================================== */

static void test_enoent_double_lstat_skips_alert(void **state)
{
    (void)state;

    /* With scanall=1, check_rc_sys overwrites basedir to "/" and calls
     * read_sys_dir("/", 0). We mock "/" as our test directory. */
    struct stat dir_stat = {0};
    dir_stat.st_mode = S_IFDIR | 0755;
    dir_stat.st_nlink = 3; /* . + .. + bait.txt entry in readdir */
    dir_stat.st_dev = 1;

    struct stat file_stat = {0};
    file_stat.st_mode = S_IFREG | 0644;

    DIR *fake_dp = (DIR *)0x1234;
    static struct dirent dot_entry, dotdot_entry, bait_entry;
    memset(&dot_entry, 0, sizeof(dot_entry));
    memset(&dotdot_entry, 0, sizeof(dotdot_entry));
    memset(&bait_entry, 0, sizeof(bait_entry));
    strncpy(dot_entry.d_name, ".", sizeof(dot_entry.d_name) - 1);
    strncpy(dotdot_entry.d_name, "..", sizeof(dotdot_entry.d_name) - 1);
    strncpy(bait_entry.d_name, "bait.txt", sizeof(bait_entry.d_name) - 1);

    /* -- read_sys_dir: lstat on "/" -- */
    expect_lstat("/", &dir_stat, 0, 0);

    /* -- wopendir("/") -- */
    expect_string(__wrap_wopendir, name, "/");
    will_return(__wrap_wopendir, fake_dp);

    /* -- readdir returns ".", "..", "bait.txt", NULL -- */
    will_return(__wrap_readdir, &dot_entry);
    will_return(__wrap_readdir, &dotdot_entry);
    will_return(__wrap_readdir, &bait_entry);

    /* -- read_sys_dir: lstat on "/bait.txt" (entry type check) -- */
    expect_lstat("/bait.txt", &file_stat, 0, 0);

    /* -- check_ignore("/bait.txt") -- */
    expect_string(__wrap_check_ignore, path_to_ignore, "/bait.txt");
    will_return(__wrap_check_ignore, 0);

    /* -- read_sys_file: first lstat -> ENOENT (file deleted) -- */
    expect_lstat("/bait.txt", NULL, ENOENT, -1);

    /* -- read_sys_file: second lstat (retry) -> ENOENT again -- */
    expect_lstat("/bait.txt", NULL, ENOENT, -1);

    /* -- readdir returns NULL (end of directory) -- */
    will_return(__wrap_readdir, NULL);

    /* -- nlink check: entry_count=2 (.+..) != st_nlink=3, but we need
     * to handle the re-lstat. Set nlink=2 after re-stat to match. -- */

    /* -- Final: _sys_errors > 0 (read_sys_file returned -1) -- No,
     * actually _sys_errors is only incremented by notify_rk calls.
     * read_sys_file returning -1 does NOT increment _sys_errors.
     * So _sys_errors == 0, and notify_rk(ALERT_OK, ...) is called. -- */

    /* For nlink: entry_count=2 (. and ..), st_nlink=3 -> mismatch.
     * Re-lstat "/" returns st_nlink=2 this time -> matches entry_count -> no alert. */
    struct stat dir_stat_recheck = {0};
    dir_stat_recheck.st_mode = S_IFDIR | 0755;
    dir_stat_recheck.st_nlink = 2;
    dir_stat_recheck.st_dev = 1;
    expect_lstat("/", &dir_stat_recheck, 0, 0);

    /* -- notify_rk(ALERT_OK, "No problem found...") -- */
    expect_value(__wrap_notify_rk, rk_type, ALERT_OK);
    expect_any(__wrap_notify_rk, msg);
    will_return(__wrap_notify_rk, 0);

    /* notify_rk for rootkit alert should NOT be called */
    check_rc_sys("/");
}

/* ===================================================================
 * Test: Permission error (EACCES) — alert should still fire
 * =================================================================== */

static void test_eacces_still_alerts(void **state)
{
    (void)state;

    struct stat dir_stat = {0};
    dir_stat.st_mode = S_IFDIR | 0755;
    dir_stat.st_nlink = 3;
    dir_stat.st_dev = 1;

    struct stat file_stat = {0};
    file_stat.st_mode = S_IFREG | 0644;

    DIR *fake_dp = (DIR *)0x1234;
    static struct dirent dot_entry, dotdot_entry, secret_entry;
    memset(&dot_entry, 0, sizeof(dot_entry));
    memset(&dotdot_entry, 0, sizeof(dotdot_entry));
    memset(&secret_entry, 0, sizeof(secret_entry));
    strncpy(dot_entry.d_name, ".", sizeof(dot_entry.d_name) - 1);
    strncpy(dotdot_entry.d_name, "..", sizeof(dotdot_entry.d_name) - 1);
    strncpy(secret_entry.d_name, "secret.txt", sizeof(secret_entry.d_name) - 1);

    /* -- read_sys_dir: lstat on "/" -- */
    expect_lstat("/", &dir_stat, 0, 0);

    /* -- wopendir -- */
    expect_string(__wrap_wopendir, name, "/");
    will_return(__wrap_wopendir, fake_dp);

    /* -- readdir returns ".", "..", "secret.txt", NULL -- */
    will_return(__wrap_readdir, &dot_entry);
    will_return(__wrap_readdir, &dotdot_entry);
    will_return(__wrap_readdir, &secret_entry);

    /* -- lstat on "/secret.txt" (entry type check) -- */
    expect_lstat("/secret.txt", &file_stat, 0, 0);

    /* -- check_ignore -- */
    expect_string(__wrap_check_ignore, path_to_ignore, "/secret.txt");
    will_return(__wrap_check_ignore, 0);

    /* -- read_sys_file: lstat -> EACCES (NOT ENOENT) -- */
    expect_lstat("/secret.txt", NULL, EACCES, -1);

    /* -- EACCES: fix does NOT retry. Alert fires. -- */
    expect_value(__wrap_notify_rk, rk_type, ALERT_ROOTKIT_FOUND);
    expect_any(__wrap_notify_rk, msg);
    will_return(__wrap_notify_rk, 0);

    /* -- readdir returns NULL -- */
    will_return(__wrap_readdir, NULL);

    /* -- nlink re-check: st_nlink=3 vs entry_count=2 -> re-lstat returns 2 -> OK -- */
    struct stat dir_stat_recheck = {0};
    dir_stat_recheck.st_mode = S_IFDIR | 0755;
    dir_stat_recheck.st_nlink = 2;
    dir_stat_recheck.st_dev = 1;
    expect_lstat("/", &dir_stat_recheck, 0, 0);

    /* -- _sys_errors > 0, so no ALERT_OK at the end.
     * But _wx/_ww/_suid are NULL, so the else-if for file output is skipped. -- */

    check_rc_sys("/");
}

/* ===================================================================
 * Test: lstat fails ENOENT then succeeds on retry — alert fires
 * (file reappeared = suspicious, could be rootkit)
 * =================================================================== */

static void test_enoent_then_success_alerts(void **state)
{
    (void)state;

    struct stat dir_stat = {0};
    dir_stat.st_mode = S_IFDIR | 0755;
    dir_stat.st_nlink = 3;
    dir_stat.st_dev = 1;

    struct stat file_stat = {0};
    file_stat.st_mode = S_IFREG | 0644;

    DIR *fake_dp = (DIR *)0x1234;
    static struct dirent dot_entry, dotdot_entry, sneaky_entry;
    memset(&dot_entry, 0, sizeof(dot_entry));
    memset(&dotdot_entry, 0, sizeof(dotdot_entry));
    memset(&sneaky_entry, 0, sizeof(sneaky_entry));
    strncpy(dot_entry.d_name, ".", sizeof(dot_entry.d_name) - 1);
    strncpy(dotdot_entry.d_name, "..", sizeof(dotdot_entry.d_name) - 1);
    strncpy(sneaky_entry.d_name, "sneaky.txt", sizeof(sneaky_entry.d_name) - 1);

    /* -- read_sys_dir: lstat on "/" -- */
    expect_lstat("/", &dir_stat, 0, 0);

    /* -- wopendir -- */
    expect_string(__wrap_wopendir, name, "/");
    will_return(__wrap_wopendir, fake_dp);

    /* -- readdir returns ".", "..", "sneaky.txt", NULL -- */
    will_return(__wrap_readdir, &dot_entry);
    will_return(__wrap_readdir, &dotdot_entry);
    will_return(__wrap_readdir, &sneaky_entry);

    /* -- lstat on "/sneaky.txt" (entry type check) -- */
    expect_lstat("/sneaky.txt", &file_stat, 0, 0);

    /* -- check_ignore -- */
    expect_string(__wrap_check_ignore, path_to_ignore, "/sneaky.txt");
    will_return(__wrap_check_ignore, 0);

    /* -- read_sys_file: first lstat -> ENOENT -- */
    expect_lstat("/sneaky.txt", NULL, ENOENT, -1);

    /* -- read_sys_file: second lstat (retry) -> SUCCESS (file reappeared!) -- */
    expect_lstat("/sneaky.txt", &file_stat, 0, 0);

    /* -- File reappeared: alert fires (suspicious) -- */
    expect_value(__wrap_notify_rk, rk_type, ALERT_ROOTKIT_FOUND);
    expect_any(__wrap_notify_rk, msg);
    will_return(__wrap_notify_rk, 0);

    /* -- readdir returns NULL -- */
    will_return(__wrap_readdir, NULL);

    /* -- nlink re-check -- */
    struct stat dir_stat_recheck = {0};
    dir_stat_recheck.st_mode = S_IFDIR | 0755;
    dir_stat_recheck.st_nlink = 2;
    dir_stat_recheck.st_dev = 1;
    expect_lstat("/", &dir_stat_recheck, 0, 0);

    check_rc_sys("/");
}

/* ===================================================================
 * Test: Existing file — no alert
 * =================================================================== */

static void test_existing_file_no_alert(void **state)
{
    (void)state;

    struct stat dir_stat = {0};
    dir_stat.st_mode = S_IFDIR | 0755;
    dir_stat.st_nlink = 2;
    dir_stat.st_dev = 1;

    struct stat file_stat = {0};
    file_stat.st_mode = S_IFREG | 0644;
    file_stat.st_size = 100;

    DIR *fake_dp = (DIR *)0x1234;
    static struct dirent dot_entry, dotdot_entry, normal_entry;
    memset(&dot_entry, 0, sizeof(dot_entry));
    memset(&dotdot_entry, 0, sizeof(dotdot_entry));
    memset(&normal_entry, 0, sizeof(normal_entry));
    strncpy(dot_entry.d_name, ".", sizeof(dot_entry.d_name) - 1);
    strncpy(dotdot_entry.d_name, "..", sizeof(dotdot_entry.d_name) - 1);
    strncpy(normal_entry.d_name, "normal.txt", sizeof(normal_entry.d_name) - 1);

    /* -- read_sys_dir: lstat on "/" -- */
    expect_lstat("/", &dir_stat, 0, 0);

    /* -- wopendir -- */
    expect_string(__wrap_wopendir, name, "/");
    will_return(__wrap_wopendir, fake_dp);

    /* -- readdir returns ".", "..", "normal.txt", NULL -- */
    will_return(__wrap_readdir, &dot_entry);
    will_return(__wrap_readdir, &dotdot_entry);
    will_return(__wrap_readdir, &normal_entry);

    /* -- lstat on "/normal.txt" (entry type check) -- */
    expect_lstat("/normal.txt", &file_stat, 0, 0);

    /* -- check_ignore -- */
    expect_string(__wrap_check_ignore, path_to_ignore, "/normal.txt");
    will_return(__wrap_check_ignore, 0);

    /* -- read_sys_file: lstat -> success (file exists, no retry) -- */
    expect_lstat("/normal.txt", &file_stat, 0, 0);

    /* -- readdir returns NULL -- */
    will_return(__wrap_readdir, NULL);

    /* -- nlink check: entry_count=2, st_nlink=2 -> match, no alert -- */

    /* -- _sys_errors == 0 -> notify_rk(ALERT_OK, ...) -- */
    expect_value(__wrap_notify_rk, rk_type, ALERT_OK);
    expect_any(__wrap_notify_rk, msg);
    will_return(__wrap_notify_rk, 0);

    check_rc_sys("/");
}

/* ===================================================================
 * Main
 * =================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_enoent_double_lstat_skips_alert, setup),
        cmocka_unit_test_setup(test_eacces_still_alerts, setup),
        cmocka_unit_test_setup(test_enoent_then_success_alerts, setup),
        cmocka_unit_test_setup(test_existing_file_no_alert, setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
