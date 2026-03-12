/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
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

rkconfig rootcheck;
int rk_sys_count;
char **rk_sys_file;
char **rk_sys_name;

static char *empty_rk_sys[] = {NULL};
int test_mode = 1;

/*
 * Custom __wrap_lstat: sets errno from the mock queue.
 * Takes 3 will_return values: (struct stat *buf, int errno_val, int return_val).
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

/* Helper: queue lstat mock expectations */
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
    check_expected(dirp);
    return mock_type(struct dirent *);
}

int __wrap_closedir(DIR *dirp)
{
    check_expected(dirp);
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
    check_expected(dir_name);
    return mock_type(short);
}

short __wrap_IsNFS(const char *dir_name)
{
    check_expected(dir_name);
    return mock_type(short);
}

FILE *__wrap_wfopen(const char *path, const char *mode)
{
    (void)path;
    (void)mode;
    return NULL;
}

/* No-op debug wrappers */
void __wrap__mtdebug1(__attribute__((unused)) const char *tag,
                      __attribute__((unused)) const char *file,
                      __attribute__((unused)) int line,
                      __attribute__((unused)) const char *func,
                      __attribute__((unused)) const char *msg, ...) {}

void __wrap__mtdebug2(__attribute__((unused)) const char *tag,
                      __attribute__((unused)) const char *file,
                      __attribute__((unused)) int line,
                      __attribute__((unused)) const char *func,
                      __attribute__((unused)) const char *msg, ...) {}

void __wrap__mterror(__attribute__((unused)) const char *tag,
                     __attribute__((unused)) const char *file,
                     __attribute__((unused)) int line,
                     __attribute__((unused)) const char *func,
                     __attribute__((unused)) const char *msg, ...) {}

void __wrap__mtwarn(__attribute__((unused)) const char *tag,
                    __attribute__((unused)) const char *file,
                    __attribute__((unused)) int line,
                    __attribute__((unused)) const char *func,
                    __attribute__((unused)) const char *msg, ...) {}

/* ===================================================================
 * Helpers for readdir / closedir expectations
 * =================================================================== */

/* Queue a readdir expectation that validates the DIR* handle */
static void expect_readdir(DIR *dp, struct dirent *entry)
{
    expect_value(__wrap_readdir, dirp, dp);
    will_return(__wrap_readdir, entry);
}

/* Queue a closedir expectation that validates the DIR* handle */
static void expect_closedir(DIR *dp)
{
    expect_value(__wrap_closedir, dirp, dp);
}

/* Queue a wopendir expectation */
static void expect_wopendir(const char *path, DIR *dp)
{
    expect_string(__wrap_wopendir, name, path);
    will_return(__wrap_wopendir, dp);
}

/* Queue a skipFS expectation (default: don't skip) */
static void expect_skipFS(const char *path, short ret)
{
    expect_string(__wrap_skipFS, dir_name, path);
    will_return(__wrap_skipFS, ret);
}

/* Queue a check_ignore expectation */
static void expect_check_ignore(const char *path, int ret)
{
    expect_string(__wrap_check_ignore, path_to_ignore, path);
    will_return(__wrap_check_ignore, ret);
}

/* Queue a notify_rk expectation */
static void expect_notify_rk(int rk_type)
{
    expect_value(__wrap_notify_rk, rk_type, rk_type);
    expect_any(__wrap_notify_rk, msg);
    will_return(__wrap_notify_rk, 0);
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

    return 0;
}

/* Helper: prepare standard dirent entries */
static struct dirent dot_entry, dotdot_entry;

static void init_dot_entries(void)
{
    memset(&dot_entry, 0, sizeof(dot_entry));
    memset(&dotdot_entry, 0, sizeof(dotdot_entry));
    strncpy(dot_entry.d_name, ".", sizeof(dot_entry.d_name) - 1);
    strncpy(dotdot_entry.d_name, "..", sizeof(dotdot_entry.d_name) - 1);
}

/* ===================================================================
 * Test 1: File deleted between readdir and lstat (ENOENT).
 * Second readdir does NOT list the file -> no alert.
 * =================================================================== */

static void test_enoent_deleted_file_no_alert(void **state)
{
    (void)state;
    init_dot_entries();

    static struct dirent bait_entry;
    memset(&bait_entry, 0, sizeof(bait_entry));
    strncpy(bait_entry.d_name, "bait.txt", sizeof(bait_entry.d_name) - 1);

    struct stat dir_stat = {0};
    dir_stat.st_mode = S_IFDIR | 0755;
    dir_stat.st_nlink = 3;
    dir_stat.st_dev = 1;

    struct stat file_stat = {0};
    file_stat.st_mode = S_IFREG | 0644;

    DIR *fake_dp = (DIR *)0x1234;
    DIR *fake_dp2 = (DIR *)0x5678;

    /* -- read_sys_dir: lstat on "/" -- */
    expect_lstat("/", &dir_stat, 0, 0);

    /* -- wopendir("/") -- */
    expect_wopendir("/", fake_dp);

    /* -- First readdir pass: ".", "..", "bait.txt", NULL -- */
    expect_readdir(fake_dp, &dot_entry);
    expect_readdir(fake_dp, &dotdot_entry);
    expect_readdir(fake_dp, &bait_entry);

    /* -- read_sys_dir: lstat on "/bait.txt" (entry type check) -- */
    expect_lstat("/bait.txt", &file_stat, 0, 0);

    /* -- check_ignore("/bait.txt") -- */
    expect_check_ignore("/bait.txt", 0);

    /* -- read_sys_file: lstat -> ENOENT (file deleted) -> returns RC_ENOENT_SUSPECT -- */
    expect_lstat("/bait.txt", NULL, ENOENT, -1);

    /* -- First readdir returns NULL (end of loop) -- */
    expect_readdir(fake_dp, NULL);

    /* -- Second wopendir for readdir re-verification -- */
    expect_wopendir("/", fake_dp2);

    /* -- Second readdir pass: file is GONE (only ".", "..", NULL) -- */
    expect_readdir(fake_dp2, &dot_entry);
    expect_readdir(fake_dp2, &dotdot_entry);
    expect_readdir(fake_dp2, NULL);

    /* -- closedir on verification handle -- */
    expect_closedir(fake_dp2);

    /* -- No rootkit alert expected -- */

    /* -- skipFS -- */
    expect_skipFS("/", 0);

    /* -- nlink: entry_count=2, st_nlink=3 -> mismatch -> re-lstat returns 2 -- */
    struct stat dir_stat_recheck = {0};
    dir_stat_recheck.st_mode = S_IFDIR | 0755;
    dir_stat_recheck.st_nlink = 2;
    dir_stat_recheck.st_dev = 1;
    expect_lstat("/", &dir_stat_recheck, 0, 0);

    /* -- closedir on main handle -- */
    expect_closedir(fake_dp);

    /* -- _sys_errors == 0 -> notify_rk(ALERT_OK) -- */
    expect_notify_rk(ALERT_OK);

    check_rc_sys("/");
}

/* ===================================================================
 * Test 2: File hidden by rootkit (ENOENT from lstat, but still in
 * second readdir) -> alert fires.
 * =================================================================== */

static void test_enoent_hidden_file_alerts(void **state)
{
    (void)state;
    init_dot_entries();

    static struct dirent hidden_entry;
    memset(&hidden_entry, 0, sizeof(hidden_entry));
    strncpy(hidden_entry.d_name, "hidden.txt", sizeof(hidden_entry.d_name) - 1);

    struct stat dir_stat = {0};
    dir_stat.st_mode = S_IFDIR | 0755;
    dir_stat.st_nlink = 3;
    dir_stat.st_dev = 1;

    struct stat file_stat = {0};
    file_stat.st_mode = S_IFREG | 0644;

    DIR *fake_dp = (DIR *)0x1234;
    DIR *fake_dp2 = (DIR *)0x5678;

    /* -- read_sys_dir: lstat on "/" -- */
    expect_lstat("/", &dir_stat, 0, 0);

    /* -- wopendir("/") -- */
    expect_wopendir("/", fake_dp);

    /* -- First readdir: ".", "..", "hidden.txt", NULL -- */
    expect_readdir(fake_dp, &dot_entry);
    expect_readdir(fake_dp, &dotdot_entry);
    expect_readdir(fake_dp, &hidden_entry);

    /* -- lstat on "/hidden.txt" (entry type check) -- */
    expect_lstat("/hidden.txt", &file_stat, 0, 0);

    /* -- check_ignore -- */
    expect_check_ignore("/hidden.txt", 0);

    /* -- read_sys_file: lstat -> ENOENT -> RC_ENOENT_SUSPECT -- */
    expect_lstat("/hidden.txt", NULL, ENOENT, -1);

    /* -- End of first readdir -- */
    expect_readdir(fake_dp, NULL);

    /* -- Second wopendir for verification -- */
    expect_wopendir("/", fake_dp2);

    /* -- Second readdir: file is STILL listed! (rootkit hiding it from lstat) -- */
    expect_readdir(fake_dp2, &dot_entry);
    expect_readdir(fake_dp2, &dotdot_entry);
    expect_readdir(fake_dp2, &hidden_entry);
    expect_readdir(fake_dp2, NULL);

    /* -- closedir on verification handle -- */
    expect_closedir(fake_dp2);

    /* -- Rootkit alert fires -- */
    expect_notify_rk(ALERT_ROOTKIT_FOUND);

    /* -- skipFS -- */
    expect_skipFS("/", 0);

    /* -- nlink re-check -- */
    struct stat dir_stat_recheck = {0};
    dir_stat_recheck.st_mode = S_IFDIR | 0755;
    dir_stat_recheck.st_nlink = 2;
    dir_stat_recheck.st_dev = 1;
    expect_lstat("/", &dir_stat_recheck, 0, 0);

    /* -- closedir on main handle -- */
    expect_closedir(fake_dp);

    /* -- _sys_errors > 0, no ALERT_OK -- */

    check_rc_sys("/");
}

/* ===================================================================
 * Test 3: Permission error (EACCES) — alert fires immediately
 * (no deferral, no second readdir).
 * =================================================================== */

static void test_eacces_still_alerts(void **state)
{
    (void)state;
    init_dot_entries();

    static struct dirent secret_entry;
    memset(&secret_entry, 0, sizeof(secret_entry));
    strncpy(secret_entry.d_name, "secret.txt", sizeof(secret_entry.d_name) - 1);

    struct stat dir_stat = {0};
    dir_stat.st_mode = S_IFDIR | 0755;
    dir_stat.st_nlink = 3;
    dir_stat.st_dev = 1;

    struct stat file_stat = {0};
    file_stat.st_mode = S_IFREG | 0644;

    DIR *fake_dp = (DIR *)0x1234;

    /* -- read_sys_dir: lstat on "/" -- */
    expect_lstat("/", &dir_stat, 0, 0);

    /* -- wopendir -- */
    expect_wopendir("/", fake_dp);

    /* -- readdir: ".", "..", "secret.txt", NULL -- */
    expect_readdir(fake_dp, &dot_entry);
    expect_readdir(fake_dp, &dotdot_entry);
    expect_readdir(fake_dp, &secret_entry);

    /* -- lstat on "/secret.txt" (entry type check) -- */
    expect_lstat("/secret.txt", &file_stat, 0, 0);

    /* -- check_ignore -- */
    expect_check_ignore("/secret.txt", 0);

    /* -- read_sys_file: lstat -> EACCES (NOT ENOENT) -> alert immediately -- */
    expect_lstat("/secret.txt", NULL, EACCES, -1);

    /* -- Alert fires -- */
    expect_notify_rk(ALERT_ROOTKIT_FOUND);

    /* -- readdir returns NULL -- */
    expect_readdir(fake_dp, NULL);

    /* No second wopendir needed (no ENOENT suspects) */

    /* -- skipFS -- */
    expect_skipFS("/", 0);

    /* -- nlink re-check -- */
    struct stat dir_stat_recheck = {0};
    dir_stat_recheck.st_mode = S_IFDIR | 0755;
    dir_stat_recheck.st_nlink = 2;
    dir_stat_recheck.st_dev = 1;
    expect_lstat("/", &dir_stat_recheck, 0, 0);

    /* -- closedir on main handle -- */
    expect_closedir(fake_dp);

    check_rc_sys("/");
}

/* ===================================================================
 * Test 4: Existing file — no alert
 * =================================================================== */

static void test_existing_file_no_alert(void **state)
{
    (void)state;
    init_dot_entries();

    static struct dirent normal_entry;
    memset(&normal_entry, 0, sizeof(normal_entry));
    strncpy(normal_entry.d_name, "normal.txt", sizeof(normal_entry.d_name) - 1);

    struct stat dir_stat = {0};
    dir_stat.st_mode = S_IFDIR | 0755;
    dir_stat.st_nlink = 2;
    dir_stat.st_dev = 1;

    struct stat file_stat = {0};
    file_stat.st_mode = S_IFREG | 0644;
    file_stat.st_size = 100;

    DIR *fake_dp = (DIR *)0x1234;

    /* -- read_sys_dir: lstat on "/" -- */
    expect_lstat("/", &dir_stat, 0, 0);

    /* -- wopendir -- */
    expect_wopendir("/", fake_dp);

    /* -- readdir: ".", "..", "normal.txt", NULL -- */
    expect_readdir(fake_dp, &dot_entry);
    expect_readdir(fake_dp, &dotdot_entry);
    expect_readdir(fake_dp, &normal_entry);

    /* -- lstat on "/normal.txt" (entry type check) -- */
    expect_lstat("/normal.txt", &file_stat, 0, 0);

    /* -- check_ignore -- */
    expect_check_ignore("/normal.txt", 0);

    /* -- read_sys_file: lstat -> success -- */
    expect_lstat("/normal.txt", &file_stat, 0, 0);

    /* -- readdir returns NULL -- */
    expect_readdir(fake_dp, NULL);

    /* No second wopendir (no suspects) */

    /* -- skipFS -- */
    expect_skipFS("/", 0);

    /* -- nlink check: entry_count=2, st_nlink=2 -> match -- */

    /* -- closedir on main handle -- */
    expect_closedir(fake_dp);

    /* -- _sys_errors == 0 -> notify_rk(ALERT_OK) -- */
    expect_notify_rk(ALERT_OK);

    check_rc_sys("/");
}

/* ===================================================================
 * Test 5: Multiple ENOENT suspects — one deleted, one hidden.
 * Verifies batch handling in the second readdir pass.
 * =================================================================== */

static void test_multiple_suspects_mixed(void **state)
{
    (void)state;
    init_dot_entries();

    static struct dirent deleted_entry, hidden_entry;
    memset(&deleted_entry, 0, sizeof(deleted_entry));
    memset(&hidden_entry, 0, sizeof(hidden_entry));
    strncpy(deleted_entry.d_name, "deleted.txt", sizeof(deleted_entry.d_name) - 1);
    strncpy(hidden_entry.d_name, "hidden.txt", sizeof(hidden_entry.d_name) - 1);

    struct stat dir_stat = {0};
    dir_stat.st_mode = S_IFDIR | 0755;
    dir_stat.st_nlink = 4; /* . + .. + deleted + hidden */
    dir_stat.st_dev = 1;

    struct stat file_stat = {0};
    file_stat.st_mode = S_IFREG | 0644;

    DIR *fake_dp = (DIR *)0x1234;
    DIR *fake_dp2 = (DIR *)0x5678;

    /* -- read_sys_dir: lstat on "/" -- */
    expect_lstat("/", &dir_stat, 0, 0);

    /* -- wopendir -- */
    expect_wopendir("/", fake_dp);

    /* -- First readdir: ".", "..", "deleted.txt", "hidden.txt", NULL -- */
    expect_readdir(fake_dp, &dot_entry);
    expect_readdir(fake_dp, &dotdot_entry);
    expect_readdir(fake_dp, &deleted_entry);

    /* -- entry type check + ignore + read_sys_file for deleted.txt -- */
    expect_lstat("/deleted.txt", &file_stat, 0, 0);
    expect_check_ignore("/deleted.txt", 0);
    expect_lstat("/deleted.txt", NULL, ENOENT, -1);

    expect_readdir(fake_dp, &hidden_entry);

    /* -- entry type check + ignore + read_sys_file for hidden.txt -- */
    expect_lstat("/hidden.txt", &file_stat, 0, 0);
    expect_check_ignore("/hidden.txt", 0);
    expect_lstat("/hidden.txt", NULL, ENOENT, -1);

    /* -- End of first readdir -- */
    expect_readdir(fake_dp, NULL);

    /* -- Second wopendir for verification -- */
    expect_wopendir("/", fake_dp2);

    /* -- Second readdir: only hidden.txt still listed (deleted.txt gone) -- */
    expect_readdir(fake_dp2, &dot_entry);
    expect_readdir(fake_dp2, &dotdot_entry);
    expect_readdir(fake_dp2, &hidden_entry);
    expect_readdir(fake_dp2, NULL);

    /* -- closedir on verification handle -- */
    expect_closedir(fake_dp2);

    /* -- Only hidden.txt triggers alert -- */
    expect_notify_rk(ALERT_ROOTKIT_FOUND);

    /* -- skipFS -- */
    expect_skipFS("/", 0);

    /* -- nlink re-check: 2 vs 4 -> re-lstat returns 2 -> match -- */
    struct stat dir_stat_recheck = {0};
    dir_stat_recheck.st_mode = S_IFDIR | 0755;
    dir_stat_recheck.st_nlink = 2;
    dir_stat_recheck.st_dev = 1;
    expect_lstat("/", &dir_stat_recheck, 0, 0);

    /* -- closedir on main handle -- */
    expect_closedir(fake_dp);

    /* _sys_errors > 0, no ALERT_OK */

    check_rc_sys("/");
}

/* ===================================================================
 * Test 6: Verification wopendir fails — conservative fallback alerts
 * all suspects.
 * =================================================================== */

static void test_wopendir_fail_fallback_alerts_all(void **state)
{
    (void)state;
    init_dot_entries();

    static struct dirent suspect_entry;
    memset(&suspect_entry, 0, sizeof(suspect_entry));
    strncpy(suspect_entry.d_name, "suspect.txt", sizeof(suspect_entry.d_name) - 1);

    struct stat dir_stat = {0};
    dir_stat.st_mode = S_IFDIR | 0755;
    dir_stat.st_nlink = 3;
    dir_stat.st_dev = 1;

    struct stat file_stat = {0};
    file_stat.st_mode = S_IFREG | 0644;

    DIR *fake_dp = (DIR *)0x1234;

    /* -- read_sys_dir: lstat on "/" -- */
    expect_lstat("/", &dir_stat, 0, 0);

    /* -- wopendir("/") -- */
    expect_wopendir("/", fake_dp);

    /* -- First readdir: ".", "..", "suspect.txt", NULL -- */
    expect_readdir(fake_dp, &dot_entry);
    expect_readdir(fake_dp, &dotdot_entry);
    expect_readdir(fake_dp, &suspect_entry);

    /* -- lstat on "/suspect.txt" (entry type check) -- */
    expect_lstat("/suspect.txt", &file_stat, 0, 0);

    /* -- check_ignore -- */
    expect_check_ignore("/suspect.txt", 0);

    /* -- read_sys_file: lstat -> ENOENT -> RC_ENOENT_SUSPECT -- */
    expect_lstat("/suspect.txt", NULL, ENOENT, -1);

    /* -- End of first readdir -- */
    expect_readdir(fake_dp, NULL);

    /* -- Second wopendir FAILS (returns NULL) -- */
    expect_wopendir("/", NULL);

    /* -- Fallback: alert fires for suspect (conservative) -- */
    expect_notify_rk(ALERT_ROOTKIT_FOUND);

    /* -- skipFS -- */
    expect_skipFS("/", 0);

    /* -- nlink re-check -- */
    struct stat dir_stat_recheck = {0};
    dir_stat_recheck.st_mode = S_IFDIR | 0755;
    dir_stat_recheck.st_nlink = 2;
    dir_stat_recheck.st_dev = 1;
    expect_lstat("/", &dir_stat_recheck, 0, 0);

    /* -- closedir on main handle -- */
    expect_closedir(fake_dp);

    /* _sys_errors > 0, no ALERT_OK */

    check_rc_sys("/");
}

/* ===================================================================
 * Test 7: Non-root directory path building via recursive call.
 * When "/" contains a directory entry "etc", read_sys_file recurses
 * into read_sys_dir("/etc", ...). Inside that call, files are
 * built as "/etc/hidden.txt" (not "/hidden.txt"). This verifies
 * the non-root path-building branch.
 * =================================================================== */

static void test_subdir_path_building(void **state)
{
    (void)state;
    init_dot_entries();

    static struct dirent etc_entry, hidden_entry;
    memset(&etc_entry, 0, sizeof(etc_entry));
    memset(&hidden_entry, 0, sizeof(hidden_entry));
    strncpy(etc_entry.d_name, "etc", sizeof(etc_entry.d_name) - 1);
    strncpy(hidden_entry.d_name, "hidden.txt", sizeof(hidden_entry.d_name) - 1);

    struct stat dir_stat = {0};
    dir_stat.st_mode = S_IFDIR | 0755;
    dir_stat.st_nlink = 3;
    dir_stat.st_size = 4096;
    dir_stat.st_dev = 1;

    struct stat subdir_stat = {0};
    subdir_stat.st_mode = S_IFDIR | 0755;
    subdir_stat.st_nlink = 3;
    subdir_stat.st_size = 4096;
    subdir_stat.st_dev = 1;

    struct stat file_stat = {0};
    file_stat.st_mode = S_IFREG | 0644;

    DIR *fake_dp_root = (DIR *)0x1000;
    DIR *fake_dp_etc = (DIR *)0x2000;
    DIR *fake_dp_etc2 = (DIR *)0x3000;

    /* === Level 1: scan "/" === */

    /* -- lstat on "/" -- */
    expect_lstat("/", &dir_stat, 0, 0);

    /* -- wopendir("/") -- */
    expect_wopendir("/", fake_dp_root);

    /* -- readdir("/") -> ".", "..", "etc", NULL -- */
    expect_readdir(fake_dp_root, &dot_entry);
    expect_readdir(fake_dp_root, &dotdot_entry);
    expect_readdir(fake_dp_root, &etc_entry);

    /* -- lstat("/etc") for entry_count (it's a dir -> count++) -- */
    expect_lstat("/etc", &subdir_stat, 0, 0);

    /* -- check_ignore("/etc") -- */
    expect_check_ignore("/etc", 0);

    /* -- read_sys_file("/etc", 0): lstat succeeds, S_ISDIR -> recurse -- */
    expect_lstat("/etc", &subdir_stat, 0, 0);

    /* === Level 2: recursive scan of "/etc" === */

    /* -- lstat on "/etc" (read_sys_dir entry) -- */
    expect_lstat("/etc", &subdir_stat, 0, 0);

    /* -- wopendir("/etc") -- */
    expect_wopendir("/etc", fake_dp_etc);

    /* -- readdir("/etc") -> ".", "..", "hidden.txt", NULL -- */
    expect_readdir(fake_dp_etc, &dot_entry);
    expect_readdir(fake_dp_etc, &dotdot_entry);
    expect_readdir(fake_dp_etc, &hidden_entry);

    /* -- lstat("/etc/hidden.txt") for entry_count -- */
    expect_lstat("/etc/hidden.txt", &file_stat, 0, 0);

    /* -- check_ignore("/etc/hidden.txt") -- */
    expect_check_ignore("/etc/hidden.txt", 0);

    /* -- read_sys_file("/etc/hidden.txt"): lstat -> ENOENT -> suspect -- */
    expect_lstat("/etc/hidden.txt", NULL, ENOENT, -1);

    /* -- End of readdir("/etc") -- */
    expect_readdir(fake_dp_etc, NULL);

    /* -- Second wopendir("/etc") for verification -- */
    expect_wopendir("/etc", fake_dp_etc2);

    /* -- Verification readdir: hidden.txt still listed -> alert -- */
    expect_readdir(fake_dp_etc2, &dot_entry);
    expect_readdir(fake_dp_etc2, &dotdot_entry);
    expect_readdir(fake_dp_etc2, &hidden_entry);
    expect_readdir(fake_dp_etc2, NULL);

    /* -- closedir on verification handle -- */
    expect_closedir(fake_dp_etc2);

    /* -- Alert with full path "/etc/hidden.txt" -- */
    expect_notify_rk(ALERT_ROOTKIT_FOUND);

    /* -- skipFS("/etc") -- */
    expect_skipFS("/etc", 0);

    /* -- nlink re-check for "/etc": 2 vs 3 -> mismatch -> re-lstat -- */
    struct stat subdir_recheck = {0};
    subdir_recheck.st_mode = S_IFDIR | 0755;
    subdir_recheck.st_nlink = 2;
    subdir_recheck.st_dev = 1;
    expect_lstat("/etc", &subdir_recheck, 0, 0);

    /* -- closedir on "/etc" main handle -- */
    expect_closedir(fake_dp_etc);

    /* === Back to level 1 === */

    /* -- readdir("/") returns NULL -- */
    expect_readdir(fake_dp_root, NULL);

    /* No suspects at root level */

    /* -- skipFS("/") -- */
    expect_skipFS("/", 0);

    /* -- nlink: entry_count=3, st_nlink=3 -> match -> no re-lstat -- */

    /* -- closedir on root handle -- */
    expect_closedir(fake_dp_root);

    /* -- _sys_errors > 0 from the nested alert, no ALERT_OK -- */

    check_rc_sys("/");
}

/* ===================================================================
 * Main
 * =================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_enoent_deleted_file_no_alert, setup),
        cmocka_unit_test_setup(test_enoent_hidden_file_alerts, setup),
        cmocka_unit_test_setup(test_eacces_still_alerts, setup),
        cmocka_unit_test_setup(test_existing_file_no_alert, setup),
        cmocka_unit_test_setup(test_multiple_suspects_mixed, setup),
        cmocka_unit_test_setup(test_wopendir_fail_fallback_alerts_all, setup),
        cmocka_unit_test_setup(test_subdir_path_building, setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
