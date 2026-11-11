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
#include <stdint.h>
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
DIR *__wrap_opendir(const char *name)
{
    check_expected(name);
    return mock_type(DIR *);
}

struct dirent *__wrap_readdir(DIR *dirp)
{
    check_expected(dirp);
    return mock_type(struct dirent *);
}

void __wrap_rewinddir(DIR *dirp)
{
    check_expected(dirp);
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

static void expect_rewinddir(DIR *dp)
{
    expect_value(__wrap_rewinddir, dirp, dp);
}

/* Queue a closedir expectation that validates the DIR* handle */
static void expect_closedir(DIR *dp)
{
    expect_value(__wrap_closedir, dirp, dp);
}

/* Queue an opendir expectation */
static void expect_opendir(const char *path, DIR *dp)
{
    expect_string(__wrap_opendir, name, path);
    will_return(__wrap_opendir, dp);
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

/* cmocka check: value contains text */
static int msg_contains(const LargestIntegralType value,
                        const LargestIntegralType text)
{
    return strstr((const char *)value, (const char *)text) != NULL;
}

/* Queue a notify_rk expectation whose message must contain the given text */
static void expect_notify_rk_containing(int rk_type, const char *text)
{
    expect_value(__wrap_notify_rk, rk_type, rk_type);
    expect_check(__wrap_notify_rk, msg, msg_contains, text);
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

    /* -- read_sys_dir: lstat on "/" -- */
    expect_lstat("/", &dir_stat, 0, 0);

    /* -- opendir("/") -- */
    expect_opendir("/", fake_dp);

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

    /* -- Second pass rewinds the already open handle -- */
    expect_rewinddir(fake_dp);

    /* -- Second readdir pass: file is GONE (only ".", "..", NULL) -- */
    expect_readdir(fake_dp, &dot_entry);
    expect_readdir(fake_dp, &dotdot_entry);
    expect_readdir(fake_dp, NULL);

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

    /* -- read_sys_dir: lstat on "/" -- */
    expect_lstat("/", &dir_stat, 0, 0);

    /* -- opendir("/") -- */
    expect_opendir("/", fake_dp);

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

    /* -- Second pass rewinds the already open handle -- */
    expect_rewinddir(fake_dp);

    /* -- Second readdir: file is STILL listed! (rootkit hiding it from lstat) -- */
    expect_readdir(fake_dp, &dot_entry);
    expect_readdir(fake_dp, &dotdot_entry);
    expect_readdir(fake_dp, &hidden_entry);
    expect_readdir(fake_dp, NULL);

    /* -- Second lstat still ENOENT -> genuinely hidden -- */
    expect_lstat("/hidden.txt", NULL, ENOENT, -1);

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

    /* -- opendir -- */
    expect_opendir("/", fake_dp);

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

    /* No verification pass needed (no ENOENT suspects) */

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

    /* -- opendir -- */
    expect_opendir("/", fake_dp);

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

    /* No verification pass (no suspects) */

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

    /* -- read_sys_dir: lstat on "/" -- */
    expect_lstat("/", &dir_stat, 0, 0);

    /* -- opendir -- */
    expect_opendir("/", fake_dp);

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

    /* -- Second pass rewinds the already open handle -- */
    expect_rewinddir(fake_dp);

    /* -- Second readdir: only hidden.txt still listed (deleted.txt gone) -- */
    expect_readdir(fake_dp, &dot_entry);
    expect_readdir(fake_dp, &dotdot_entry);
    expect_readdir(fake_dp, &hidden_entry);
    expect_readdir(fake_dp, NULL);

    /* -- Second lstat for hidden.txt still ENOENT -- */
    expect_lstat("/hidden.txt", NULL, ENOENT, -1);

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
 * Test 6: Directory deleted mid-scan. The rewound handle yields nothing,
 * so the suspect is not alerted.
 * =================================================================== */

static void test_dir_deleted_mid_scan_no_alert(void **state)
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

    expect_lstat("/", &dir_stat, 0, 0);
    expect_opendir("/", fake_dp);

    expect_readdir(fake_dp, &dot_entry);
    expect_readdir(fake_dp, &dotdot_entry);
    expect_readdir(fake_dp, &suspect_entry);

    expect_lstat("/suspect.txt", &file_stat, 0, 0);
    expect_check_ignore("/suspect.txt", 0);
    expect_lstat("/suspect.txt", NULL, ENOENT, -1);

    expect_readdir(fake_dp, NULL);

    /* -- Directory is gone: the rewound read returns no entries -- */
    expect_rewinddir(fake_dp);
    expect_readdir(fake_dp, NULL);

    expect_skipFS("/", 0);

    struct stat dir_stat_recheck = {0};
    dir_stat_recheck.st_mode = S_IFDIR | 0755;
    dir_stat_recheck.st_nlink = 2;
    dir_stat_recheck.st_dev = 1;
    expect_lstat("/", &dir_stat_recheck, 0, 0);

    expect_closedir(fake_dp);

    /* -- No suspect alert -> notify_rk(ALERT_OK) -- */
    expect_notify_rk(ALERT_OK);

    check_rc_sys("/");
}

/* ===================================================================
 * Test 6b: File deleted and recreated under the same name. It is listed
 * on the second readdir but the second lstat succeeds -> no alert.
 * =================================================================== */

static void test_recreated_file_no_alert(void **state)
{
    (void)state;
    init_dot_entries();

    static struct dirent recreated_entry;
    memset(&recreated_entry, 0, sizeof(recreated_entry));
    strncpy(recreated_entry.d_name, "recreated.txt", sizeof(recreated_entry.d_name) - 1);

    struct stat dir_stat = {0};
    dir_stat.st_mode = S_IFDIR | 0755;
    dir_stat.st_nlink = 3;
    dir_stat.st_dev = 1;

    struct stat file_stat = {0};
    file_stat.st_mode = S_IFREG | 0644;

    DIR *fake_dp = (DIR *)0x1234;

    expect_lstat("/", &dir_stat, 0, 0);
    expect_opendir("/", fake_dp);

    expect_readdir(fake_dp, &dot_entry);
    expect_readdir(fake_dp, &dotdot_entry);
    expect_readdir(fake_dp, &recreated_entry);

    expect_lstat("/recreated.txt", &file_stat, 0, 0);
    expect_check_ignore("/recreated.txt", 0);
    expect_lstat("/recreated.txt", NULL, ENOENT, -1);

    expect_readdir(fake_dp, NULL);

    expect_rewinddir(fake_dp);
    expect_readdir(fake_dp, &dot_entry);
    expect_readdir(fake_dp, &dotdot_entry);
    expect_readdir(fake_dp, &recreated_entry);
    expect_readdir(fake_dp, NULL);

    /* -- Second lstat succeeds: the file was recreated -- */
    expect_lstat("/recreated.txt", &file_stat, 0, 0);

    expect_skipFS("/", 0);

    struct stat dir_stat_recheck = {0};
    dir_stat_recheck.st_mode = S_IFDIR | 0755;
    dir_stat_recheck.st_nlink = 2;
    dir_stat_recheck.st_dev = 1;
    expect_lstat("/", &dir_stat_recheck, 0, 0);

    expect_closedir(fake_dp);

    expect_notify_rk(ALERT_OK);

    check_rc_sys("/");
}

/* ===================================================================
 * Test 6c: Over-long path. Nested directories push the hidden file's
 * full path past OS_SIZE_1024. The path is trimmed to fit but the fixed
 * alert wording is preserved.
 * =================================================================== */

#define LP_DEPTH 5
#define LP_NAME_LEN 250

static char lp_path[LP_DEPTH + 1][LP_DEPTH * (LP_NAME_LEN + 1) + 2];
static struct dirent lp_entry[LP_DEPTH];
static struct dirent lp_hidden;
static struct stat lp_dir_stat[LP_DEPTH + 1];
static struct stat lp_file_stat;
static struct stat lp_dir_recheck;
static char lp_hidden_path[sizeof(lp_path[0]) + 16];

/* Queue the expectations for read_sys_dir() on lp_path[lvl], recursing into
 * the single child directory until the leaf holding the hidden file. All
 * data handed to cmocka is static: it is read after this function returns. */
static void expect_long_path_level(int lvl)
{
    struct stat *dir_stat = &lp_dir_stat[lvl];
    memset(dir_stat, 0, sizeof(*dir_stat));
    dir_stat->st_mode = S_IFDIR | 0755;
    dir_stat->st_nlink = 3;
    dir_stat->st_size = 4096;
    dir_stat->st_dev = 1;

    DIR *dp = (DIR *)(uintptr_t)(0x1000 + lvl);

    expect_lstat(lp_path[lvl], dir_stat, 0, 0);
    expect_opendir(lp_path[lvl], dp);

    expect_readdir(dp, &dot_entry);
    expect_readdir(dp, &dotdot_entry);

    if (lvl < LP_DEPTH) {
        expect_readdir(dp, &lp_entry[lvl]);

        expect_lstat(lp_path[lvl + 1], dir_stat, 0, 0);
        expect_check_ignore(lp_path[lvl + 1], 0);
        expect_lstat(lp_path[lvl + 1], dir_stat, 0, 0);

        expect_long_path_level(lvl + 1);

        expect_readdir(dp, NULL);
        expect_skipFS(lp_path[lvl], 0);
        expect_closedir(dp);
    } else {
        memset(&lp_file_stat, 0, sizeof(lp_file_stat));
        lp_file_stat.st_mode = S_IFREG | 0644;

        snprintf(lp_hidden_path, sizeof(lp_hidden_path), "%s/hidden.txt", lp_path[lvl]);

        expect_readdir(dp, &lp_hidden);
        expect_lstat(lp_hidden_path, &lp_file_stat, 0, 0);
        expect_check_ignore(lp_hidden_path, 0);
        expect_lstat(lp_hidden_path, NULL, ENOENT, -1);
        expect_readdir(dp, NULL);

        expect_rewinddir(dp);
        expect_readdir(dp, &dot_entry);
        expect_readdir(dp, &dotdot_entry);
        expect_readdir(dp, &lp_hidden);
        expect_readdir(dp, NULL);
        expect_lstat(lp_hidden_path, NULL, ENOENT, -1);

        expect_notify_rk_containing(ALERT_ROOTKIT_FOUND, "Hidden from stats");

        expect_skipFS(lp_path[lvl], 0);

        memset(&lp_dir_recheck, 0, sizeof(lp_dir_recheck));
        lp_dir_recheck.st_mode = S_IFDIR | 0755;
        lp_dir_recheck.st_nlink = 2;
        lp_dir_recheck.st_dev = 1;
        expect_lstat(lp_path[lvl], &lp_dir_recheck, 0, 0);

        expect_closedir(dp);
    }
}

static void test_long_path_alert_keeps_message(void **state)
{
    (void)state;
    init_dot_entries();

    memset(&lp_hidden, 0, sizeof(lp_hidden));
    strncpy(lp_hidden.d_name, "hidden.txt", sizeof(lp_hidden.d_name) - 1);

    snprintf(lp_path[0], sizeof(lp_path[0]), "/");

    for (int i = 0; i < LP_DEPTH; i++) {
        memset(&lp_entry[i], 0, sizeof(lp_entry[i]));
        memset(lp_entry[i].d_name, 'a' + i, LP_NAME_LEN);
        snprintf(lp_path[i + 1], sizeof(lp_path[i + 1]), "%s%s%s",
                 lp_path[i], (i == 0) ? "" : "/", lp_entry[i].d_name);
    }

    expect_long_path_level(0);

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

    /* === Level 1: scan "/" === */

    /* -- lstat on "/" -- */
    expect_lstat("/", &dir_stat, 0, 0);

    /* -- opendir("/") -- */
    expect_opendir("/", fake_dp_root);

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

    /* -- opendir("/etc") -- */
    expect_opendir("/etc", fake_dp_etc);

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

    /* -- Verification pass rewinds the already open handle -- */
    expect_rewinddir(fake_dp_etc);

    /* -- Verification readdir: hidden.txt still listed -> alert -- */
    expect_readdir(fake_dp_etc, &dot_entry);
    expect_readdir(fake_dp_etc, &dotdot_entry);
    expect_readdir(fake_dp_etc, &hidden_entry);
    expect_readdir(fake_dp_etc, NULL);

    /* -- Second lstat still ENOENT -- */
    expect_lstat("/etc/hidden.txt", NULL, ENOENT, -1);

    /* -- Alert with full path "/etc/hidden.txt" -- */
    expect_notify_rk_containing(ALERT_ROOTKIT_FOUND, "'/etc/hidden.txt'");

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
        cmocka_unit_test_setup(test_dir_deleted_mid_scan_no_alert, setup),
        cmocka_unit_test_setup(test_recreated_file_no_alert, setup),
        cmocka_unit_test_setup(test_long_path_alert_keeps_message, setup),
        cmocka_unit_test_setup(test_subdir_path_building, setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
