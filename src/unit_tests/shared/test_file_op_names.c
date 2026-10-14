/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* w_path_names_fd() and w_move_file_nofollow() on real files in a scratch directory. Only rename()
 * is wrapped, to fail the way it does over a single-file bind mount (EBUSY) or across filesystems
 * (EXDEV), which a test can't set up for real. */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* Sized for the mkdtemp() template below, so a name never truncates */
static char g_dir[64];
static char g_src[96];
static char g_dst[96];
/* Another name in the directory: a link target, a second link, a file to leave alone */
static char g_other[96];
static char g_expected_log[512];

/* 0 calls the real rename() */
static int g_rename_errno;

int __real_rename(const char *oldpath, const char *newpath);

int __wrap_rename(const char *oldpath, const char *newpath) {
    if (g_rename_errno != 0) {
        errno = g_rename_errno;
        return -1;
    }

    return __real_rename(oldpath, newpath);
}

static void write_file(const char *path, const char *content, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);

    assert_int_not_equal(fd, -1);
    assert_int_equal(write(fd, content, strlen(content)), (ssize_t)strlen(content));
    assert_int_equal(close(fd), 0);
    /* The mode asked for, whatever the umask */
    assert_int_equal(chmod(path, mode), 0);
}

static const char *read_file(const char *path) {
    static char content[256];
    int fd = open(path, O_RDONLY);
    ssize_t length;

    assert_int_not_equal(fd, -1);
    length = read(fd, content, sizeof(content) - 1);
    assert_true(length >= 0);
    content[length] = '\0';
    close(fd);
    return content;
}

static ino_t inode_of(const char *path) {
    struct stat info;

    assert_int_equal(lstat(path, &info), 0);
    return info.st_ino;
}

static int setup_dir(void **state) {
    (void)state;
    snprintf(g_dir, sizeof(g_dir), "/tmp/wazuh_file_op_names_XXXXXX");
    assert_non_null(mkdtemp(g_dir));
    snprintf(g_src, sizeof(g_src), "%s/staged", g_dir);
    snprintf(g_dst, sizeof(g_dst), "%s/installed", g_dir);
    snprintf(g_other, sizeof(g_other), "%s/other", g_dir);
    g_rename_errno = 0;
    return 0;
}

static int teardown_dir(void **state) {
    (void)state;
    unlink(g_src);
    unlink(g_dst);
    unlink(g_other);
    rmdir(g_dir);
    return 0;
}

/* w_path_names_fd() */

static void test_path_names_fd_for_the_open_file(void **state) {
    (void)state;
    write_file(g_src, "staged", 0600);
    int fd = open(g_src, O_RDONLY);

    assert_true(w_path_names_fd(g_src, fd));

    close(fd);
}

static void test_path_names_fd_not_once_the_name_is_swapped(void **state) {
    (void)state;
    write_file(g_src, "staged", 0600);
    int fd = open(g_src, O_RDONLY);
    assert_int_equal(unlink(g_src), 0);
    write_file(g_src, "swapped", 0600);

    assert_false(w_path_names_fd(g_src, fd));

    close(fd);
}

static void test_path_names_fd_not_through_a_symlink(void **state) {
    (void)state;
    write_file(g_other, "staged", 0600);
    int fd = open(g_other, O_RDONLY);
    assert_int_equal(symlink(g_other, g_src), 0);

    assert_false(w_path_names_fd(g_src, fd));

    close(fd);
}

static void test_path_names_fd_not_with_a_second_hard_link(void **state) {
    (void)state;
    write_file(g_src, "staged", 0600);
    int fd = open(g_src, O_RDONLY);
    assert_int_equal(link(g_src, g_other), 0);

    assert_false(w_path_names_fd(g_src, fd));

    close(fd);
}

static void test_path_names_fd_not_once_the_name_is_gone(void **state) {
    (void)state;
    write_file(g_src, "staged", 0600);
    int fd = open(g_src, O_RDONLY);
    assert_int_equal(unlink(g_src), 0);

    assert_false(w_path_names_fd(g_src, fd));

    close(fd);
}

/* w_move_file_nofollow() */

static void test_move_nofollow_renames(void **state) {
    (void)state;
    write_file(g_src, "new", 0640);
    write_file(g_dst, "old", 0600);
    ino_t staged = inode_of(g_src);

    assert_int_equal(w_move_file_nofollow(g_src, g_dst), 0);

    assert_int_equal(inode_of(g_dst), staged);
    assert_string_equal(read_file(g_dst), "new");
    assert_int_equal(access(g_src, F_OK), -1);
}

/* What a single-file bind mount does: rename() can't replace it, but it can be written. */
static void test_move_nofollow_copies_into_what_rename_cannot_replace(void **state) {
    (void)state;
    write_file(g_src, "new", 0640);
    write_file(g_dst, "a longer old content", 0600);
    ino_t installed = inode_of(g_dst);
    g_rename_errno = EBUSY;
    snprintf(g_expected_log, sizeof(g_expected_log), "Couldn't rename '%s' to '%s': %s (%d). Copying it instead.",
             g_src, g_dst, strerror(EBUSY), EBUSY);

    expect_string(__wrap__mdebug1, formatted_msg, g_expected_log);

    assert_int_equal(w_move_file_nofollow(g_src, g_dst), 0);

    assert_int_equal(inode_of(g_dst), installed);
    assert_string_equal(read_file(g_dst), "new");
    assert_int_equal(access(g_src, F_OK), -1);
}

static void test_move_nofollow_creates_a_missing_destination_with_the_source_mode(void **state) {
    (void)state;
    struct stat info;
    mode_t old_mask = umask(022);
    write_file(g_src, "new", 0640);
    g_rename_errno = EXDEV;

    expect_any(__wrap__mdebug1, formatted_msg);

    assert_int_equal(w_move_file_nofollow(g_src, g_dst), 0);

    umask(old_mask);
    assert_int_equal(lstat(g_dst, &info), 0);
    assert_true(S_ISREG(info.st_mode));
    assert_int_equal(info.st_mode & 07777, 0640);
    assert_string_equal(read_file(g_dst), "new");
    assert_int_equal(access(g_src, F_OK), -1);
}

/* The refusals: nothing goes through a link, and the staged file stays for the caller. */

static void test_move_nofollow_refuses_a_symlinked_destination(void **state) {
    (void)state;
    write_file(g_src, "new", 0640);
    write_file(g_other, "untouched", 0600);
    assert_int_equal(symlink(g_other, g_dst), 0);
    g_rename_errno = EBUSY;

    expect_any(__wrap__mdebug1, formatted_msg);
    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(w_move_file_nofollow(g_src, g_dst), -1);

    assert_int_equal(errno, ELOOP);
    assert_string_equal(read_file(g_other), "untouched");
    assert_string_equal(read_file(g_src), "new");
}

static void test_move_nofollow_refuses_a_hard_linked_destination(void **state) {
    (void)state;
    write_file(g_src, "new", 0640);
    write_file(g_dst, "untouched", 0600);
    assert_int_equal(link(g_dst, g_other), 0);
    g_rename_errno = EBUSY;

    expect_any(__wrap__mdebug1, formatted_msg);
    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(w_move_file_nofollow(g_src, g_dst), -1);

    assert_int_equal(errno, EMLINK);
    assert_string_equal(read_file(g_other), "untouched");
    assert_string_equal(read_file(g_src), "new");
}

static void test_move_nofollow_refuses_a_symlinked_source(void **state) {
    (void)state;
    write_file(g_other, "not to be copied", 0600);
    assert_int_equal(symlink(g_other, g_src), 0);
    write_file(g_dst, "untouched", 0600);
    g_rename_errno = EBUSY;

    expect_any(__wrap__mdebug1, formatted_msg);
    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(w_move_file_nofollow(g_src, g_dst), -1);

    assert_int_equal(errno, ELOOP);
    assert_string_equal(read_file(g_dst), "untouched");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_path_names_fd_for_the_open_file, setup_dir, teardown_dir),
        cmocka_unit_test_setup_teardown(test_path_names_fd_not_once_the_name_is_swapped, setup_dir, teardown_dir),
        cmocka_unit_test_setup_teardown(test_path_names_fd_not_through_a_symlink, setup_dir, teardown_dir),
        cmocka_unit_test_setup_teardown(test_path_names_fd_not_with_a_second_hard_link, setup_dir, teardown_dir),
        cmocka_unit_test_setup_teardown(test_path_names_fd_not_once_the_name_is_gone, setup_dir, teardown_dir),
        cmocka_unit_test_setup_teardown(test_move_nofollow_renames, setup_dir, teardown_dir),
        cmocka_unit_test_setup_teardown(test_move_nofollow_copies_into_what_rename_cannot_replace, setup_dir,
                                        teardown_dir),
        cmocka_unit_test_setup_teardown(test_move_nofollow_creates_a_missing_destination_with_the_source_mode,
                                        setup_dir, teardown_dir),
        cmocka_unit_test_setup_teardown(test_move_nofollow_refuses_a_symlinked_destination, setup_dir, teardown_dir),
        cmocka_unit_test_setup_teardown(test_move_nofollow_refuses_a_hard_linked_destination, setup_dir,
                                        teardown_dir),
        cmocka_unit_test_setup_teardown(test_move_nofollow_refuses_a_symlinked_source, setup_dir, teardown_dir),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
