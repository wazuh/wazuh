/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* w_path_names_fd() on real files in a scratch directory. */

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
/* Another name in the directory: a link target, a second link, a file to leave alone */
static char g_other[96];

static void write_file(const char *path, const char *content, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);

    assert_int_not_equal(fd, -1);
    assert_int_equal(write(fd, content, strlen(content)), (ssize_t)strlen(content));
    assert_int_equal(close(fd), 0);
    /* The mode asked for, whatever the umask */
    assert_int_equal(chmod(path, mode), 0);
}

static int setup_dir(void **state) {
    (void)state;
    snprintf(g_dir, sizeof(g_dir), "/tmp/wazuh_file_op_names_XXXXXX");
    assert_non_null(mkdtemp(g_dir));
    snprintf(g_src, sizeof(g_src), "%s/staged", g_dir);
    snprintf(g_other, sizeof(g_other), "%s/other", g_dir);
    return 0;
}

static int teardown_dir(void **state) {
    (void)state;
    unlink(g_src);
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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_path_names_fd_for_the_open_file, setup_dir, teardown_dir),
        cmocka_unit_test_setup_teardown(test_path_names_fd_not_once_the_name_is_swapped, setup_dir, teardown_dir),
        cmocka_unit_test_setup_teardown(test_path_names_fd_not_through_a_symlink, setup_dir, teardown_dir),
        cmocka_unit_test_setup_teardown(test_path_names_fd_not_with_a_second_hard_link, setup_dir, teardown_dir),
        cmocka_unit_test_setup_teardown(test_path_names_fd_not_once_the_name_is_gone, setup_dir, teardown_dir),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
