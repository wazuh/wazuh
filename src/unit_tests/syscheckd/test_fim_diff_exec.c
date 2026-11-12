/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "../../syscheckd/include/syscheck.h"
#include "../wrappers/common.h"

// These run the real child process: diff for the normal cases and small scripts for the limits

extern unsigned int fim_diff_exec_timeout;
extern const char *fim_diff_exec_bins[];

typedef struct exec_paths {
    char dir[64];
    char old_file[128];
    char new_file[128];
    char out_file[128];
    char script[128];
    const char *saved_bin;
} exec_paths;

static void write_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "w");
    assert_non_null(fp);
    fputs(content, fp);
    fclose(fp);
}

static long file_size(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 ? (long)st.st_size : -1;
}

// Writes an executable script and makes fim_diff_exec() run it instead of diff
static void use_script(exec_paths *paths, const char *body) {
    char content[OS_SIZE_1024];

    snprintf(content, sizeof(content), "#!/bin/sh\n%s\n", body);
    write_file(paths->script, content);
    assert_int_equal(chmod(paths->script, 0700), 0);
    fim_diff_exec_bins[0] = paths->script;
}

static int setup(void **state) {
    exec_paths *paths = calloc(1, sizeof(exec_paths));

    if (paths == NULL) {
        return -1;
    }

    snprintf(paths->dir, sizeof(paths->dir), "/tmp/test_fim_diff_exec.XXXXXX");
    if (mkdtemp(paths->dir) == NULL) {
        free(paths);
        return -1;
    }

    snprintf(paths->old_file, sizeof(paths->old_file), "%s/old", paths->dir);
    snprintf(paths->new_file, sizeof(paths->new_file), "%s/new", paths->dir);
    snprintf(paths->out_file, sizeof(paths->out_file), "%s/diff-file", paths->dir);
    snprintf(paths->script, sizeof(paths->script), "%s/fake-diff", paths->dir);
    paths->saved_bin = fim_diff_exec_bins[0];
    fim_diff_exec_timeout = 10;

    *state = paths;
    return 0;
}

static int teardown(void **state) {
    exec_paths *paths = *state;
    char cmd[PATH_MAX + 16];

    fim_diff_exec_bins[0] = paths->saved_bin;
    fim_diff_exec_timeout = 10;

    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", paths->dir);
    if (system(cmd) != 0) {
        return -1;
    }

    free(paths);
    return 0;
}

static int setup_group(void **state) {
    test_mode = 0;
    return 0;
}

/* Tests */

void test_fim_diff_exec_same(void **state) {
    exec_paths *paths = *state;

    write_file(paths->old_file, "a\nb\n");
    write_file(paths->new_file, "a\nb\n");

    assert_int_equal(fim_diff_exec(paths->old_file, paths->new_file, paths->out_file), FIM_DIFF_EXEC_SAME);
    assert_int_equal(file_size(paths->out_file), 0);
}

void test_fim_diff_exec_diff(void **state) {
    exec_paths *paths = *state;
    char buffer[OS_SIZE_256] = {0};

    write_file(paths->old_file, "a\nb\n");
    write_file(paths->new_file, "a\nc\n");

    assert_int_equal(fim_diff_exec(paths->old_file, paths->new_file, paths->out_file), FIM_DIFF_EXEC_DIFF);

    FILE *fp = fopen(paths->out_file, "r");
    assert_non_null(fp);
    assert_true(fread(buffer, 1, sizeof(buffer) - 1, fp) > 0);
    fclose(fp);
    assert_string_equal(buffer, "2c2\n< b\n---\n> c\n");

    // The stderr file is removed
    char err_file[160];
    snprintf(err_file, sizeof(err_file), "%s-err", paths->out_file);
    assert_int_equal(file_size(err_file), -1);
}

void test_fim_diff_exec_output_cut(void **state) {
    exec_paths *paths = *state;
    FILE *old_fp = fopen(paths->old_file, "w");
    FILE *new_fp = fopen(paths->new_file, "w");

    assert_non_null(old_fp);
    assert_non_null(new_fp);

    // Every line differs, so the output is about twice the input
    for (int i = 0; i < 20000; i++) {
        fprintf(old_fp, "old-%d\n", i);
        fprintf(new_fp, "new-%d\n", i);
    }
    fclose(old_fp);
    fclose(new_fp);

    assert_int_equal(fim_diff_exec(paths->old_file, paths->new_file, paths->out_file), FIM_DIFF_EXEC_DIFF);

    long size = file_size(paths->out_file);
    assert_true(size > OS_MAXSTR - OS_SK_HEADER);
    assert_true(size <= OS_MAXSTR);
}

void test_fim_diff_exec_timeout(void **state) {
    exec_paths *paths = *state;

    write_file(paths->old_file, "a\n");
    write_file(paths->new_file, "b\n");
    use_script(paths, "sleep 30");
    fim_diff_exec_timeout = 1;

    time_t start = time(NULL);
    assert_int_equal(fim_diff_exec(paths->old_file, paths->new_file, paths->out_file), FIM_DIFF_EXEC_TIMEOUT);
    assert_true(time(NULL) - start < 10);
}

void test_fim_diff_exec_out_of_memory(void **state) {
    exec_paths *paths = *state;

    write_file(paths->old_file, "a\n");
    write_file(paths->new_file, "b\n");
    use_script(paths, "echo 'diff: memory exhausted' >&2; exit 2");

    assert_int_equal(fim_diff_exec(paths->old_file, paths->new_file, paths->out_file), FIM_DIFF_EXEC_MEMORY);
}

void test_fim_diff_exec_killed_by_memory_signal(void **state) {
    exec_paths *paths = *state;

    write_file(paths->old_file, "a\n");
    write_file(paths->new_file, "b\n");
    use_script(paths, "kill -SEGV $$");

    assert_int_equal(fim_diff_exec(paths->old_file, paths->new_file, paths->out_file), FIM_DIFF_EXEC_MEMORY);
}

void test_fim_diff_exec_error(void **state) {
    exec_paths *paths = *state;

    write_file(paths->old_file, "a\n");
    write_file(paths->new_file, "b\n");
    use_script(paths, "echo 'diff: something else' >&2; exit 2");

    assert_int_equal(fim_diff_exec(paths->old_file, paths->new_file, paths->out_file), FIM_DIFF_EXEC_ERROR);
}

void test_fim_diff_exec_limits_applied(void **state) {
    exec_paths *paths = *state;
    char body[OS_SIZE_1024];
    char limits_file[128];
    char buffer[OS_SIZE_256] = {0};

    snprintf(limits_file, sizeof(limits_file), "%s/limits", paths->dir);
    snprintf(body, sizeof(body), "ulimit -f > '%s'; ulimit -v >> '%s'; ulimit -t >> '%s'; ulimit -c >> '%s'; echo \"$LC_ALL\" >> '%s'; exit 1",
             limits_file, limits_file, limits_file, limits_file, limits_file);

    write_file(paths->old_file, "a\n");
    write_file(paths->new_file, "b\n");
    use_script(paths, body);

    assert_int_equal(fim_diff_exec(paths->old_file, paths->new_file, paths->out_file), FIM_DIFF_EXEC_DIFF);

    FILE *fp = fopen(limits_file, "r");
    assert_non_null(fp);
    assert_true(fread(buffer, 1, sizeof(buffer) - 1, fp) > 0);
    fclose(fp);

    // ulimit reports the file size in 512-byte blocks and the address space in KiB
    char expected[OS_SIZE_256];
    snprintf(expected, sizeof(expected), "%d\n%d\n10\n0\nC\n", OS_MAXSTR / 512, 512 * 1024);
    assert_string_equal(buffer, expected);
}

void test_fim_diff_exec_output_exists(void **state) {
    exec_paths *paths = *state;

    write_file(paths->old_file, "a\n");
    write_file(paths->new_file, "b\n");
    write_file(paths->out_file, "");

    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(fim_diff_exec(paths->old_file, paths->new_file, paths->out_file), FIM_DIFF_EXEC_ERROR);
}

void test_fim_diff_exec_output_symlink(void **state) {
    exec_paths *paths = *state;
    char target[128];

    write_file(paths->old_file, "a\n");
    write_file(paths->new_file, "b\n");
    snprintf(target, sizeof(target), "%s/target", paths->dir);
    assert_int_equal(symlink(target, paths->out_file), 0);

    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(fim_diff_exec(paths->old_file, paths->new_file, paths->out_file), FIM_DIFF_EXEC_ERROR);
    assert_int_equal(file_size(target), -1);
}

void test_fim_diff_exec_not_found(void **state) {
    exec_paths *paths = *state;
    const char *saved = fim_diff_exec_bins[1];

    fim_diff_exec_bins[0] = "/nonexistent/diff";
    fim_diff_exec_bins[1] = NULL;

    expect_string(__wrap__merror, formatted_msg, "(6721): Could not find the command to compute report_changes diffs.");

    fim_diff_exec_rc rc = fim_diff_exec(paths->old_file, paths->new_file, paths->out_file);

    fim_diff_exec_bins[1] = saved;
    assert_int_equal(rc, FIM_DIFF_EXEC_ERROR);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_fim_diff_exec_same, setup, teardown),
        cmocka_unit_test_setup_teardown(test_fim_diff_exec_diff, setup, teardown),
        cmocka_unit_test_setup_teardown(test_fim_diff_exec_output_cut, setup, teardown),
        cmocka_unit_test_setup_teardown(test_fim_diff_exec_timeout, setup, teardown),
        cmocka_unit_test_setup_teardown(test_fim_diff_exec_out_of_memory, setup, teardown),
        cmocka_unit_test_setup_teardown(test_fim_diff_exec_killed_by_memory_signal, setup, teardown),
        cmocka_unit_test_setup_teardown(test_fim_diff_exec_error, setup, teardown),
        cmocka_unit_test_setup_teardown(test_fim_diff_exec_limits_applied, setup, teardown),
        cmocka_unit_test_setup_teardown(test_fim_diff_exec_output_exists, setup, teardown),
        cmocka_unit_test_setup_teardown(test_fim_diff_exec_output_symlink, setup, teardown),
        cmocka_unit_test_setup_teardown(test_fim_diff_exec_not_found, setup, teardown),
    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}
