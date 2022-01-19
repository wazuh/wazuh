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
#include <errno.h>
#include <string.h>

#include "../../headers/shared.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"

/* setup/teardown */

static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}

// set_agent_group

static void test_set_agent_group_success(void ** state) {
    const char PATH[] = "queue/agent-groups/001";

    expect_value(__wrap_umask, mode, 0006);
    will_return(__wrap_umask, 0);

    FILE * fp = (FILE *)1;
    expect_fopen(PATH, "w", fp);

    expect_value(__wrap_umask, mode, 0);
    will_return(__wrap_umask, 0006);

    expect_value(__wrap_fileno, __stream, fp);
    will_return(__wrap_fileno, 1);

    expect_value(__wrap_fchmod, fd, 1);
    expect_value(__wrap_fchmod, mode, 0660);
    will_return(__wrap_fchmod, 0);

    expect_fprintf(fp, "default\n", 0);
    expect_fclose(fp, 0);

    int r = set_agent_group("001", "default");
    assert_int_equal(r, 0);
}

static void test_set_agent_group_open_error(void ** state) {
    const char PATH[] = "queue/agent-groups/001";

    expect_value(__wrap_umask, mode, 0006);
    will_return(__wrap_umask, 0);

    expect_fopen(PATH, "w", NULL);

    expect_value(__wrap_umask, mode, 0);
    will_return(__wrap_umask, 0006);

    expect_string(__wrap__merror, formatted_msg, "At set_agent_group(): open(queue/agent-groups/001): Permission denied");

    errno = EACCES;
    int r = set_agent_group("001", "default");
    assert_int_equal(r, -1);
}

static void test_set_agent_group_chmod_error(void ** state) {
    const char PATH[] = "queue/agent-groups/001";

    expect_value(__wrap_umask, mode, 0006);
    will_return(__wrap_umask, 0);

    FILE * fp = (FILE *)1;
    expect_fopen(PATH, "w", fp);

    expect_value(__wrap_umask, mode, 0);
    will_return(__wrap_umask, 0006);

    expect_value(__wrap_fileno, __stream, fp);
    will_return(__wrap_fileno, 1);

    expect_value(__wrap_fchmod, fd, 1);
    expect_value(__wrap_fchmod, mode, 0660);
    will_return(__wrap_fchmod, -1);

    expect_fprintf(fp, "default\n", 0);
    expect_fclose(fp, 0);

    expect_string(__wrap__merror, formatted_msg, "(1127): Could not chmod object 'queue/agent-groups/001' due to [(13)-(Permission denied)].");

    errno = EACCES;
    int r = set_agent_group("001", "default");
    assert_int_equal(r, 0);
}

static void test_set_agent_group_write_error(void ** state) {
    const char PATH[] = "queue/agent-groups/001";

    expect_value(__wrap_umask, mode, 0006);
    will_return(__wrap_umask, 0);

    FILE * fp = (FILE *)1;
    expect_fopen(PATH, "w", fp);

    expect_value(__wrap_umask, mode, 0);
    will_return(__wrap_umask, 0006);

    expect_value(__wrap_fileno, __stream, fp);
    will_return(__wrap_fileno, 1);

    expect_value(__wrap_fchmod, fd, 1);
    expect_value(__wrap_fchmod, mode, 0660);
    will_return(__wrap_fchmod, 0);

    expect_fprintf(fp, "default\n", -1);
    expect_fclose(fp, 0);

    expect_string(__wrap_unlink, file, PATH);
    will_return(__wrap_unlink, 0);

    expect_string(__wrap__merror, formatted_msg, "(1110): Could not write file 'queue/agent-groups/001' due to [(28)-(No space left on device)].");

    errno = ENOSPC;
    int r = set_agent_group("001", "default");
    assert_int_equal(r, -1);
}

static void test_set_agent_group_close_error(void ** state) {
    const char PATH[] = "queue/agent-groups/001";

    expect_value(__wrap_umask, mode, 0006);
    will_return(__wrap_umask, 0);

    FILE * fp = (FILE *)1;
    expect_fopen(PATH, "w", fp);

    expect_value(__wrap_umask, mode, 0);
    will_return(__wrap_umask, 0006);

    expect_value(__wrap_fileno, __stream, fp);
    will_return(__wrap_fileno, 1);

    expect_value(__wrap_fchmod, fd, 1);
    expect_value(__wrap_fchmod, mode, 0660);
    will_return(__wrap_fchmod, 0);

    expect_fprintf(fp, "default\n", 0);
    expect_fclose(fp, -1);

    expect_string(__wrap_unlink, file, PATH);
    will_return(__wrap_unlink, 0);

    expect_string(__wrap__merror, formatted_msg, "(1140): Could not close file 'queue/agent-groups/001' due to [(28)-(No space left on device)].");

    errno = ENOSPC;
    int r = set_agent_group("001", "default");
    assert_int_equal(r, -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_set_agent_group_success),
        cmocka_unit_test(test_set_agent_group_open_error),
        cmocka_unit_test(test_set_agent_group_chmod_error),
        cmocka_unit_test(test_set_agent_group_write_error),
        cmocka_unit_test(test_set_agent_group_close_error),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
