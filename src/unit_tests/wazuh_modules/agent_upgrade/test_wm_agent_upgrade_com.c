/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#include "../../headers/shared.h"
#include "../../wrappers/wazuh/shared/file_op_wrappers.h"

extern int _jailfile(char finalpath[PATH_MAX + 1], const char * basedir, const char * filename);

int setup_jailfile(void **state) {
    char *filename = malloc(sizeof(char) * OS_MAXSTR);
    sprintf(filename, "test_filename");
    *state = filename;
    return 0;
}

int teardown_jailfile(void **state) {
    char *filename = *state;
    os_free(filename);
    return 0;
}

void test_jailfile_invalid_path(void **state) {
    char finalpath[PATH_MAX + 1];
    char *filename = *state;

    expect_string(__wrap_w_ref_parent_folder, path, filename);
    will_return(__wrap_w_ref_parent_folder, 1);
    int ret = _jailfile(finalpath, TMP_DIR, filename);
    assert_int_equal(ret, -1);
}

void test_jailfile_valid_path(void **state) {
    char finalpath[PATH_MAX + 1];
    char *filename = *state;

    expect_string(__wrap_w_ref_parent_folder, path, filename);
    will_return(__wrap_w_ref_parent_folder, 0);
    int ret = _jailfile(finalpath, TMP_DIR, filename);
    assert_int_equal(ret, 0);
#ifdef TEST_WINAGENT
    assert_string_equal(finalpath, "tmp\\test_filename");
#else
    assert_string_equal(finalpath, "/var/ossec/tmp/test_filename");
#endif
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_jailfile_invalid_path, setup_jailfile, teardown_jailfile),
        cmocka_unit_test_setup_teardown(test_jailfile_valid_path, setup_jailfile, teardown_jailfile)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
