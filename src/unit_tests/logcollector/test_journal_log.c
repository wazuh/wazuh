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
#include <time.h>

#include "../../logcollector/journal_log.h"

#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/common.h"
#include "../wrappers/externals/pcre2/pcre2_wrappers.h"

bool is_owned_by_root(const char * library_path);

/* setup/teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    w_test_pcre2_wrappers(false);
    return 0;

}

static int group_teardown(void ** state) {
    test_mode = 0;
    w_test_pcre2_wrappers(true);
    return 0;

}

void test_is_owned_by_root_root_owned(void **state) {
    (void)state;

    const char * library_path = "existent_file_root";

    struct stat mock_stat;
    mock_stat.st_uid = 0;

    // Assert
    expect_value(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    bool result = is_owned_by_root(library_path);

    assert_true(result);
}

void test_is_owned_by_root_not_root_owned(void **state) {
    (void)state;

    const char * library_path = "existent_file_no_root";

    struct stat mock_stat;
    mock_stat.st_uid = 1000;

    // Assert
    expect_value(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, 0);

    bool result = is_owned_by_root(library_path);

    assert_false(result);
}

void test_is_owned_by_root_stat_fails(void **state) {
    (void)state;

    const char * library_path = "nonexistent_file";

    struct stat mock_stat;
    mock_stat.st_uid = 1000;

    // Assert
    expect_string(__wrap_stat, __file, library_path);
    will_return(__wrap_stat, &mock_stat);
    will_return(__wrap_stat, -1);

    bool result = is_owned_by_root(library_path);

    assert_false(result);
}


int main(void) {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_is_owned_by_root_root_owned),
        cmocka_unit_test(test_is_owned_by_root_not_root_owned),
        cmocka_unit_test(test_is_owned_by_root_stat_fails),
        //cmocka_unit_test(test_w_journald_poc),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
