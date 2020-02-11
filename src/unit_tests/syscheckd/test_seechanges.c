/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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
#include <string.h>

#include "../syscheckd/syscheck.h"
#include "../config/syscheck-config.h"

#ifdef TEST_AGENT
char *_read_file(const char *high_name, const char *low_name, const char *defines_file) __attribute__((nonnull(3)));
#endif

/* redefinitons/wrapping */

#ifdef TEST_AGENT
int __wrap_getDefine_Int(const char *high_name, const char *low_name, int min, int max) {
    int ret;
    char *value;
    char *pt;

    /* Try to read from the local define file */
    value = _read_file(high_name, low_name, "./internal_options.conf");
    if (!value) {
        merror_exit(DEF_NOT_FOUND, high_name, low_name);
    }

    pt = value;
    while (*pt != '\0') {
        if (!isdigit((int)*pt)) {
            merror_exit(INV_DEF, high_name, low_name, value);
        }
        pt++;
    }

    ret = atoi(value);
    if ((ret < min) || (ret > max)) {
        merror_exit(INV_DEF, high_name, low_name, value);
    }

    /* Clear memory */
    free(value);

    return (ret);
}

int __wrap_isChroot() {
    return 1;
}
#endif

/* setups/teardowns */
static int setup_group(void **state) {
    Read_Syscheck_Config("test_syscheck.conf");

    return 0;
}

/* tests */

void test_is_nodiff_true(void **state) {
    int ret;

    const char * file_name = "/etc/ssl/private.key";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 1);
}


void test_is_nodiff_false(void **state) {
    int ret;

    const char * file_name = "/dummy_file.key";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 0);
}


void test_is_nodiff_regex_true(void **state) {
    int ret;

    const char * file_name = "file.test";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 1);
}


void test_is_nodiff_regex_false(void **state) {
    int ret;

    const char * file_name = "test.file";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 0);
}


void test_is_nodiff_no_nodiff(void **state) {
    int ret;

    syscheck.nodiff = NULL;
    syscheck.nodiff_regex = NULL;

    const char * file_name = "test.file";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 0);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_is_nodiff_true),
        cmocka_unit_test(test_is_nodiff_false),
        cmocka_unit_test(test_is_nodiff_regex_true),
        cmocka_unit_test(test_is_nodiff_regex_false),
        cmocka_unit_test(test_is_nodiff_no_nodiff),
    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}
