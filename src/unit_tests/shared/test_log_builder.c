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

#include "../../headers/shared.h"
#include "../wrappers/common.h"

// Tests

void test_log_builder(void **state)
{
    const char * PATTERN = "location: $(location), log: $(log), escaped: $(json_escaped_log)";
    const char * LOG = "Hello \"World\"";
    const char * LOCATION = "test";
    const char * EXPECTED_OUTPUT = "location: test, log: Hello \"World\", escaped: Hello \\\"World\\\"";

    will_return(__wrap_getDefine_Int, 60);

    int retval = 1;
    log_builder_t * builder = log_builder_init(false);

    char * output = log_builder_build(builder, PATTERN, LOG, LOCATION);

    assert_string_equal(output, EXPECTED_OUTPUT);

    free(output);
    log_builder_destroy(builder);
}

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_log_builder),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
