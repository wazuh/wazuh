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
#include "../wrappers/wazuh/client-agent/notify_wrappers.h"

extern int g_ip_update_interval;
int log_builder_update_host_ip(log_builder_t * builder);

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

void test_log_builder_update(void **state)
{
    will_return(__wrap_getDefine_Int, 1);
    log_builder_t * builder = log_builder_init(false);
    assert_int_equal(g_ip_update_interval, 1);
    assert_non_null(builder);

#ifdef WIN32
    char * return_ip = "1.2.3.4";
    time_mock_value = 1000;
    will_return(wrap_get_agent_ip_legacy_win32, strdup(return_ip));
#elif defined __linux__ || defined __MACH__ || defined sun || defined FreeBSD || defined OpenBSD
    will_return(__wrap_control_check_connection, 16);
    will_return(__wrap_send, 7);
    will_return(__wrap_recv, 0);
#endif

    int r = log_builder_update_host_ip(builder);
    assert_int_equal(r, 0);
#ifdef WIN32
    assert_string_equal(builder->host_ip, "1.2.3.4");
#endif
    log_builder_destroy(builder);
}

void test_log_builder_not_update(void **state) {
    will_return(__wrap_getDefine_Int, 0);

    log_builder_t * builder = log_builder_init(false);
    assert_int_equal(g_ip_update_interval, 0);
    assert_non_null(builder);

    int r = log_builder_update_host_ip(builder);
    assert_int_equal(r, 0);

    log_builder_destroy(builder);
}

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_log_builder),
            cmocka_unit_test(test_log_builder_update),
            cmocka_unit_test(test_log_builder_not_update),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
