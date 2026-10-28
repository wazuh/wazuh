/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* wm_task_manager_read_json() reports a refused `global` or `remote` section with a positive answer, which
 * wm_config() passes on so that `wazuh-manager-modulesd -t` fails while the daemon itself still starts. */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <limits.h>
#include <cJSON.h>

#include "shared.h"
#include "wmodules.h"
#include "mconf-config.h"
#include "../../wrappers/common.h"

static void test_read_json_reports_unreadable_sections(void **state) {
    (void) state;
    wm_task_manager data;
    wmodule module;

    memset(&data, 0, sizeof(data));
    memset(&module, 0, sizeof(module));
    module.data = &data;

    /* Nothing loaded: neither `global` nor `remote` can be read. */
    w_mconf_free();
    expect_string(__wrap__mwarn, formatted_msg,
                  "Cannot read the global configuration; the agent disconnection sweep will use its default window.");
    expect_string(__wrap__mwarn, formatted_msg,
                  "Cannot read the remote configuration; the agent upgrade delivery checks will be skipped.");

    assert_int_equal(wm_task_manager_read_json(NULL, &module), 1);
    assert_int_equal(data.disconnection_time, 0);
    assert_int_equal(data.remoted_config_read, 0);
}

/* cJSON saturates valueint at INT_MAX: a larger value must be refused, not clamped. */
static void test_read_json_refuses_integer_above_int_max(void **state) {
    (void) state;
    wm_task_manager data;
    wmodule module;
    cJSON *section = cJSON_Parse("{\"task_ttl\": 3000000000, \"cleanup_interval\": 2147483647, "
                                 "\"max_payload_bytes\": 65536}");

    assert_non_null(section);
    memset(&data, 0, sizeof(data));
    memset(&module, 0, sizeof(module));
    module.data = &data;

    w_mconf_free();
    expect_string(__wrap__mwarn, formatted_msg,
                  "Cannot read the global configuration; the agent disconnection sweep will use its default window.");
    expect_string(__wrap__mwarn, formatted_msg,
                  "Cannot read the remote configuration; the agent upgrade delivery checks will be skipped.");
    expect_string(__wrap__merror, formatted_msg,
                  "Invalid value for element 'task_ttl': 3000000000 is out of range (0 to 2147483647); "
                  "the module default applies.");

    assert_int_equal(wm_task_manager_read_json(section, &module), 1);
    assert_int_equal(data.task_ttl, 0);
    assert_int_equal(data.cleanup_interval, INT_MAX);
    assert_int_equal(data.max_payload_bytes, 65536);

    cJSON_Delete(section);
}

static void test_read_json_without_module_reads_nothing(void **state) {
    (void) state;
    wmodule module;

    memset(&module, 0, sizeof(module));
    assert_int_equal(wm_task_manager_read_json(NULL, NULL), 0);
    assert_int_equal(wm_task_manager_read_json(NULL, &module), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_read_json_reports_unreadable_sections),
        cmocka_unit_test(test_read_json_refuses_integer_above_int_max),
        cmocka_unit_test(test_read_json_without_module_reads_nothing),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
