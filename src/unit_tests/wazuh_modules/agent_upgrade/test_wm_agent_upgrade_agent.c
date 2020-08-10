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

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/agent_upgrade/agent/wm_agent_upgrade_agent.h"
#include "../../headers/shared.h"

void test_test(void **state)
{
    assert_int_equal(1, 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_test)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
