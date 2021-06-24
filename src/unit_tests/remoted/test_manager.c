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

#include "../../remoted/remoted.h"
#include "../../headers/shared.h"

#include "../../remoted/manager.c"

/* Forward declarations */
void save_controlmsg(const keyentry * key, char *r_msg, size_t msg_length, int *wdb_sock);

/* setup/teardown */

static int setup_remoted(void **state) {
    return OS_SUCCESS;
}

static int teardown_remoted(void **state) {
    return OS_SUCCESS;
}

/* tests */

/* Tests save_controlmsg*/

void test_save_controlmsg(void **state)
{
    assert_int_equal(OS_SUCCESS, 0);
}

void test_lookfor_agent_group_null_groups(void **state)
{
    const char *agent_id = "001";
    char *msg = "Linux |localhost.localdomain |4.18.0-240.22.1.el8_3.x86_64 |#1 SMP Thu Apr 8 19:01:30 UTC 2021 |x86_64 [CentOS Linux|centos: 8.3] - Wazuh v4.2.0 / ab73af41699f13fdd81903b5f23d8d00\nc2305e0ac17e7176e924294c69cc7a24 merged.mg\n#\"_agent_ip\":10.0.2.4";
    char *r_group = NULL;

    expect_string(__wrap__mdebug2, formatted_msg, "Nothing to share with agent");

    int ret = lookfor_agent_group(agent_id, msg, &r_group);
    assert_int_equal(OS_INVALID, ret);
    assert_null(r_group);
}

void test_lookfor_agent_group_group_not_found(void **state)
{
    const char *agent_id = "001";
    char *msg = "Linux |localhost.localdomain |4.18.0-240.22.1.el8_3.x86_64 |#1 SMP Thu Apr 8 19:01:30 UTC 2021 |x86_64 [CentOS Linux|centos: 8.3] - Wazuh v4.2.0 / ab73af41699f13fdd81903b5f23d8d00\nc2305e0ac17e7176e924294c69cc7a24 merged.mg\n#\"_agent_ip\":10.0.2.4";
    char *r_group = NULL;

    static group_t *test_groups;
    // groups is a manager.c global variable
    groups = &test_groups;

    expect_string(__wrap__mdebug2, formatted_msg, "queue/agent-groups/001' not found.");
    expect_string(__wrap__mdebug2, formatted_msg, "Agent '001' group is ''");

    int ret = lookfor_agent_group(agent_id, msg, &r_group);
    assert_int_equal(OS_INVALID, ret);
    assert_null(r_group);

    groups = NULL;
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests save_controlmsg
        cmocka_unit_test(test_save_controlmsg),
        cmocka_unit_test_setup_teardown(test_lookfor_agent_group_null_groups, setup_remoted, teardown_remoted),
        cmocka_unit_test_setup_teardown(test_lookfor_agent_group_group_not_found, setup_remoted, teardown_remoted),
        };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
