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

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/agent_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_global_helpers_wrappers.h"

#include "../remoted/remoted.h"
#include "../remoted/shared_download.h"

/* tests */

int lookfor_agent_group(const char *agent_id, char *msg, char **r_group, int* wdb_sock);

/* Tests lookfor_agent_group */
void test_lookfor_agent_group_null_groups()
{
    const int agent_id = 1;
    const char agent_id_str[] = "001";
    char *msg = "Linux |localhost.localdomain |4.18.0-240.22.1.el8_3.x86_64 |#1 SMP Thu Apr 8 19:01:30 UTC 2021 |x86_64 [CentOS Linux|centos: 8.3] - Wazuh v4.2.0 / ab73af41699f13fdd81903b5f23d8d00\nc2305e0ac17e7176e924294c69cc7a24 merged.mg\n#\"_agent_ip\":10.0.2.4";
    char *r_group = NULL;

    expect_value(__wrap_get_agent_group, id, agent_id);
    will_return(__wrap_get_agent_group, "");
    will_return(__wrap_get_agent_group, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '001' group is ''");
    expect_string(__wrap__mdebug2, formatted_msg, "Agent '001' with group '' file 'merged.mg' MD5 'c2305e0ac17e7176e924294c69cc7a24'");

    will_return(__wrap_w_is_worker, 0);

    expect_value(__wrap_wdb_set_agent_groups_csv, id, agent_id);
    will_return(__wrap_wdb_set_agent_groups_csv, 0);

    int ret = lookfor_agent_group(agent_id_str, msg, &r_group, NULL);
    assert_int_equal(OS_SUCCESS, ret);
    assert_string_equal(r_group, "default");

    os_free(r_group);
}

void test_lookfor_agent_group_set_default_group()
{
    const int agent_id = 1;
    const char agent_id_str[] = "001";
    char *msg = "Linux |localhost.localdomain |4.18.0-240.22.1.el8_3.x86_64 |#1 SMP Thu Apr 8 19:01:30 UTC 2021 |x86_64 [CentOS Linux|centos: 8.3] - Wazuh v4.2.0 / ab73af41699f13fdd81903b5f23d8d00\nc2305e0ac17e7176e924294c69cc7a24 merged.mg\n#\"_agent_ip\":10.0.2.4";
    char *r_group = NULL;

    expect_value(__wrap_get_agent_group, id, agent_id);
    will_return(__wrap_get_agent_group, "");
    will_return(__wrap_get_agent_group, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '001' group is ''");
    expect_string(__wrap__mdebug2, formatted_msg, "Agent '001' with group '' file 'merged.mg' MD5 'c2305e0ac17e7176e924294c69cc7a24'");

    will_return(__wrap_w_is_worker, 0);

    expect_value(__wrap_wdb_set_agent_groups_csv, id, agent_id);
    will_return(__wrap_wdb_set_agent_groups_csv, 0);

    int ret = lookfor_agent_group(agent_id_str, msg, &r_group, NULL);
    assert_int_equal(OS_SUCCESS, ret);
    assert_string_equal(r_group, "default");

    os_free(r_group);
}

void test_lookfor_agent_group_msg_without_enter()
{
    const int agent_id = 2;
    const char agent_id_str[] = "002";
    char *msg = "Linux |localhost.localdomain |4.18.0-240.22.1.el8_3.x86_64 |#1 SMP Thu Apr 8 19:01:30 UTC 2021 |x86_64 [CentOS Linux|centos: 8.3] - Wazuh v4.2.0 / ab73af41699f13fdd81903b5f23d8d00c2305e0ac17e7176e924294c69cc7a24 merged.mg";
    char *r_group = NULL;

    expect_value(__wrap_get_agent_group, id, agent_id);
    will_return(__wrap_get_agent_group, "");
    will_return(__wrap_get_agent_group, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '002' group is ''");

    expect_string(__wrap__merror, formatted_msg, "Invalid message from agent ID '002' (strchr \\n)");

    int ret = lookfor_agent_group(agent_id_str, msg, &r_group, NULL);
    assert_int_equal(OS_INVALID, ret);
    assert_null(r_group);
}

void test_lookfor_agent_group_bad_message()
{
    const int agent_id = 3;
    const char agent_id_str[] = "003";
    char *msg = "Linux |localhost.localdomain\n#c2305e0ac17e7176e924294c69cc7a24 merged.mg\nc2305e0ac17e7176e924294c69cc7a24merged.mg\n#\"_agent_ip\":10.0.2.4";
    char *r_group = NULL;

    expect_value(__wrap_get_agent_group, id, agent_id);
    will_return(__wrap_get_agent_group, "");
    will_return(__wrap_get_agent_group, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '003' group is ''");

    expect_string(__wrap__merror, formatted_msg, "Invalid message from agent ID '003' (strchr ' ')");

    int ret = lookfor_agent_group(agent_id_str, msg, &r_group, NULL);
    assert_int_equal(OS_INVALID, ret);
    assert_null(r_group);
}

void test_lookfor_agent_group_message_without_second_enter()
{
    const int agent_id = 4;
    const char agent_id_str[] = "004";
    char *msg = "Linux |localhost.localdomain \n#\"_agent_ip\":10.0.2.4";
    char *r_group = NULL;

    expect_value(__wrap_get_agent_group, id, agent_id);
    will_return(__wrap_get_agent_group, "");
    will_return(__wrap_get_agent_group, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent '004' group is ''");

    expect_string(__wrap__merror, formatted_msg, "Invalid message from agent ID '004' (strchr \\n)");

    int ret = lookfor_agent_group(agent_id_str, msg, &r_group, NULL);
    assert_int_equal(OS_INVALID, ret);
    assert_null(r_group);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests lookfor_agent_group
        cmocka_unit_test(test_lookfor_agent_group_null_groups),
        cmocka_unit_test(test_lookfor_agent_group_set_default_group),
        cmocka_unit_test(test_lookfor_agent_group_msg_without_enter),
        cmocka_unit_test(test_lookfor_agent_group_bad_message),
        cmocka_unit_test(test_lookfor_agent_group_message_without_second_enter),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
