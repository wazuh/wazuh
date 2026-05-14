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

#include "../../config/client-config.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"

/* tests */

/* Validate_IPv6_Link_Local_Interface */

void test_Validate_IPv6_Link_Local_Interface_ipv4(void ** state) {
    agent_server *servers = NULL;

    os_calloc(2, sizeof(agent_server), servers);
    os_strdup("192.168.0.11", servers[0].rip);
    servers[1].rip = NULL;

    expect_string(__wrap_OS_GetHost, host, servers[0].rip);
    will_return(__wrap_OS_GetHost, strdup(servers[0].rip));

    bool retval = Validate_IPv6_Link_Local_Interface(servers);

    assert_true(retval);

    os_free(servers[0].rip);
    os_free(servers);
}

void test_Validate_IPv6_Link_Local_Interface_ipv6_no_link_local(void ** state) {
    agent_server *servers = NULL;

    os_calloc(2, sizeof(agent_server), servers);
    os_strdup("ABCD::ABCD", servers[0].rip);
    servers[1].rip = NULL;

    expect_string(__wrap_OS_GetHost, host, servers[0].rip);
    will_return(__wrap_OS_GetHost, strdup(servers[0].rip));

    bool retval = Validate_IPv6_Link_Local_Interface(servers);

    assert_true(retval);

    os_free(servers[0].rip);
    os_free(servers);
}

void test_Validate_IPv6_Link_Local_Interface_ipv6_one_link_local_no_interface(void ** state) {
    agent_server *servers = NULL;

    os_calloc(2, sizeof(agent_server), servers);
    os_strdup("FE80:0000:0000:0000::ABCD", servers[0].rip);

    expect_string(__wrap_OS_GetHost, host, servers[0].rip);
    will_return(__wrap_OS_GetHost, strdup(servers[0].rip));

    expect_string(__wrap__mwarn, formatted_msg, "No network interface index provided to use FE80:0000:0000:0000::ABCD link-local IPv6 address.");

    bool retval = Validate_IPv6_Link_Local_Interface(servers);

    assert_false(retval);

    os_free(servers[0].rip);
    os_free(servers);
}

void test_Validate_IPv6_Link_Local_Interface_ipv6_one_link_local_with_interface(void ** state) {
    agent_server *servers = NULL;

    os_calloc(2, sizeof(agent_server), servers);
    os_strdup("FE80:0000:0000:0000::ABCD", servers[0].rip);
    servers[0].network_interface = 1;

    expect_string(__wrap_OS_GetHost, host, servers[0].rip);
    will_return(__wrap_OS_GetHost, strdup(servers[0].rip));

    bool retval = Validate_IPv6_Link_Local_Interface(servers);

    assert_true(retval);

    os_free(servers[0].rip);
    os_free(servers);
}

void test_Validate_IPv6_Link_Local_Interface_multi_ipv4(void ** state) {
    agent_server *servers = NULL;

    os_calloc(3, sizeof(agent_server), servers);
    os_strdup("192.168.0.10", servers[0].rip);
    os_strdup("192.168.0.20", servers[1].rip);
    servers[2].rip = NULL;

    expect_string(__wrap_OS_GetHost, host, servers[0].rip);
    will_return(__wrap_OS_GetHost, strdup(servers[0].rip));

    expect_string(__wrap_OS_GetHost, host, servers[1].rip);
    will_return(__wrap_OS_GetHost, strdup(servers[1].rip));

    bool retval = Validate_IPv6_Link_Local_Interface(servers);

    assert_true(retval);

    os_free(servers[0].rip);
    os_free(servers[1].rip);
    os_free(servers);
}

void test_Validate_IPv6_Link_Local_Interface_multi_ipv4_ipv6(void ** state) {
    agent_server *servers = NULL;

    os_calloc(3, sizeof(agent_server), servers);
    os_strdup("192.168.0.10", servers[0].rip);
    os_strdup("FE80:0000:0000:0000::ABCD", servers[1].rip);
    servers[2].rip = NULL;

    expect_string(__wrap_OS_GetHost, host, servers[0].rip);
    will_return(__wrap_OS_GetHost, strdup(servers[0].rip));

    expect_string(__wrap_OS_GetHost, host, servers[1].rip);
    will_return(__wrap_OS_GetHost, strdup(servers[1].rip));

    expect_string(__wrap__mwarn, formatted_msg, "No network interface index provided to use FE80:0000:0000:0000::ABCD link-local IPv6 address.");

    bool retval = Validate_IPv6_Link_Local_Interface(servers);

    assert_true(retval);

    os_free(servers[0].rip);
    os_free(servers[1].rip);
    os_free(servers);
}

void test_Validate_IPv6_Link_Local_Interface_multi_ipv6_ipv4(void ** state) {
    agent_server *servers = NULL;

    os_calloc(3, sizeof(agent_server), servers);
    os_strdup("FE80:0000:0000:0000::ABCD", servers[0].rip);
    os_strdup("192.168.0.10", servers[1].rip);
    servers[2].rip = NULL;

    expect_string(__wrap_OS_GetHost, host, servers[0].rip);
    will_return(__wrap_OS_GetHost, strdup(servers[0].rip));

    expect_string(__wrap_OS_GetHost, host, servers[1].rip);
    will_return(__wrap_OS_GetHost, strdup(servers[1].rip));

    expect_string(__wrap__mwarn, formatted_msg, "No network interface index provided to use FE80:0000:0000:0000::ABCD link-local IPv6 address.");

    bool retval = Validate_IPv6_Link_Local_Interface(servers);

    assert_true(retval);

    os_free(servers[0].rip);
    os_free(servers[1].rip);
    os_free(servers);
}

void test_Validate_IPv6_Link_Local_Interface_multi_ipv6_ipv6_no_interface(void ** state) {
    agent_server *servers = NULL;

    os_calloc(3, sizeof(agent_server), servers);
    os_strdup("FE80:0000:0000:0000::ABCD", servers[0].rip);
    os_strdup("FE80:0000:0000:0000::EF11", servers[1].rip);
    servers[2].rip = NULL;

    expect_string(__wrap_OS_GetHost, host, servers[0].rip);
    will_return(__wrap_OS_GetHost, strdup(servers[0].rip));

    expect_string(__wrap_OS_GetHost, host, servers[1].rip);
    will_return(__wrap_OS_GetHost, strdup(servers[1].rip));

    expect_string(__wrap__mwarn, formatted_msg, "No network interface index provided to use FE80:0000:0000:0000::ABCD link-local IPv6 address.");
    expect_string(__wrap__mwarn, formatted_msg, "No network interface index provided to use FE80:0000:0000:0000::EF11 link-local IPv6 address.");

    bool retval = Validate_IPv6_Link_Local_Interface(servers);

    assert_false(retval);

    os_free(servers[0].rip);
    os_free(servers[1].rip);
    os_free(servers);
}

void test_Validate_IPv6_Link_Local_Interface_multi_ipv6_ipv6_interface(void ** state) {
    agent_server *servers = NULL;

    os_calloc(3, sizeof(agent_server), servers);
    os_strdup("FE80:0000:0000:0000::ABCD", servers[0].rip);
    os_strdup("FE80:0000:0000:0000::ABCD", servers[1].rip);
    servers[2].rip = NULL;
    servers[1].network_interface = 1;

    expect_string(__wrap_OS_GetHost, host, servers[0].rip);
    will_return(__wrap_OS_GetHost, strdup(servers[0].rip));

    expect_string(__wrap_OS_GetHost, host, servers[1].rip);
    will_return(__wrap_OS_GetHost, strdup(servers[1].rip));

    expect_string(__wrap__mwarn, formatted_msg, "No network interface index provided to use FE80:0000:0000:0000::ABCD link-local IPv6 address.");

    bool retval = Validate_IPv6_Link_Local_Interface(servers);

    assert_true(retval);

    os_free(servers[0].rip);
    os_free(servers[1].rip);
    os_free(servers);
}

void test_Validate_IPv6_Link_Local_Interface_multi_ipv6_ipv6_all_interface(void ** state) {
    agent_server *servers = NULL;

    os_calloc(3, sizeof(agent_server), servers);
    os_strdup("FE80:0000:0000:0000::ABCD", servers[0].rip);
    servers[0].network_interface = 2;
    os_strdup("FE80:0000:0000:0000::ABCD", servers[1].rip);
    servers[1].network_interface = 1;
    servers[2].rip = NULL;

    expect_string(__wrap_OS_GetHost, host, servers[0].rip);
    will_return(__wrap_OS_GetHost, strdup(servers[0].rip));
    expect_string(__wrap_OS_GetHost, host, servers[0].rip);
    will_return(__wrap_OS_GetHost, strdup(servers[0].rip));

    bool retval = Validate_IPv6_Link_Local_Interface(servers);

    assert_true(retval);

    os_free(servers[0].rip);
    os_free(servers[1].rip);
    os_free(servers);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Tests w_agentd_get_buffer_lenght
        cmocka_unit_test(test_Validate_IPv6_Link_Local_Interface_ipv4),
        cmocka_unit_test(test_Validate_IPv6_Link_Local_Interface_ipv6_no_link_local),
        cmocka_unit_test(test_Validate_IPv6_Link_Local_Interface_ipv6_one_link_local_no_interface),
        cmocka_unit_test(test_Validate_IPv6_Link_Local_Interface_ipv6_one_link_local_with_interface),
        cmocka_unit_test(test_Validate_IPv6_Link_Local_Interface_multi_ipv4),
        cmocka_unit_test(test_Validate_IPv6_Link_Local_Interface_multi_ipv4_ipv6),
        cmocka_unit_test(test_Validate_IPv6_Link_Local_Interface_multi_ipv6_ipv4),
        cmocka_unit_test(test_Validate_IPv6_Link_Local_Interface_multi_ipv6_ipv6_no_interface),
        cmocka_unit_test(test_Validate_IPv6_Link_Local_Interface_multi_ipv6_ipv6_interface),
        cmocka_unit_test(test_Validate_IPv6_Link_Local_Interface_multi_ipv6_ipv6_all_interface),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
