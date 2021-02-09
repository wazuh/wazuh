/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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

#include "remoted/remoted.h"
#include "headers/shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

int w_remoted_get_net_protocol(const char * content);


/* setup/teardown */



/* wraps */


/* tests */

// Test w_remoted_get_net_protocol
void test_w_remoted_get_net_protocol_content_NULL(void **state)
{
    const char * content = NULL;

    expect_string(__wrap__mwarn, formatted_msg, "(9000): Error getting protocol. Default value (TCP) will be used.");

    int ret = w_remoted_get_net_protocol(content);
    assert_int_equal(ret, REMOTED_PROTO_DEFAULT);

}

void test_w_remoted_get_net_protocol_content_empty(void **state)
{
    const char * content = "";

    expect_string(__wrap__mwarn, formatted_msg, "(9001): Ignored invalid value '' for 'protocol'.");

    expect_string(__wrap__mwarn, formatted_msg, "(9000): Error getting protocol. Default value (TCP) will be used.");

    int ret = w_remoted_get_net_protocol(content);
    assert_int_equal(ret, REMOTED_PROTO_DEFAULT);

}

void test_w_remoted_get_net_protocol_content_ignore_values(void **state)
{
    const char * content = "hello, world";

    expect_string(__wrap__mwarn, formatted_msg, "(9001): Ignored invalid value 'hello' for 'protocol'.");

    expect_string(__wrap__mwarn, formatted_msg, "(9001): Ignored invalid value 'world' for 'protocol'.");

    expect_string(__wrap__mwarn, formatted_msg, "(9000): Error getting protocol. Default value (TCP) will be used.");

    int ret = w_remoted_get_net_protocol(content);
    assert_int_equal(ret, REMOTED_PROTO_DEFAULT);

}

void test_w_remoted_get_net_protocol_content_tcp(void **state)
{
    const char * content = "tcp";

    int ret = w_remoted_get_net_protocol(content);
    assert_int_equal(ret, 1);

}

void test_w_remoted_get_net_protocol_content_udp(void **state)
{
    const char * content = "udp";

    int ret = w_remoted_get_net_protocol(content);
    assert_int_equal(ret, 2);

}

void test_w_remoted_get_net_protocol_content_tcp_udp(void **state)
{
    const char * content = "tcp,udp";

    int ret = w_remoted_get_net_protocol(content);
    assert_int_equal(ret, 3);

}

void test_w_remoted_get_net_protocol_content_udp_tcp(void **state)
{
    const char * content = "udp, tcp";

    int ret = w_remoted_get_net_protocol(content);
    assert_int_equal(ret, 3);

}

void test_w_remoted_get_net_protocol_content_mix(void **state)
{
    const char * content = "hello, tcp, , world, udp";

    expect_string(__wrap__mwarn, formatted_msg, "(9001): Ignored invalid value 'hello' for 'protocol'.");

    expect_string(__wrap__mwarn, formatted_msg, "(9001): Ignored invalid value '' for 'protocol'.");
    
    expect_string(__wrap__mwarn, formatted_msg, "(9001): Ignored invalid value 'world' for 'protocol'.");

    int ret = w_remoted_get_net_protocol(content);
    assert_int_equal(ret, 3);

}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests 
        cmocka_unit_test(test_w_remoted_get_net_protocol_content_NULL),
        cmocka_unit_test(test_w_remoted_get_net_protocol_content_empty),
        cmocka_unit_test(test_w_remoted_get_net_protocol_content_ignore_values),
        cmocka_unit_test(test_w_remoted_get_net_protocol_content_tcp),
        cmocka_unit_test(test_w_remoted_get_net_protocol_content_udp),
        cmocka_unit_test(test_w_remoted_get_net_protocol_content_tcp_udp),
        cmocka_unit_test(test_w_remoted_get_net_protocol_content_udp_tcp),
        cmocka_unit_test(test_w_remoted_get_net_protocol_content_mix),
        
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
