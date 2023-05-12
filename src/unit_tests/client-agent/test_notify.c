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

#include "../client-agent/agentd.h"

#define DUMMY_VALID_SOCKET_FD 1
static agent global_config = { .sock = DUMMY_VALID_SOCKET_FD };

static int setup_group(void **state) {
    agt = &global_config;

    return 0;
}

#ifdef TEST_AGENT
// get_agent_ip
static void get_agent_ip_fail_to_connect(void **state) {
    char *retval;

    will_return(__wrap_getsockname, -1);
    will_return(__wrap_getsockname, AF_UNSPEC);

    retval = get_agent_ip();

    assert_string_equal(retval, "");

    free(retval);
}

static void get_agent_ip_invalid_socket(void **state) {
    char *retval;

    // force bad socket id
    agt->sock = 0;
    retval = get_agent_ip();

    assert_string_equal(retval, "");

    free(retval);

    // reset good socket id
    agt->sock = DUMMY_VALID_SOCKET_FD;
}

static void get_agent_ip_ipv4_updated_successfully(void **state) {
    char *retval;
    static const char* const IPV4_ADDRESS = "10.1.2.3";

    expect_any(__wrap_get_ipv4_string, address_size);
    will_return(__wrap_get_ipv4_string, OS_SUCCESS);
    will_return(__wrap_get_ipv4_string, IPV4_ADDRESS);

    will_return(__wrap_getsockname, 0);
    will_return(__wrap_getsockname, AF_INET);

    retval = get_agent_ip();

    assert_string_equal(retval, IPV4_ADDRESS);

    free(retval);
}

static void get_agent_ip_ipv6_updated_successfully(void **state) {
    char *retval;
    static const char* const IPV6_ADDRESS = "2001:0db8:3c4d:0015:0000:0000:1a2f:1a2b";

    expect_any(__wrap_get_ipv6_string, address_size);
    will_return(__wrap_get_ipv6_string, OS_SUCCESS);
    will_return(__wrap_get_ipv6_string, IPV6_ADDRESS);

    will_return(__wrap_getsockname, 0);
    will_return(__wrap_getsockname, AF_INET6);

    retval = get_agent_ip();

    assert_string_equal(retval, IPV6_ADDRESS);

    free(retval);
}

#endif // TEST_AGENT

int main(void) {
    const struct CMUnitTest tests[] = {
#ifdef TEST_AGENT
        cmocka_unit_test(get_agent_ip_fail_to_connect),
        cmocka_unit_test(get_agent_ip_invalid_socket),
        cmocka_unit_test(get_agent_ip_ipv4_updated_successfully),
        cmocka_unit_test(get_agent_ip_ipv6_updated_successfully)
#endif // TEST_AGENT
    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}
