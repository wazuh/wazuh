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
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

#define DUMMY_VALID_SOCKET_FD 1

static int setup(void **state) {
    static agent global_config;
    agt = &global_config;
    // force init value on every call
    agt->sock = DUMMY_VALID_SOCKET_FD;
    errno = 0;
    return 0;
}

#ifdef TEST_AGENT
// get_agent_ip
static void get_agent_ip_fail_to_connect(void **state) {
    char *retval;

    will_return(__wrap_getsockname, -1);
    will_return(__wrap_getsockname, AF_UNSPEC);

    errno = ENOTSOCK;
    expect_string(__wrap__mdebug2, formatted_msg, "getsockname() failed: Socket operation on non-socket");

    retval = get_agent_ip();

    assert_string_equal(retval, "");

    free(retval);
}

static void get_agent_ip_invalid_socket(void **state) {
    char *retval;

    // force bad socket id
    agt->sock = 0;
    errno = EBADF;
    expect_string(__wrap__mdebug2, formatted_msg, "getsockname() failed: Bad file descriptor");

    retval = get_agent_ip();

    assert_string_equal(retval, "");

    free(retval);
}

static void get_agent_ip_unknown_address_family(void **state) {
    char *retval;

    will_return(__wrap_getsockname, 0);
    will_return(__wrap_getsockname, AF_UNIX);

    expect_string(__wrap__mdebug2, formatted_msg, "Unknown address family: 1");

    retval = get_agent_ip();

    assert_string_equal(retval, "");

    free(retval);
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
        cmocka_unit_test_setup(get_agent_ip_fail_to_connect, setup),
        cmocka_unit_test_setup(get_agent_ip_invalid_socket, setup),
        cmocka_unit_test_setup(get_agent_ip_unknown_address_family, setup),
        cmocka_unit_test_setup(get_agent_ip_ipv4_updated_successfully, setup),
        cmocka_unit_test_setup(get_agent_ip_ipv6_updated_successfully, setup)
#endif // TEST_AGENT
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
