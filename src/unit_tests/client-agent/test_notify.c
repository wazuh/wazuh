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

#define TIME_INCREMENT ((time_t)(60))

static time_t base_time = 123456;
static const char * REQUEST = "host_ip";

static agent global_config = { .main_ip_update_interval = (int)TIME_INCREMENT };

static int setup_group(void **state) {
    agt = &global_config;

    return 0;
}

#ifdef TEST_AGENT
// get_agent_ip
static void get_agent_ip_fail_to_connect(void **state) {
    char *retval;

    expect_any_count(__wrap__mdebug2, formatted_msg, SOCK_ATTEMPTS);

    for (int i = SOCK_ATTEMPTS; i > 0; i--) {
        will_return(__wrap_control_check_connection, -1);
        expect_value(__wrap_sleep, seconds, 1);
    }

    expect_any(__wrap__mdebug1, formatted_msg);

    retval = get_agent_ip();

    assert_string_equal(retval, "");

    free(retval);
}

static void get_agent_ip_fail_to_send_request(void **state) {
    char *retval;
    static const int socket = 8;

    will_return(__wrap_control_check_connection, socket);

    expect_value(__wrap_OS_SendUnix, socket, socket);
    expect_string(__wrap_OS_SendUnix, msg, REQUEST);
    expect_value(__wrap_OS_SendUnix, size, strlen(REQUEST));
    will_return(__wrap_OS_SendUnix, OS_SOCKTERR);

    expect_any(__wrap__mdebug1, formatted_msg);

    retval = get_agent_ip();

    assert_string_equal(retval, "");

    free(retval);
}

static void get_agent_ip_fail_to_receive_response(void **state) {
    char *retval;
    static const int socket = 8;

    will_return(__wrap_control_check_connection, socket);

    expect_value(__wrap_OS_SendUnix, socket, socket);
    expect_string(__wrap_OS_SendUnix, msg, REQUEST);
    expect_value(__wrap_OS_SendUnix, size, strlen(REQUEST));
    will_return(__wrap_OS_SendUnix, OS_SUCCESS);

    expect_value(__wrap_OS_RecvUnix, socket, socket);
    expect_value(__wrap_OS_RecvUnix, sizet, IPSIZE);
    will_return(__wrap_OS_RecvUnix, "");
    will_return(__wrap_OS_RecvUnix, -1);

    expect_any(__wrap__mdebug1, formatted_msg);

    retval = get_agent_ip();

    assert_string_equal(retval, "");

    free(retval);
}

static void get_agent_ip_updated_successfully(void **state) {
    char *retval;
    static const int socket = 8;
    static const char *const RESPONSE = "10.0.2.15";

    will_return(__wrap_control_check_connection, socket);

    expect_value(__wrap_OS_SendUnix, socket, socket);
    expect_string(__wrap_OS_SendUnix, msg, REQUEST);
    expect_value(__wrap_OS_SendUnix, size, strlen(REQUEST));
    will_return(__wrap_OS_SendUnix, OS_SUCCESS);

    expect_value(__wrap_OS_RecvUnix, socket, socket);
    expect_value(__wrap_OS_RecvUnix, sizet, IPSIZE);
    will_return(__wrap_OS_RecvUnix, RESPONSE);
    will_return(__wrap_OS_RecvUnix, strlen(RESPONSE));

    retval = get_agent_ip();

    assert_string_equal(retval, RESPONSE);

    free(retval);

    will_return(__wrap_control_check_connection, socket);

    expect_value(__wrap_OS_SendUnix, socket, socket);
    expect_string(__wrap_OS_SendUnix, msg, REQUEST);
    expect_value(__wrap_OS_SendUnix, size, strlen(REQUEST));
    will_return(__wrap_OS_SendUnix, OS_SUCCESS);

    expect_value(__wrap_OS_RecvUnix, socket, socket);
    expect_value(__wrap_OS_RecvUnix, sizet, IPSIZE);
    will_return(__wrap_OS_RecvUnix, RESPONSE);
    will_return(__wrap_OS_RecvUnix, strlen(RESPONSE));

    retval = get_agent_ip();

    assert_string_equal(retval, RESPONSE);

    free(retval);

    // Check the IP gets refreshed after the interval
    base_time += TIME_INCREMENT;

    will_return(__wrap_control_check_connection, socket);

    expect_value(__wrap_OS_SendUnix, socket, socket);
    expect_string(__wrap_OS_SendUnix, msg, REQUEST);
    expect_value(__wrap_OS_SendUnix, size, strlen(REQUEST));
    will_return(__wrap_OS_SendUnix, OS_SUCCESS);

    expect_value(__wrap_OS_RecvUnix, socket, socket);
    expect_value(__wrap_OS_RecvUnix, sizet, IPSIZE);
    will_return(__wrap_OS_RecvUnix, RESPONSE);
    will_return(__wrap_OS_RecvUnix, strlen(RESPONSE));

    retval = get_agent_ip();

    assert_string_equal(retval, RESPONSE);

    free(retval);
}

#endif // TEST_AGENT

int main(void) {
    const struct CMUnitTest tests[] = {
#ifdef TEST_AGENT
        cmocka_unit_test(get_agent_ip_fail_to_connect),
        cmocka_unit_test(get_agent_ip_fail_to_send_request),
        cmocka_unit_test(get_agent_ip_fail_to_receive_response),
        cmocka_unit_test(get_agent_ip_updated_successfully)
#endif // TEST_AGENT
    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}
