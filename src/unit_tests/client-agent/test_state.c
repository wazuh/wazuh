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

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/posix/pthread_wrappers.h"

#include "../../client-agent/state.h"

const char * get_str_status(agent_status_t status);
void w_agentd_state_update(w_agentd_state_update_t type, void * data);
char * w_agentd_state_get();

extern agent_state_t agent_state;

/* setup/teardown */

/* tests */

/* get_str_status */

void test_get_str_status_pending(void ** state)
{
    agent_status_t status = GA_STATUS_PENDING;

    const char * retval = get_str_status(status);

    assert_string_equal(retval,"pending");

}

void test_get_str_status_connected(void ** state)
{
    agent_status_t status = GA_STATUS_ACTIVE;

    const char * retval = get_str_status(status);

    assert_string_equal(retval,"connected");

}

void test_get_str_status_disconnected(void ** state)
{
    agent_status_t status = GA_STATUS_NACTIVE;

    const char * retval = get_str_status(status);

    assert_string_equal(retval,"disconnected");

}

void test_get_str_status_unknown(void ** state)
{
    agent_status_t status = 10;

    expect_string(__wrap__merror, formatted_msg, "At get_str_status(): Unknown status (10)");

    const char * retval = get_str_status(status);

    assert_string_equal(retval,"unknown");

}

/* w_agentd_state_update */

void test_w_agentd_state_update_status(void ** state)
{
    w_agentd_state_update_t type = UPDATE_STATUS;
    agent_status_t data = GA_STATUS_ACTIVE;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    w_agentd_state_update(type, &data);

}

void test_w_agentd_state_update_keepalive_NULL(void ** state)
{
    w_agentd_state_update_t type = UPDATE_KEEPALIVE;
    time_t * data = NULL;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    w_agentd_state_update(type, data);

}

void test_w_agentd_state_update_keepalive(void ** state)
{
    w_agentd_state_update_t type = UPDATE_KEEPALIVE;
    time_t data = 10;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    w_agentd_state_update(type, &data);

}

void test_w_agentd_state_update_ack_NULL(void ** state)
{
    w_agentd_state_update_t type = UPDATE_ACK;
    time_t * data = NULL;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    w_agentd_state_update(type, &data);

}

void test_w_agentd_state_update_ack(void ** state)
{
    w_agentd_state_update_t type = UPDATE_ACK;
    time_t data = 10;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    w_agentd_state_update(type, &data);

}

void test_w_agentd_state_update_msg_count(void ** state)
{
    w_agentd_state_update_t type = INCREMENT_MSG_COUNT;
    time_t data = 10;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    w_agentd_state_update(type, &data);

}

void test_w_agentd_state_update_msg_send(void ** state) 
{
    w_agentd_state_update_t type = INCREMENT_MSG_SEND;
    time_t data = 10;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    w_agentd_state_update(type, &data);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Tests get_str_status
        cmocka_unit_test(test_get_str_status_pending),
        cmocka_unit_test(test_get_str_status_connected),
        cmocka_unit_test(test_get_str_status_disconnected),
        cmocka_unit_test(test_get_str_status_unknown),

        // Tests w_agentd_state_update
        cmocka_unit_test(test_w_agentd_state_update_status),
        cmocka_unit_test(test_w_agentd_state_update_keepalive_NULL),
        cmocka_unit_test(test_w_agentd_state_update_keepalive),
        cmocka_unit_test(test_w_agentd_state_update_ack_NULL),
        cmocka_unit_test(test_w_agentd_state_update_ack),
        cmocka_unit_test(test_w_agentd_state_update_msg_count),
        cmocka_unit_test(test_w_agentd_state_update_msg_send),
        
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
