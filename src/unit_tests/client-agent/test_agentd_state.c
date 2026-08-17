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

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/posix/pthread_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/libc/time_wrappers.h"

#include "state.h"

const char * get_str_status(agent_status_t status);
void w_agentd_state_update(w_agentd_state_update_t type, void * data);
cJSON * w_agentd_state_get(void);

extern agent_state_t agent_state;

/* setup/teardown */

static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}

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

void test_w_agentd_state_update_task_dispatched(void ** state)
{
    w_agentd_state_update_t type = INCREMENT_TASK_DISPATCHED;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    w_agentd_state_update(type, NULL);
}

void test_w_agentd_state_update_task_discarded_duplicate(void ** state)
{
    w_agentd_state_update_t type = INCREMENT_TASK_DISCARDED_DUPLICATE;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    w_agentd_state_update(type, NULL);
}

void test_w_agentd_state_update_task_failed(void ** state)
{
    w_agentd_state_update_t type = INCREMENT_TASK_FAILED;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    w_agentd_state_update(type, NULL);
}

/* w_agentd_state_get */

/* The getter now builds the body the manager indexes: no {"error","data"}
 * envelope (agcom_getstate adds that), counters grouped, and only fields with a
 * real producer behind them. The mocked cJSON_CreateObject hands back the same
 * pointer for the body and every nested object, which is all these need. */
static void expect_counter(const char * name)
{
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_TOTAL);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);
    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);
    (void)name;
}

void test_w_agentd_state_get_groups_the_counters(void ** state)
{
    agent_state.status = GA_STATUS_ACTIVE;
    agent_state.last_keepalive = 10;

    /* body, messages, tasks */
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_strftime, "2021-01-25T12:18:37Z");
    will_return(__wrap_strftime, 21);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_STATUS);
    expect_string(__wrap_cJSON_AddStringToObject, string, "connected");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_KEEP_ALIVE);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25T12:18:37Z");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MESSAGES_COUNT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);
    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_counter(W_AGENTD_FIELD_TASK_DISPATCHED);
    expect_counter(W_AGENTD_FIELD_TASK_DUPLICATE);
    expect_counter(W_AGENTD_FIELD_TASK_FAILED);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    cJSON * retval = w_agentd_state_get();

    assert_ptr_equal(retval, (cJSON *)1);
}

void test_w_agentd_state_get_omits_an_unset_keepalive(void ** state)
{
    agent_state.status = GA_STATUS_ACTIVE;
    /* No UPDATE_KEEPALIVE has landed yet. The field is mapped `date` in the
     * index and an empty string does not parse as one, which rejects the whole
     * document -- so it must be left out entirely, not sent as "". */
    agent_state.last_keepalive = 0;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_STATUS);
    expect_string(__wrap_cJSON_AddStringToObject, string, "connected");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    /* No second AddStringToObject: that is the assertion. */

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MESSAGES_COUNT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);
    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_counter(W_AGENTD_FIELD_TASK_DISPATCHED);
    expect_counter(W_AGENTD_FIELD_TASK_DUPLICATE);
    expect_counter(W_AGENTD_FIELD_TASK_FAILED);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    cJSON * retval = w_agentd_state_get();

    assert_ptr_equal(retval, (cJSON *)1);
}

void test_w_agentd_state_get_unknown_status(void ** state)
{
    agent_state.status = 5;
    agent_state.last_keepalive = 0;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_string(__wrap__merror, formatted_msg, "At get_str_status(): Unknown status (5)");
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_STATUS);
    expect_string(__wrap_cJSON_AddStringToObject, string, "unknown");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MESSAGES_COUNT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);
    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_counter(W_AGENTD_FIELD_TASK_DISPATCHED);
    expect_counter(W_AGENTD_FIELD_TASK_DUPLICATE);
    expect_counter(W_AGENTD_FIELD_TASK_FAILED);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    cJSON * retval = w_agentd_state_get();

    assert_ptr_equal(retval, (cJSON *)1);
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
        cmocka_unit_test(test_w_agentd_state_update_msg_count),
        cmocka_unit_test(test_w_agentd_state_update_msg_send),

        // Tests w_agentd_state_get
        cmocka_unit_test(test_w_agentd_state_get_groups_the_counters),
        cmocka_unit_test(test_w_agentd_state_get_omits_an_unset_keepalive),
        cmocka_unit_test(test_w_agentd_state_get_unknown_status),
        
        
        
        
        

        // Tests w_agentd_state_update (task dispatch metrics) -- run
        // after the get_* tests above, which assert the fields start at 0.
        cmocka_unit_test(test_w_agentd_state_update_task_dispatched),
        cmocka_unit_test(test_w_agentd_state_update_task_discarded_duplicate),
        cmocka_unit_test(test_w_agentd_state_update_task_failed)
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
