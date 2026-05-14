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
#include "../wrappers/wazuh/client-agent/buffer_wrappers.h"
#include "../wrappers/libc/time_wrappers.h"

#include "../../client-agent/state.h"

const char * get_str_status(agent_status_t status);
void w_agentd_state_update(w_agentd_state_update_t type, void * data);
char * w_agentd_state_get();

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

/* w_agentd_state_get */

void test_w_agentd_state_get_last_keepalive(void ** state)
{
    agent_state.status = GA_STATUS_ACTIVE;
    agent_state.last_keepalive = 10;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    expect_function_call(__wrap_pthread_mutex_lock);

    will_return(__wrap_strftime,"2021-01-25 12:18:37");
    will_return(__wrap_strftime, 20);

    will_return(__wrap_strftime,"2021-01-25 13:00:00");
    will_return(__wrap_strftime, 20);

    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_w_agentd_get_buffer_lenght, 0);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_JSON_ERROR);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_STATUS);
    expect_string(__wrap_cJSON_AddStringToObject, string, "connected");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_KEEP_ALIVE);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25 12:18:37");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_LAST_ACK);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25 13:00:00");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_COUNT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_SENT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_BUFF);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    will_return(__wrap_cJSON_AddBoolToObject, (cJSON *)1);

    will_return(__wrap_cJSON_PrintUnformatted, "unknown");

    expect_function_call(__wrap_cJSON_Delete);

    const char * retval = w_agentd_state_get();

    assert_string_equal(retval,"unknown");

}

void test_w_agentd_state_get_last_ack(void ** state)
{
    agent_state.status = GA_STATUS_ACTIVE;
    agent_state.last_keepalive = 10;
    agent_state.last_ack = 10;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_strftime,"2021-01-25 12:18:37");
    will_return(__wrap_strftime, 20);

    will_return(__wrap_strftime,"2021-01-25 13:00:00");
    will_return(__wrap_strftime, 20);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_w_agentd_get_buffer_lenght, 0);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_JSON_ERROR);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_STATUS);
    expect_string(__wrap_cJSON_AddStringToObject, string, "connected");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_KEEP_ALIVE);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25 12:18:37");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_LAST_ACK);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25 13:00:00");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_COUNT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_SENT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_BUFF);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    will_return(__wrap_cJSON_AddBoolToObject, (cJSON *)1);

    will_return(__wrap_cJSON_PrintUnformatted, "unknown");

    expect_function_call(__wrap_cJSON_Delete);

    const char * retval = w_agentd_state_get();

    assert_string_equal(retval,"unknown");

}

void test_w_agentd_state_get_buffer_disabled(void ** state)
{
    agent_state.status = GA_STATUS_ACTIVE;
    agent_state.last_keepalive = 10;
    agent_state.last_ack = 10;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_strftime,"2021-01-25 12:18:37");
    will_return(__wrap_strftime, 20);

    will_return(__wrap_strftime,"2021-01-25 13:00:00");
    will_return(__wrap_strftime, 20);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_w_agentd_get_buffer_lenght, -1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_JSON_ERROR);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_STATUS);
    expect_string(__wrap_cJSON_AddStringToObject, string, "connected");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_KEEP_ALIVE);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25 12:18:37");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_LAST_ACK);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25 13:00:00");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_COUNT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_SENT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_BUFF);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    will_return(__wrap_cJSON_AddBoolToObject, (cJSON *)1);

    will_return(__wrap_cJSON_PrintUnformatted, "unknown");

    expect_function_call(__wrap_cJSON_Delete);

    const char * retval = w_agentd_state_get();

    assert_string_equal(retval,"unknown");

}

void test_w_agentd_state_get_buffer_empty(void ** state)
{
    agent_state.status = GA_STATUS_ACTIVE;
    agent_state.last_keepalive = 10;
    agent_state.last_ack = 10;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_strftime, "2021-01-25 12:18:37");
    will_return(__wrap_strftime, 20);

    will_return(__wrap_strftime, "2021-01-25 13:00:00");
    will_return(__wrap_strftime, 20);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_w_agentd_get_buffer_lenght, 0);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_JSON_ERROR);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_STATUS);
    expect_string(__wrap_cJSON_AddStringToObject, string, "connected");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_KEEP_ALIVE);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25 12:18:37");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_LAST_ACK);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25 13:00:00");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_COUNT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_SENT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_BUFF);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    will_return(__wrap_cJSON_AddBoolToObject, (cJSON *)1);

    will_return(__wrap_cJSON_PrintUnformatted, "unknown");

    expect_function_call(__wrap_cJSON_Delete);

    const char * retval = w_agentd_state_get();

    assert_string_equal(retval,"unknown");

}

void test_w_agentd_state_get_pending(void ** state)
{
    agent_state.status = GA_STATUS_PENDING;
    agent_state.last_keepalive = 10;
    agent_state.last_ack = 10;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_strftime, "2021-01-25 12:18:37");
    will_return(__wrap_strftime, 20);

    will_return(__wrap_strftime, "2021-01-25 13:00:00");
    will_return(__wrap_strftime, 20);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_w_agentd_get_buffer_lenght, 1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_JSON_ERROR);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_STATUS);
    expect_string(__wrap_cJSON_AddStringToObject, string, "pending");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_KEEP_ALIVE);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25 12:18:37");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_LAST_ACK);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25 13:00:00");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_COUNT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_SENT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_BUFF);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    will_return(__wrap_cJSON_AddBoolToObject, (cJSON *)1);

    will_return(__wrap_cJSON_PrintUnformatted, "unknown");

    expect_function_call(__wrap_cJSON_Delete);

    const char * retval = w_agentd_state_get();

    assert_string_equal(retval,"unknown");

}

void test_w_agentd_state_get_conected(void ** state)
{
    agent_state.status = GA_STATUS_ACTIVE;
    agent_state.last_keepalive = 10;
    agent_state.last_ack = 10;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_strftime, "2021-01-25 12:18:37");
    will_return(__wrap_strftime, 20);

    will_return(__wrap_strftime, "2021-01-25 13:00:00");
    will_return(__wrap_strftime, 20);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_w_agentd_get_buffer_lenght, 1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_JSON_ERROR);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_STATUS);
    expect_string(__wrap_cJSON_AddStringToObject, string, "connected");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_KEEP_ALIVE);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25 12:18:37");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_LAST_ACK);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25 13:00:00");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_COUNT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_SENT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_BUFF);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    will_return(__wrap_cJSON_AddBoolToObject, (cJSON *)1);

    will_return(__wrap_cJSON_PrintUnformatted, "unknown");

    expect_function_call(__wrap_cJSON_Delete);

    const char * retval = w_agentd_state_get();

    assert_string_equal(retval,"unknown");

}

void test_w_agentd_state_get_disconected(void ** state)
{
    agent_state.status = GA_STATUS_NACTIVE;
    agent_state.last_keepalive = 10;
    agent_state.last_ack = 10;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_strftime, "2021-01-25 12:18:37");
    will_return(__wrap_strftime, 20);

    will_return(__wrap_strftime, "2021-01-25 13:00:00");
    will_return(__wrap_strftime, 20);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_w_agentd_get_buffer_lenght, 1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_JSON_ERROR);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_STATUS);
    expect_string(__wrap_cJSON_AddStringToObject, string, "disconnected");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_KEEP_ALIVE);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25 12:18:37");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_LAST_ACK);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25 13:00:00");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_COUNT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_SENT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_BUFF);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    will_return(__wrap_cJSON_AddBoolToObject, (cJSON *)1);

    will_return(__wrap_cJSON_PrintUnformatted, "unknown");

    expect_function_call(__wrap_cJSON_Delete);

    const char * retval = w_agentd_state_get();

    assert_string_equal(retval,"unknown");

}

void test_w_agentd_state_get_unknown(void ** state)
{
    agent_state.status = 5;
    agent_state.last_keepalive = 10;
    agent_state.last_ack = 10;

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);

    expect_string(__wrap__merror, formatted_msg, "At get_str_status(): Unknown status (5)");

    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_strftime, "2021-01-25 12:18:37");
    will_return(__wrap_strftime, 20);

    will_return(__wrap_strftime, "2021-01-25 13:00:00");
    will_return(__wrap_strftime, 20);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_w_agentd_get_buffer_lenght, 1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_JSON_ERROR);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_function_call(__wrap_cJSON_AddItemToObject);
    will_return(__wrap_cJSON_AddItemToObject, true);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_STATUS);
    expect_string(__wrap_cJSON_AddStringToObject, string, "unknown");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_KEEP_ALIVE);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25 12:18:37");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddStringToObject, name, W_AGENTD_FIELD_LAST_ACK);
    expect_string(__wrap_cJSON_AddStringToObject, string, "2021-01-25 13:00:00");
    will_return(__wrap_cJSON_AddStringToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_COUNT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_SENT);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    expect_string(__wrap_cJSON_AddNumberToObject, name, W_AGENTD_FIELD_MSG_BUFF);
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, (cJSON *)1);

    will_return(__wrap_cJSON_AddBoolToObject, (cJSON *)1);

    will_return(__wrap_cJSON_PrintUnformatted, "unknown");

    expect_function_call(__wrap_cJSON_Delete);

    const char * retval = w_agentd_state_get();

    assert_string_equal(retval,"unknown");

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

        // Tests w_agentd_state_get
        cmocka_unit_test(test_w_agentd_state_get_last_keepalive),
        cmocka_unit_test(test_w_agentd_state_get_last_ack),
        cmocka_unit_test(test_w_agentd_state_get_buffer_disabled),
        cmocka_unit_test(test_w_agentd_state_get_buffer_empty),
        cmocka_unit_test(test_w_agentd_state_get_pending),
        cmocka_unit_test(test_w_agentd_state_get_conected),
        cmocka_unit_test(test_w_agentd_state_get_disconected),
        cmocka_unit_test(test_w_agentd_state_get_unknown)
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
