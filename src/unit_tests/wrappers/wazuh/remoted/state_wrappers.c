/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "state_wrappers.h"

void __wrap_rem_inc_tcp() {
    function_called();
    return;
}

void __wrap_rem_dec_tcp() {
    function_called();
    return;
}

void __wrap_rem_inc_recv_evt() {
    function_called();
    return;
}

void __wrap_rem_add_recv(unsigned long bytes) {
    check_expected(bytes);
}

void __wrap_rem_inc_recv_ctrl(const char *agent_id) {
    check_expected(agent_id);
}

void __wrap_rem_inc_recv_ctrl_request(const char *agent_id) {
    check_expected(agent_id);
}

void __wrap_rem_inc_recv_ctrl_startup(const char *agent_id) {
    check_expected(agent_id);
}

void __wrap_rem_inc_recv_ctrl_shutdown(const char *agent_id) {
    check_expected(agent_id);
}

void __wrap_rem_inc_recv_ctrl_keepalive(const char *agent_id) {
    check_expected(agent_id);
}

void __wrap_rem_inc_recv_unknown() {
    function_called();
    return;
}

void __wrap_rem_add_send(unsigned long bytes) {
    check_expected(bytes);
}

void __wrap_rem_inc_send_ack(const char *agent_id) {
    check_expected(agent_id);
}

void __wrap_rem_inc_send_discarded(const char *agent_id) {
    check_expected(agent_id);
}

cJSON* __wrap_rem_create_state_json() {
    return mock_type(cJSON *);
}

cJSON* __wrap_rem_create_agents_state_json(int *agents_ids) {
    check_expected(agents_ids);
    return mock_type(cJSON *);
}
