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

void __wrap_rem_inc_recv_events() {
    function_called();
}

void __wrap_rem_add_recv(unsigned long bytes) {
    check_expected(bytes);
}

void __wrap_rem_inc_recv_ctrl() {
    function_called();
}

void __wrap_rem_inc_recv_discarded() {
    function_called();
}

void __wrap_rem_inc_recv_events_failed() {
    function_called();
}

void __wrap_rem_inc_recv_ctrl_request() {
    function_called();
}

void __wrap_rem_inc_recv_ctrl_startup() {
    function_called();
}

void __wrap_rem_inc_recv_ctrl_shutdown() {
    function_called();
}

void __wrap_rem_inc_recv_ctrl_keepalive() {
    function_called();
}

void __wrap_rem_inc_recv_unknown() {
    function_called();
    return;
}

void __wrap_rem_add_send(unsigned long bytes) {
    check_expected(bytes);
}

void __wrap_rem_inc_send_ack() {
    function_called();
}

void __wrap_rem_inc_send_discarded() {
    function_called();
}

cJSON* __wrap_rem_create_state_json() {
    return mock_type(cJSON *);
}
