/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <shared.h>
#include <os_net/os_net.h>

#include "state_wrappers.h"


void __wrap_rem_inc_tcp() {
    function_called();
}

void __wrap_rem_dec_tcp() {
    function_called();
}

void __wrap_rem_inc_evt() {
    function_called();
}

void __wrap_rem_inc_ctrl_msg() {
    function_called();
}

void __wrap_rem_inc_msg_queued() {
    function_called();
}

void __wrap_rem_add_send(unsigned long bytes) {
    function_called();
    check_expected(bytes);
}

void __wrap_rem_inc_discarded() {
    function_called();
}

void __wrap_rem_add_recv(unsigned long bytes) {
    function_called();
    check_expected(bytes);
}

void __wrap_rem_inc_dequeued() {
    function_called();
}
