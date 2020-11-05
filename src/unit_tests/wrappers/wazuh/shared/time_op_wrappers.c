/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "time_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

time_t current_time = 0;

void __wrap_w_sleep_until(const time_t new_time){
    current_time = new_time;
}

void __wrap_w_time_delay(unsigned long int msec){
    current_time += (msec/1000);
}

char* __wrap_w_get_timestamp(time_t time) {
    check_expected(time);

    return mock_type(char*);
}
