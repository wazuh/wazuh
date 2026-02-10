/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "shared.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

#include <stdint.h>
#include <sec_api/stdlib_s.h>
#include <winerror.h>
#include <winevt.h>

/* No tests currently defined for read_win_event_channel.c
 * The get_message function has been removed as it is no longer used.
 * 
 * Future test coverage needed:
 * - send_channel_event(): XML header stripping logic
 *   - Test with XML header present
 *   - Test without XML header
 *   - Test with malformed XML header
 * 
 * Tests can be added here for send_channel_event or other functions as needed.
 */

int main(void) {
    /* No tests to run */
    return 0;
}
