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

typedef struct _os_channel {
    char *evt_log;
    char *bookmark_name;
    unsigned int flags;
    EVT_HANDLE bookmark;
    int bookmark_enabled;
    EVT_HANDLE subscription;
} os_channel;

void send_channel_event(EVT_HANDLE evt, os_channel *channel);

/* Setup & Teardown */

static int test_setup(void ** state) {
    os_channel *channel = NULL;

    os_calloc(1, sizeof(os_channel), channel);
    channel->evt_log = strdup("Application");
    channel->bookmark_name = NULL;
    channel->bookmark_enabled = 0;
    *state = channel;

    test_mode = 1;
    return 0;
}

static int test_teardown(void ** state) {
    os_channel *channel = (os_channel *)*state;

    os_free(channel->evt_log);
    os_free(channel->bookmark_name);
    os_free(channel);

    test_mode = 0;
    return 0;
}

/* Tests */

void test_send_channel_event_render_buffer_size_fail(void ** state) {
    os_channel *channel = (os_channel *)*state;
    EVT_HANDLE evt = (EVT_HANDLE)1;

    expect_value(wrap_EvtRender, Context, NULL);
    expect_value(wrap_EvtRender, Fragment, evt);
    expect_value(wrap_EvtRender, Flags, EvtRenderEventXml);
    expect_value(wrap_EvtRender, BufferSize, 0);
    will_return(wrap_EvtRender, NULL);
    will_return(wrap_EvtRender, 100);
    will_return(wrap_EvtRender, 0);
    will_return(wrap_EvtRender, FALSE);

    /* GetLastError called twice: once in condition check, once in merror */
    will_return(wrap_GetLastError, ERROR_INVALID_PARAMETER);
    will_return(wrap_GetLastError, ERROR_INVALID_PARAMETER);

    expect_string(__wrap__merror, formatted_msg,
        "Could not EvtRender() to determine buffer size for (Application) which returned (87)");

    send_channel_event(evt, channel);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_send_channel_event_render_buffer_size_fail, test_setup, test_teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
