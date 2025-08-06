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
#include <stdlib.h>

#include "../../headers/shared.h"
#include "../../remoted/remoted.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/wazuh/shared/queue_op_wrappers.h"

#include "../wrappers/wazuh/remoted/queue_wrappers.h"
#include "../wrappers/wazuh/remoted/manager_wrappers.h"
#include "../../remoted/secure.c"

void * save_control_thread(void * control_msg_queue);

void test_save_control_message_empty(void **state)
{
    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_queue_pop_ex, (w_queue_t *) -1);
    expect_value(__wrap_queue_pop_ex, queue, 0x1);


    will_return(__wrap_FOREVER, 0);

    assert_null(save_control_thread((void *) 0x1));
}


void test_save_control_message_ok(void **state)
{
    w_queue_t * queue = queue_init(10);

    w_ctrl_msg_data_t * ctrl_msg_data;
    os_calloc(sizeof(w_ctrl_msg_data_t), 1, ctrl_msg_data);
    os_calloc(sizeof(keyentry), 1, ctrl_msg_data->key);

    ctrl_msg_data->length = strlen("test message") + 1;
    os_calloc(ctrl_msg_data->length, sizeof(char), ctrl_msg_data->message);
    memcpy(ctrl_msg_data->message, "test message", ctrl_msg_data->length);

    queue_push(queue, ctrl_msg_data);

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_queue_pop_ex, (void *) ctrl_msg_data);
    expect_value(__wrap_queue_pop_ex, queue, queue);

    expect_value(__wrap_save_controlmsg, key, ctrl_msg_data->key);
    expect_value(__wrap_save_controlmsg, r_msg, ctrl_msg_data->message);
    expect_any(__wrap_save_controlmsg, wdb_sock);

    will_return(__wrap_FOREVER, 0);

    assert_null(save_control_thread((void *) queue));
    queue_free(queue);
}


int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_save_control_message_empty),
        cmocka_unit_test(test_save_control_message_ok),
        };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
