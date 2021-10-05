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
#include <stdlib.h>

#include "../wrappers/common.h"
#include "../wrappers/linux/socket_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/bqueue_op_wrappers.h"
#include "../wrappers/wazuh/shared/notify_op_wrappers.h"

#include "remoted/remoted.h"

extern wnotify_t * notify;

int sock = 15;

/* setup/teardown */

static int test_setup(void ** state) {
    test_mode = 1;

    send_buffer_size = 100;

    netbuffer_t *netbuffer;
    struct sockaddr_in peer_info;

    memset(&peer_info, 0, sizeof(struct sockaddr_in));

    os_calloc(1, sizeof(netbuffer_t), netbuffer);
    nb_open(netbuffer, sock, &peer_info);

    *state = netbuffer;

    os_calloc(1, sizeof(wnotify_t), notify);

    return 0;
}

static int test_teardown(void ** state) {
    test_mode = 0;

    send_buffer_size = 0;

    netbuffer_t *netbuffer = *state;

    nb_close(netbuffer, sock);
    os_free(netbuffer->buffers);
    os_free(netbuffer);

    os_free(notify);

    return 0;
}

/* Tests */

void test_nb_queue_ok(void ** state) {
    netbuffer_t *netbuffer = *state;
    char msg[10] = {0};
    char final_msg[14] = {0};

    ssize_t size = snprintf(msg, 10, "abcdefghi");
    ssize_t final_size = snprintf(final_msg, 14, "4321abcdefghi");

    expect_value(__wrap_wnet_order, value, 9);
    will_return(__wrap_wnet_order, 0b00110001001100100011001100110100); //1234

    expect_memory(__wrap_bqueue_push, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    expect_memory(__wrap_bqueue_push, data, final_msg, final_size);
    expect_value(__wrap_bqueue_push, length, final_size);
    expect_value(__wrap_bqueue_push, flags, BQUEUE_NOFLAG);
    will_return(__wrap_bqueue_push, 0);

    expect_memory(__wrap_wnotify_modify, notify, notify, sizeof(wnotify_t *));
    expect_value(__wrap_wnotify_modify, fd, sock);
    expect_value(__wrap_wnotify_modify, op, WO_READ | WO_WRITE);
    will_return(__wrap_wnotify_modify, 0);

    int retval = nb_queue(netbuffer, sock, msg, size);

    assert_int_equal(retval, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nb_queue_ok, test_setup, test_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
