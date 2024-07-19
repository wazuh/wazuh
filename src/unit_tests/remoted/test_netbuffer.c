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

#include "../../remoted/remoted.h"

#include "../wrappers/common.h"
#include "../wrappers/linux/socket_wrappers.h"
#include "../wrappers/posix/pthread_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/bqueue_op_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/notify_op_wrappers.h"
#include "../wrappers/wazuh/remoted/queue_wrappers.h"

extern wnotify_t * notify;
extern unsigned int send_chunk;

int sock = 15;

/* setup/teardown */

static int test_setup(void ** state) {
    test_mode = 1;

    send_buffer_size = 100;

    netbuffer_t *netbuffer;
    struct sockaddr_storage peer_info;

    memset(&peer_info, 0, sizeof(struct sockaddr_storage));

    os_calloc(1, sizeof(netbuffer_t), netbuffer);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    nb_open(netbuffer, sock, &peer_info);

    *state = netbuffer;

    os_calloc(1, sizeof(wnotify_t), notify);

    send_chunk = 14;

    return 0;
}

static int test_teardown(void ** state) {
    test_mode = 0;

    netbuffer_t *netbuffer = *state;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

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
    char *agent_id = "001";

    expect_value(__wrap_wnet_order, value, 9);
    will_return(__wrap_wnet_order, 0b00110001001100100011001100110100); //1234

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_memory(__wrap_bqueue_push, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    expect_memory(__wrap_bqueue_push, data, final_msg, final_size);
    expect_value(__wrap_bqueue_push, length, final_size);
    expect_value(__wrap_bqueue_push, flags, BQUEUE_NOFLAG);
    will_return(__wrap_bqueue_push, 0);

    expect_memory(__wrap_bqueue_used, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    will_return(__wrap_bqueue_used, final_size);

    expect_memory(__wrap_wnotify_modify, notify, notify, sizeof(wnotify_t *));
    expect_value(__wrap_wnotify_modify, fd, sock);
    expect_value(__wrap_wnotify_modify, op, WO_READ | WO_WRITE);
    will_return(__wrap_wnotify_modify, 0);

    expect_function_call(__wrap_pthread_mutex_unlock);

    int retval = nb_queue(netbuffer, sock, msg, size, agent_id);

    assert_int_equal(retval, 0);
}

void test_nb_queue_retry_ok(void ** state) {
    netbuffer_t *netbuffer = *state;
    char msg[10] = {0};
    char final_msg[14] = {0};

    ssize_t size = snprintf(msg, 10, "abcdefghi");
    ssize_t final_size = snprintf(final_msg, 14, "4321abcdefghi");
    char *agent_id = "001";

    send_timeout_to_retry = 5;

    expect_value(__wrap_wnet_order, value, 9);
    will_return(__wrap_wnet_order, 0b00110001001100100011001100110100); //1234

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_memory(__wrap_bqueue_push, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    expect_memory(__wrap_bqueue_push, data, final_msg, final_size);
    expect_value(__wrap_bqueue_push, length, final_size);
    expect_value(__wrap_bqueue_push, flags, BQUEUE_NOFLAG);
    will_return(__wrap_bqueue_push, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Not enough buffer space. Retrying... [buffer_size=100, used=0, msg_size=9]");

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_value(__wrap_sleep, seconds, 5);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_memory(__wrap_bqueue_push, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    expect_memory(__wrap_bqueue_push, data, final_msg, final_size);
    expect_value(__wrap_bqueue_push, length, final_size);
    expect_value(__wrap_bqueue_push, flags, BQUEUE_NOFLAG);
    will_return(__wrap_bqueue_push, 0);

    expect_memory(__wrap_bqueue_used, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    will_return(__wrap_bqueue_used, final_size);

    expect_memory(__wrap_wnotify_modify, notify, notify, sizeof(wnotify_t *));
    expect_value(__wrap_wnotify_modify, fd, sock);
    expect_value(__wrap_wnotify_modify, op, WO_READ | WO_WRITE);
    will_return(__wrap_wnotify_modify, 0);

    expect_function_call(__wrap_pthread_mutex_unlock);

    int retval = nb_queue(netbuffer, sock, msg, size, agent_id);

    assert_int_equal(retval, 0);
}

void test_nb_queue_retry_err(void ** state) {
    netbuffer_t *netbuffer = *state;
    char msg[10] = {0};
    char final_msg[14] = {0};

    ssize_t size = snprintf(msg, 10, "abcdefghi");
    ssize_t final_size = snprintf(final_msg, 14, "4321abcdefghi");
    char *agent_id = "001";

    send_timeout_to_retry = 5;

    expect_value(__wrap_wnet_order, value, 9);
    will_return(__wrap_wnet_order, 0b00110001001100100011001100110100); //1234

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_memory(__wrap_bqueue_push, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    expect_memory(__wrap_bqueue_push, data, final_msg, final_size);
    expect_value(__wrap_bqueue_push, length, final_size);
    expect_value(__wrap_bqueue_push, flags, BQUEUE_NOFLAG);
    will_return(__wrap_bqueue_push, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Not enough buffer space. Retrying... [buffer_size=100, used=0, msg_size=9]");

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_value(__wrap_sleep, seconds, 5);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_memory(__wrap_bqueue_push, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    expect_memory(__wrap_bqueue_push, data, final_msg, final_size);
    expect_value(__wrap_bqueue_push, length, final_size);
    expect_value(__wrap_bqueue_push, flags, BQUEUE_NOFLAG);
    will_return(__wrap_bqueue_push, -1);

    expect_string(__wrap_rem_inc_send_discarded, agent_id, agent_id);

    expect_string(__wrap__mwarn, formatted_msg, "Package dropped. Could not append data into buffer.");

    expect_function_call(__wrap_pthread_mutex_unlock);

    int retval = nb_queue(netbuffer, sock, msg, size, agent_id);

    assert_int_equal(retval, -1);
}

void test_nb_send_ok(void ** state) {
    netbuffer_t *netbuffer = *state;
    char final_msg[14] = {0};

    ssize_t final_size = snprintf(final_msg, 14, "4321abcdefghi");

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_memory(__wrap_bqueue_peek, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    expect_value(__wrap_bqueue_peek, flags, BQUEUE_NOFLAG);
    will_return(__wrap_bqueue_peek, 1);
    will_return(__wrap_bqueue_peek, final_msg);
    will_return(__wrap_bqueue_peek, final_size);

    will_return(__wrap_send, final_size);

    expect_memory(__wrap_bqueue_drop, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    expect_value(__wrap_bqueue_drop, length, final_size);
    will_return(__wrap_bqueue_drop, final_size);

    expect_memory(__wrap_bqueue_used, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    will_return(__wrap_bqueue_used, 0);

    expect_memory(__wrap_wnotify_modify, notify, notify, sizeof(wnotify_t *));
    expect_value(__wrap_wnotify_modify, fd, sock);
    expect_value(__wrap_wnotify_modify, op, WO_READ);
    will_return(__wrap_wnotify_modify, 0);

    expect_function_call(__wrap_pthread_mutex_unlock);

    int retval = nb_send(netbuffer, sock);

    assert_int_equal(retval, final_size);
}

void test_nb_send_zero_ok(void ** state) {
    netbuffer_t *netbuffer = *state;
    char final_msg[14] = {0};

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_memory(__wrap_bqueue_peek, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    expect_value(__wrap_bqueue_peek, flags, BQUEUE_NOFLAG);
    will_return(__wrap_bqueue_peek, 0);
    will_return(__wrap_bqueue_peek, 0);

    expect_memory(__wrap_wnotify_modify, notify, notify, sizeof(wnotify_t *));
    expect_value(__wrap_wnotify_modify, fd, sock);
    expect_value(__wrap_wnotify_modify, op, WO_READ);
    will_return(__wrap_wnotify_modify, 0);

    expect_function_call(__wrap_pthread_mutex_unlock);

    int retval = nb_send(netbuffer, sock);

    assert_int_equal(retval, 0);
}

void test_nb_send_would_block_ok(void ** state) {
    netbuffer_t *netbuffer = *state;
    char final_msg[14] = {0};

    ssize_t final_size = snprintf(final_msg, 14, "4321abcdefghi");

    errno = EWOULDBLOCK;

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_memory(__wrap_bqueue_peek, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    expect_value(__wrap_bqueue_peek, flags, BQUEUE_NOFLAG);
    will_return(__wrap_bqueue_peek, 1);
    will_return(__wrap_bqueue_peek, final_msg);
    will_return(__wrap_bqueue_peek, final_size);

    will_return(__wrap_send, -1);

    expect_memory(__wrap_bqueue_used, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    will_return(__wrap_bqueue_used, final_size);

    expect_function_call(__wrap_pthread_mutex_unlock);

    int retval = nb_send(netbuffer, sock);

    assert_int_equal(retval, -1);
}

void test_nb_send_err(void ** state) {
    netbuffer_t *netbuffer = *state;
    char final_msg[14] = {0};

    ssize_t final_size = snprintf(final_msg, 14, "4321abcdefghi");

    errno = ECONNRESET;

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_memory(__wrap_bqueue_peek, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    expect_value(__wrap_bqueue_peek, flags, BQUEUE_NOFLAG);
    will_return(__wrap_bqueue_peek, 1);
    will_return(__wrap_bqueue_peek, final_msg);
    will_return(__wrap_bqueue_peek, final_size);

    will_return(__wrap_send, -1);

    expect_string(__wrap__merror, formatted_msg, "Could not send data to socket 15: Connection reset by peer (104)");

    expect_memory(__wrap_bqueue_used, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    will_return(__wrap_bqueue_used, 0);

    expect_memory(__wrap_wnotify_modify, notify, notify, sizeof(wnotify_t *));
    expect_value(__wrap_wnotify_modify, fd, sock);
    expect_value(__wrap_wnotify_modify, op, WO_READ);
    will_return(__wrap_wnotify_modify, 0);

    expect_function_call(__wrap_pthread_mutex_unlock);

    int retval = nb_send(netbuffer, sock);

    assert_int_equal(retval, -1);
}

void test_nb_recv_incomplete_first_message(void ** state) {
    netbuffer_t *netbuffer = *state;
    char buffer_data[14] = {0xFB,0x03,0x00,0x00,0x21,0x31,0x36,0x30,0x37,0x21,0x23,0x41,0x45,0x53};

    void *buffer = &buffer_data;
    os_calloc(14, sizeof(char*), netbuffer->buffers[sock].data);
    memcpy((char*)netbuffer->buffers[sock].data, (char*)buffer, 14);

    netbuffer->buffers[sock].data_len = 0;

    expect_function_call(__wrap_pthread_mutex_lock);

    will_return(__wrap_recv, 14);

    expect_value(__wrap_wnet_order, value, 1019);
    will_return(__wrap_wnet_order, 1019);

    expect_function_call(__wrap_pthread_mutex_unlock);

    int retval = nb_recv(netbuffer, sock);

    assert_int_equal(retval, 14);
}

void test_nb_recv_incomplete_second_message(void ** state) {
    netbuffer_t *netbuffer = *state;
    char buffer_data[26] = {0x08,0x00,0x00,0x00,0x21,0x31,0x36,0x30,0x37,0x37,0x31,0x36,0xFB,0x03,0x00,0x00,0x21,0x31,0x36,0x30,0x37,0x21,0x23,0x41,0x45,0x53};

    void *buffer = &buffer_data;
    os_calloc(26, sizeof(char*), netbuffer->buffers[sock].data);
    memcpy((char*)netbuffer->buffers[sock].data, (char*)buffer, 26);

    netbuffer->buffers[sock].data_len = 0;

    expect_function_call(__wrap_pthread_mutex_lock);

    will_return(__wrap_recv, 26);

    expect_value(__wrap_wnet_order, value, 8);
    will_return(__wrap_wnet_order, 8);

    expect_value(__wrap_rem_msgpush, size, 8);
    expect_value(__wrap_rem_msgpush, addr, (struct sockaddr_storage *)&netbuffer->buffers[sock].peer_info);
    expect_value(__wrap_rem_msgpush, sock, 15);
    will_return(__wrap_rem_msgpush, 0);

    expect_value(__wrap_wnet_order, value, 1019);
    will_return(__wrap_wnet_order, 1019);

    expect_function_call(__wrap_pthread_mutex_unlock);

    int retval = nb_recv(netbuffer, sock);

    assert_int_equal(retval, 26);
    assert_int_equal(*(uint32_t *)netbuffer->buffers[sock].data, 1019);
    assert_int_equal(netbuffer->buffers[sock].data_len, 14);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nb_queue_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_queue_retry_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_queue_retry_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_send_zero_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_send_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_send_would_block_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_send_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_recv_incomplete_first_message, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_recv_incomplete_second_message, test_setup, test_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
