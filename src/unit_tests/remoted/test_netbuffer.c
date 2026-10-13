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

#include "remoted.h"

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

static netbuffer_t send_netbuffer;

// function_called() lets the tests check close() runs between the mutex lock and unlock.
int __wrap_close(int fd) {
    function_called();
    check_expected(fd);

    int retval = mock();

    if (retval) {
        errno = mock();
    }

    return retval;
}

// Message counter fence of the last closed fd. function_called() pins rem_setCounter() before close().
static int fence_fd = -1;
static size_t fence_counter = 0;

void __wrap_rem_setCounter(int fd, size_t counter) {
    function_called();
    fence_fd = fd;
    fence_counter = counter;
}

size_t __wrap_rem_getCounter(int fd) {
    return fd == fence_fd ? fence_counter : 0;
}

/* nb_close_socket() over fd, with close() returning close_ret (and setting close_errno when it fails) */
static bool close_socket_ret(netbuffer_t * netbuffer, int fd, int close_ret, int close_errno) {
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_rem_setCounter);
    expect_function_call(__wrap_close);
    expect_value(__wrap_close, fd, fd);
    will_return(__wrap_close, close_ret);

    if (close_ret) {
        will_return(__wrap_close, close_errno);
    }

    expect_function_call(__wrap_pthread_mutex_unlock);

    return nb_close_socket(netbuffer, &send_netbuffer, fd);
}

static void close_slot(netbuffer_t * netbuffer, int fd) {
    assert_true(close_socket_ret(netbuffer, fd, 0, 0));
}

/* setup/teardown */

static int test_setup(void ** state) {
    test_mode = 1;

    send_buffer_size = 100;
    global_counter = 0;
    fence_fd = -1;
    fence_counter = 0;

    netbuffer_t *netbuffer;
    struct sockaddr_storage peer_info;

    memset(&peer_info, 0, sizeof(struct sockaddr_storage));

    os_calloc(1, sizeof(netbuffer_t), netbuffer);
    netbuffer->tracks_authentication = true;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    nb_open(netbuffer, sock, &peer_info);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    nb_open(&send_netbuffer, sock, &peer_info);

    *state = netbuffer;

    os_calloc(1, sizeof(wnotify_t), notify);

    send_chunk = 14;

    return 0;
}

static int test_teardown(void ** state) {
    test_mode = 0;

    netbuffer_t *netbuffer = *state;

    close_slot(netbuffer, sock);
    os_free(netbuffer->buffers);
    os_free(netbuffer);
    os_free(send_netbuffer.buffers);
    memset(&send_netbuffer, 0, sizeof(netbuffer_t));

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

    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_function_call(__wrap_rem_inc_send_discarded);

    expect_string(__wrap__mwarn, formatted_msg, "Package dropped. Could not append data into buffer.");

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

void test_nb_queue_nowait_ok(void ** state) {
    netbuffer_t *netbuffer = *state;
    char final_msg[10] = {0};
    ssize_t final_size = snprintf(final_msg, sizeof(final_msg), "4321#pong");

    expect_value(__wrap_wnet_order, value, 5);
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

    assert_int_equal(nb_queue_nowait(netbuffer, sock, "#pong", 5), 0);
}

void test_nb_queue_nowait_full(void ** state) {
    netbuffer_t *netbuffer = *state;
    char final_msg[10] = {0};
    ssize_t final_size = snprintf(final_msg, sizeof(final_msg), "4321#pong");

    expect_value(__wrap_wnet_order, value, 5);
    will_return(__wrap_wnet_order, 0b00110001001100100011001100110100); //1234

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_memory(__wrap_bqueue_push, queue, (bqueue_t *)netbuffer->buffers[sock].bqueue, sizeof(bqueue_t *));
    expect_memory(__wrap_bqueue_push, data, final_msg, final_size);
    expect_value(__wrap_bqueue_push, length, final_size);
    expect_value(__wrap_bqueue_push, flags, BQUEUE_NOFLAG);
    will_return(__wrap_bqueue_push, -1);

    // No sleep, no retry, no warning: the caller decides what a full buffer means
    expect_function_call(__wrap_pthread_mutex_unlock);

    assert_int_equal(nb_queue_nowait(netbuffer, sock, "#pong", 5), -1);
}

void test_nb_queue_nowait_closed(void ** state) {
    netbuffer_t *netbuffer = *state;

    expect_value(__wrap_wnet_order, value, 5);
    will_return(__wrap_wnet_order, 0b00110001001100100011001100110100); //1234

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    // Beyond every slot ever opened
    assert_int_equal(nb_queue_nowait(netbuffer, sock + 100, "#pong", 5), -2);

    expect_value(__wrap_wnet_order, value, 5);
    will_return(__wrap_wnet_order, 0b00110001001100100011001100110100); //1234

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    // A slot below the end that was never opened
    assert_int_equal(nb_queue_nowait(netbuffer, sock - 1, "#pong", 5), -2);
}

void test_nb_set_authenticated(void ** state) {
    netbuffer_t *netbuffer = *state;

    assert_int_equal(netbuffer->unauthenticated, 1);
    assert_false(netbuffer->buffers[sock].authenticated);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    nb_set_authenticated(netbuffer, sock, ++global_counter);

    assert_true(netbuffer->buffers[sock].authenticated);
    assert_int_equal(netbuffer->unauthenticated, 0);

    // Idempotent
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    nb_set_authenticated(netbuffer, sock, ++global_counter);

    // A socket with no open slot is ignored
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    nb_set_authenticated(netbuffer, sock + 100, ++global_counter);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    assert_int_equal(nb_unauthenticated_count(netbuffer), 0);

    // Closing an authenticated connection does not touch the count
    close_slot(netbuffer, sock);
    assert_int_equal(netbuffer->unauthenticated, 0);
}

// A message queued before the fd was closed must not authenticate a new connection accepted on that fd.
void test_nb_set_authenticated_stale_counter(void ** state) {
    netbuffer_t *netbuffer = *state;
    struct sockaddr_storage peer_info = {0};
    size_t stale = ++global_counter;

    close_slot(netbuffer, sock);
    assert_int_equal(fence_fd, sock);
    assert_int_equal(fence_counter, stale);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    nb_open(netbuffer, sock, &peer_info);
    assert_int_equal(netbuffer->unauthenticated, 1);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    nb_set_authenticated(netbuffer, sock, stale);
    assert_false(netbuffer->buffers[sock].authenticated);
    assert_int_equal(netbuffer->unauthenticated, 1);

    // A message of the new connection carries a newer counter
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    nb_set_authenticated(netbuffer, sock, ++global_counter);
    assert_true(netbuffer->buffers[sock].authenticated);
    assert_int_equal(netbuffer->unauthenticated, 0);
}

void test_nb_close_unauthenticated(void ** state) {
    netbuffer_t *netbuffer = *state;

    close_slot(netbuffer, sock);

    assert_int_equal(netbuffer->unauthenticated, 0);
    assert_null(netbuffer->buffers[sock].bqueue);
    assert_null(send_netbuffer.buffers[sock].bqueue);

    // A second close (teardown) finds nothing to release
}

// The fence is set to the current counter, so messages already queued by this connection are older.
void test_nb_close_socket_sets_fence(void ** state) {
    netbuffer_t *netbuffer = *state;

    global_counter = 42;
    close_slot(netbuffer, sock);

    assert_int_equal(fence_fd, sock);
    assert_int_equal(fence_counter, 42);
}

// close() fails with anything but EBADF: Linux frees the descriptor anyway, so both slots go too.
void test_nb_close_socket_close_fails_releases(void ** state) {
    netbuffer_t *netbuffer = *state;

    assert_true(close_socket_ret(netbuffer, sock, -1, EINTR));

    assert_int_equal(netbuffer->unauthenticated, 0);
    assert_null(netbuffer->buffers[sock].bqueue);
    assert_null(send_netbuffer.buffers[sock].bqueue);
}

// EBADF: another close already released the slots, and the number may belong to a new connection.
void test_nb_close_socket_ebadf_leaves_slots(void ** state) {
    netbuffer_t *netbuffer = *state;
    bqueue_t * recv_queue = netbuffer->buffers[sock].bqueue;
    bqueue_t * send_queue = send_netbuffer.buffers[sock].bqueue;

    assert_false(close_socket_ret(netbuffer, sock, -1, EBADF));

    assert_int_equal(netbuffer->unauthenticated, 1);
    assert_ptr_equal(netbuffer->buffers[sock].bqueue, recv_queue);
    assert_ptr_equal(send_netbuffer.buffers[sock].bqueue, send_queue);
}

void test_nb_open_zeroes_new_slots(void ** state) {
    netbuffer_t *netbuffer = *state;
    struct sockaddr_storage peer_info = {0};
    const int other = sock + 5;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    nb_open(netbuffer, other, &peer_info);

    assert_int_equal(netbuffer->max_fd, other);
    assert_int_equal(netbuffer->unauthenticated, 2);
    assert_non_null(netbuffer->buffers[other].bqueue);
    assert_true(netbuffer->buffers[other].opened_at > 0);

    for (int i = sock + 1; i < other; i++) {
        assert_null(netbuffer->buffers[i].bqueue);
        assert_null(netbuffer->buffers[i].data);
        assert_false(netbuffer->buffers[i].authenticated);
        assert_int_equal(netbuffer->buffers[i].opened_at, 0);
    }

    close_slot(netbuffer, other);

    assert_int_equal(netbuffer->unauthenticated, 1);
}

void test_nb_open_reused_slot(void ** state) {
    netbuffer_t *netbuffer = *state;
    struct sockaddr_storage peer_info = {0};

    // The descriptor number comes back while its slot is still open (nb_close_socket() rules this out, but
    // nb_open() keeps it as a safety net): the old queue is released (LeakSanitizer checks it) and the
    // count is not inflated.
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    nb_open(netbuffer, sock, &peer_info);

    assert_int_equal(netbuffer->unauthenticated, 1);
    assert_non_null(netbuffer->buffers[sock].bqueue);
}

void test_nb_collect_unauthenticated(void ** state) {
    netbuffer_t *netbuffer = *state;
    size_t count = 99;
    int * socks;

    netbuffer->buffers[sock].opened_at = 100;

    // Not expired yet
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    socks = nb_collect_unauthenticated(netbuffer, 99, &count);
    assert_null(socks);
    assert_int_equal(count, 0);

    // Expired: collected, slot left untouched for _close_sock() to release
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    socks = nb_collect_unauthenticated(netbuffer, 100, &count);
    assert_non_null(socks);
    assert_int_equal(count, 1);
    assert_int_equal(socks[0], sock);
    assert_int_equal(netbuffer->buffers[sock].opened_at, 100);
    os_free(socks);

    // Authenticated connections are never collected
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    nb_set_authenticated(netbuffer, sock, ++global_counter);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    socks = nb_collect_unauthenticated(netbuffer, 1000, &count);
    assert_null(socks);
    assert_int_equal(count, 0);
}

void test_nb_untracked_buffer_keeps_no_count(void ** state) {
    netbuffer_t *netbuffer = *state;
    struct sockaddr_storage peer_info = {0};
    const int other = sock + 1;

    // The send side: opened and closed like the receive side, but authentication is never marked there
    netbuffer->tracks_authentication = false;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    nb_open(netbuffer, other, &peer_info);
    assert_int_equal(netbuffer->unauthenticated, 1); // only the slot opened while tracking

    close_slot(netbuffer, other);
    close_slot(netbuffer, sock);
    assert_int_equal(netbuffer->unauthenticated, 1); // closes do not touch it either
    assert_int_equal(send_netbuffer.unauthenticated, 0); // the send side never counts
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nb_queue_nowait_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_queue_nowait_full, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_queue_nowait_closed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_set_authenticated, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_set_authenticated_stale_counter, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_close_unauthenticated, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_close_socket_sets_fence, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_close_socket_close_fails_releases, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_close_socket_ebadf_leaves_slots, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_open_zeroes_new_slots, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_open_reused_slot, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_collect_unauthenticated, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_nb_untracked_buffer_keeps_no_count, test_setup, test_teardown),
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
