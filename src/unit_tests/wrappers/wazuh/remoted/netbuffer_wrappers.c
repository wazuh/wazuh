/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WIN32

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <shared.h>
#include "os_net.h"
#include "netbuffer_wrappers.h"

bool __wrap_nb_close_socket(__attribute__((unused)) netbuffer_t * recv,
                            __attribute__((unused)) netbuffer_t * send,
                            int sock) {
    check_expected(sock);

    return mock_type(bool);
}

void __wrap_nb_open(__attribute__((unused)) netbuffer_t * buffer, int sock, const struct sockaddr_storage * peer_info) {
    check_expected(sock);
    check_expected_ptr(peer_info);
}

int __wrap_nb_queue(__attribute__((unused)) netbuffer_t * buffer, int socket, char * crypt_msg, ssize_t msg_size, char * agent_id) {
    check_expected(socket);
    check_expected(crypt_msg);
    check_expected(msg_size);
    check_expected(agent_id);

    return mock();
}

int __wrap_nb_recv(__attribute__((unused)) netbuffer_t * buffer, int sock) {
    check_expected(sock);

    return mock();
}

int __wrap_nb_send(__attribute__((unused)) netbuffer_t * buffer, int sock) {
    check_expected(sock);

    return mock();
}

int __wrap_nb_queue_nowait(__attribute__((unused)) netbuffer_t * buffer, int socket, const char * msg, size_t msg_size) {
    check_expected(socket);
    check_expected(msg);
    check_expected(msg_size);

    return mock();
}

void __wrap_nb_set_authenticated(__attribute__((unused)) netbuffer_t * buffer,
                                 int sock,
                                 __attribute__((unused)) size_t counter) {
    check_expected(sock);
}

size_t __wrap_nb_unauthenticated_count(__attribute__((unused)) netbuffer_t * buffer) {
    return mock();
}

/* Returns a copy of the mocked socket array: the caller frees what it gets back. */
int * __wrap_nb_collect_unauthenticated(__attribute__((unused)) netbuffer_t * buffer, time_t deadline, size_t * count) {
    check_expected(deadline);

    *count = mock_type(size_t);
    const int * socks = mock_ptr_type(const int *);
    int * copy = NULL;

    if (*count > 0) {
        os_malloc(sizeof(int) * *count, copy);
        memcpy(copy, socks, sizeof(int) * *count);
    }

    return copy;
}

#endif
