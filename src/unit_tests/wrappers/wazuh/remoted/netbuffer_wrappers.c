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
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <shared.h>
#include <os_net/os_net.h>
#include "netbuffer_wrappers.h"

int __wrap_nb_close_socket(__attribute__((unused)) netbuffer_t * recv,
                           __attribute__((unused)) netbuffer_t * send,
                           int sock,
                           int * was_unassociated) {
    check_expected(sock);

    int retval = mock();

    if (!retval) {
        *was_unassociated = mock();
    }

    return retval;
}

int __wrap_nb_mark_associated(__attribute__((unused)) netbuffer_t * buffer, int sock) {
    check_expected(sock);

    return mock();
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

#endif
