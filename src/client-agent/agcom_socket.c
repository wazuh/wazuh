/* Agent local socket listener
 * Copyright (C) 2015, Wazuh Inc.
 * January 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include "agentd.h"
#include "os_net/os_net.h"
#include "wazuh_modules/wmodules.h"

#ifndef WIN32

// Global socket fd (created before privilege drop)
static int agcom_socket_fd = -1;

int agcom_init(uid_t uid, gid_t gid) {
    // Create and bind socket BEFORE dropping privileges
    // This function should be called before Privsep_SetUser()

    if (agcom_socket_fd = OS_BindUnixDomainWithPerms(AGENT_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR, uid, gid, 0660), agcom_socket_fd < 0) {
        merror("Unable to bind to socket '%s': (%d) %s.", AGENT_LOCAL_SOCK, errno, strerror(errno));
        return -1;
    }

    mdebug1("Agent local socket created successfully");
    return 0;
}

void * agcom_main(__attribute__((unused)) void * arg) {
    int peer;
    char *buffer = NULL;
    char *response = NULL;
    ssize_t length;
    fd_set fdset;

    if (agcom_socket_fd < 0) {
        merror("Agent local socket not initialized. Socket fd is invalid.");
        return NULL;
    }

    mdebug1("Agent local socket listener ready");

    while (1) {

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(agcom_socket_fd, &fdset);

        switch (select(agcom_socket_fd + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                merror_exit("At agcom_main(): select(): %s", strerror(errno));
            }

            continue;

        case 0:
            continue;
        }

        if (peer = accept(agcom_socket_fd, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                merror("At agcom_main(): accept(): %s", strerror(errno));
            }

            continue;
        }

        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        switch (length = OS_RecvSecureTCP(peer, buffer, OS_MAXSTR), length) {
        case OS_SOCKTERR:
            merror("At agcom_main(): OS_RecvSecureTCP(): response size is bigger than expected");
            break;

        case -1:
            merror("At agcom_main(): OS_RecvSecureTCP(): %s", strerror(errno));
            break;

        case 0:
            mdebug1("Empty message from local client.");
            close(peer);
            break;

        case OS_MAXLEN:
            merror("Received message > %i", MAX_DYN_STR);
            close(peer);
            break;

        default:
            buffer[length] = '\0';
            mdebug2("agcom_main(): received command '%s'", buffer);

            // Process command with agcom_dispatch
            length = agcom_dispatch(buffer, &response);
            if (length > 0 && response) {
                mdebug2("agcom_main(): sending response (%zu bytes)", length);
                OS_SendSecureTCP(peer, length, response);
                os_free(response);
            } else {
                mdebug1("agcom_main(): no response from dispatcher");
            }
            close(peer);
        }
        os_free(buffer);
    }

    mdebug1("Agent local socket listener finished.");

    close(agcom_socket_fd);
    return NULL;
}

#endif
