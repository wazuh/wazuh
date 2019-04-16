/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * April 15, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CLIENT

#include "wazuhdb_op.h"


int wdb_send_query(char *wazuhdb_query, char **output) {
    struct timeval timeout = {0, 1000};
    fd_set fdset;
    char response[OS_SIZE_6144];
    int wdb_socket = -1;
    int size = strlen(wazuhdb_query);
    int retval = -2;
    int attempts;

    // Connect to socket if disconnected
    if (wdb_socket < 0) {
        for (attempts = 1; attempts <= 3 && (wdb_socket = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_SIZE_6144)) < 0; attempts++) {
            switch (errno) {
            case ENOENT:
                mtinfo(ARGV0, "Cannot find '%s'. Waiting %d seconds to reconnect.", WDB_LOCAL_SOCK, attempts);
                break;
            default:
                mtinfo(ARGV0, "Cannot connect to '%s': %s (%d). Waiting %d seconds to reconnect.", WDB_LOCAL_SOCK, strerror(errno), errno, attempts);
            }
            sleep(attempts);
        }

        if (wdb_socket < 0) {
            mterror(ARGV0, "Unable to connect to socket '%s'.", WDB_LOCAL_SOCK);
            return retval;
        }
    }

    // Send query to Wazuh DB
    if (OS_SendSecureTCP(wdb_socket, size + 1, wazuhdb_query) != 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            mterror(ARGV0, "database socket is full");
        } else if (errno == EPIPE) {
            // Retry to connect
            mterror(ARGV0, "Connection with wazuh-db lost. Reconnecting.");
            close(wdb_socket);

            if (wdb_socket = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_SIZE_6144), wdb_socket < 0) {
                switch (errno) {
                case ENOENT:
                    mterror(ARGV0, "Cannot find '%s'. Please check that Wazuh DB is running.", WDB_LOCAL_SOCK);
                    break;
                default:
                    mterror(ARGV0, "Cannot connect to '%s': %s (%d)", WDB_LOCAL_SOCK, strerror(errno), errno);
                }
                return retval;
            }

            if (OS_SendSecureTCP(wdb_socket, size + 1, wazuhdb_query)) {
                mterror(ARGV0, "in send reattempt (%d) '%s'.", errno, strerror(errno));
                return retval;
            }
        } else {
            mterror(ARGV0, "in send (%d) '%s'.", errno, strerror(errno));
            return retval;
        }
    }

    // Wait for socket
    FD_ZERO(&fdset);
    FD_SET(wdb_socket, &fdset);

    if (select(wdb_socket + 1, &fdset, NULL, NULL, &timeout) < 0) {
        mterror(ARGV0, "in select (%d) '%s'.", errno, strerror(errno));
        return retval;
    }
    retval = -1;

    // Receive response from socket
    if (OS_RecvSecureTCP(wdb_socket, response, OS_SIZE_6144 - 1) > 0) {
        os_strdup(response, *output);

        if (response[0] == 'o' && response[1] == 'k') {
            retval = 0;
        } else {
            mterror(ARGV0, "Bad response '%s'.", response);
        }
    } else {
        mterror(ARGV0, "no response from wazuh-db.");
    }

    return retval;
}

#endif
