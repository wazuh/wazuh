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

/**
 * @brief Connects to Wazuh-DB socket
 *
 * @return Socket descriptor or -1 if error.
 */
int wdbc_connect() {

    int attempts;
    int wdb_socket = -1;
    char sockname[PATH_MAX + 1];

    if (isChroot()) {
		strcpy(sockname, WDB_LOCAL_SOCK);
	} else {
		strcpy(sockname, DEFAULTDIR WDB_LOCAL_SOCK);
	}

    for (attempts = 1; attempts <= 3 && (wdb_socket = OS_ConnectUnixDomain(sockname, SOCK_STREAM, OS_SIZE_6144)) < 0; attempts++) {
        switch (errno) {
        case ENOENT:
            mtinfo(ARGV0, "Cannot find '%s'. Waiting %d seconds to reconnect.", sockname, attempts);
            break;
        default:
            mtinfo(ARGV0, "Cannot connect to '%s': %s (%d). Waiting %d seconds to reconnect.", sockname, strerror(errno), errno, attempts);
        }
        sleep(attempts);
    }

    if (wdb_socket < 0) {
        mterror(ARGV0, "Unable to connect to socket '%s'.", sockname);
    }

    return wdb_socket;
}


/**
 * @brief Sends query to Wazuh-DB and stores the response.
 *
 * @param[in] sock Client socket descriptor.
 * @param[in] query Query to be sent to Wazuh-DB.
 * @param[out] response Char pointer where the response from Wazuh-DB will be stored.
 * @param[in] len Lenght of the response param.
 * @retval -2 Error in the communication.
 * @retval -1 Error in the response from socket.
 * @retval 0 Success.
 */
int wdbc_query(const int sock, const char *query, char *response, const int len) {

    int size = strlen(query);
    int retval = -2;
    struct timeval timeout = {0, 1000};
    fd_set fdset;
    ssize_t recv_len;

    // Send query to Wazuh DB
    if (OS_SendSecureTCP(sock, size + 1, query) != 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            mterror(ARGV0, "database socket is full");
            goto end;
        } else {
            mterror(ARGV0, "in send (%d) '%s'.", errno, strerror(errno));
            goto end;
        }
    }

    // Wait for socket
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    if (select(sock + 1, &fdset, NULL, NULL, &timeout) < 0) {
        mterror(ARGV0, "in select (%d) '%s'.", errno, strerror(errno));
        goto end;
    }
    retval = -1;

    // Receive response from socket
    recv_len = OS_RecvSecureTCP(sock, response, len);

    switch (recv_len) {
    case OS_SOCKTERR:
        merror("OS_RecvSecureTCP(): response size is bigger than expected");
        break;
    case -1:
        merror("at OS_RecvSecureTCP(): %s (%d)", strerror(errno), errno);
        break;
    default:
        response[recv_len] = '\0';
        retval = 0;
        mdebug1("Got wazuh-db response: %s", response);
    }

end:
    return retval;
}


/**
 * @brief Check connection to Wazuh-DB, sends query and stores the response.
 *
 * @param[in] sock Pointer to the client socket descriptor.
 * @param[in] query Query to be sent to Wazuh-DB.
 * @param[out] response Char pointer where the response from Wazuh-DB will be stored.
 * @param[in] len Lenght of the response param.
 * @retval -2 Error in the communication.
 * @retval -1 Error in the response from socket.
 * @retval 0 Success.
 */
int wdbc_query_ex(int *sock, const char *query, char *response, const int len) {

    int retval = -2;

    // Connect to socket if disconnected
    if (*sock < 0) {
        // Connect
        *sock = wdbc_connect();

        if (*sock < 0) {
            mterror(ARGV0, "Unable to connect to socket '%s'.", WDB_LOCAL_SOCK);
            return retval;
        }
    }

    // Send query to Wazuh DB
    if (retval = wdbc_query(*sock, query, response, len), retval != 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            mterror(ARGV0, "database socket is full");
            return retval;
        } else if (errno == EPIPE) {
            // Retry to connect
            mterror(ARGV0, "Connection with wazuh-db lost. Reconnecting.");
            close(*sock);
            if (*sock = wdbc_connect(), *sock < 0) {
                return retval;
            }
            // Send query
            if (retval = wdbc_query(*sock, query, response, len), retval != 0) {
                return retval;
            }
        } else {
            mterror(ARGV0, "in send (%d) '%s'.", errno, strerror(errno));
            return retval;
        }
    }

    return retval;
}


/**
 * @brief Parse the result of the query to Wazuh-DB
 *
 * @param result Result from the query to Wazuh-DB.
 * @param payload Pointer inside the result where the payload starts.
 * @return Enum wdbc_result.
 */
int wdbc_parse_result(char *result, char **payload) {

    int retval = WDBC_UNKNOWN;
    char *ptr;

    ptr = strchr(result, ' ');

    if (ptr) {
        *ptr = '\0';
        *payload = ++ptr;
    } else {
        *payload = result;
    }

    if (!strcmp(result, "ok")) {
        retval = WDBC_OK;
    } else if (!strcmp(result, "err")) {
        retval = WDBC_ERROR;
    } else if (!strcmp(result, "ign")) {
        retval = WDBC_IGNORE;
    }

    return retval;
}

#endif
