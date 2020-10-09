/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 * April 15, 2019.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

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
            minfo("Cannot find '%s'. Waiting %d seconds to reconnect.", sockname, attempts);
            break;
        default:
            minfo("Cannot connect to '%s': %s (%d). Waiting %d seconds to reconnect.", sockname, strerror(errno), errno, attempts);
        }
        sleep(attempts);
    }

    if (wdb_socket < 0) {
        merror("Unable to connect to socket '%s'.", sockname);
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
 * @post This function will read up to len bytes from Wazuh DB.
 * @post This function will null-terminate response, the last byte may be truncated.
 * @retval -2 Error in the communication.
 * @retval -1 Error in the response from socket.
 * @retval 0 Success.
 */
int wdbc_query(const int sock, const char *query, char *response, const int len) {

    int size = strlen(query);
    int retval = -2;
    ssize_t recv_len;

    // Send query to Wazuh DB
    if (OS_SendSecureTCP(sock, size + 1, query) != 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            merror("database socket is full");
            goto end;
        } else {
            merror("Cannot send message: (%d) '%s'.", errno, strerror(errno));
            goto end;
        }
    }

    retval = -1;

    // Receive response from socket
    recv_len = OS_RecvSecureTCP(sock, response, len);

    switch (recv_len) {
    case OS_SOCKTERR:
        merror("Cannot receive message: response size is bigger than expected");
        break;
    case -1:
        merror("Cannot receive message: %s (%d)", strerror(errno), errno);
        break;
    default:
        response[len - 1] = '\0';
        retval = 0;
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
 * @post This function will read up to len bytes from Wazuh DB.
 * @post This function will null-terminate response, the last byte may be truncated.
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
            merror("Unable to connect to socket '%s'.", WDB_LOCAL_SOCK);
            return retval;
        }
    }

    // Send query to Wazuh DB
    if (retval = wdbc_query(*sock, query, response, len), retval != 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            merror("database socket is full");
            return retval;
        } else if (errno == EPIPE) {
            // Retry to connect
            merror("Connection with wazuh-db lost. Reconnecting.");
            close(*sock);
            if (*sock = wdbc_connect(), *sock < 0) {
                return retval;
            }
            // Send query
            if (retval = wdbc_query(*sock, query, response, len), retval != 0) {
                return retval;
            }
        } else {
            merror("Cannot send message: (%d) '%s'.", errno, strerror(errno));
            return retval;
        }
    }

    return retval;
}


/**
 * @brief Parse the result of the query to Wazuh-DB
 *
 * If payload is not NULL, this function stores the address of the result
 * argument, this is the substring after the first whitespace.
 *
 * @param result Result from the query to Wazuh-DB.
 * @param payload[out] Pointer inside the result where the payload starts.
 * @return Enum wdbc_result.
 */
int wdbc_parse_result(char *result, char **payload) {

    int retval = WDBC_UNKNOWN;
    char *ptr;

    ptr = strchr(result, ' ');

    if (ptr) {
        *ptr++ = '\0';
    } else {
        ptr = result;
    }

    if (payload) {
        *payload = ptr;
    }

    if (!strcmp(result, WDBC_RESULT[WDBC_OK])) {
        retval = WDBC_OK;
    } else if (!strcmp(result, WDBC_RESULT[WDBC_ERROR])) {
        retval = WDBC_ERROR;
    } else if (!strcmp(result, WDBC_RESULT[WDBC_IGNORE])) {
        retval = WDBC_IGNORE;
    } else if (!strcmp(result, WDBC_RESULT[WDBC_DUE])) {
        retval = WDBC_DUE;
    }

    return retval;
}


/**
 * @brief Combine wdbc_query_ex and wdbc_parse_result functions and return a JSON item.
 * 
 * @param[in] sock Pointer to the client socket descriptor.
 * @param[in] query Query to be sent to Wazuh-DB.
 * @param[out] response Char pointer where the response from Wazuh-DB will be stored.
 * @param[in] len Lenght of the response param.
 * @return cJSON* on success or NULL on failure.
 */
cJSON * wdbc_query_parse_json(int *sock, const char *query, char *response, const int len) {
    int result;
    char * arg;
    cJSON * root = NULL;

    result = wdbc_query_ex(sock, query, response, len);
    switch (result) {
    case -2:
        merror("Unable to connect to socket '%s'", WDB_LOCAL_SOCK);
        return NULL;
    case -1:
        merror("No response from wazuh-db.");
        return NULL;
    }

    switch (wdbc_parse_result(response, &arg)) {
    case WDBC_OK:
        break;
    case WDBC_ERROR:
        merror("Bad response from wazuh-db: %s", arg);
        // Fallthrough
    default:
        return NULL;
    }

    root = cJSON_Parse(arg);
    return root;
}

int wdbc_close(int* sock) {
    int ret = 0;
    if (*sock >= 0) {
        ret = close(*sock);
        *sock = -1;
    }
    return ret;
}
