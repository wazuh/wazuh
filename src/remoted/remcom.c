/* Remote request listener
 * Copyright (C) 2015, Wazuh Inc.
 * May 16, 2022.
 *
 * This program is os_free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

#include <shared.h>
#include "os_net/os_net.h"
#include "remoted.h"
#include "state.h"

typedef enum _error_codes {
    ERROR_OK = 0,
    ERROR_INVALID_INPUT,
    ERROR_EMPTY_COMMAND,
    ERROR_UNRECOGNIZED_COMMAND
} error_codes;

const char * error_messages[] = {
    [ERROR_OK] = "ok",
    [ERROR_INVALID_INPUT] = "Invalid JSON input",
    [ERROR_EMPTY_COMMAND] = "Empty command",
    [ERROR_UNRECOGNIZED_COMMAND] = "Unrecognized command"
};

/**
 * Format message into the response format
 * @param error_code code error
 * @param message string message of the error
 * @param data_json data to return from request
 * @return string meessage with the response format
 * */
STATIC char* remcom_output_builder(int error_code, const char* message, cJSON* data_json);

/**
 * @brief Check and dexecute the input request
 * @param command message received from api
 * @param output the response to send
 * @return the size of the string "output" containing the configuration
 */
STATIC size_t remcom_dispatch(char * command, char ** output);


STATIC char* remcom_output_builder(int error_code, const char* message, cJSON* data_json) {
    cJSON* root = cJSON_CreateObject();

    cJSON_AddNumberToObject(root, "error", error_code);
    cJSON_AddStringToObject(root, "message", message);
    cJSON_AddItemToObject(root, "data", data_json);

    char *msg_string = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    return msg_string;
}

STATIC size_t remcom_dispatch(char * request, char ** output) {
    cJSON *request_json = NULL;
    cJSON *command_json = NULL;
    const char *json_err;

    if (request_json = cJSON_ParseWithOpts(request, &json_err, 0), !request_json) {
        *output = remcom_output_builder(ERROR_INVALID_INPUT, error_messages[ERROR_INVALID_INPUT], NULL);
        return strlen(*output);
    }

    if (command_json = cJSON_GetObjectItem(request_json, "command"), cJSON_IsString(command_json)) {
        if (strcmp(command_json->valuestring, "getstats") == 0) {
            *output = remcom_output_builder(ERROR_OK, error_messages[ERROR_OK], rem_create_state_json());
        } else {
            *output = remcom_output_builder(ERROR_UNRECOGNIZED_COMMAND, error_messages[ERROR_UNRECOGNIZED_COMMAND], NULL);
        }
    } else {
        *output = remcom_output_builder(ERROR_EMPTY_COMMAND, error_messages[ERROR_EMPTY_COMMAND], NULL);
    }

    return strlen(*output);
}

void * remcom_main(__attribute__((unused)) void * arg) {
    int sock;
    int peer;
    char *buffer = NULL;
    char *response = NULL;
    ssize_t length;
    fd_set fdset;

    mdebug1("Local requests thread ready");

    if (sock = OS_BindUnixDomain(REMOTE_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror("Unable to bind to socket '%s': (%d) %s.", REMOTE_LOCAL_SOCK, errno, strerror(errno));
        return NULL;
    }

    while (1) {

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                merror_exit("At select(): %s", strerror(errno));
            }

            continue;

        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                merror("At accept(): %s", strerror(errno));
            }

            continue;
        }
        os_calloc(OS_MAXSTR, sizeof(char), buffer);

        switch (length = OS_RecvSecureTCP(peer, buffer, OS_MAXSTR), length) {
        case OS_SOCKTERR:
            merror("At OS_RecvSecureTCP(): response size is bigger than expected");
            break;

        case -1:
            merror("At OS_RecvSecureTCP: %s", strerror(errno));
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
            length = remcom_dispatch(buffer, &response);
            OS_SendSecureTCP(peer, length, response);
            os_free(response);
            close(peer);
        }
        os_free(buffer);
    }

    mdebug1("Local server thread finished.");

    close(sock);
    return NULL;
}
