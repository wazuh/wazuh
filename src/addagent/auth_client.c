/*
 * Local Authd client
 * Copyright (C) 2017 Wazuh Inc.
 * May 30, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "manage_agents.h"
#include <os_net/os_net.h>
#include <external/cJSON/cJSON.h>

// Connect to Agentd. Returns socket or -1 on error.
int auth_connect() {
    return OS_ConnectUnixDomain(AUTH_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
}

// Close socket if valid.
int auth_close(int sock) {
    return (sock >= 0) ? close(sock) : 0;
}

// Add agent. Returns 0 on success or -1 on error.
int auth_add_agent(int sock, char *id, const char *name, const char *ip, int force, int json_format) {
    char buffer[OS_MAXSTR + 1];
    char * output;
    int result;
    ssize_t length;
    cJSON * response;
    cJSON * error;
    cJSON * message;
    cJSON * data;
    cJSON * data_id;
    cJSON * request = cJSON_CreateObject();
    cJSON * arguments = cJSON_CreateObject();

    cJSON_AddItemToObject(request, "arguments", arguments);
    cJSON_AddStringToObject(request, "function", "add");
    cJSON_AddStringToObject(arguments, "name", name);
    cJSON_AddStringToObject(arguments, "ip", ip);

    if (force >= 0) {
        cJSON_AddNumberToObject(arguments, "force", force);
    }

    output = cJSON_PrintUnformatted(request);
    send(sock, output, strlen(output), 0);
    cJSON_Delete(request);
    free(output);

    switch (length = recv(sock, buffer, OS_MAXSTR, 0), length) {
    case -1:
        ErrorExit("%s: ERROR: recv(): %s", __local_name, strerror(errno));
        break;

    case 0:
        ErrorExit("%s: ERROR: empty message from local server.", __local_name);
        break;

    default:
        buffer[length] = '\0';

        // Decode response

        if (response = cJSON_Parse(buffer), !response) {
            ErrorExit("%s: ERROR: Parsing JSON response.", __local_name);
        }

        // Detect error condition

        if (error = cJSON_GetObjectItem(response, "error"), !error) {
            ErrorExit("%s: ERROR: No such status from response.", __local_name);
        } else if (error->valueint > 0) {
            if (json_format) {
                printf("%s", buffer);
            } else {
                message = cJSON_GetObjectItem(response, "message");
                merror("%s: ERROR %d: %s", __local_name, error->valueint, message ? message->valuestring : "(undefined)");
            }

            result = -1;
        } else {
            if (data = cJSON_GetObjectItem(response, "data"), !data) {
                ErrorExit("%s: ERROR: No data received.", __local_name);
            }

            if (data_id = cJSON_GetObjectItem(data, "id"), !data) {
                ErrorExit("%s: ERROR: No id received.", __local_name);
            }

            strncpy(id, data_id->valuestring, FILE_SIZE);
            id[FILE_SIZE] = '\0';
            result = 0;
        }

        cJSON_Delete(response);
    }

    return result;
}

// Remove agent. Returns 0 on success or -1 on error.
int auth_remove_agent(int sock, const char *id, int json_format) {
    char buffer[OS_MAXSTR + 1];
    char *output;
    int result;
    ssize_t length;
    cJSON *response;
    cJSON *error;
    cJSON *message;
    cJSON *request = cJSON_CreateObject();
    cJSON *arguments = cJSON_CreateObject();

    cJSON_AddItemToObject(request, "arguments", arguments);
    cJSON_AddStringToObject(request, "function", "remove");
    cJSON_AddStringToObject(arguments, "id", id);

    output = cJSON_PrintUnformatted(request);
    send(sock, output, strlen(output), 0);
    cJSON_Delete(request);
    free(output);

    switch (length = recv(sock, buffer, OS_MAXSTR, 0), length) {
    case -1:
        ErrorExit("%s: ERROR: recv(): %s", __local_name, strerror(errno));
        break;

    case 0:
        ErrorExit("%s: DEBUG: empty message from local server.", __local_name);
        break;

    default:
        buffer[length] = '\0';

        // Decode response

        if (response = cJSON_Parse(buffer), !response) {
            ErrorExit("%s: ERROR: Parsing JSON response.", __local_name);
        }

        // Detect error condition

        if (error = cJSON_GetObjectItem(response, "error"), !error) {
            ErrorExit("%s: ERROR: No such status from response.", __local_name);
        } else if (error->valueint > 0) {
            if (json_format) {
                printf("%s", buffer);
            } else {
                message = cJSON_GetObjectItem(response, "message");
                merror("%s: ERROR %d: %s", __local_name, error->valueint, message ? message->valuestring : "(undefined)");
            }

            result = -1;
        } else {
            result = 0;
        }

        cJSON_Delete(response);
    }


    return result;
}
