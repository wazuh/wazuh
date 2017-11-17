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
#ifndef WIN32
    return OS_ConnectUnixDomain(AUTH_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
#else
    return -1;
#endif
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

    if (send(sock, output, strlen(output), 0) < 0) {
        merror_exit("send(): %s", strerror(errno));
    }

    cJSON_Delete(request);
    free(output);

    switch (length = recv(sock, buffer, OS_MAXSTR, 0), length) {
    case -1:
        merror_exit("recv(): %s", strerror(errno));
        break;

    case 0:
        merror_exit("Empty message from local server.");
        break;

    default:
        buffer[length] = '\0';

        // Decode response

        if (response = cJSON_Parse(buffer), !response) {
            merror_exit("Parsing JSON response.");
        }

        // Detect error condition

        if (error = cJSON_GetObjectItem(response, "error"), !error) {
            merror_exit("No such status from response.");
        } else if (error->valueint > 0) {
            if (json_format) {
                printf("%s", buffer);
            } else {
                message = cJSON_GetObjectItem(response, "message");
                merror("ERROR %d: %s", error->valueint, message ? message->valuestring : "(undefined)");
            }

            result = -1;
        } else {
            if (data = cJSON_GetObjectItem(response, "data"), !data) {
                merror_exit("No data received.");
            }

            if (data_id = cJSON_GetObjectItem(data, "id"), !data) {
                merror_exit("No id received.");
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

    if (send(sock, output, strlen(output), 0) < 0) {
        merror_exit("send(): %s", strerror(errno));
    }

    cJSON_Delete(request);
    free(output);

    switch (length = recv(sock, buffer, OS_MAXSTR, 0), length) {
    case -1:
        merror_exit("recv(): %s", strerror(errno));
        break;

    case 0:
        merror_exit("Empty message from local server.");
        break;

    default:
        buffer[length] = '\0';

        // Decode response

        if (response = cJSON_Parse(buffer), !response) {
            merror_exit("Parsing JSON response.");
        }

        // Detect error condition

        if (error = cJSON_GetObjectItem(response, "error"), !error) {
            merror_exit("No such status from response.");
        } else if (error->valueint > 0) {
            if (json_format) {
                printf("%s", buffer);
            } else {
                message = cJSON_GetObjectItem(response, "message");
                merror("ERROR %d: %s", error->valueint, message ? message->valuestring : "(undefined)");
            }

            result = -1;
        } else {
            result = 0;
        }

        cJSON_Delete(response);
    }


    return result;
}
