/*
 * Local Authd client
 * Copyright (C) 2015-2019, Wazuh Inc.
 * May 30, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include <os_net/os_net.h>
#include <external/cJSON/cJSON.h>

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

    if (OS_SendSecureTCP(sock, strlen(output), output) < 0) {
        merror_exit("OS_SendSecureTCP(): %s", strerror(errno));
    }

    cJSON_Delete(request);
    free(output);

    if (length = OS_RecvSecureTCP(sock, buffer, OS_MAXSTR), length < 0) {
        merror_exit("OS_RecvSecureTCP(): %s", strerror(errno));
    } else if (length == 0) {
        merror_exit("Empty message from local server.");
    } else {
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
