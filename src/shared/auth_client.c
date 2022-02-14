/*
 * Local Authd client
 * Copyright (C) 2015, Wazuh Inc.
 * May 30, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CLIENT

#include "shared.h"
#include <os_net/os_net.h>
#include <external/cJSON/cJSON.h>
#include "wazuhdb_op.h"

// Remove agent. Returns 0 on success or -1 on error.
int auth_remove_agent(int sock, const char *id, int json_format) {
    char buffer[OS_MAXSTR + 1];
    char *output;
    char wdbquery[OS_SIZE_128];
    char *wdboutput;
    int result = -1;
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

        const char *jsonErrPtr;
        if (response = cJSON_ParseWithOpts(buffer, &jsonErrPtr, 0), !response) {
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
                merror("%d: %s", error->valueint, message ? message->valuestring : "(undefined)");
            }
        } else {
            int wdb_sock = -1;
            int error;

            snprintf(wdbquery, OS_SIZE_128, "wazuhdb remove %s", id);
            os_calloc(OS_SIZE_6144, sizeof(char), wdboutput);
            if (error = wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, OS_SIZE_6144), error) {
                merror("Could not remove the agent %s. Error: %d.", id, error);
            } else {
                result = 0;
            }

            if (wdb_sock >= 0) {
                close(wdb_sock);
            }

            os_free(wdboutput);
        }

        cJSON_Delete(response);
    }

    return result;
}

#endif
