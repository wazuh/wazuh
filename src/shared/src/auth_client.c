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
#include "os_net.h"
#include <cJSON.h>
#include "wazuhdb_op.h"

// Remove agent. Returns 0 on success or -1 on error.
int auth_remove_agent(int sock, const char *id, int json_format) {
    char buffer[OS_MAXSTR + 1];
    char *output;
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
            result = 0;
        }

        cJSON_Delete(response);
    }

    return result;
}

int auth_remove_agent_code(int sock, const char *id, int *error_code) {
    char buffer[OS_MAXSTR + 1];
    char *output = NULL;
    ssize_t length = 0;
    cJSON *response = NULL;
    cJSON *error = NULL;
    cJSON *request = NULL;
    cJSON *arguments = NULL;
    int retval = -1;

    if (!id) {
        return -1;
    }

    request = cJSON_CreateObject();
    arguments = cJSON_CreateObject();

    cJSON_AddItemToObject(request, "arguments", arguments);
    cJSON_AddStringToObject(request, "function", "remove");
    cJSON_AddStringToObject(arguments, "id", id);

    output = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);

    // Every failure below returns rather than exiting, which is the whole difference from
    // auth_remove_agent(): the caller is a daemon thread that has its own retry schedule.
    if (OS_SendSecureTCP(sock, strlen(output), output) < 0) {
        mdebug1("Cannot send the removal of agent '%s' to authd: %s", id, strerror(errno));
        os_free(output);
        return -1;
    }

    os_free(output);

    if (length = OS_RecvSecureTCP(sock, buffer, OS_MAXSTR), length <= 0) {
        mdebug1("No answer from authd to the removal of agent '%s'.", id);
        return -1;
    }

    buffer[length] = '\0';

    if (response = cJSON_Parse(buffer), !response) {
        mdebug1("Cannot parse authd's answer to the removal of agent '%s'.", id);
        return -1;
    }

    if (error = cJSON_GetObjectItem(response, "error"), error && cJSON_IsNumber(error)) {
        if (error_code) {
            *error_code = error->valueint;
        }

        // An answer is an answer even when it reports a refusal: which code it carries is exactly
        // what the caller asked for, and reading a refusal as a transport failure would cost it
        // the distinction.
        retval = 0;
    } else {
        mdebug1("authd's answer to the removal of agent '%s' carries no status.", id);
    }

    cJSON_Delete(response);

    return retval;
}

#endif
