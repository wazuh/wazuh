/*
 * Wazuh Manager Task producer client
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "manager_task_op.h"
#include "http_op.h"

#include <openssl/sha.h>

#ifdef WAZUH_UNIT_TESTING
#define STATIC
#else
#define STATIC static
#endif

/// Bytes of randomness behind a random task id.
#define MANAGER_TASK_RANDOM_BYTES 16

/**
 * @brief Hash a string into 64 lowercase hex characters.
 *
 * Full width, unlike the agent-task helper this deliberately does not share: that one keeps the
 * first 16 bytes only, and widening it would change ids on a shipping path for no benefit here.
 *
 * @return Caller-owned hex string, or NULL on a bad argument.
 */
STATIC char* manager_task_hash(const char *input) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char *hex = NULL;

    if (!input) {
        return NULL;
    }

    SHA256((const unsigned char *)input, strlen(input), digest);

    os_calloc((SHA256_DIGEST_LENGTH * 2) + 1, sizeof(char), hex);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(hex + (i * 2), 3, "%02x", digest[i]);
    }

    return hex;
}

char* manager_task_id_agent_delete(const char *agent_id, long long journal_seq) {
    char input[OS_SIZE_128];

    if (!agent_id || !*agent_id) {
        return NULL;
    }

    snprintf(input, sizeof(input), "mt:del:%s:%lld", agent_id, journal_seq);

    return manager_task_hash(input);
}

char* manager_task_id_schedule(const char *schedule_id, long long scheduled_run_at) {
    char input[OS_SIZE_128];

    if (!schedule_id || !*schedule_id) {
        return NULL;
    }

    snprintf(input, sizeof(input), "mt:sched:%s:%lld", schedule_id, scheduled_run_at);

    return manager_task_hash(input);
}

char* manager_task_id_random(const char *tag) {
    unsigned char random[MANAGER_TASK_RANDOM_BYTES];
    char input[OS_SIZE_128];
    size_t offset;

    if (!tag || !*tag) {
        return NULL;
    }

    randombytes(random, sizeof(random));

    offset = (size_t)snprintf(input, sizeof(input), "mt:%s:", tag);

    for (size_t i = 0; i < sizeof(random) && offset + 2 < sizeof(input); i++, offset += 2) {
        snprintf(input + offset, 3, "%02x", random[i]);
    }

    return manager_task_hash(input);
}

/// Response capture. The three responses a producer reads are small -- a result and an id, a
/// count, or one row of a type whose payload is a single agent id -- and a truncated body simply
/// fails to parse, which every caller already treats as "could not be determined".
#define MANAGER_TASK_RESPONSE_LEN 16384

/// Connect deadline for the task manager socket, in milliseconds. Separate from the caller's
/// timeout, which bounds the whole round trip: reaching a socket on the same host either works
/// almost immediately or is not going to, and a slow connect is really an absent consumer.
#define MANAGER_TASK_CONNECT_TIMEOUT_MS 2000

/**
 * @brief POST one request to the task manager and return its parsed response.
 *
 * A client per call, not a cached one. The task manager's transport answers one request per
 * connection and closes it, so there is no connection to reuse; what a cached handle would save is
 * a curl_easy_init, measured in microseconds, against the cost of making this function thread-safe
 * for authd, which calls it from more than one thread.
 *
 * @param route Path on the task manager socket.
 * @param parameters Request body. ALWAYS consumed, including on every early return.
 * @param timeout Seconds for the whole round trip; 0 means no deadline.
 * @param[out] http_status Optional: the status the server answered with, so a caller can tell
 *                         "refused" from "unreachable". 0 when the request never got an answer.
 * @return The parsed response object, caller frees, or NULL.
 */
STATIC cJSON* manager_task_request(const char *route, cJSON *parameters, int timeout, long *http_status) {
    char response[MANAGER_TASK_RESPONSE_LEN] = "";
    char url[512] = "";
    uhttp_options_t options = {0};
    uhttp_result_t result = {0};
    uhttp_client_t *client = NULL;
    char *body = NULL;
    cJSON *parsed = NULL;
    int rc = 0;

    if (http_status) {
        *http_status = 0;
    }

    body = cJSON_PrintUnformatted(parameters);
    cJSON_Delete(parameters);

    if (!body) {
        return NULL;
    }

    /* An ABSOLUTE url, not the bare route: libcurl parses it before it consults the socket option,
     * and a path on its own fails the transfer with no HTTP status -- indistinguishable, to the
     * caller below, from a task manager that is not listening. */
    snprintf(url, sizeof(url), "%s%s", WM_TASK_MODULE_URL, route);

    options.unix_socket_path = WM_TASK_MODULE_SOCK;
    options.url = url;
    options.content_type = "application/json";
    options.connect_timeout_ms = MANAGER_TASK_CONNECT_TIMEOUT_MS;
    options.timeout_ms = timeout > 0 ? (long)timeout * 1000 : 0;

    if (client = uhttp_client_new(&options), !client) {
        os_free(body);
        return NULL;
    }

    uhttp_client_set_response_buffer(client, response, sizeof(response) - 1);

    rc = uhttp_post(client, body, strlen(body), &result);

    uhttp_client_free(client);
    os_free(body);

    if (http_status) {
        *http_status = result.http_status;
    }

    /* A non-2xx still carries a body worth parsing: a refused creation answers with a `result`
     * that names WHY, and discarding it here would flatten "the queue is full" into "the request
     * failed", which is the difference between backing off and giving up. */
    if (rc != 0 && result.http_status == 0) {
        mdebug1("Manager task request '%s' did not reach the task manager.", route);
        return NULL;
    }

    if (parsed = cJSON_Parse(response), !parsed) {
        mdebug1("Manager task request '%s' answered something that is not JSON.", route);
        return NULL;
    }

    return parsed;
}

int manager_task_create(const manager_task_request_t *request, int timeout, char **surviving_task_id) {
    cJSON *parameters = NULL;
    cJSON *response = NULL;
    cJSON *item = NULL;
    int outcome = MANAGER_TASK_CREATE_FAILED;

    if (surviving_task_id) {
        *surviving_task_id = NULL;
    }

    if (!request || !request->task_id || !request->task_type || !request->payload) {
        return MANAGER_TASK_CREATE_FAILED;
    }

    parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "task_id", request->task_id);
    cJSON_AddStringToObject(parameters, "task_type", request->task_type);
    cJSON_AddStringToObject(parameters, "payload", request->payload);

    if (request->agent_id) {
        cJSON_AddStringToObject(parameters, "agent_id", request->agent_id);
    }

    cJSON_AddNumberToObject(parameters, "create_time", (double)request->create_time);

    if (request->next_attempt_at > 0) {
        cJSON_AddNumberToObject(parameters, "next_attempt_at", (double)request->next_attempt_at);
    }

    /* Sent, but only honoured for a type the task manager does not recognise. For a registered
     * type its own descriptor decides both, so the queue's policy has one home rather than being
     * a thing a producer could contradict. */
    cJSON_AddBoolToObject(parameters, "coalesce", request->coalesce);

    if (request->max_pending > 0) {
        cJSON_AddNumberToObject(parameters, "max_pending", request->max_pending);
    }

    response = manager_task_request("/v1/manager-tasks", parameters, timeout, NULL);

    if (!response) {
        return MANAGER_TASK_CREATE_FAILED;
    }

    if (item = cJSON_GetObjectItem(response, "result"), item && cJSON_IsString(item)) {
        if (!strcmp(item->valuestring, "created")) {
            outcome = MANAGER_TASK_CREATED;
        } else if (!strcmp(item->valuestring, "coalesced")) {
            outcome = MANAGER_TASK_COALESCED;
        } else if (!strcmp(item->valuestring, "collided")) {
            outcome = MANAGER_TASK_COLLIDED;
        } else if (!strcmp(item->valuestring, "queue_full")) {
            outcome = MANAGER_TASK_QUEUE_FULL;
        }
    }

    if (surviving_task_id && outcome != MANAGER_TASK_CREATE_FAILED) {
        if (item = cJSON_GetObjectItem(response, "task_id"), item && cJSON_IsString(item)) {
            os_strdup(item->valuestring, *surviving_task_id);
        }
    }

    cJSON_Delete(response);

    return outcome;
}

int manager_task_count(const char *task_type, const char *status, int timeout) {
    cJSON *parameters = NULL;
    cJSON *response = NULL;
    cJSON *item = NULL;
    int count = -1;

    if (!task_type || !status) {
        return -1;
    }

    parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "task_type", task_type);
    cJSON_AddStringToObject(parameters, "status", status);

    response = manager_task_request("/v1/manager-tasks/count", parameters, timeout, NULL);

    if (!response) {
        return -1;
    }

    if (item = cJSON_GetObjectItem(response, "count"), item && cJSON_IsNumber(item)) {
        count = item->valueint;
    }

    cJSON_Delete(response);

    return count;
}

int manager_task_agent_status(const char *agent_id, const char *task_type, int timeout) {
    cJSON *parameters = NULL;
    cJSON *response = NULL;
    cJSON *task = NULL;
    cJSON *status = NULL;
    long http_status = 0;
    int outcome = MANAGER_TASK_STATUS_FAILED;

    if (!agent_id || !task_type) {
        return MANAGER_TASK_STATUS_FAILED;
    }

    parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "agent_id", agent_id);
    cJSON_AddStringToObject(parameters, "task_type", task_type);

    response = manager_task_request("/v1/manager-tasks/by-agent", parameters, timeout, &http_status);

    if (!response) {
        return MANAGER_TASK_STATUS_FAILED;
    }

    /* Only a 200 may be read as an answer about the agent. Anything else is the request failing,
     * and a caller that used this to decide whether an agent id may be reused must fail safe
     * rather than conclude "nothing outstanding" from an error. */
    if (http_status != 200) {
        cJSON_Delete(response);
        return MANAGER_TASK_STATUS_FAILED;
    }

    task = cJSON_GetObjectItem(response, "task");

    if (!task) {
        // No row at all. Reachable without any failure: an id enters a caller's pending set at
        // phase 1, OS_WriteKeys then fails, and the row is never created.
        outcome = MANAGER_TASK_STATUS_NONE;
    } else if (status = cJSON_GetObjectItem(task, "status"), status && cJSON_IsString(status)) {
        outcome = (!strcmp(status->valuestring, MANAGER_TASK_STATUS_PENDING) ||
                   !strcmp(status->valuestring, MANAGER_TASK_STATUS_CLAIMED))
                      ? MANAGER_TASK_STATUS_OUTSTANDING
                      : MANAGER_TASK_STATUS_TERMINAL;
    }

    cJSON_Delete(response);

    return outcome;
}
