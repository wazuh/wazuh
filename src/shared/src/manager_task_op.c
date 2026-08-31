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
#include "wazuhdb_op.h"

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

/**
 * @brief Send one `task` sub-command and return its parsed payload.
 *
 * The response is `ok <json>` with an `error` member, which wdbc_parse_result() strips down to the
 * JSON. A payload whose `error` is negative is wazuh-db reporting a failure inside the command, as
 * opposed to a malformed request, which comes back as `err`.
 *
 * @return The parsed object, caller frees, or NULL on any failure.
 */
STATIC cJSON* manager_task_query(const char *command, cJSON *parameters, int timeout, int *sock) {
    char *parameters_str = NULL;
    char *query = NULL;
    char response[WDBOUTPUT_SIZE] = "";
    char *payload = NULL;
    cJSON *parsed = NULL;
    cJSON *error = NULL;
    int private_sock = -1;
    size_t query_len;
    int result;

    parameters_str = cJSON_PrintUnformatted(parameters);

    if (!parameters_str) {
        return NULL;
    }

    // Sized to fit rather than a fixed buffer: a payload near the 16 KB cap would be silently
    // truncated by a snprintf into a smaller one, and the row would then be malformed rather than
    // rejected.
    query_len = strlen("task ") + strlen(command) + 1 + strlen(parameters_str) + 1;
    os_calloc(query_len, sizeof(char), query);
    snprintf(query, query_len, "task %s %s", command, parameters_str);
    os_free(parameters_str);

    result = wdbc_query_ex_timeout(sock ? sock : &private_sock, query, response, sizeof(response), timeout);

    os_free(query);

    if (!sock) {
        wdbc_close(&private_sock);
    }

    if (result != 0) {
        mdebug1("Manager task command '%s' did not complete.", command);
        return NULL;
    }

    if (wdbc_parse_result(response, &payload) != WDBC_OK) {
        mdebug1("Manager task command '%s' was refused: %s", command, payload ? payload : "no detail");
        return NULL;
    }

    if (parsed = cJSON_Parse(payload), !parsed) {
        mdebug1("Manager task command '%s' answered something that is not JSON.", command);
        return NULL;
    }

    if (error = cJSON_GetObjectItem(parsed, "error"), error && cJSON_IsNumber(error) && error->valueint < 0) {
        mdebug1("Manager task command '%s' failed inside wazuh-db.", command);
        cJSON_Delete(parsed);
        return NULL;
    }

    return parsed;
}

int manager_task_create(const manager_task_request_t *request, int timeout, int *sock, char **surviving_task_id) {
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

    cJSON_AddBoolToObject(parameters, "coalesce", request->coalesce);

    if (request->max_pending > 0) {
        cJSON_AddNumberToObject(parameters, "max_pending", request->max_pending);
    }

    response = manager_task_query("create_manager_task", parameters, timeout, sock);

    cJSON_Delete(parameters);

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

int manager_task_count(const char *task_type, const char *status, int timeout, int *sock) {
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

    response = manager_task_query("count_manager_tasks", parameters, timeout, sock);

    cJSON_Delete(parameters);

    if (!response) {
        return -1;
    }

    if (item = cJSON_GetObjectItem(response, "count"), item && cJSON_IsNumber(item)) {
        count = item->valueint;
    }

    cJSON_Delete(response);

    return count;
}

int manager_task_agent_status(const char *agent_id, const char *task_type, int timeout, int *sock) {
    cJSON *parameters = NULL;
    cJSON *response = NULL;
    cJSON *task = NULL;
    cJSON *status = NULL;
    int outcome = MANAGER_TASK_STATUS_FAILED;

    if (!agent_id || !task_type) {
        return MANAGER_TASK_STATUS_FAILED;
    }

    parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "agent_id", agent_id);
    cJSON_AddStringToObject(parameters, "task_type", task_type);

    response = manager_task_query("get_manager_task_by_agent", parameters, timeout, sock);

    cJSON_Delete(parameters);

    if (!response) {
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

