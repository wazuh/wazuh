/* Durable task_id registry client (agentd side)
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "task_registry_client.h"

#include "os_net.h"
#include "cJSON.h"

#ifdef WIN32
#include "wmodules.h"
#endif

/* Bounded: agent-info is a local, normally-responsive process, but agentd
 * must never hang indefinitely on it -- a stalled/dead modulesd must not
 * stall the /control notify cycle for longer than this. */
#define TASK_REGISTRY_RECV_TIMEOUT_S 5

/* Parses a response of the standard module-query envelope
 * (module_query_errors.h, src/wazuh_modules/src/wm_agent_info.c's
 * wm_agent_info_query(): {"error":0,"data":{"new":true|false}} on success,
 * {"error":<code>,"message":"..."} otherwise -- the same shape SCA/
 * Syscollector's own query handlers use, so this is not a bespoke protocol.
 * {"error":0,"data":{"new":true}} -> NEW; {"error":0,"data":{"new":false}} ->
 * DUPLICATE (agent-info explicitly confirmed this exact id was already seen);
 * anything else (malformed JSON, a non-zero error code) -> ERROR: agent-info
 * itself is telling us something went wrong, not that this is a duplicate --
 * distinct from DUPLICATE so a real registry failure is never miscounted as one. */
static task_registry_result_t parse_check_and_record_response(const char *response) {
    if (!response) {
        return TASK_REGISTRY_RESULT_ERROR;
    }

    cJSON *root = cJSON_Parse(response);
    if (!root) {
        mdebug1("task_registry_client: malformed response from agent-info: '%s'.", response);
        return TASK_REGISTRY_RESULT_ERROR;
    }

    const cJSON *error = cJSON_GetObjectItem(root, "error");
    task_registry_result_t result;

    if (error && cJSON_IsNumber(error) && error->valueint == 0) {
        const cJSON *data = cJSON_GetObjectItem(root, "data");
        const cJSON *is_new_item = data ? cJSON_GetObjectItem(data, "new") : NULL;
        bool is_new = is_new_item && cJSON_IsBool(is_new_item) && cJSON_IsTrue(is_new_item);
        result = is_new ? TASK_REGISTRY_RESULT_NEW : TASK_REGISTRY_RESULT_DUPLICATE;
    } else {
        const cJSON *message = cJSON_GetObjectItem(root, "message");
        mdebug1("task_registry_client: agent-info reported an error (%d): %s",
                error && cJSON_IsNumber(error) ? error->valueint : -1,
                (message && cJSON_IsString(message) && message->valuestring) ? message->valuestring : "?");
        result = TASK_REGISTRY_RESULT_ERROR;
    }

    cJSON_Delete(root);
    return result;
}

#ifndef WIN32
/* Linux/macOS: agent-info runs in wazuh-modulesd, a separate process from
 * agentd, so this is a local Unix-domain round trip over the existing wmcom
 * request socket (WM_LOCAL_SOCK) -- the same generic per-module query verb
 * ("query <module_name> <args>") wmcom_dispatch() already supports
 * (src/wazuh_modules/src/wmcom.c / wmodules.c:wm_module_query), reused here
 * rather than inventing a dedicated socket. */
static task_registry_result_t task_registry_check_and_record_posix(const char *task_id) {
    char query[OS_MAXSTR];
    int sock = -1;
    char response[OS_MAXSTR + 1] = {0};
    ssize_t recv_len;

    snprintf(query, sizeof(query),
             "query agent-info {\"command\":\"task_check_and_record\",\"task_id\":\"%s\"}",
             task_id);

    sock = OS_ConnectUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
    if (sock < 0) {
        mdebug1("task_registry_client: could not connect to '%s': %s (%d); "
                "treating task %s as non-dispatchable (fail closed).",
                WM_LOCAL_SOCK, strerror(errno), errno, task_id);
        return TASK_REGISTRY_RESULT_ERROR;
    }

    if (OS_SetRecvTimeout(sock, TASK_REGISTRY_RECV_TIMEOUT_S, 0) < 0) {
        mdebug2("task_registry_client: OS_SetRecvTimeout failed: %s (%d).", strerror(errno), errno);
    }

    if (OS_SendSecureTCP(sock, strlen(query), query) < 0) {
        merror("task_registry_client: OS_SendSecureTCP failed for task %s: %s (%d).",
               task_id, strerror(errno), errno);
        close(sock);
        return TASK_REGISTRY_RESULT_ERROR;
    }

    recv_len = OS_RecvSecureTCP(sock, response, OS_MAXSTR);
    close(sock);

    if (recv_len <= 0) {
        merror("task_registry_client: no/invalid response from agent-info for task %s "
               "(recv_len=%zd); treating as non-dispatchable (fail closed).",
               task_id, recv_len);
        return TASK_REGISTRY_RESULT_ERROR;
    }

    response[recv_len < OS_MAXSTR ? recv_len : OS_MAXSTR] = '\0';
    return parse_check_and_record_response(response);
}
#else
/* Windows: agentd and the wazuh_modules (including agent-info) run in the
 * same service process (src/win32/win_service.c), so this is an in-process
 * call through the same generic query path used elsewhere in-process
 * (wm_module_query_json_ex -> wm_find_module("agent-info") ->
 * module->context->query(...)), no socket involved. */
static task_registry_result_t task_registry_check_and_record_win(const char *task_id) {
    char command[OS_MAXSTR];
    char *output = NULL;
    task_registry_result_t result;

    snprintf(command, sizeof(command),
             "{\"command\":\"task_check_and_record\",\"task_id\":\"%s\"}", task_id);

    wm_module_query_json_ex("agent-info", command, &output);

    if (!output) {
        merror("task_registry_client: agent-info query returned no output for task %s; "
               "treating as non-dispatchable (fail closed).", task_id);
        return TASK_REGISTRY_RESULT_ERROR;
    }

    result = parse_check_and_record_response(output);
    os_free(output);
    return result;
}
#endif

task_registry_result_t task_registry_check_and_record(const char *task_id) {
    if (!task_id || !*task_id) {
        return TASK_REGISTRY_RESULT_ERROR;
    }

#ifndef WIN32
    return task_registry_check_and_record_posix(task_id);
#else
    return task_registry_check_and_record_win(task_id);
#endif
}
