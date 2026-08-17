/* Durable VD feed offset registry client (agentd side)
 * Copyright (C) 2015, Wazuh Inc.
 * August 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "vd_offset_client.h"

#include "os_net.h"
#include "cJSON.h"

#ifdef WIN32
#include "wmodules.h"
#endif

/* Bounded, same rationale as task_registry_client.c: agent-info is a local,
 * normally-responsive process, but agentd must never hang indefinitely on it. */
#define VD_OFFSET_RECV_TIMEOUT_S 5

#ifndef WIN32
static bool vd_offset_send_query(const char *query, char *response, size_t response_cap) {
    int sock = -1;
    ssize_t recv_len;

    sock = OS_ConnectUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
    if (sock < 0) {
        mdebug1("vd_offset_client: could not connect to '%s': %s (%d).",
                WM_LOCAL_SOCK, strerror(errno), errno);
        return false;
    }

    if (OS_SetRecvTimeout(sock, VD_OFFSET_RECV_TIMEOUT_S, 0) < 0) {
        mdebug2("vd_offset_client: OS_SetRecvTimeout failed: %s (%d).", strerror(errno), errno);
    }

    if (OS_SendSecureTCP(sock, strlen(query), query) < 0) {
        merror("vd_offset_client: OS_SendSecureTCP failed: %s (%d).", strerror(errno), errno);
        close(sock);
        return false;
    }

    recv_len = OS_RecvSecureTCP(sock, response, response_cap - 1);
    close(sock);

    if (recv_len <= 0) {
        merror("vd_offset_client: no/invalid response from agent-info (recv_len=%zd).", recv_len);
        return false;
    }

    response[(size_t)recv_len < response_cap - 1 ? (size_t)recv_len : response_cap - 1] = '\0';
    return true;
}
#else
static bool vd_offset_send_query(const char *command, char *response, size_t response_cap) {
    char *output = NULL;

    wm_module_query_json_ex("agent-info", command, &output);

    if (!output) {
        merror("vd_offset_client: agent-info query returned no output.");
        return false;
    }

    strncpy(response, output, response_cap - 1);
    response[response_cap - 1] = '\0';
    os_free(output);
    return true;
}
#endif

static bool parse_error_field(const cJSON *root, int *out_error) {
    const cJSON *error = cJSON_GetObjectItem(root, "error");

    if (!error || !cJSON_IsNumber(error)) {
        return false;
    }

    *out_error = error->valueint;
    return true;
}

bool vd_offset_client_observe(uint64_t offset, bool *out_changed, bool *out_pending,
                              uint64_t *out_pending_offset) {
    char query[OS_MAXSTR];
    char response[OS_MAXSTR + 1] = {0};
    bool ok = false;

    if (out_changed) {
        *out_changed = false;
    }
    if (out_pending) {
        *out_pending = false;
    }
    if (out_pending_offset) {
        *out_pending_offset = 0;
    }

#ifndef WIN32
    snprintf(query, sizeof(query),
             "query agent-info {\"command\":\"vd_offset_observe\",\"offset\":%llu}",
             (unsigned long long)offset);
#else
    snprintf(query, sizeof(query),
             "{\"command\":\"vd_offset_observe\",\"offset\":%llu}",
             (unsigned long long)offset);
#endif

    if (!vd_offset_send_query(query, response, sizeof(response))) {
        return false;
    }

    cJSON *root = cJSON_Parse(response);
    if (!root) {
        mdebug1("vd_offset_client: malformed response from agent-info: '%s'.", response);
        return false;
    }

    int error_code = -1;
    if (!parse_error_field(root, &error_code) || error_code != 0) {
        const cJSON *message = cJSON_GetObjectItem(root, "message");
        mdebug1("vd_offset_client: agent-info reported an error (%d): %s", error_code,
                (message && cJSON_IsString(message) && message->valuestring) ? message->valuestring : "?");
        cJSON_Delete(root);
        return false;
    }

    const cJSON *data = cJSON_GetObjectItem(root, "data");
    if (data) {
        const cJSON *changed_item = cJSON_GetObjectItem(data, "changed");
        if (out_changed && changed_item && cJSON_IsBool(changed_item)) {
            *out_changed = cJSON_IsTrue(changed_item);
        }

        const cJSON *pending_item = cJSON_GetObjectItem(data, "pending");
        if (out_pending && pending_item && cJSON_IsBool(pending_item)) {
            *out_pending = cJSON_IsTrue(pending_item);
        }

        const cJSON *pending_offset_item = cJSON_GetObjectItem(data, "pending_offset");
        if (out_pending_offset && pending_offset_item && cJSON_IsNumber(pending_offset_item)) {
            *out_pending_offset = (uint64_t)pending_offset_item->valuedouble;
        }
    }

    ok = true;
    cJSON_Delete(root);
    return ok;
}

bool vd_offset_client_clear_pending(uint64_t offset) {
    char query[OS_MAXSTR];
    char response[OS_MAXSTR + 1] = {0};

#ifndef WIN32
    snprintf(query, sizeof(query),
             "query agent-info {\"command\":\"vd_offset_clear_pending\",\"offset\":%llu}",
             (unsigned long long)offset);
#else
    snprintf(query, sizeof(query),
             "{\"command\":\"vd_offset_clear_pending\",\"offset\":%llu}",
             (unsigned long long)offset);
#endif

    if (!vd_offset_send_query(query, response, sizeof(response))) {
        return false;
    }

    cJSON *root = cJSON_Parse(response);
    if (!root) {
        mdebug1("vd_offset_client: malformed response from agent-info: '%s'.", response);
        return false;
    }

    int error_code = -1;
    if (!parse_error_field(root, &error_code) || error_code != 0) {
        cJSON_Delete(root);
        return false;
    }

    bool cleared = false;
    const cJSON *data = cJSON_GetObjectItem(root, "data");
    if (data) {
        const cJSON *cleared_item = cJSON_GetObjectItem(data, "cleared");
        if (cleared_item && cJSON_IsBool(cleared_item)) {
            cleared = cJSON_IsTrue(cleared_item);
        }
    }

    cJSON_Delete(root);
    return cleared;
}
