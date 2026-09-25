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
#include "module_query_errors.h"
#endif

/* Bounded, same rationale as task_registry_client.c: agent-info is a local,
 * normally-responsive process, but agentd must never hang indefinitely on it. */
#define VD_OFFSET_RECV_TIMEOUT_S 5

/* The very first Notify after agentd starts races modulesd's own startup, on both platforms --
 * just through a different transport, so it needs a different signal for "not up yet" below.
 *
 * POSIX: the connect targets WM_LOCAL_SOCK, which agent-info (inside modulesd, a separate
 * process there) does not open until modulesd's startup_gate releases it -- gated on the
 * config_hash carried in that SAME first Notify response (startup_gate_check_manager_config_hash(),
 * processed a few lines earlier in the same handleNotifyBody() call this ultimately comes from).
 *
 * Windows: agentd and every wazuh_modules wodle (including agent-info) run as threads of the
 * same service process (src/win32/win_service.c) -- there is no socket to connect, but the same
 * race exists one layer up: wm_module_query_json_ex()'s wm_find_module("agent-info") answers
 * immediately with MQ_ERR_MODULE_NOT_FOUND, no wait, if agent-info has not registered itself
 * into the module list yet.
 *
 * Either way: the one response that carries a real (non-zero) vd_feed_offset is, on every fresh
 * agent, guaranteed to find nobody listening/registered yet on a single attempt -- it used to be
 * silently dropped on POSIX, leaving syscollector's first VD sync to race an empty
 * metadata_provider (a manager 409 version_mismatch). A short, bounded retry closes that window
 * on the POSIX branch below; the identical race was left open on the WIN32 branch below until it
 * got the same treatment. Bounded, not indefinite: at most VD_OFFSET_CONNECT_RETRIES attempts,
 * VD_OFFSET_CONNECT_RETRY_DELAY_US apart, so a genuinely-unavailable agent-info (not just "not
 * started yet") still costs only a small, known, one-shot-comparable tax per notify -- the loop
 * breaks on the first success, so the steady-state case (modulesd already up, the overwhelming
 * majority of calls over an agent's lifetime) pays nothing extra at all. */
#define VD_OFFSET_CONNECT_RETRIES 10
#define VD_OFFSET_CONNECT_RETRY_DELAY_US 300000 /* 300 ms; ~2.7s worst case across all retries */

#ifdef WIN32
/* Wider budget than the POSIX constants above: live-verified that agent-info's module
 * registration on Windows can take noticeably longer than a POSIX modulesd's socket-open --
 * one clean-install run measured ~4s between the first Notify (carrying the real offset) and
 * agent-info's own "Started" log line, already past VD_OFFSET_CONNECT_RETRIES/_DELAY_US's 2.7s
 * budget and still producing the 409 this whole retry exists to prevent. Windows loads/verifies
 * several separate DLLs per wodle (Authenticode checks against unsigned dev builds add real,
 * measured latency here) where POSIX's modulesd is a single process already listening once its
 * socket exists, so the two platforms' realistic "not ready yet" windows are not the same order
 * of magnitude. ~9s worst case, still bounded, still free in the steady state (loop breaks on
 * first success). */
#define VD_OFFSET_WIN_LOOKUP_RETRIES 30
#define VD_OFFSET_WIN_LOOKUP_RETRY_DELAY_US 300000
#endif

/* Shared by both branches below: pulls the "error" field an agent-info (or, on Windows, the
 * module-query dispatcher itself) JSON response carries. */
static bool parse_error_field(const cJSON *root, int *out_error) {
    const cJSON *error = cJSON_GetObjectItem(root, "error");

    if (!error || !cJSON_IsNumber(error)) {
        return false;
    }

    *out_error = error->valueint;
    return true;
}

#ifndef WIN32
static bool vd_offset_send_query(const char *query, char *response, size_t response_cap) {
    int sock = -1;
    ssize_t recv_len;
    int attempt;

    for (attempt = 0; attempt < VD_OFFSET_CONNECT_RETRIES; attempt++) {
        sock = OS_ConnectUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
        if (sock >= 0) {
            break;
        }

        if (attempt + 1 < VD_OFFSET_CONNECT_RETRIES) {
            usleep(VD_OFFSET_CONNECT_RETRY_DELAY_US);
        }
    }

    if (sock < 0) {
        mdebug1("vd_offset_client: could not connect to '%s' after %d attempt(s): %s (%d).",
                WM_LOCAL_SOCK, VD_OFFSET_CONNECT_RETRIES, strerror(errno), errno);
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
/* True only for the specific, transient "agent-info hasn't registered itself into the module
 * list yet" answer -- never for a genuine, lasting error (bad JSON, unsupported query, disabled
 * module, ...), which the retry below must not loop on. */
static bool vd_offset_is_module_not_registered(const char *json) {
    cJSON *root = cJSON_Parse(json);
    if (!root) {
        return false;
    }

    int error_code = -1;
    bool notRegistered = parse_error_field(root, &error_code) && error_code == MQ_ERR_MODULE_NOT_FOUND;
    cJSON_Delete(root);
    return notRegistered;
}

static bool vd_offset_send_query(const char *command, char *response, size_t response_cap) {
    char *output = NULL;
    int attempt;

    for (attempt = 0; attempt < VD_OFFSET_WIN_LOOKUP_RETRIES; attempt++) {
        os_free(output);

        wm_module_query_json_ex("agent-info", command, &output);

        if (!output || !vd_offset_is_module_not_registered(output)) {
            break;
        }

        if (attempt + 1 < VD_OFFSET_WIN_LOOKUP_RETRIES) {
            w_time_delay(VD_OFFSET_WIN_LOOKUP_RETRY_DELAY_US / 1000);
        }
    }

    if (!output) {
        merror("vd_offset_client: agent-info query returned no output after %d attempt(s).",
               VD_OFFSET_WIN_LOOKUP_RETRIES);
        return false;
    }

    if (vd_offset_is_module_not_registered(output)) {
        mdebug1("vd_offset_client: agent-info not registered yet after %d attempt(s); "
                "will retry next notify.", VD_OFFSET_WIN_LOOKUP_RETRIES);
        os_free(output);
        return false;
    }

    strncpy(response, output, response_cap - 1);
    response[response_cap - 1] = '\0';
    os_free(output);
    return true;
}
#endif

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
