/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/*
 * Legacy (< v5.0.0) remote_upgrade task delivery.
 *
 * 4.x agents only speak the legacy encrypted 1514 protocol, so they can't use the manager's
 * future HTTPS control endpoint. This poller bridges that gap for the one task type that matters
 * during a mixed-version migration: `remote_upgrade` (WPK) tasks.
 *
 * Every legacy_task_polling_interval seconds, this thread walks the set of currently-connected
 * agents; for each one confirmed to be below v5.0.0, it asks the Task Manager for its pending
 * tasks (over the existing, unmodified `queue/tasks/task` socket) and pushes any `remote_upgrade`
 * task to the agent using the same six-step wire protocol (lock_restart / open / write / close /
 * sha1 / upgrade) the agent-side handlers in wm_agent_upgrade_com.c already understand.
 *
 * `get_pending_tasks` marks everything it returns `delivered` unconditionally, for every task
 * type -- so the version check must run strictly before calling it for a given agent, or a
 * >= v5.0.0 agent's tasks would be permanently stranded.
 *
 * A push is retried up to LEGACY_TASK_MAX_PUSH_ATTEMPTS times within the same cycle for the
 * wire-level failure classes a retry can plausibly fix (see legacy_task_push_result_t). Two
 * classes are never retried: anything strictly local to the manager or the task payload itself
 * (a malformed task, a missing local WPK file, an installer that already ran and reported
 * failure) since repeating the identical push changes nothing; and losing the ack on the
 * 'upgrade' step specifically, since we can't tell whether the agent already started running the
 * installer before the ack was lost -- retrying there risks a double install, which is worse than
 * losing the task.
 *
 * Separately, and still fundamentally unrecoverable regardless of retries: if the Task Manager's
 * response to get_pending_tasks itself is lost after it has already marked the task delivered
 * server-side, this poller has nothing left to retry with. Fixing that would require changing the
 * shared Task Manager wire contract, which this design deliberately avoids touching.
 *
 * The synchronous per-step ack reuses remoted's own request/response machinery (req_create() /
 * the req_table hash / the per-node condition variable in request.c) directly, through the
 * req_send_and_wait() helper -- not a second local loopback connection to remoted's own request
 * socket, and not a second copy of that hash table.
 */

#include "shared.h"
#include "remoted.h"
#include "agent_metadata_db.h"
#include "wazuhdb_queries_op.h"
#include "version_op.h"
#include "os_net.h"
#include "legacy_task_delivery.h"
#include "queue_linked_op.h"

#include <limits.h>

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

/* Only remote_upgrade tasks are eligible for legacy delivery; active_response/agent_restart/
 * agent_reload are logged and dropped (they have no legacy delivery path at all). */
#define LEGACY_TASK_TYPE_REMOTE_UPGRADE "remote_upgrade"

/* Agents at or above this version are left alone: their pending tasks are for the manager's
 * future HTTPS control endpoint to serve, not this poller. */
#define LEGACY_TASK_MIN_HTTPS_VERSION "v5.0.0"

/* Fixed at the old default, not configurable: the agent-side 'write' handler
 * (wm_agent_upgrade_com.c, unchanged) only ever accepts one chunk's buffer per call, so this is a
 * property of the existing wire protocol, not a delivery-logic knob. */
#define LEGACY_TASK_WPK_CHUNK_SIZE 32768

/* Location on the manager filesystem where the agent_upgrade module downloads WPK files before
 * creating the task (matches WM_UPGRADE_WPK_DEFAULT_PATH in wm_agent_upgrade_manager.h).
 * Duplicated as a plain constant here rather than pulled in from that module's header: this
 * poller only ever consumes a task's payload, it never touches task creation. */
#define LEGACY_TASK_WPK_DEFAULT_PATH "var/upgrade/"

/* Delay before the very first poll cycle after a remoted (re)start, giving reconnecting agents
 * time to report their version before the poller starts deciding eligibility from stale/absent
 * agent metadata. */
#define LEGACY_TASK_STARTUP_DELAY_SEC 65

/* Fixed cap on push attempts per task, per poll cycle -- deliberately not configurable. A bounded
 * retry here only smooths over a transient wire hiccup within the few seconds a push takes; if it
 * hasn't recovered by the Nth attempt, retrying more won't help. Keep this a plain counted loop --
 * never a wait-until-condition loop -- so it can never become unbounded. */
#define LEGACY_TASK_MAX_PUSH_ATTEMPTS 3

/* How often the poller drains pending clear_upgrade_result replies -- deliberately much shorter
 * than legacy_task_polling_interval (whose minimum is 300s) and deliberately not configurable.
 * The full task-delivery sweep still only runs once per legacy_task_polling_interval; only the
 * lightweight ack-reply drain runs on this tighter cadence, so an agent's own ack/backoff loop
 * doesn't keep resending for the full, much longer poll interval. */
#define LEGACY_TASK_ACK_DRAIN_INTERVAL_SEC 5

/* FIFO of agent IDs (heap-allocated strings, owned by the queue until drained) awaiting a
 * clear_upgrade_result reply. Decouples ack detection -- done inline on a rem_handler worker
 * thread in secure.c, which must stay fast since that fixed-size pool is what dequeues and
 * processes every incoming secure message from every connected agent -- from the reply itself,
 * which needs a blocking round-trip to the agent (req_send_and_wait, up to response_timeout
 * seconds). Draining a burst of acks inline used to be able to tie up the whole worker pool for
 * that long, stalling every other agent's traffic; this queue lets this module's own poller
 * thread perform that blocking wait instead, off the shared pool entirely. */
static w_linked_queue_t *pending_clear_upgrade_replies = NULL;

/* Distinguishes failures a retry can plausibly fix from ones it can't -- see each return site in
 * legacy_task_deliver_remote_upgrade() for the specific reasoning behind its classification. */
typedef enum {
    LEGACY_TASK_PUSH_SUCCESS,
    LEGACY_TASK_PUSH_RETRYABLE,
    LEGACY_TASK_PUSH_PERMANENT
} legacy_task_push_result_t;

STATIC bool legacy_task_agent_is_pre_v5(const char *agent_id, char **out_version) __attribute__((nonnull(1)));
STATIC cJSON *legacy_task_get_pending(const char *agent_id) __attribute__((nonnull));
STATIC legacy_task_push_result_t legacy_task_deliver_remote_upgrade(const char *agent_id, const cJSON *payload_obj) __attribute__((nonnull));
STATIC bool legacy_task_send_step(const char *agent_id, const char *target, const char *rest, char **out_message) __attribute__((nonnull(1, 2, 3)));
STATIC bool legacy_task_send_upgrade_step(const char *agent_id, const char *command_name, cJSON *params, char **out_data) __attribute__((nonnull(1, 2, 3)));
STATIC void legacy_upgrade_poll_cycle(void);
STATIC void legacy_task_send_clear_upgrade_result(const char *agent_id) __attribute__((nonnull));
STATIC void legacy_task_drain_clear_upgrade_replies(void);

void legacy_task_delivery_init(void) {
    pending_clear_upgrade_replies = linked_queue_init();
}

void legacy_task_delivery_teardown(void) {
    if (pending_clear_upgrade_replies) {
        char *agent_id;

        // linked_queue_pop_ex() blocks on an empty queue (waits on its condition variable), so
        // draining must check for a pending node first rather than looping on its NULL return.
        while (pending_clear_upgrade_replies->first) {
            agent_id = (char *) linked_queue_pop_ex(pending_clear_upgrade_replies);
            os_free(agent_id);
        }

        linked_queue_free(pending_clear_upgrade_replies);
        pending_clear_upgrade_replies = NULL;
    }
}

/**
 * @brief Determine whether a connected agent is confirmed to be below v5.0.0.
 *
 * Cache-first (agent_meta_map via agent_meta_snapshot_str, no socket round trip), wazuh-db
 * fallback (wdb_get_agent_info) only on a cache miss. An agent whose version cannot be
 * determined at all is treated the same as one on v5.0.0+: not eligible, left untouched for the
 * HTTPS control endpoint. This check is load-bearing and must run before legacy_task_get_pending()
 * is ever called for the agent -- see the file header comment.
 *
 * @param agent_id Agent identifier.
 * @param out_version On a positive result, set to a caller-owned copy of the resolved version
 * string (must be freed with os_free); left untouched otherwise.
 * @return true if confirmed < v5.0.0, false if unknown or >= v5.0.0.
 */
STATIC bool legacy_task_agent_is_pre_v5(const char *agent_id, char **out_version) {
    char *version = NULL;
    agent_version_check_t result = agent_meta_check_version(agent_id, LEGACY_TASK_MIN_HTTPS_VERSION, &version);

    switch (result) {
        case AGENT_VERSION_CHECK_UNKNOWN:
            mdebug1("legacy_task_delivery: agent '%s' has no known version, skipping this cycle "
                    "(leaving any pending tasks for the HTTPS control endpoint)", agent_id);
            return false;

        case AGENT_VERSION_CHECK_UNPARSEABLE:
            mdebug1("legacy_task_delivery: agent '%s' reported an unparseable version '%s', skipping", agent_id, version);
            os_free(version);
            return false;

        case AGENT_VERSION_CHECK_GE_MIN: {
            char *version_ptr = strchr(version, 'v');
            mdebug2("legacy_task_delivery: agent '%s' is on '%s' (>= %s), skipping",
                    agent_id, version_ptr ? version_ptr : version, LEGACY_TASK_MIN_HTTPS_VERSION);
            os_free(version);
            return false;
        }

        case AGENT_VERSION_CHECK_LT_MIN:
        default:
            if (out_version) {
                *out_version = version;
            } else {
                os_free(version);
            }
            return true;
    }
}

/**
 * @brief Ask the Task Manager for an agent's pending tasks.
 *
 * Read-only client of the existing, unmodified `queue/tasks/task` socket
 * (`get_pending_tasks` action). As a side effect of the call (server-side, not something this
 * poller controls), every returned task is marked `delivered` in tasks.db regardless of task
 * type -- callers must only invoke this once the agent has been confirmed eligible (see
 * legacy_task_agent_is_pre_v5()).
 *
 * @param agent_id Agent identifier.
 * @return JSON array of pending tasks (caller must cJSON_Delete), or NULL on any failure.
 */
STATIC cJSON *legacy_task_get_pending(const char *agent_id) {
    cJSON *request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "action", "get_pending_tasks");
    cJSON_AddStringToObject(request, "agent_id", agent_id);
    char *request_str = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);

    int sock = OS_ConnectUnixDomain(WM_TASK_MODULE_SOCK, SOCK_STREAM, OS_MAXSTR);

    if (sock < 0) {
        mdebug1("legacy_task_delivery: could not connect to the Task Manager socket '%s': %s",
                WM_TASK_MODULE_SOCK, strerror(errno));
        os_free(request_str);
        return NULL;
    }

    OS_SendSecureTCP(sock, strlen(request_str), request_str);
    os_free(request_str);

    char *response = NULL;
    os_calloc(OS_MAXSTR, sizeof(char), response);
    int length = OS_RecvSecureTCP(sock, response, OS_MAXSTR);
    close(sock);

    if (length <= 0) {
        mdebug1("legacy_task_delivery: no response from the Task Manager for agent '%s'", agent_id);
        os_free(response);
        return NULL;
    }

    cJSON *json_response = cJSON_Parse(response);
    os_free(response);

    if (!json_response) {
        mdebug1("legacy_task_delivery: invalid JSON response from the Task Manager for agent '%s'", agent_id);
        return NULL;
    }

    cJSON *status = cJSON_GetObjectItem(json_response, "status");
    if (!cJSON_IsString(status) || strcmp(status->valuestring, "ok") != 0) {
        mdebug1("legacy_task_delivery: Task Manager returned a non-ok status for agent '%s'", agent_id);
        cJSON_Delete(json_response);
        return NULL;
    }

    cJSON *tasks_json = cJSON_GetObjectItem(json_response, "tasks");
    cJSON *tasks = cJSON_IsArray(tasks_json) ? cJSON_Duplicate(tasks_json, 1) : NULL;

    cJSON_Delete(json_response);

    return tasks;
}

/**
 * @brief Send one wire-protocol step to an agent and wait for its synchronous ack.
 *
 * Builds "<target> <rest>" and hands it to req_send_and_wait(), which frames it exactly like
 * remoted's existing request/ack path (request.c) already does for AR/getconfig/getstats,
 * reusing that same req_table/condvar machinery instead of a second implementation of it.
 *
 * @param agent_id Target agent identifier.
 * @param target Local socket name the agent should forward to ("com" for execd's wcom_dispatch,
 * "upgrade" for the agent_upgrade module's wm_agent_upgrade_process_command).
 * @param rest Command text/JSON to send after target.
 * @param out_message On success, if non-NULL: set to a JSON response's "message" field
 * (caller-owned, must be freed with os_free). Used only by the sha1/upgrade steps.
 * @return true on a successful ack, false on any send/timeout/error response.
 */
STATIC bool legacy_task_send_step(const char *agent_id, const char *target, const char *rest, char **out_message) {
    size_t payload_len = strlen(target) + 1 + strlen(rest);
    char *payload;
    os_malloc(payload_len + 1, payload);
    snprintf(payload, payload_len + 1, "%s %s", target, rest);

    char *response = NULL;
    int rc = req_send_and_wait(agent_id, payload, payload_len, &response, response_timeout);
    os_free(payload);

    if (rc != 0 || !response) {
        mwarn("legacy_task_delivery: agent '%s': no response for step targeting '%s'", agent_id, target);
        os_free(response);
        return false;
    }

    bool ok = false;

    if (strcmp(target, "com") == 0) {
        // execd's wcom_dispatch speaks plain "ok ..."/"err ..." text, not JSON.
        ok = (strncmp(response, "ok", 2) == 0);
    } else {
        cJSON *json_resp = cJSON_Parse(response);

        if (json_resp) {
            cJSON *error_obj = cJSON_GetObjectItem(json_resp, "error");
            cJSON *message_obj = cJSON_GetObjectItem(json_resp, "message");

            if (cJSON_IsNumber(error_obj) && error_obj->valueint == 0) {
                ok = true;
                if (out_message && cJSON_IsString(message_obj)) {
                    os_strdup(message_obj->valuestring, *out_message);
                }
            } else {
                mwarn("legacy_task_delivery: agent '%s' rejected step targeting '%s': %s", agent_id, target,
                      cJSON_IsString(message_obj) ? message_obj->valuestring : "unknown error");
            }

            cJSON_Delete(json_resp);
        } else {
            mwarn("legacy_task_delivery: agent '%s' returned a malformed response for step targeting '%s'",
                  agent_id, target);
        }
    }

    os_free(response);
    return ok;
}

/**
 * @brief Build, send and parse one "upgrade {...}" JSON command step
 * (open/write/close/sha1/upgrade).
 *
 * @param agent_id Target agent identifier.
 * @param command_name One of open/write/close/sha1/upgrade.
 * @param params Command parameters object; ownership passes in (attached to, and freed with, the
 * wrapping request object built here).
 * @param out_data If non-NULL and the step succeeds, set to the agent's "message" field
 * (caller-owned, must be freed with os_free) -- carries the sha1 or the installer exit code.
 * @return true on success.
 */
STATIC bool legacy_task_send_upgrade_step(const char *agent_id, const char *command_name, cJSON *params, char **out_data) {
    cJSON *cmd = cJSON_CreateObject();
    cJSON_AddStringToObject(cmd, "command", command_name);
    cJSON_AddItemToObject(cmd, "parameters", params);
    char *cmd_str = cJSON_PrintUnformatted(cmd);

    bool ok = legacy_task_send_step(agent_id, "upgrade", cmd_str, out_data);

    os_free(cmd_str);
    cJSON_Delete(cmd);
    return ok;
}

/**
 * @brief Run the six-step WPK push (lock_restart / open / write / close / sha1 / upgrade)
 * against one agent for one remote_upgrade task.
 *
 * Sequential, synchronous: each step must ack before the next is sent. Any step failing aborts
 * the whole push, no partial cleanup beyond logging; the caller decides whether the failure
 * classification returned warrants a retry.
 *
 * @param agent_id Target agent identifier.
 * @param payload_obj Parsed task payload: {"wpk_file":...,"wpk_sha1":...,"installer":...}.
 * @return LEGACY_TASK_PUSH_SUCCESS if all six steps succeeded and the reported sha1 matched,
 * otherwise LEGACY_TASK_PUSH_RETRYABLE or LEGACY_TASK_PUSH_PERMANENT depending on the failure.
 */
STATIC legacy_task_push_result_t legacy_task_deliver_remote_upgrade(const char *agent_id, const cJSON *payload_obj) {
    cJSON *wpk_file_obj = cJSON_GetObjectItem(payload_obj, "wpk_file");
    cJSON *wpk_sha1_obj = cJSON_GetObjectItem(payload_obj, "wpk_sha1");
    cJSON *installer_obj = cJSON_GetObjectItem(payload_obj, "installer");

    if (!cJSON_IsString(wpk_file_obj) || !cJSON_IsString(wpk_sha1_obj) || !cJSON_IsString(installer_obj)) {
        merror("legacy_task_delivery: agent '%s': invalid or incomplete remote_upgrade payload, not delivered", agent_id);
        // The payload is malformed; retrying won't change what's in it.
        return LEGACY_TASK_PUSH_PERMANENT;
    }

    const char *wpk_file = wpk_file_obj->valuestring;
    const char *wpk_sha1 = wpk_sha1_obj->valuestring;
    const char *installer = installer_obj->valuestring;

    // wpk_file is always a bare filename (both the repo-resolved and custom-WPK task-creation
    // paths in wm_agent_upgrade_commands.c only ever emit a basename), so the wire "file" field to
    // the agent and the manager's own local read both resolve it the same way, against this
    // poller's fixed default upgrade path.
    char file_path[PATH_MAX + 1];
    snprintf(file_path, sizeof(file_path), "%s%s", LEGACY_TASK_WPK_DEFAULT_PATH, wpk_file);
    const char *wpk_basename = wpk_file;

    minfo("legacy_task_delivery: delivering remote_upgrade task to agent '%s' (wpk: '%s')", agent_id, wpk_file);

    // Step 1: lock_restart (execd, plain-text protocol)
    if (!legacy_task_send_step(agent_id, "com", "lock_restart -1", NULL)) {
        merror("legacy_task_delivery: agent '%s': 'lock_restart' step failed, aborting push", agent_id);
        // Nothing has been sent to the agent yet at this point; a clean retry is safe.
        return LEGACY_TASK_PUSH_RETRYABLE;
    }

    // Step 2: open
    {
        cJSON *params = cJSON_CreateObject();
        cJSON_AddStringToObject(params, "mode", "wb");
        cJSON_AddStringToObject(params, "file", wpk_basename);

        if (!legacy_task_send_upgrade_step(agent_id, "open", params, NULL)) {
            merror("legacy_task_delivery: agent '%s': 'open' step failed, aborting push", agent_id);
            // Same as lock_restart: no partial state on the agent side yet.
            return LEGACY_TASK_PUSH_RETRYABLE;
        }
    }

    // Step 3: write, chunked at a fixed 32KB (LEGACY_TASK_WPK_CHUNK_SIZE) -- a wire-protocol
    // property, not a config option; see the file header/macro comment.
    {
        FILE *file = wfopen(file_path, "rb");

        if (!file) {
            merror("legacy_task_delivery: agent '%s': cannot open local WPK file '%s': %s",
                   agent_id, file_path, strerror(errno));
            // A manager-local filesystem problem (missing/unreadable file on this host), not a
            // wire issue -- retrying the network push again does nothing to fix it.
            return LEGACY_TASK_PUSH_PERMANENT;
        }

        char chunk[LEGACY_TASK_WPK_CHUNK_SIZE];
        size_t bytes_read;
        bool write_ok = true;

        while ((bytes_read = fread(chunk, 1, sizeof(chunk), file)) > 0) {
            char *base64 = encode_base64((int)bytes_read, chunk);

            if (!base64) {
                // A local encoding failure (e.g. OOM), not a network condition a retry addresses.
                merror("legacy_task_delivery: agent '%s': base64 encoding failed writing '%s'", agent_id, wpk_file);
                fclose(file);
                return LEGACY_TASK_PUSH_PERMANENT;
            }

            cJSON *params = cJSON_CreateObject();
            cJSON_AddStringToObject(params, "buffer", base64);
            cJSON_AddNumberToObject(params, "length", (double)bytes_read);
            cJSON_AddStringToObject(params, "file", wpk_basename);
            os_free(base64);

            write_ok = legacy_task_send_upgrade_step(agent_id, "write", params, NULL);

            if (!write_ok) {
                break;
            }
        }

        fclose(file);

        if (!write_ok) {
            merror("legacy_task_delivery: agent '%s': 'write' step failed, aborting push", agent_id);
            // 'open' is always called in "wb" mode, which truncates/restarts the file fresh on
            // the agent side, so a full retry from the top safely discards whatever partial
            // bytes made it through before a disconnect.
            return LEGACY_TASK_PUSH_RETRYABLE;
        }
    }

    // Step 4: close
    {
        cJSON *params = cJSON_CreateObject();
        cJSON_AddStringToObject(params, "file", wpk_basename);

        if (!legacy_task_send_upgrade_step(agent_id, "close", params, NULL)) {
            merror("legacy_task_delivery: agent '%s': 'close' step failed, aborting push", agent_id);
            // Same reasoning as 'write': a fresh retry re-opens in "wb" mode and starts clean.
            return LEGACY_TASK_PUSH_RETRYABLE;
        }
    }

    // Step 5: sha1 -- compare the agent-reported hash against the expected one
    {
        cJSON *params = cJSON_CreateObject();
        cJSON_AddStringToObject(params, "file", wpk_basename);

        char *reported_sha1 = NULL;
        bool ok = legacy_task_send_upgrade_step(agent_id, "sha1", params, &reported_sha1);

        if (!ok) {
            merror("legacy_task_delivery: agent '%s': 'sha1' step failed, aborting push", agent_id);
            os_free(reported_sha1);
            // Transient wire issue; a fresh transfer attempt is a reasonable next step.
            return LEGACY_TASK_PUSH_RETRYABLE;
        }

        if (!reported_sha1 || strcmp(reported_sha1, wpk_sha1) != 0) {
            merror("legacy_task_delivery: agent '%s': sha1 mismatch after transfer (expected '%s', got '%s'), aborting",
                   agent_id, wpk_sha1, reported_sha1 ? reported_sha1 : "(none)");
            os_free(reported_sha1);
            // Most likely one-off corruption in transit; a fresh transfer is likely to match.
            return LEGACY_TASK_PUSH_RETRYABLE;
        }

        os_free(reported_sha1);
    }

    // Step 6: upgrade
    {
        cJSON *params = cJSON_CreateObject();
        cJSON_AddStringToObject(params, "file", wpk_basename);
        cJSON_AddStringToObject(params, "installer", installer);

        char *exit_status = NULL;
        bool ok = legacy_task_send_upgrade_step(agent_id, "upgrade", params, &exit_status);

        if (!ok) {
            merror("legacy_task_delivery: agent '%s': 'upgrade' step failed", agent_id);
            os_free(exit_status);
            // Unlike the earlier steps' ack loss, we cannot tell whether the agent already
            // started running the installer before this ack was lost. Blindly retrying risks
            // triggering the installer a second time, which is worse than losing this one task.
            return LEGACY_TASK_PUSH_PERMANENT;
        }

        if (!exit_status || strncmp("0", exit_status, 1) != 0) {
            merror("legacy_task_delivery: agent '%s': installer script failed (exit status: %s)",
                   agent_id, exit_status ? exit_status : "unknown");
            os_free(exit_status);
            // The agent ran the installer and it affirmatively reported failure (bad package,
            // wrong arch, disk full, etc.) -- retrying the identical WPK will fail the same way.
            return LEGACY_TASK_PUSH_PERMANENT;
        }

        os_free(exit_status);
    }

    minfo("legacy_task_delivery: successfully delivered remote_upgrade task to agent '%s' (wpk: '%s')", agent_id, wpk_file);
    return LEGACY_TASK_PUSH_SUCCESS;
}

/**
 * @brief Send `clear_upgrade_result` to an agent over the existing upgrade command channel.
 *
 * This is what stops the agent's ack retry loop
 * (wm_agent_upgrade_check_status(), agent-side, unmodified): on receipt it deletes its local
 * `upgrade_result` file and the loop exits.
 *
 * @param agent_id Target agent identifier.
 */
STATIC void legacy_task_send_clear_upgrade_result(const char *agent_id) {
    cJSON *params = cJSON_CreateObject();

    if (!legacy_task_send_upgrade_step(agent_id, "clear_upgrade_result", params, NULL)) {
        mwarn("legacy_task_delivery: agent '%s': failed to deliver 'clear_upgrade_result', "
              "the agent may keep resending its upgrade acknowledgment", agent_id);
    }
}

/**
 * @brief One full poll cycle: snapshot the connected-agent set, version-gate each one, and
 * deliver eligible remote_upgrade tasks.
 */
STATIC void legacy_upgrade_poll_cycle(void) {
    char **agent_ids = NULL;
    size_t agent_count = 0;

    key_lock_read();
    os_calloc(keys.keysize + 1, sizeof(char *), agent_ids);
    for (unsigned int i = 0; i < keys.keysize; i++) {
        if (keys.keyentries[i]->sock >= 0 && keys.keyentries[i]->id) {
            os_strdup(keys.keyentries[i]->id, agent_ids[agent_count]);
            agent_count++;
        }
    }
    key_unlock();

    mdebug2("legacy_task_delivery: checking %zu connected agent(s)", agent_count);

    for (size_t i = 0; i < agent_count; i++) {
        const char *agent_id = agent_ids[i];
        char *version = NULL;

        if (!legacy_task_agent_is_pre_v5(agent_id, &version)) {
            continue;
        }

        mdebug2("legacy_task_delivery: agent '%s' (version '%s') is eligible, retrieving pending tasks", agent_id, version);
        os_free(version);

        cJSON *tasks = legacy_task_get_pending(agent_id);

        if (!tasks) {
            continue;
        }

        cJSON *task = NULL;
        cJSON_ArrayForEach(task, tasks) {
            cJSON *task_type_obj = cJSON_GetObjectItem(task, "task_type");
            cJSON *task_id_obj = cJSON_GetObjectItem(task, "task_id");
            cJSON *payload_obj = cJSON_GetObjectItem(task, "payload");

            const char *task_type = cJSON_IsString(task_type_obj) ? task_type_obj->valuestring : NULL;
            const char *task_id = cJSON_IsString(task_id_obj) ? task_id_obj->valuestring : "unknown";

            if (!task_type || strcmp(task_type, LEGACY_TASK_TYPE_REMOTE_UPGRADE) != 0) {
                minfo("legacy_task_delivery: task type '%s' not supported for legacy agents, not delivered "
                      "(task '%s', agent '%s')", task_type ? task_type : "unknown", task_id, agent_id);
                continue;
            }

            if (!cJSON_IsString(payload_obj)) {
                merror("legacy_task_delivery: task '%s' for agent '%s' has an invalid payload, not delivered", task_id, agent_id);
                continue;
            }

            cJSON *payload_json = cJSON_Parse(payload_obj->valuestring);

            if (!payload_json) {
                merror("legacy_task_delivery: task '%s' for agent '%s' has an unparsable payload, not delivered", task_id, agent_id);
                continue;
            }

            legacy_task_push_result_t push_result = LEGACY_TASK_PUSH_RETRYABLE;
            for (int attempt = 1;
                 attempt <= LEGACY_TASK_MAX_PUSH_ATTEMPTS && push_result == LEGACY_TASK_PUSH_RETRYABLE;
                 attempt++) {
                push_result = legacy_task_deliver_remote_upgrade(agent_id, payload_json);
            }

            if (push_result == LEGACY_TASK_PUSH_RETRYABLE) {
                merror("legacy_task_delivery: agent '%s': task '%s' did not succeed after %d attempt(s), giving up "
                       "-- the Task Manager has already marked it delivered, so it will not be offered again",
                       agent_id, task_id, LEGACY_TASK_MAX_PUSH_ATTEMPTS);
            }

            cJSON_Delete(payload_json);
        }

        cJSON_Delete(tasks);
    }

    for (size_t i = 0; i < agent_count; i++) {
        os_free(agent_ids[i]);
    }
    os_free(agent_ids);
}

bool legacy_task_process_upgrade_ack(const char *agent_id, const char *ack_json) {
    cJSON *ack = cJSON_Parse(ack_json);

    if (!ack) {
        mdebug1("legacy_task_delivery: agent '%s' sent an unparseable upgrade acknowledgment, ignoring", agent_id);
        return false;
    }

    cJSON *command_obj = cJSON_GetObjectItem(ack, "command");

    if (!cJSON_IsString(command_obj) || strcmp(command_obj->valuestring, "upgrade_update_status") != 0) {
        mdebug1("legacy_task_delivery: agent '%s' sent an upgrade acknowledgment with an unexpected "
                "'command', ignoring", agent_id);
        cJSON_Delete(ack);
        return false;
    }

    cJSON *parameters_obj = cJSON_GetObjectItem(ack, "parameters");

    if (!cJSON_IsObject(parameters_obj)) {
        mdebug1("legacy_task_delivery: agent '%s' sent an upgrade acknowledgment with a missing or "
                "invalid 'parameters', ignoring", agent_id);
        cJSON_Delete(ack);
        return false;
    }

    cJSON *error_obj = cJSON_GetObjectItem(parameters_obj, "error");

    // The explicit NULL check is redundant with cJSON_IsNumber(NULL) == false, but scan-build
    // cannot see across translation units, so without it the error_obj->valueint read below is
    // reported as a possible NULL dereference.
    if (error_obj == NULL || !cJSON_IsNumber(error_obj)) {
        mdebug1("legacy_task_delivery: agent '%s' sent an upgrade acknowledgment with a missing or "
                "invalid 'parameters.error', ignoring", agent_id);
        cJSON_Delete(ack);
        return false;
    }

    cJSON *message_obj = cJSON_GetObjectItem(parameters_obj, "message");
    const char *message = cJSON_IsString(message_obj) ? message_obj->valuestring : "(no message)";

    minfo("legacy_task_delivery: agent '%s' reported upgrade result (error %d: %s), replying with "
          "clear_upgrade_result", agent_id, error_obj->valueint, message);

    cJSON_Delete(ack);

    // Enqueue rather than reply inline: this function runs on a shared rem_handler worker-pool
    // thread (secure.c) and must not block it. legacy_task_send_clear_upgrade_result() performs a
    // synchronous round-trip to the agent (up to response_timeout seconds) -- doing that here,
    // under a burst of acks (e.g. right after a mass upgrade completes), could occupy every
    // worker thread at once and stall all other agents' traffic. The poller thread drains this
    // queue and performs the actual round-trip off the shared pool instead.
    char *agent_id_copy;
    os_strdup(agent_id, agent_id_copy);
    linked_queue_push_ex(pending_clear_upgrade_replies, agent_id_copy);

    return true;
}

/**
 * @brief Drain and reply to every agent ID currently queued for a clear_upgrade_result reply.
 *
 * Runs on this module's own poller thread, off the shared rem_handler worker pool -- see
 * pending_clear_upgrade_replies' doc comment. No dedup: the same agent ID may appear more than
 * once (its own backoff loop can resend an ack before this drains), and replying twice is
 * harmless, so each queued entry is answered independently.
 */
STATIC void legacy_task_drain_clear_upgrade_replies(void) {
    char *agent_id;

    // linked_queue_pop_ex() blocks on an empty queue (waits on its condition variable), so
    // draining must check for a pending node first rather than looping on its NULL return.
    while (pending_clear_upgrade_replies->first) {
        agent_id = (char *) linked_queue_pop_ex(pending_clear_upgrade_replies);
        legacy_task_send_clear_upgrade_result(agent_id);
        os_free(agent_id);
    }
}

void *legacy_upgrade_task_delivery(void *arg) {
    (void)arg;

    minfo("legacy_task_delivery: poller thread started (startup delay %ds, poll interval %ds)",
          LEGACY_TASK_STARTUP_DELAY_SEC, legacy_task_polling_interval);

    // Startup delay: see LEGACY_TASK_STARTUP_DELAY_SEC doc comment above.
    sleep(LEGACY_TASK_STARTUP_DELAY_SEC);

    while (1) {
        legacy_upgrade_poll_cycle();
        legacy_task_drain_clear_upgrade_replies();

        int slept = 0;
        while (slept < legacy_task_polling_interval) {
            int nap = (legacy_task_polling_interval - slept < LEGACY_TASK_ACK_DRAIN_INTERVAL_SEC)
                      ? (legacy_task_polling_interval - slept)
                      : LEGACY_TASK_ACK_DRAIN_INTERVAL_SEC;
            sleep(nap);
            slept += nap;
            legacy_task_drain_clear_upgrade_replies();

#ifdef WAZUH_UNIT_TESTING
            break;
#endif
        }

#ifdef WAZUH_UNIT_TESTING
        break;
#endif
    }

    return NULL;
}
