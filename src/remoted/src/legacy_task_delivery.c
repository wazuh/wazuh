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
 * tasks (over the existing, unmodified `queue/sockets/task.sock` socket) and pushes any `remote_upgrade`
 * task to the agent using the same six-step wire protocol (lock_restart / open / write / close /
 * sha1 / upgrade) the agent-side handlers in wm_agent_upgrade_com.c already understand.
 *
 * `get_pending_tasks` marks everything it returns `delivered` unconditionally, for every task
 * type -- so the version check must run strictly before calling it for a given agent, or a
 * >= v5.0.0 agent's tasks would be permanently stranded.
 *
 * A push is retried up to LEGACY_TASK_MAX_PUSH_ATTEMPTS times, in-memory, for the wire-level
 * rejection classes a retry can plausibly fix (see legacy_task_push_result_t). Two classes are
 * never retried at all: anything strictly local to the manager or the task payload itself (a
 * malformed task, a missing local WPK file, an installer that already ran and reported failure)
 * since repeating the identical push changes nothing; and losing the ack on the 'upgrade' step
 * specifically, since we can't tell whether the agent already started running the installer
 * before the ack was lost -- retrying there risks a double install, which is worse than losing the
 * task. Each retryable attempt logs at `debug1`, except the last one (no more attempts left),
 * which logs at `warning` -- so a task that recovers within its attempt budget never produces log
 * noise above debug, and only a task that's about to be given up on raises its voice.
 *
 * A *rejection* (the agent answered, just not with success) and a true *no-response* (nothing came
 * back at all within response_timeout) are handled very differently, because they cost very
 * differently: a rejection is cheap to retry (the agent replied in milliseconds), so this poller
 * spends its whole in-cycle attempt budget on those. A no-response costs a full response_timeout
 * per attempt -- burning all LEGACY_TASK_MAX_PUSH_ATTEMPTS on that would block this whole poll
 * cycle's sweep of every other agent for minutes. So the very first no-response for a task cuts
 * the in-cycle loop short (see legacy_task_attempt_delivery()) and hands the task to
 * legacy_task_retry_list -- a small in-memory list this poller checks at the start of every future
 * cycle, giving the task another shot without blocking the rest of the sweep.
 *
 * Because get_pending_tasks marks a task 'delivered' purely as a side effect of reading it (see
 * above), a push that then fails would otherwise be silently lost forever: nothing else ever
 * offers that task again. legacy_task_retry_list is what keeps a no-response failure from being
 * lost this way -- everything else (a rejection that exhausted its in-cycle attempts, or a
 * permanent failure) is simply logged and dropped: this poller does not report a task's outcome
 * back to the Task Manager in any way, so `tasks.db` has no way to distinguish a task that
 * ultimately failed from one that succeeded -- both stay 'delivered'. This is a deliberate
 * trade-off: simplicity over that distinction, with the manager's own logs as the only
 * observability into a genuine failure.
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

/* Fixed cap on in-cycle push attempts per task -- deliberately not configurable. A bounded retry
 * here only smooths over a transient wire hiccup within the few seconds a push takes; if it hasn't
 * recovered by the Nth attempt, retrying more won't help. Keep this a plain counted loop -- never a
 * wait-until-condition loop -- so it can never become unbounded.
 *
 * Only applies to *rejections* (the agent answered, just not with success) -- the very first true
 * no-response cuts this loop short instead of spending it, see legacy_task_attempt_delivery(). A
 * rejection that exhausts every attempt here is simply logged and dropped, never added to
 * legacy_task_retry_list: it already got its full budget of chances this cycle. */
#define LEGACY_TASK_MAX_PUSH_ATTEMPTS 5

/* Bounds for legacy_task_retry_list, the small in-memory list of tasks whose push got no response
 * at all and is deferred to a future poll cycle instead of blocking this one (see the file header
 * comment). Both deliberately mirror wm_task_manager.h's WM_TASK_DEFAULT_MAX_TASKS_PER_POLL /
 * WM_TASK_DEFAULT_TTL defaults rather than including that header: this poller only ever consumes a
 * task's payload, it never touches the Task Manager's own config. */
#define LEGACY_TASK_RETRY_LIST_MAX_SIZE 100
#define LEGACY_TASK_RETRY_MAX_AGE_SEC 3600

/* The agent's own wm_agent_upgrade_com.c rejects the 'open' step with exactly this text
 * (ERROR_UPGRADES_NOT_ALLOWED) when its agent_upgrade module hasn't finished starting up yet --
 * a transient readiness race right after the agent (re)connects, not a wire/network failure or a
 * bad payload. Matched by text rather than by the wire "error" numeric code: that enum is private
 * to wm_agent_upgrade_com.c, not exposed through any shared header, so there is nothing more
 * structured to key off without introducing a new cross-module dependency for this one check.
 * Keep this in sync with error_messages[ERROR_UPGRADES_NOT_ALLOWED] there if it ever changes. */
#define LEGACY_TASK_AGENT_NOT_READY_MESSAGE "Upgrade module is disabled or not ready yet"

/* Backoff applied once, before the next push attempt, after an 'open' step either rejected
 * specifically with LEGACY_TASK_AGENT_NOT_READY_MESSAGE or answered with a malformed (non-JSON)
 * response -- both observed in practice as early-startup symptoms of the same readiness race (the
 * agent_upgrade module hasn't finished starting up yet), see legacy_task_send_step()'s
 * out_malformed doc comment. Gives the module a real chance to finish starting up instead of
 * burning all LEGACY_TASK_MAX_PUSH_ATTEMPTS back-to-back within the same second. */
#define LEGACY_TASK_AGENT_NOT_READY_BACKOFF_SEC 15

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

/* One task deferred to a future poll cycle because its push got no response at all -- see the
 * file header comment and LEGACY_TASK_RETRY_LIST_MAX_SIZE/LEGACY_TASK_RETRY_MAX_AGE_SEC. Holds the
 * raw payload string exactly as returned by get_pending_tasks, so retrying it needs no further
 * Task Manager round trip -- it's re-parsed with cJSON_Parse() each time it's retried. */
typedef struct {
    char *agent_id;
    char *task_id;
    char *payload_json;
    time_t create_time;
    int attempts;
} legacy_task_retry_entry_t;

/* Fixed-capacity, compacted (no gaps) array of pointers -- only ever touched by this module's own
 * poller thread, so no lock is needed, same assumption pending_clear_upgrade_replies makes for its
 * queue. LEGACY_TASK_RETRY_LIST_MAX_SIZE bounds it; legacy_task_retry_list_count tracks how many of
 * the leading slots are actually populated. */
static legacy_task_retry_entry_t *legacy_task_retry_list[LEGACY_TASK_RETRY_LIST_MAX_SIZE];
static size_t legacy_task_retry_list_count = 0;

STATIC bool legacy_task_agent_is_pre_v5(const char *agent_id, char **out_version) __attribute__((nonnull(1)));
STATIC char *legacy_task_manager_socket_request(const char *request_str) __attribute__((nonnull));
STATIC cJSON *legacy_task_get_pending(const char *agent_id) __attribute__((nonnull));
STATIC legacy_task_push_result_t legacy_task_deliver_remote_upgrade(const char *agent_id, const char *task_id, const cJSON *payload_obj, bool is_last_attempt, bool *out_no_response) __attribute__((nonnull(1, 2, 3, 5)));
STATIC legacy_task_push_result_t legacy_task_attempt_delivery(const char *agent_id, const char *task_id, const cJSON *payload_json, bool *out_no_response) __attribute__((nonnull));
STATIC bool legacy_task_send_step(const char *agent_id, const char *target, const char *rest, char **out_message, bool *out_malformed, bool *out_no_response, bool is_last_attempt) __attribute__((nonnull(1, 2, 3)));
STATIC bool legacy_task_send_upgrade_step(const char *agent_id, const char *command_name, cJSON *params, char **out_data, bool *out_malformed, bool *out_no_response, bool is_last_attempt) __attribute__((nonnull(1, 2, 3)));
STATIC void legacy_upgrade_poll_cycle(void);
STATIC void legacy_task_send_clear_upgrade_result(const char *agent_id) __attribute__((nonnull));
STATIC void legacy_task_drain_clear_upgrade_replies(void);
STATIC void legacy_task_retry_list_free_entry(legacy_task_retry_entry_t *entry);
STATIC void legacy_task_retry_list_remove_at(size_t index);
STATIC void legacy_task_retry_list_purge_expired(void);
STATIC bool legacy_task_retry_list_contains(const char *task_id) __attribute__((nonnull));
STATIC void legacy_task_retry_list_add(const char *agent_id, const char *task_id, const char *payload_json, time_t create_time) __attribute__((nonnull));
STATIC void legacy_task_retry_list_process(char **connected_agent_ids, size_t agent_count);

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

    while (legacy_task_retry_list_count > 0) {
        legacy_task_retry_list_remove_at(0);
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
 * @brief Send a pre-serialized request to the Task Manager socket and return its raw response.
 *
 * Connect/send/recv plumbing for legacy_task_get_pending()'s `get_pending_tasks` action.
 * Deliberately does no JSON parsing and no logging of its own -- the caller wants specific
 * wording/severity when the round trip fails; a connect failure and a timed-out response are
 * folded into the same NULL return here rather than distinguished, since the caller couldn't act
 * on that distinction differently anyway.
 *
 * @param request_str Pre-serialized JSON request to send.
 * @return Caller-owned raw response string on success, or NULL if the socket couldn't be reached
 * or no response came back.
 */
STATIC char *legacy_task_manager_socket_request(const char *request_str) {
    int sock = OS_ConnectUnixDomain(WM_TASK_MODULE_SOCK, SOCK_STREAM, OS_MAXSTR);

    if (sock < 0) {
        return NULL;
    }

    OS_SendSecureTCP(sock, strlen(request_str), request_str);

    char *response = NULL;
    os_calloc(OS_MAXSTR, sizeof(char), response);
    int length = OS_RecvSecureTCP(sock, response, OS_MAXSTR);
    close(sock);

    if (length <= 0) {
        os_free(response);
        return NULL;
    }

    return response;
}

/**
 * @brief Ask the Task Manager for an agent's pending tasks.
 *
 * Read-only client of the existing, unmodified `queue/sockets/task.sock` socket
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

    char *response = legacy_task_manager_socket_request(request_str);
    os_free(request_str);

    if (!response) {
        mwarn("legacy_task_delivery: could not reach the Task Manager socket '%s' for agent '%s'",
              WM_TASK_MODULE_SOCK, agent_id);
        return NULL;
    }

    cJSON *json_response = cJSON_Parse(response);
    os_free(response);

    if (!json_response) {
        mwarn("legacy_task_delivery: invalid JSON response from the Task Manager for agent '%s'", agent_id);
        return NULL;
    }

    cJSON *status = cJSON_GetObjectItem(json_response, "status");
    if (!cJSON_IsString(status) || strcmp(status->valuestring, "ok") != 0) {
        mwarn("legacy_task_delivery: Task Manager returned a non-ok status for agent '%s'", agent_id);
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
 * @param out_message If non-NULL and the agent returned a well-formed JSON response (success or
 * rejection): set to that response's "message" field (caller-owned, must be freed with os_free).
 * Left untouched (not set, not even to NULL) on a send/timeout failure or a malformed response --
 * callers must initialize *out_message themselves before the call.
 * @param out_malformed If non-NULL, set to true when the agent replied but the response wasn't
 * valid JSON -- observed in practice as an early-startup symptom distinct from the structured
 * LEGACY_TASK_AGENT_NOT_READY_MESSAGE rejection: the agent_upgrade module's local socket isn't
 * bound yet, so whatever answers on its behalf doesn't speak the JSON protocol at all. Left
 * untouched (not set to anything, including false) on every other outcome -- callers must
 * initialize *out_malformed themselves before the call.
 * @param out_no_response If non-NULL, set to true when the agent didn't answer at all within
 * response_timeout -- a true no-response, distinct from a fast rejection or malformed response:
 * see legacy_task_attempt_delivery() for why this matters (it cuts the in-cycle retry loop short
 * instead of spending it). Left untouched on every other outcome -- callers must initialize
 * *out_no_response themselves before the call.
 * @param is_last_attempt Whether this is the final push attempt for this task this cycle (see
 * LEGACY_TASK_MAX_PUSH_ATTEMPTS) -- controls the severity of any failure logged here: `debug1`
 * for an attempt that still has budget left to recover on its own, `warning` for the one that
 * doesn't.
 * @return true on a successful ack, false on any send/timeout/error response.
 */
STATIC bool legacy_task_send_step(const char *agent_id, const char *target, const char *rest, char **out_message, bool *out_malformed, bool *out_no_response, bool is_last_attempt) {
    size_t payload_len = strlen(target) + 1 + strlen(rest);
    char *payload;
    os_malloc(payload_len + 1, payload);
    snprintf(payload, payload_len + 1, "%s %s", target, rest);

    char *response = NULL;
    int rc = req_send_and_wait(agent_id, payload, payload_len, &response, response_timeout);
    os_free(payload);

    if (rc != 0 || !response) {
        if (is_last_attempt) {
            mwarn("legacy_task_delivery: agent '%s': no response for step targeting '%s'", agent_id, target);
        } else {
            mdebug1("legacy_task_delivery: agent '%s': no response for step targeting '%s'", agent_id, target);
        }
        if (out_no_response) {
            *out_no_response = true;
        }
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
                if (is_last_attempt) {
                    mwarn("legacy_task_delivery: agent '%s' rejected step targeting '%s': %s", agent_id, target,
                          cJSON_IsString(message_obj) ? message_obj->valuestring : "unknown error");
                } else {
                    mdebug1("legacy_task_delivery: agent '%s' rejected step targeting '%s': %s", agent_id, target,
                            cJSON_IsString(message_obj) ? message_obj->valuestring : "unknown error");
                }
                if (out_message && cJSON_IsString(message_obj)) {
                    os_strdup(message_obj->valuestring, *out_message);
                }
            }

            cJSON_Delete(json_resp);
        } else {
            if (is_last_attempt) {
                mwarn("legacy_task_delivery: agent '%s' returned a malformed response for step targeting '%s'",
                      agent_id, target);
            } else {
                mdebug1("legacy_task_delivery: agent '%s' returned a malformed response for step targeting '%s'",
                        agent_id, target);
            }
            if (out_malformed) {
                *out_malformed = true;
            }
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
 * @param out_malformed Forwarded to legacy_task_send_step() -- see its doc comment.
 * @param out_no_response Forwarded to legacy_task_send_step() -- see its doc comment.
 * @param is_last_attempt Forwarded to legacy_task_send_step() -- see its doc comment.
 * @return true on success.
 */
STATIC bool legacy_task_send_upgrade_step(const char *agent_id, const char *command_name, cJSON *params, char **out_data, bool *out_malformed, bool *out_no_response, bool is_last_attempt) {
    cJSON *cmd = cJSON_CreateObject();
    cJSON_AddStringToObject(cmd, "command", command_name);
    cJSON_AddItemToObject(cmd, "parameters", params);
    char *cmd_str = cJSON_PrintUnformatted(cmd);

    bool ok = legacy_task_send_step(agent_id, "upgrade", cmd_str, out_data, out_malformed, out_no_response, is_last_attempt);

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
 * @param task_id Task identifier -- only used for the delivering/delivered log lines, so a log-only
 * postmortem (no access to tasks.db, e.g. after delete_old's retention window) can still tell which
 * task a given push was for.
 * @param payload_obj Parsed task payload: {"wpk_file":...,"wpk_sha1":...,"installer":...}.
 * @param is_last_attempt Whether this is the final push attempt for this task this cycle -- see
 * LEGACY_TASK_MAX_PUSH_ATTEMPTS's doc comment. Only affects the severity of retryable-failure
 * logging; permanent failures always log at `error` regardless, since they're never retried.
 * @param out_no_response Set to true if any of the five *retryable* steps (lock_restart, open,
 * write, close, sha1) got no response at all -- never set for the 'upgrade' step, whose lost ack
 * is always PERMANENT (see that step's own comment) and must never be redirected to
 * legacy_task_retry_list. Left untouched (not set to anything, including false) on every other
 * outcome -- callers must initialize *out_no_response themselves before the call.
 * @return LEGACY_TASK_PUSH_SUCCESS if all six steps succeeded and the reported sha1 matched,
 * otherwise LEGACY_TASK_PUSH_RETRYABLE or LEGACY_TASK_PUSH_PERMANENT depending on the failure.
 */
STATIC legacy_task_push_result_t legacy_task_deliver_remote_upgrade(const char *agent_id, const char *task_id, const cJSON *payload_obj, bool is_last_attempt, bool *out_no_response) {
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

    minfo("legacy_task_delivery: delivering remote_upgrade task '%s' to agent '%s' (wpk: '%s')", task_id, agent_id, wpk_file);

    // Step 1: lock_restart (execd, plain-text protocol)
    if (!legacy_task_send_step(agent_id, "com", "lock_restart -1", NULL, NULL, out_no_response, is_last_attempt)) {
        // debug1 while attempts remain, warning on the last one -- retryable, and either a later
        // in-cycle attempt recovers, a no-response defers it to legacy_task_retry_list for a future
        // cycle, or every in-cycle attempt is spent and this poller simply logs and drops it (see
        // the file header comment). Nothing is actually lost yet either way.
        if (is_last_attempt) {
            mwarn("legacy_task_delivery: agent '%s': 'lock_restart' step failed, aborting push", agent_id);
        } else {
            mdebug1("legacy_task_delivery: agent '%s': 'lock_restart' step failed, aborting push", agent_id);
        }
        // Nothing has been sent to the agent yet at this point; a clean retry is safe.
        return LEGACY_TASK_PUSH_RETRYABLE;
    }

    // Step 2: open
    {
        cJSON *params = cJSON_CreateObject();
        cJSON_AddStringToObject(params, "mode", "wb");
        cJSON_AddStringToObject(params, "file", wpk_basename);

        char *reject_message = NULL;
        bool malformed = false;
        bool ok = legacy_task_send_upgrade_step(agent_id, "open", params, &reject_message, &malformed, out_no_response, is_last_attempt);

        if (!ok) {
            // debug1/warning ladder -- see the lock_restart step's comment.
            if (is_last_attempt) {
                mwarn("legacy_task_delivery: agent '%s': 'open' step failed, aborting push", agent_id);
            } else {
                mdebug1("legacy_task_delivery: agent '%s': 'open' step failed, aborting push", agent_id);
            }

            bool is_not_ready = (reject_message && strcmp(reject_message, LEGACY_TASK_AGENT_NOT_READY_MESSAGE) == 0);

            if (!is_last_attempt && (is_not_ready || malformed)) {
                // A readiness race, not a wire failure -- give the agent's agent_upgrade module a
                // real chance to finish starting up before the next attempt instead of retrying
                // immediately, see LEGACY_TASK_AGENT_NOT_READY_BACKOFF_SEC's doc comment. Skipped
                // on the last attempt: there is no next attempt left to back off for.
                mdebug1("legacy_task_delivery: agent '%s': 'open' %s, backing off %ds before the next attempt",
                        agent_id, is_not_ready ? "rejected as not ready yet" : "answered with a malformed response",
                        LEGACY_TASK_AGENT_NOT_READY_BACKOFF_SEC);
                sleep(LEGACY_TASK_AGENT_NOT_READY_BACKOFF_SEC);
            }

            os_free(reject_message);
            // Same as lock_restart: no partial state on the agent side yet.
            return LEGACY_TASK_PUSH_RETRYABLE;
        }

        os_free(reject_message);
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

            write_ok = legacy_task_send_upgrade_step(agent_id, "write", params, NULL, NULL, out_no_response, is_last_attempt);

            if (!write_ok) {
                break;
            }
        }

        fclose(file);

        if (!write_ok) {
            // debug1/warning ladder -- see the lock_restart step's comment.
            if (is_last_attempt) {
                mwarn("legacy_task_delivery: agent '%s': 'write' step failed, aborting push", agent_id);
            } else {
                mdebug1("legacy_task_delivery: agent '%s': 'write' step failed, aborting push", agent_id);
            }
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

        if (!legacy_task_send_upgrade_step(agent_id, "close", params, NULL, NULL, out_no_response, is_last_attempt)) {
            // debug1/warning ladder -- see the lock_restart step's comment.
            if (is_last_attempt) {
                mwarn("legacy_task_delivery: agent '%s': 'close' step failed, aborting push", agent_id);
            } else {
                mdebug1("legacy_task_delivery: agent '%s': 'close' step failed, aborting push", agent_id);
            }
            // Same reasoning as 'write': a fresh retry re-opens in "wb" mode and starts clean.
            return LEGACY_TASK_PUSH_RETRYABLE;
        }
    }

    // Step 5: sha1 -- compare the agent-reported hash against the expected one
    {
        cJSON *params = cJSON_CreateObject();
        cJSON_AddStringToObject(params, "file", wpk_basename);

        char *reported_sha1 = NULL;
        bool ok = legacy_task_send_upgrade_step(agent_id, "sha1", params, &reported_sha1, NULL, out_no_response, is_last_attempt);

        if (!ok) {
            // debug1/warning ladder -- see the lock_restart step's comment.
            if (is_last_attempt) {
                mwarn("legacy_task_delivery: agent '%s': 'sha1' step failed, aborting push", agent_id);
            } else {
                mdebug1("legacy_task_delivery: agent '%s': 'sha1' step failed, aborting push", agent_id);
            }
            os_free(reported_sha1);
            // Transient wire issue; a fresh transfer attempt is a reasonable next step.
            return LEGACY_TASK_PUSH_RETRYABLE;
        }

        if (!reported_sha1 || strcmp(reported_sha1, wpk_sha1) != 0) {
            // debug1/warning ladder -- see the lock_restart step's comment.
            if (is_last_attempt) {
                mwarn("legacy_task_delivery: agent '%s': sha1 mismatch after transfer (expected '%s', got '%s'), aborting",
                       agent_id, wpk_sha1, reported_sha1 ? reported_sha1 : "(none)");
            } else {
                mdebug1("legacy_task_delivery: agent '%s': sha1 mismatch after transfer (expected '%s', got '%s'), aborting",
                        agent_id, wpk_sha1, reported_sha1 ? reported_sha1 : "(none)");
            }
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
        // out_no_response deliberately not forwarded here (passed NULL instead): this step is
        // always PERMANENT on failure, ack lost or not, and must never be redirected to
        // legacy_task_retry_list -- see this function's own doc comment.
        bool ok = legacy_task_send_upgrade_step(agent_id, "upgrade", params, &exit_status, NULL, NULL, is_last_attempt);

        if (!ok) {
            // Always ERROR, regardless of is_last_attempt: this is classified PERMANENT below and
            // never retried, so there is no "attempts remaining" to soften the severity for.
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

    minfo("legacy_task_delivery: successfully delivered remote_upgrade task '%s' to agent '%s' (wpk: '%s')", task_id, agent_id, wpk_file);
    return LEGACY_TASK_PUSH_SUCCESS;
}

/**
 * @brief Attempt one task's delivery, spending up to LEGACY_TASK_MAX_PUSH_ATTEMPTS in-memory
 * retries on *rejections*, but breaking out the first time an attempt gets no response at all.
 *
 * A rejection is cheap to retry (the agent answered in milliseconds); a no-response costs a full
 * response_timeout per attempt, so spending the whole attempt budget on it would block this poll
 * cycle's sweep of every other agent for minutes (see the file header comment). The caller is
 * expected to add the task to legacy_task_retry_list when this returns with *out_no_response set,
 * instead of treating it the same as an exhausted-rejection RETRYABLE result.
 *
 * @param agent_id Target agent identifier.
 * @param task_id Task identifier (only used for the "giving up" log line).
 * @param payload_json Parsed task payload, forwarded to legacy_task_deliver_remote_upgrade().
 * @param out_no_response Set to true if the loop broke early due to a true no-response failure;
 * set to false otherwise. Always set (unlike the lower-level functions' out params).
 * @return The push result from the last attempt made.
 */
STATIC legacy_task_push_result_t legacy_task_attempt_delivery(const char *agent_id, const char *task_id, const cJSON *payload_json, bool *out_no_response) {
    legacy_task_push_result_t push_result = LEGACY_TASK_PUSH_RETRYABLE;
    int attempt;

    *out_no_response = false;

    for (attempt = 1;
         attempt <= LEGACY_TASK_MAX_PUSH_ATTEMPTS && push_result == LEGACY_TASK_PUSH_RETRYABLE;
         attempt++) {
        bool is_last_attempt = (attempt == LEGACY_TASK_MAX_PUSH_ATTEMPTS);
        bool no_response = false;

        push_result = legacy_task_deliver_remote_upgrade(agent_id, task_id, payload_json, is_last_attempt, &no_response);

        if (no_response) {
            *out_no_response = true;
            break;
        }
    }

    if (push_result == LEGACY_TASK_PUSH_RETRYABLE && !*out_no_response) {
        // Every in-cycle attempt this poller is willing to spend on this task is now spent on
        // rejections -- this poller does not report a task's outcome anywhere (see the file
        // header comment), so this is simply the final word on it in the log.
        mwarn("legacy_task_delivery: agent '%s': task '%s' did not succeed after %d attempt(s) of "
              "rejections, giving up", agent_id, task_id, LEGACY_TASK_MAX_PUSH_ATTEMPTS);
    }

    return push_result;
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

    // Not part of the push-attempt retry loop -- always pass true so a failure here keeps logging
    // at its usual severity regardless of any in-progress task delivery.
    if (!legacy_task_send_upgrade_step(agent_id, "clear_upgrade_result", params, NULL, NULL, NULL, true)) {
        mwarn("legacy_task_delivery: agent '%s': failed to deliver 'clear_upgrade_result', "
              "the agent may keep resending its upgrade acknowledgment", agent_id);
    }
}

/**
 * @brief Free one legacy_task_retry_list entry (its owned strings and the struct itself).
 */
STATIC void legacy_task_retry_list_free_entry(legacy_task_retry_entry_t *entry) {
    if (entry) {
        os_free(entry->agent_id);
        os_free(entry->task_id);
        os_free(entry->payload_json);
        os_free(entry);
    }
}

/**
 * @brief Remove the entry at the given index from legacy_task_retry_list, freeing it and shifting
 * every later entry down by one slot to keep the array gap-free.
 *
 * @param index Index to remove; must be < legacy_task_retry_list_count.
 */
STATIC void legacy_task_retry_list_remove_at(size_t index) {
    legacy_task_retry_list_free_entry(legacy_task_retry_list[index]);

    for (size_t i = index; i + 1 < legacy_task_retry_list_count; i++) {
        legacy_task_retry_list[i] = legacy_task_retry_list[i + 1];
    }

    legacy_task_retry_list_count--;
    legacy_task_retry_list[legacy_task_retry_list_count] = NULL;
}

/**
 * @brief Discard every legacy_task_retry_list entry older than LEGACY_TASK_RETRY_MAX_AGE_SEC.
 *
 * Run once at the start of every poll cycle, before retrying anything in the list -- without
 * this, a task for an agent that never comes back ready would be retried forever.
 */
STATIC void legacy_task_retry_list_purge_expired(void) {
    time_t now = time(0);

    for (size_t i = 0; i < legacy_task_retry_list_count; /* no increment: removal shifts i's slot */) {
        if (now - legacy_task_retry_list[i]->create_time > LEGACY_TASK_RETRY_MAX_AGE_SEC) {
            mdebug1("legacy_task_delivery: agent '%s': task '%s' dropped from the retry list, "
                    "older than %ds", legacy_task_retry_list[i]->agent_id,
                    legacy_task_retry_list[i]->task_id, LEGACY_TASK_RETRY_MAX_AGE_SEC);
            legacy_task_retry_list_remove_at(i);
        } else {
            i++;
        }
    }
}

/**
 * @brief Check whether a task_id is already present in legacy_task_retry_list.
 */
STATIC bool legacy_task_retry_list_contains(const char *task_id) {
    for (size_t i = 0; i < legacy_task_retry_list_count; i++) {
        if (strcmp(legacy_task_retry_list[i]->task_id, task_id) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * @brief Add a task to legacy_task_retry_list, to be retried on a future poll cycle.
 *
 * No-op (with a debug log) if task_id is already present -- get_pending_tasks can never return
 * the same task_id twice (it's already 'delivered' after the first read), but a reordering could
 * still hand this function the same task twice within unusual call patterns, and a silent
 * duplicate would otherwise retry it twice per cycle. If the list is already at
 * LEGACY_TASK_RETRY_LIST_MAX_SIZE, the single oldest entry (by create_time) is evicted first to
 * make room -- an unbounded list is worse than losing the oldest, presumably least likely to still
 * matter, entry.
 *
 * @param agent_id Agent identifier.
 * @param task_id Task identifier.
 * @param payload_json Raw payload string exactly as returned by get_pending_tasks (copied).
 * @param create_time Task's original creation time (from get_pending_tasks's own "create_time"),
 * not the time it's added to this list -- age is measured from when the Task Manager created the
 * task, not from when this poller first failed to deliver it.
 */
STATIC void legacy_task_retry_list_add(const char *agent_id, const char *task_id, const char *payload_json, time_t create_time) {
    if (legacy_task_retry_list_contains(task_id)) {
        mdebug1("legacy_task_delivery: agent '%s': task '%s' is already in the retry list, not duplicating",
                agent_id, task_id);
        return;
    }

    if (legacy_task_retry_list_count >= LEGACY_TASK_RETRY_LIST_MAX_SIZE) {
        size_t oldest = 0;

        for (size_t i = 1; i < legacy_task_retry_list_count; i++) {
            if (legacy_task_retry_list[i]->create_time < legacy_task_retry_list[oldest]->create_time) {
                oldest = i;
            }
        }

        mwarn("legacy_task_delivery: retry list full (%d entries), dropping oldest task '%s' for "
              "agent '%s' to make room for task '%s' for agent '%s'", LEGACY_TASK_RETRY_LIST_MAX_SIZE,
              legacy_task_retry_list[oldest]->task_id, legacy_task_retry_list[oldest]->agent_id,
              task_id, agent_id);
        legacy_task_retry_list_remove_at(oldest);
    }

    legacy_task_retry_entry_t *entry;
    os_calloc(1, sizeof(legacy_task_retry_entry_t), entry);
    os_strdup(agent_id, entry->agent_id);
    os_strdup(task_id, entry->task_id);
    os_strdup(payload_json, entry->payload_json);
    entry->create_time = create_time;
    entry->attempts = 1;

    legacy_task_retry_list[legacy_task_retry_list_count++] = entry;

    mdebug1("legacy_task_delivery: agent '%s': task '%s' added to the retry list for a future poll cycle",
            agent_id, task_id);
}

/**
 * @brief Retry every legacy_task_retry_list entry whose agent is currently connected and still
 * confirmed below v5.0.0.
 *
 * Called once at the start of every poll cycle, before the normal get_pending_tasks sweep --
 * LEGACY_TASK_RETRY_LIST_MAX_SIZE bounds this to a small, cheap scan. An entry whose agent isn't
 * connected right now, or whose version no longer gates it in, is simply left in the list for a
 * later cycle to try again; only LEGACY_TASK_RETRY_MAX_AGE_SEC ever retires one.
 *
 * @param connected_agent_ids Agent IDs from this cycle's connected-agent snapshot.
 * @param agent_count Number of entries in connected_agent_ids.
 */
STATIC void legacy_task_retry_list_process(char **connected_agent_ids, size_t agent_count) {
    for (size_t i = 0; i < legacy_task_retry_list_count; /* conditional increment below */) {
        legacy_task_retry_entry_t *entry = legacy_task_retry_list[i];
        bool agent_connected = false;

        for (size_t j = 0; j < agent_count; j++) {
            if (strcmp(connected_agent_ids[j], entry->agent_id) == 0) {
                agent_connected = true;
                break;
            }
        }

        if (!agent_connected) {
            i++;
            continue;
        }

        // Re-gate on version, exactly as the normal sweep does before delivering anything: an
        // entry can sit here for up to LEGACY_TASK_RETRY_MAX_AGE_SEC, long enough for the agent to
        // reach v5.0.0 by some other route and reconnect, and a >= v5.0.0 agent must never be sent
        // legacy push steps. Left in the list rather than dropped, since this also covers an agent
        // whose version simply isn't known yet; the age bound is what eventually retires it.
        if (!legacy_task_agent_is_pre_v5(entry->agent_id, NULL)) {
            i++;
            continue;
        }

        cJSON *payload_json = cJSON_Parse(entry->payload_json);

        if (!payload_json) {
            // Can't happen in practice (this string came from a successful cJSON_Parse the first
            // time this task was seen), but a corrupted entry here must not be retried forever.
            merror("legacy_task_delivery: agent '%s': task '%s' has an unparsable payload in the "
                   "retry list, dropping it", entry->agent_id, entry->task_id);
            legacy_task_retry_list_remove_at(i);
            continue;
        }

        entry->attempts++;
        mdebug1("legacy_task_delivery: agent '%s': retrying task '%s' from the retry list (attempt %d)",
                entry->agent_id, entry->task_id, entry->attempts);

        bool no_response = false;
        legacy_task_push_result_t push_result = legacy_task_attempt_delivery(entry->agent_id, entry->task_id,
                                                                              payload_json, &no_response);
        cJSON_Delete(payload_json);

        if (no_response) {
            // Still no response; leave it in the list (attempts already incremented above) for a
            // future cycle. Don't advance i: the array didn't shift.
            i++;
        } else {
            // Success, a rejection that exhausted its in-cycle budget, or a permanent failure --
            // either way this poller is done with it (see the file header comment on why nothing
            // gets reported anywhere for any of these three outcomes).
            (void) push_result;
            legacy_task_retry_list_remove_at(i);
        }
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

    legacy_task_retry_list_purge_expired();
    legacy_task_retry_list_process(agent_ids, agent_count);

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
            cJSON *create_time_obj = cJSON_GetObjectItem(task, "create_time");

            const char *task_type = cJSON_IsString(task_type_obj) ? task_type_obj->valuestring : NULL;
            bool has_task_id = cJSON_IsString(task_id_obj);
            const char *task_id = has_task_id ? task_id_obj->valuestring : "unknown";
            time_t create_time = cJSON_IsNumber(create_time_obj) ? (time_t) create_time_obj->valuedouble : time(0);

            if (!task_type || strcmp(task_type, LEGACY_TASK_TYPE_REMOTE_UPGRADE) != 0) {
                minfo("legacy_task_delivery: task type '%s' not supported for legacy agents, not delivered "
                      "(task '%s', agent '%s')", task_type ? task_type : "unknown", task_id, agent_id);
                // Never reintroduced later: a pre-v5.0.0 agent has no legacy delivery path at all
                // for any task type other than remote_upgrade (see the file header comment), so
                // retrying would hit the exact same rejection. Just logged, not added to
                // legacy_task_retry_list.
                continue;
            }

            if (!cJSON_IsString(payload_obj)) {
                merror("legacy_task_delivery: task '%s' for agent '%s' has an invalid payload, not delivered", task_id, agent_id);
                // The payload shape is wrong regardless of how many times it's read -- logged, not retried.
                continue;
            }

            cJSON *payload_json = cJSON_Parse(payload_obj->valuestring);

            if (!payload_json) {
                merror("legacy_task_delivery: task '%s' for agent '%s' has an unparsable payload, not delivered", task_id, agent_id);
                // Same malformed payload string every time -- logged, not retried.
                continue;
            }

            bool no_response = false;
            legacy_task_attempt_delivery(agent_id, task_id, payload_json, &no_response);

            if (no_response) {
                if (has_task_id) {
                    legacy_task_retry_list_add(agent_id, task_id, payload_obj->valuestring, create_time);
                } else {
                    // Can't be keyed into legacy_task_retry_list without a task_id. This task is
                    // already 'delivered' in tasks.db (get_pending_tasks's own side effect) and
                    // will now never be offered again -- loud on purpose, since silently dropping
                    // it here would reopen the exact "delivered but lost forever" bug this whole
                    // poller exists to close, just for this one edge case.
                    merror("legacy_task_delivery: agent '%s': a remote_upgrade task got no response "
                           "but has no 'task_id', cannot add it to the retry list -- it will not be "
                           "retried", agent_id);
                }
            }
            // Success, a rejection that exhausted its in-cycle attempt budget (already logged
            // inside legacy_task_attempt_delivery), or a permanent failure (already logged inside
            // legacy_task_deliver_remote_upgrade): nothing further to do for any of those -- see
            // the file header comment on why this poller doesn't report a task's outcome anywhere.

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

    if (error_obj->valueint == 0) {
        minfo("legacy_task_delivery: agent '%s' reported upgrade result (error %d: %s), replying with "
              "clear_upgrade_result", agent_id, error_obj->valueint, message);
    } else {
        // A non-zero error means the agent's own upgrade attempt failed (bad package, wrong arch,
        // disk full, etc.). Warning, not info: at info it disappears from any severity-filtered
        // log monitoring. Warning, not error: the delivery itself succeeded and the manager has
        // nothing left to do or fix here -- the cause and the actionable detail live in the
        // agent's own logs/upgrade.log, and a fleet-wide install problem would otherwise raise one
        // error per agent for a condition the manager can neither retry nor act on.
        mwarn("legacy_task_delivery: agent '%s' reported upgrade result (error %d: %s), replying with "
              "clear_upgrade_result", agent_id, error_obj->valueint, message);
    }

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
