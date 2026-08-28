/*
 * Wazuh Module for Task management: manager task registry.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WAZUH_UNIT_TESTING
#define STATIC
#else
#define STATIC static
#endif

#include "wmodules.h"
#include "wm_task_manager.h"
#include "wm_manager_task_registry.h"

/* Task type names. Kept as constants rather than an enum so that the only place a type name
 * appears is the table below and the producer that creates the row. */
#define WM_MANAGER_TASK_AGENT_DELETE_INDEXER "agent_delete_indexer"
#define WM_MANAGER_TASK_VD_SCAN              "vd_scan"
#define WM_MANAGER_TASK_AGENT_DISCONNECT     "agent_disconnect_sweep"
#define WM_MANAGER_TASK_AGENT_DELETE_OLD     "agent_delete_old"
#define WM_MANAGER_TASK_LOG_ROTATE_DAILY     "log_rotate_daily"

/* Defaults for the shared tunables, all overridable through internal options. */
#define WM_MANAGER_TASK_DEFAULT_BACKOFF_BASE 30
#define WM_MANAGER_TASK_DEFAULT_BACKOFF_CAP  900
#define WM_MANAGER_TASK_DEFAULT_DEFER_BASE   5
#define WM_MANAGER_TASK_DEFAULT_MAX_ATTEMPTS 8
#define WM_MANAGER_TASK_DEFAULT_MAX_DEFER    48

/* Route timeouts, in milliseconds. The delete timeout must exceed the scan timeout: a scan
 * holding an agent parks that agent's deletion behind it in the consumer's per-agent queue, and
 * with both deadlines equal the deletion would expire while parked and be re-queued over an
 * unrelated scan. The dispatcher asserts the ordering at startup rather than trusting a comment. */
#define WM_MANAGER_TASK_DEFAULT_VD_SCAN_TIMEOUT 300
#define WM_MANAGER_TASK_DEFAULT_DELETE_TIMEOUT  600
#define WM_MANAGER_TASK_DEFAULT_CONNECT_TIMEOUT 2

/* Admission bound on pending on-demand scans, preserving the in-memory deque this replaces. */
#define WM_MANAGER_TASK_DEFAULT_MAX_PENDING_SCANS 64
#define WM_MANAGER_TASK_DEFAULT_MAX_PENDING_DELETES 20000

/* libcurl result codes, spelled out because http_op.h deliberately does not leak curl.h to its
 * callers. Both are stable parts of libcurl's public ABI. Only these two are reachable over a
 * Unix socket besides the mid-transfer errors the default branch absorbs: there is no name to
 * resolve, no TLS to negotiate and no proxy to fail. */
#define WM_MANAGER_TASK_CURLE_COULDNT_CONNECT 7
#define WM_MANAGER_TASK_CURLE_OPERATION_TIMEDOUT 28

/// Escalate a deferral warning at this many consecutive deferrals, and to an error at the next.
#define WM_MANAGER_TASK_DEFER_WARN 3
#define WM_MANAGER_TASK_DEFER_ERROR 20

/* Lane depths. Depth 4 on the delete lane does not buy four-way parallel drain -- a deletion
 * executes on the consumer shard its agent hashes to -- but it keeps the lane from serialising
 * behind one slow call. */
STATIC const int WM_MANAGER_TASK_LANE_DEPTH[WM_MANAGER_TASK_LANE_COUNT] = {
    [WM_MANAGER_TASK_LANE_DELETE] = 4,
    [WM_MANAGER_TASK_LANE_SCAN] = 1,
    [WM_MANAGER_TASK_LANE_LOCAL] = 1,
};

STATIC const char *WM_MANAGER_TASK_LANE_NAMES[WM_MANAGER_TASK_LANE_COUNT] = {
    [WM_MANAGER_TASK_LANE_DELETE] = "delete",
    [WM_MANAGER_TASK_LANE_SCAN] = "scan",
    [WM_MANAGER_TASK_LANE_LOCAL] = "local",
};

/* Stands in for the three periodic handlers until the monitord port replaces each of them with
 * the ported implementation. Nothing creates a row of these types before then -- their schedules
 * arrive in the same change -- so this is unreachable rather than dormant; it exists so that
 * every type in the table below has an executor and the startup check stays meaningful. A row
 * that somehow reaches it dead-letters with a legible reason instead of being claimed and
 * dropped. */
STATIC wm_manager_task_result wm_manager_task_handler_unimplemented(__attribute__((unused)) const char *agent_id,
                                                                   __attribute__((unused)) const char *payload,
                                                                   char *error,
                                                                   size_t error_len) {
    snprintf(error, error_len, "Task type is registered but its handler is not implemented yet.");
    return WM_MANAGER_TASK_TERMINAL;
}

/* The registry itself. Built once at startup from the constants above plus the resolved consumer
 * socket, then read-only. */
STATIC wm_manager_task_descriptor manager_task_registry[] = {
    {
        /* The indexer half of an agent deletion. Once client.keys is written the agent is gone
         * and nobody will ask again, so this type is the one that must never give up: no attempt
         * budget, no deferral budget, and a 4xx re-queues rather than failing. Setting only the
         * first would not be enough, because a 4xx maps to terminal, which is just as final. */
        .name = WM_MANAGER_TASK_AGENT_DELETE_INDEXER,
        .lane = WM_MANAGER_TASK_LANE_DELETE,
        .method = "POST",
        .path = "/_internal/agents/delete",
        .max_attempts = WM_MANAGER_TASK_UNBOUNDED,
        .max_defer = WM_MANAGER_TASK_UNBOUNDED,
        .allow_terminal_failure = false,
        /* Never coalesced. Two deletions of one agent are two obligations, and folding them
         * together would rely on another subsystem refusing to reuse an agent id while a purge
         * is outstanding -- a guard that is load-bearing here and documented nowhere. */
        .coalesce = false,
        .max_pending = WM_MANAGER_TASK_DEFAULT_MAX_PENDING_DELETES,
    },
    {
        /* An on-demand vulnerability scan. Re-requested on the next feed-offset change, so a
         * finite budget is safe here in a way it is not above. */
        .name = WM_MANAGER_TASK_VD_SCAN,
        .lane = WM_MANAGER_TASK_LANE_SCAN,
        .method = "POST",
        .path = "/_internal/vd/scan",
        .max_attempts = WM_MANAGER_TASK_USE_DEFAULT,
        .max_defer = WM_MANAGER_TASK_USE_DEFAULT,
        .allow_terminal_failure = true,
        .coalesce = true,
        .max_pending = WM_MANAGER_TASK_DEFAULT_MAX_PENDING_SCANS,
    },
    {
        .name = WM_MANAGER_TASK_AGENT_DISCONNECT,
        .lane = WM_MANAGER_TASK_LANE_LOCAL,
        .handler = wm_manager_task_handler_unimplemented,
        .max_attempts = WM_MANAGER_TASK_USE_DEFAULT,
        .max_defer = WM_MANAGER_TASK_USE_DEFAULT,
        .allow_terminal_failure = true,
        .coalesce = false,
        .max_pending = WM_MANAGER_TASK_UNBOUNDED,
    },
    {
        .name = WM_MANAGER_TASK_AGENT_DELETE_OLD,
        .lane = WM_MANAGER_TASK_LANE_LOCAL,
        .handler = wm_manager_task_handler_unimplemented,
        .max_attempts = WM_MANAGER_TASK_USE_DEFAULT,
        .max_defer = WM_MANAGER_TASK_USE_DEFAULT,
        .allow_terminal_failure = true,
        .coalesce = false,
        .max_pending = WM_MANAGER_TASK_UNBOUNDED,
    },
    {
        .name = WM_MANAGER_TASK_LOG_ROTATE_DAILY,
        .lane = WM_MANAGER_TASK_LANE_LOCAL,
        .handler = wm_manager_task_handler_unimplemented,
        .max_attempts = WM_MANAGER_TASK_USE_DEFAULT,
        .max_defer = WM_MANAGER_TASK_USE_DEFAULT,
        .allow_terminal_failure = true,
        .coalesce = false,
        .max_pending = WM_MANAGER_TASK_UNBOUNDED,
    },
};

#define REGISTRY_COUNT (sizeof(manager_task_registry) / sizeof(*manager_task_registry))

/* Per-lane views of the registry, built alongside it so a lane thread can rotate through its
 * types without filtering the whole table on every wake. */
STATIC const wm_manager_task_descriptor *manager_task_lane_types[WM_MANAGER_TASK_LANE_COUNT][REGISTRY_COUNT];
STATIC size_t manager_task_lane_type_count[WM_MANAGER_TASK_LANE_COUNT];

void wm_manager_task_policy_load(wm_manager_task_policy *policy) {
    if (!policy) {
        return;
    }

    // getDefine_Int_default, never bare getDefine_Int: the latter calls merror_exit on a key that
    // is not present, and none of these keys ships in internal_options.conf.
    policy->backoff_base = getDefine_Int_default("wazuh_modules", "manager_task_backoff_base", 1, 3600,
                                                 WM_MANAGER_TASK_DEFAULT_BACKOFF_BASE);
    policy->backoff_cap = getDefine_Int_default("wazuh_modules", "manager_task_backoff_cap", 1, 86400,
                                                WM_MANAGER_TASK_DEFAULT_BACKOFF_CAP);
    policy->defer_base = getDefine_Int_default("wazuh_modules", "manager_task_defer_base", 1, 3600,
                                               WM_MANAGER_TASK_DEFAULT_DEFER_BASE);
    policy->max_attempts = getDefine_Int_default("wazuh_modules", "manager_task_max_attempts", 1, 1000,
                                                 WM_MANAGER_TASK_DEFAULT_MAX_ATTEMPTS);
    policy->max_defer = getDefine_Int_default("wazuh_modules", "manager_task_max_defer", 1, 10000,
                                              WM_MANAGER_TASK_DEFAULT_MAX_DEFER);

    // A base above the cap would make the first delay the longest and every later one shorter.
    if (policy->backoff_base > policy->backoff_cap) {
        policy->backoff_base = policy->backoff_cap;
    }

    if (policy->defer_base > policy->backoff_cap) {
        policy->defer_base = policy->backoff_cap;
    }
}

int wm_manager_task_registry_init(const char *inventory_sync_socket) {
    int vd_scan_timeout = getDefine_Int_default("wazuh_modules", "manager_task_vd_scan_timeout", 1, 3600,
                                                WM_MANAGER_TASK_DEFAULT_VD_SCAN_TIMEOUT);
    int delete_timeout = getDefine_Int_default("wazuh_modules", "manager_task_delete_timeout", 1, 7200,
                                               WM_MANAGER_TASK_DEFAULT_DELETE_TIMEOUT);
    int connect_timeout = getDefine_Int_default("wazuh_modules", "manager_task_create_timeout", 1, 60,
                                                WM_MANAGER_TASK_DEFAULT_CONNECT_TIMEOUT);

    // Asserted, not commented. A scan can park a deletion behind it on the consumer's per-agent
    // queue; if the deletion's own deadline can expire while it waits, it re-queues for the full
    // backoff over work that was never its own fault.
    if (delete_timeout <= vd_scan_timeout) {
        mterror(WM_TASK_MANAGER_LOGTAG,
                "manager_task_delete_timeout (%d) must be greater than manager_task_vd_scan_timeout (%d).",
                delete_timeout, vd_scan_timeout);
        return -1;
    }

    memset(manager_task_lane_type_count, 0, sizeof(manager_task_lane_type_count));

    for (size_t i = 0; i < REGISTRY_COUNT; i++) {
        wm_manager_task_descriptor *desc = &manager_task_registry[i];

        if (desc->lane >= WM_MANAGER_TASK_LANE_COUNT) {
            mterror(WM_TASK_MANAGER_LOGTAG, "Task type '%s' names an unknown lane.", desc->name);
            return -1;
        }

        if (desc->path) {
            if (!inventory_sync_socket || !*inventory_sync_socket) {
                mterror(WM_TASK_MANAGER_LOGTAG,
                        "Task type '%s' needs a consumer socket and none was resolved.", desc->name);
                return -1;
            }

            // The socket is configuration rather than a constant: the consumer's own socket_path
            // option can move it, and both descriptors must follow it there.
            strncpy(desc->socket_path, inventory_sync_socket, sizeof(desc->socket_path) - 1);
            desc->socket_path[sizeof(desc->socket_path) - 1] = '\0';

            desc->connect_timeout_ms = (long)connect_timeout * 1000;
            desc->request_timeout_ms =
                (long)(strcmp(desc->name, WM_MANAGER_TASK_VD_SCAN) == 0 ? vd_scan_timeout : delete_timeout) * 1000;

            // Both are set explicitly and neither may be left at zero: libcurl reads a zero
            // request timeout as "wait forever" and a zero connect timeout as its own 300 second
            // default, so the two zeroes would mean different and equally wrong things.
            if (desc->connect_timeout_ms <= 0 || desc->request_timeout_ms <= 0) {
                mterror(WM_TASK_MANAGER_LOGTAG, "Task type '%s' has a non-positive timeout.", desc->name);
                return -1;
            }
        } else if (!desc->handler) {
            // A type with neither a route nor a handler would be claimed and then dropped.
            mterror(WM_TASK_MANAGER_LOGTAG, "Task type '%s' has neither a route nor a handler.", desc->name);
            return -1;
        }

        manager_task_lane_types[desc->lane][manager_task_lane_type_count[desc->lane]++] = desc;
    }

    return 0;
}

const wm_manager_task_descriptor* wm_manager_task_registry_get(const char *name) {
    if (!name) {
        return NULL;
    }

    for (size_t i = 0; i < REGISTRY_COUNT; i++) {
        if (strcmp(manager_task_registry[i].name, name) == 0) {
            return &manager_task_registry[i];
        }
    }

    return NULL;
}

const wm_manager_task_descriptor* wm_manager_task_registry_at(size_t index) {
    return index < REGISTRY_COUNT ? &manager_task_registry[index] : NULL;
}

size_t wm_manager_task_registry_count(void) {
    return REGISTRY_COUNT;
}

const wm_manager_task_descriptor** wm_manager_task_registry_lane(wm_manager_task_lane lane, size_t *count) {
    if (lane >= WM_MANAGER_TASK_LANE_COUNT) {
        if (count) {
            *count = 0;
        }
        return NULL;
    }

    if (count) {
        *count = manager_task_lane_type_count[lane];
    }

    return manager_task_lane_types[lane];
}

int wm_manager_task_lane_depth(wm_manager_task_lane lane) {
    return lane < WM_MANAGER_TASK_LANE_COUNT ? WM_MANAGER_TASK_LANE_DEPTH[lane] : 0;
}

const char* wm_manager_task_lane_name(wm_manager_task_lane lane) {
    return lane < WM_MANAGER_TASK_LANE_COUNT ? WM_MANAGER_TASK_LANE_NAMES[lane] : "unknown";
}

int wm_manager_task_max_attempts(const wm_manager_task_descriptor *desc, const wm_manager_task_policy *policy) {
    if (!desc) {
        return 0;
    }

    return desc->max_attempts == WM_MANAGER_TASK_USE_DEFAULT ? policy->max_attempts : desc->max_attempts;
}

int wm_manager_task_max_defer(const wm_manager_task_descriptor *desc, const wm_manager_task_policy *policy) {
    if (!desc) {
        return 0;
    }

    return desc->max_defer == WM_MANAGER_TASK_USE_DEFAULT ? policy->max_defer : desc->max_defer;
}

/**
 * @brief Double a base delay a given number of times without overflowing.
 *
 * @param[in] steps Doublings to apply, from zero.
 * @param[in] base First delay.
 * @param[in] cap Ceiling.
 * @return Delay in seconds.
 */
STATIC int wm_manager_task_ladder(int steps, int base, int cap) {
    long long delay = base;

    if (base <= 0) {
        return cap > 0 ? cap : 0;
    }

    for (int i = 0; i < steps && delay < cap; i++) {
        delay *= 2;
    }

    return (int)(delay > cap ? cap : delay);
}

int wm_manager_task_backoff(int attempts, int base, int cap) {
    // The first retry uses the base, so the number of doublings is one fewer than the attempt
    // count. A caller passing zero has not attempted anything and gets the base.
    return wm_manager_task_ladder(attempts > 0 ? attempts - 1 : 0, base, cap);
}

int wm_manager_task_defer_delay(int defer_count, int base, int cap) {
    return wm_manager_task_ladder(defer_count > 0 ? defer_count - 1 : 0, base, cap);
}

void wm_manager_task_apply_result(const wm_manager_task_descriptor *desc,
                                  const wm_manager_task_policy *policy,
                                  wm_manager_task_result result,
                                  int attempts,
                                  int defer_count,
                                  long long now,
                                  wm_manager_task_transition_t *transition) {
    int max_attempts = 0;
    int max_defer = 0;

    if (!desc || !policy || !transition) {
        return;
    }

    max_attempts = wm_manager_task_max_attempts(desc, policy);
    max_defer = wm_manager_task_max_defer(desc, policy);

    transition->status = NULL;
    transition->attempts = attempts;
    transition->defer_count = defer_count;
    transition->next_attempt_at = now;

    switch (result) {
    case WM_MANAGER_TASK_OK:
        transition->status = "completed";
        break;

    case WM_MANAGER_TASK_RETRYABLE:
    case WM_MANAGER_TASK_TIMEOUT:
        transition->attempts = attempts + 1;

        // Zeroed on any real attempt. The deferral counter counts *consecutive* no-fault
        // deferrals, and without the reset both the ladder and the log escalation are wrong from
        // the first time a task flaps between deferring and genuinely failing.
        transition->defer_count = 0;

        if (max_attempts != WM_MANAGER_TASK_UNBOUNDED && transition->attempts >= max_attempts) {
            transition->status = "dead_letter";
        } else {
            transition->next_attempt_at =
                now + wm_manager_task_backoff(transition->attempts, policy->backoff_base, policy->backoff_cap);
        }
        break;

    case WM_MANAGER_TASK_TERMINAL:
        // Terminal does not consume the attempt budget: the row is not being given up on after
        // trying, it is being declared impossible.
        transition->status = "failed";
        break;

    case WM_MANAGER_TASK_NOT_READY:
    case WM_MANAGER_TASK_BUSY:
        transition->defer_count = defer_count + 1;

        // Deferral has a ceiling for the same reason retry does, and for every type that can be
        // asked again. Without one, a consumer that never appears leaves rows deferring at the
        // cap forever while coalescing folds every new request into them, the admission bound
        // fills permanently, and nothing lands in dead_letter for anyone to find. That is worse
        // than dead-lettering, because it is invisible.
        if (max_defer != WM_MANAGER_TASK_UNBOUNDED && transition->defer_count >= max_defer) {
            transition->status = "dead_letter";
        } else {
            transition->next_attempt_at =
                now + wm_manager_task_defer_delay(transition->defer_count, policy->defer_base, policy->backoff_cap);
        }
        break;

    case WM_MANAGER_TASK_INCOMPLETE:
        // Real progress on a self-bounded handler: neither success nor failure. Completing would
        // end the row with the work half done; consuming an attempt would dead-letter a fleet
        // that needs more batches than the budget allows.
        transition->defer_count = 0;
        transition->next_attempt_at = now;
        break;
    }
}

/**
 * @brief Parse a consumer's JSON body defensively.
 *
 * The body buffer is caller-owned, is not NUL-terminated and truncates silently, so a body that
 * did not fit has to be indistinguishable from one that failed to parse.
 *
 * @param[in] body Response bytes.
 * @param[in] body_len Bytes written.
 * @return Parsed object, or NULL when the body is absent, truncated or malformed. Caller frees.
 */
STATIC cJSON* wm_manager_task_parse_body(const char *body, size_t body_len) {
    char *copy = NULL;
    cJSON *parsed = NULL;

    if (!body || body_len == 0) {
        return NULL;
    }

    os_calloc(body_len + 1, sizeof(char), copy);
    memcpy(copy, body, body_len);

    parsed = cJSON_Parse(copy);

    os_free(copy);

    return parsed;
}

wm_manager_task_result wm_manager_task_classify_response(int rc,
                                                         const uhttp_result_t *result,
                                                         const char *body,
                                                         size_t body_len,
                                                         bool allow_terminal_failure,
                                                         char *error,
                                                         size_t error_len) {
    cJSON *parsed = NULL;
    wm_manager_task_result outcome = WM_MANAGER_TASK_RETRYABLE;

    if (error && error_len) {
        *error = '\0';
    }

    if (rc == 0) {
        return WM_MANAGER_TASK_OK;
    }

    // The "request was never sent" sentinel, documented on uhttp_post: a return of -1 with the
    // result struct untouched. It fires only on local errors -- a NULL client, NULL data with a
    // positive length, a failed setopt -- so it is a dispatcher bug, not a consumer that is down.
    // Distinguishing it from -CURLE_UNSUPPORTED_PROTOCOL is safe because the URL and socket are
    // fixed constants; it depends on the result struct having been zeroed before the call.
    if (rc == -1 && result && result->curl_code == 0 && result->http_status == 0) {
        if (error && error_len) {
            snprintf(error, error_len, "request was never sent (dispatcher bug)");
        }
        return WM_MANAGER_TASK_TERMINAL;
    }

    if (rc < 0) {
        int curl_code = -rc;

        switch (curl_code) {
        case WM_MANAGER_TASK_CURLE_COULDNT_CONNECT:
            // The socket is missing, or present with nothing listening. Classifying this as a
            // generic transport error would burn the whole retry budget on a boot race.
            if (error && error_len) {
                snprintf(error, error_len, "consumer not listening");
            }
            return WM_MANAGER_TASK_NOT_READY;

        case WM_MANAGER_TASK_CURLE_OPERATION_TIMEDOUT:
            if (error && error_len) {
                snprintf(error, error_len, "consumer did not answer before the deadline");
            }
            return WM_MANAGER_TASK_TIMEOUT;

        default:
            // Everything else reachable over a Unix socket is mid-transfer: the peer died while
            // the request was in flight. Retryable.
            if (error && error_len) {
                snprintf(error, error_len, "transport error %d", curl_code);
            }
            return WM_MANAGER_TASK_RETRYABLE;
        }
    }

    parsed = wm_manager_task_parse_body(body, body_len);

    if (rc == 409) {
        // A 409 means the consumer is already running this work, whatever the body says. Falling
        // through to the 4xx rule on an unparseable body would, for a type that must never fail,
        // be exactly the orphan that allow_terminal_failure exists to prevent.
        const cJSON *code = parsed ? cJSON_GetObjectItem(parsed, "error") : NULL;

        if (error && error_len) {
            snprintf(error, error_len, "consumer busy: %s",
                     (code && cJSON_IsString(code)) ? code->valuestring : "no detail");
        }

        cJSON_Delete(parsed);
        return WM_MANAGER_TASK_BUSY;
    }

    if (rc >= 500 || rc == 408 || rc == 429) {
        outcome = WM_MANAGER_TASK_RETRYABLE;
    } else if (rc >= 400) {
        // A 4xx is the consumer saying the request itself is wrong. For a type carrying an
        // obligation nobody will raise again, that is a dispatcher bug or a transient
        // misconfiguration, and neither is a reason to abandon the work.
        outcome = allow_terminal_failure ? WM_MANAGER_TASK_TERMINAL : WM_MANAGER_TASK_RETRYABLE;
    } else {
        // A non-2xx that is not 4xx or 5xx. uhttp_post only returns a status here when it was
        // not a success, so this is a redirect or something equally unexpected on a local socket.
        outcome = WM_MANAGER_TASK_RETRYABLE;
    }

    if (parsed) {
        // A consumer may say a failure is worth retrying even when its status suggests otherwise.
        const cJSON *retryable = cJSON_GetObjectItem(parsed, "retryable");

        if (retryable && cJSON_IsTrue(retryable) && outcome == WM_MANAGER_TASK_TERMINAL) {
            outcome = WM_MANAGER_TASK_RETRYABLE;
        }
    }

    if (error && error_len) {
        const cJSON *code = parsed ? cJSON_GetObjectItem(parsed, "error") : NULL;

        snprintf(error, error_len, "HTTP %d: %s", rc,
                 (code && cJSON_IsString(code)) ? code->valuestring : "no detail");
    }

    cJSON_Delete(parsed);

    return outcome;
}
