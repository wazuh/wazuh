/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/*
 * One feed: the manager-reported config_hash (SHA-256, #37733) against a
 * SHA-256 of the local merged.mg. The legacy handshake fed the same decision an
 * MD5 merged_sum -- two digests that could never agree -- and went with the TCP
 * data path (#38030). SHA-256 survives: it is what the manager advertises and
 * what /download already verifies with (configFetcher.cpp).
 */

#include "shared.h"
#include "agentd.h"
#include "sha256_op.h"

static pthread_mutex_t startup_gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool startup_gate_enabled = false;
static bool startup_gate_ready = true;
static char startup_gate_reason[OS_SIZE_128] = "disabled";
static bool startup_gate_download_pending = false;

/* When this process's own gate opened. The other daemons each poll it (via
 * startup_gate_wait_for_ready()) on their own STARTUP_GATE_POLL_INTERVAL and
 * then still need a moment to open their own command socket, so "the gate is
 * open" is not the same instant as "every daemon is answering" -- see
 * startup_gate_is_settled(). */
static time_t startup_gate_ready_since = 0;

static void startup_gate_set_locked(bool ready, const char *reason) {
    startup_gate_ready = ready;
    startup_gate_ready_since = ready ? time(NULL) : 0;

    if (reason && reason[0]) {
        snprintf(startup_gate_reason, sizeof(startup_gate_reason), "%s", reason);
    } else {
        snprintf(startup_gate_reason, sizeof(startup_gate_reason), "unknown");
    }
}

void startup_gate_initialize(void) {
    const bool enabled = agt->flags.remote_conf;

    w_mutex_lock(&startup_gate_mutex);

    startup_gate_enabled = enabled;
    startup_gate_download_pending = false;

    if (enabled) {
        startup_gate_set_locked(false, "waiting_config_hash");
    } else {
        startup_gate_set_locked(true, "disabled");
    }

    w_mutex_unlock(&startup_gate_mutex);
}

void startup_gate_mark_download_pending(void) {
    w_mutex_lock(&startup_gate_mutex);
    startup_gate_download_pending = true;
    w_mutex_unlock(&startup_gate_mutex);
}

void startup_gate_release_from_https_apply(void) {
    // /download already verified the bytes' SHA-256 against the manager's
    // config_hash before the callback fired, and bridge_on_config_downloaded()
    // has since written and applied those exact bytes. That is the invariant
    // the gate exists for, so it opens directly, with no second comparison.
    w_mutex_lock(&startup_gate_mutex);
    startup_gate_download_pending = false;

    if (startup_gate_enabled && !startup_gate_ready) {
        startup_gate_set_locked(true, "https_config_applied");
        w_mutex_unlock(&startup_gate_mutex);
        mdebug1("Startup hash gate released via HTTPS configuration apply (https_config_applied).");
        return;
    }

    w_mutex_unlock(&startup_gate_mutex);
}

void startup_gate_check_manager_config_hash(const char *manager_sha256) {
    bool should_check = false;
    os_sha256 local_sha256;

    w_mutex_lock(&startup_gate_mutex);
    should_check = startup_gate_enabled && !startup_gate_ready && !startup_gate_download_pending;
    w_mutex_unlock(&startup_gate_mutex);

    if (!should_check) {
        return;
    }

    if (!manager_sha256 || !manager_sha256[0]) {
        // An empty config_hash is contract-legal ("Empty when the manager
        // reported none", hc_callbacks_t): the manager has no configuration for
        // this agent's groups, so nothing will be downloaded and there is
        // nothing to wait for. maybeDownloadConfig() also returns early on it,
        // so without this the gate would never open and every module would
        // block forever in startup_gate_wait_for_ready(). The legacy handshake
        // released the gate on an absent merged_sum for the same reason.
        w_mutex_lock(&startup_gate_mutex);
        startup_gate_set_locked(true, "no_manager_config");
        w_mutex_unlock(&startup_gate_mutex);
        mdebug1("Startup hash gate: the manager reported no configuration, gate released.");
        return;
    }

    if (OS_SHA256_File(SHAREDCFG_FILE, local_sha256, OS_BINARY) != 0) {
        return; // No local merged.mg yet (nothing downloaded so far): nothing to compare.
    }

    if (strcmp(local_sha256, manager_sha256) == 0) {
        w_mutex_lock(&startup_gate_mutex);
        startup_gate_set_locked(true, "https_hash_match");
        w_mutex_unlock(&startup_gate_mutex);
        mdebug1("Startup hash gate: manager config hash (SHA-256) matches local, gate released.");
    }
}

void startup_gate_get_status(bool *ready, char *reason, size_t reason_size) {
    w_mutex_lock(&startup_gate_mutex);

    if (ready) {
        *ready = startup_gate_ready;
    }

    if (reason && reason_size > 0) {
        snprintf(reason, reason_size, "%s", startup_gate_reason);
    }

    w_mutex_unlock(&startup_gate_mutex);
}

bool startup_gate_is_ready(void) {
    bool ready = false;

    startup_gate_get_status(&ready, NULL, 0);
    return ready;
}

/* Stricter than startup_gate_is_ready(): also demands margin_seconds have
 * elapsed since it opened, so the other daemons (each polling the same gate
 * on their own STARTUP_GATE_POLL_INTERVAL and then still opening their own
 * command socket) have very likely caught up too. Only report_query() should
 * use this -- everyone else that means "may I start now?" wants the gate the
 * instant it opens, not delayed by someone else's margin. */
bool startup_gate_is_settled(unsigned int margin_seconds)
{
    bool ready = false;
    time_t ready_since = 0;

    w_mutex_lock(&startup_gate_mutex);
    ready = startup_gate_ready;
    ready_since = startup_gate_ready_since;
    w_mutex_unlock(&startup_gate_mutex);

    return ready && ready_since != 0 && (time(NULL) - ready_since) >= (time_t)margin_seconds;
}
