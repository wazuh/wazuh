/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "../os_crypto/md5/md5_op.h"
#include <ctype.h>

static pthread_mutex_t startup_gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool startup_gate_enabled = false;
static bool startup_gate_ready = true;
static os_md5 startup_gate_expected_sum = {0};
static char startup_gate_reason[OS_SIZE_128] = "disabled";

static void startup_gate_set_locked(bool ready, const char *reason) {
    startup_gate_ready = ready;

    if (reason && reason[0]) {
        snprintf(startup_gate_reason, sizeof(startup_gate_reason), "%s", reason);
    } else {
        snprintf(startup_gate_reason, sizeof(startup_gate_reason), "unknown");
    }
}

static bool startup_gate_valid_md5(const char *hash) {
    size_t i;

    if (!hash || strlen(hash) != 32) {
        return false;
    }

    for (i = 0; i < 32; ++i) {
        if (!isxdigit((unsigned char)hash[i])) {
            return false;
        }
    }

    return true;
}

static bool startup_gate_hash_matches_local(void) {
    bool match = false;
    char expected[sizeof(os_md5)] = {0};
    char *current_hash = NULL;

    w_mutex_lock(&startup_gate_mutex);
    snprintf(expected, sizeof(expected), "%s", startup_gate_expected_sum);
    w_mutex_unlock(&startup_gate_mutex);

    if (!expected[0]) {
        return false;
    }

    current_hash = getsharedfiles();
    if (!current_hash) {
        return false;
    }

    match = strcmp(expected, current_hash) == 0;
    os_free(current_hash);
    return match;
}

void startup_gate_initialize(void) {
    const bool enabled = startup_hash_block && agt->flags.remote_conf;

    w_mutex_lock(&startup_gate_mutex);

    startup_gate_enabled = enabled;
    startup_gate_expected_sum[0] = '\0';

    if (enabled) {
        startup_gate_set_locked(false, "waiting_handshake");
    } else {
        startup_gate_set_locked(true, "disabled");
    }

    w_mutex_unlock(&startup_gate_mutex);
}

void startup_gate_process_handshake(bool is_startup, const char *merged_sum) {
    if (!is_startup) {
        return;
    }

    w_mutex_lock(&startup_gate_mutex);

    if (!startup_gate_enabled) {
        startup_gate_set_locked(true, "disabled");
        w_mutex_unlock(&startup_gate_mutex);
        return;
    }

    if (!merged_sum || !merged_sum[0]) {
        startup_gate_expected_sum[0] = '\0';
        startup_gate_set_locked(true, "legacy_handshake");
        w_mutex_unlock(&startup_gate_mutex);
        return;
    }

    if (!startup_gate_valid_md5(merged_sum)) {
        startup_gate_expected_sum[0] = '\0';
        startup_gate_set_locked(false, "invalid_handshake_hash");
        w_mutex_unlock(&startup_gate_mutex);
        return;
    }

    snprintf(startup_gate_expected_sum, sizeof(startup_gate_expected_sum), "%s", merged_sum);
    startup_gate_set_locked(false, "waiting_hash_match");

    w_mutex_unlock(&startup_gate_mutex);

    if (startup_gate_hash_matches_local()) {
        w_mutex_lock(&startup_gate_mutex);
        startup_gate_set_locked(true, "hash_match");
        w_mutex_unlock(&startup_gate_mutex);
    }
}

void startup_gate_refresh_from_local_hash(void) {
    bool can_check = false;

    w_mutex_lock(&startup_gate_mutex);
    can_check = startup_gate_enabled && startup_gate_expected_sum[0];
    w_mutex_unlock(&startup_gate_mutex);

    if (!can_check) {
        return;
    }

    if (startup_gate_hash_matches_local()) {
        w_mutex_lock(&startup_gate_mutex);
        startup_gate_set_locked(true, "hash_match");
        w_mutex_unlock(&startup_gate_mutex);
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
