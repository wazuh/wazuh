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
#include "sha256_op.h"
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
    const bool enabled = agt->flags.remote_conf;

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
        mdebug1("Startup hash gate: remote configuration disabled, gate released.");
        return;
    }

    if (!merged_sum || !merged_sum[0]) {
        startup_gate_expected_sum[0] = '\0';
        startup_gate_set_locked(true, "legacy_handshake");
        w_mutex_unlock(&startup_gate_mutex);
        mdebug1("Startup hash gate: legacy handshake (no merged_sum), gate released.");
        return;
    }

    if (!startup_gate_valid_md5(merged_sum)) {
        // The gate stays blocked: an invalid merged_sum means the manager
        // sent us nothing we can validate against, so modules must not
        // start. Recovery requires a fresh handshake with a valid hash
        // (typically after an agentd restart).
        startup_gate_expected_sum[0] = '\0';
        startup_gate_set_locked(false, "invalid_handshake_hash");
        w_mutex_unlock(&startup_gate_mutex);
        mdebug1("Startup hash gate: invalid merged_sum in handshake, gate stays blocked.");
        return;
    }

    snprintf(startup_gate_expected_sum, sizeof(startup_gate_expected_sum), "%s", merged_sum);
    startup_gate_set_locked(false, "waiting_hash_match");

    w_mutex_unlock(&startup_gate_mutex);

    mdebug1("Startup hash gate: expected merged_sum set to '%s'.", merged_sum);

    if (startup_gate_hash_matches_local()) {
        w_mutex_lock(&startup_gate_mutex);
        startup_gate_set_locked(true, "hash_match");
        w_mutex_unlock(&startup_gate_mutex);
        mdebug1("Startup hash gate: local hash matches expected, gate released immediately.");
    } else {
        mdebug1("Startup hash gate: local hash does not match expected, waiting for merged.mg update.");
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

void startup_gate_release_from_https_apply(void) {
    // The HTTPS /control contract (#37733) has no merged_sum handshake field
    // to seed startup_gate_expected_sum with (unlike the legacy handshake), so
    // startup_gate_refresh_from_local_hash()'s MD5-comparison machinery is
    // structurally unusable here: it only ever does anything once
    // startup_gate_process_handshake() has already set an expected value, and
    // that function is legacy-only. Worse, the two sides would compare
    // different hash algorithms anyway -- the HTTPS config_hash is a SHA-256
    // ("SHA256 hash of group configuration", #37733 OpenAPI), while
    // getsharedfiles()/startup_gate_expected_sum are MD5 -- so even seeding
    // expected_sum with config_hash could never produce a real match.
    //
    // The HTTPS /download client (configFetcher.cpp) already verifies the
    // downloaded bytes' SHA-256 against the manager-advertised config_hash
    // BEFORE handing the file to the C side at all (see hc_callbacks_t's
    // on_config_downloaded doc). By the time bridge_on_config_downloaded()
    // calls this function, it has itself written those exact verified bytes
    // to SHAREDCFG_FILE and applied them (UnmergeFiles + verifyRemoteConf).
    // That is the same real-world invariant the legacy MD5 comparison exists
    // to establish ("the config on disk is the one the manager just gave
    // us"), just reached via a different, HTTPS-native verification path --
    // so it is safe to open the gate directly here instead of going through
    // the (inapplicable) MD5 matching helpers.
    w_mutex_lock(&startup_gate_mutex);

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

    if (!manager_sha256 || !manager_sha256[0]) {
        return;
    }

    w_mutex_lock(&startup_gate_mutex);
    should_check = startup_gate_enabled && !startup_gate_ready;
    w_mutex_unlock(&startup_gate_mutex);

    if (!should_check) {
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

bool startup_gate_check_hash_match(void) {
    bool can_check = false;

    w_mutex_lock(&startup_gate_mutex);
    can_check = startup_gate_enabled && !startup_gate_ready && startup_gate_expected_sum[0];
    w_mutex_unlock(&startup_gate_mutex);

    if (!can_check) {
        return false;
    }

    return startup_gate_hash_matches_local();
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
