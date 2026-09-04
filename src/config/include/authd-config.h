/*
 * Authd settings manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 29, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef AUTH_CONFIG_H
#define AUTH_CONFIG_H

#define AUTHD_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT false    ///< Default allow_higher_versions value (false)

#include <stdbool.h>
#include <time.h>

/**
 * @brief Structure that defines the force options for agent replacement.
 **/
typedef struct authd_force_options_t {
    bool enabled;                    ///< Sets to enabled or disabled the force options for agent replacement
    bool key_mismatch;               ///< Sets to enabled or disabled the key_mismatch auth setting
    bool disconnected_time_enabled;  ///< Sets to enabled or disabled the disconnected_time auth setting
    time_t disconnected_time;        ///< Sets the time to be used by the disconnected_time auth setting if enabled
    time_t after_registration_time;  ///< Sets the time to be used by the after_registration_time auth setting
} authd_force_options_t;

typedef struct authd_flags_t {
    unsigned short disabled:3;
    unsigned short use_source_ip:1;
    unsigned short clear_removed:1;
    unsigned short use_password:1;
    unsigned short verify_host:1;
    unsigned short remote_enrollment:1;
    unsigned short legacy_enrollment:1;  ///< Gates only the legacy TCP/TLS listener (port 1515);
                                          ///< remote_enrollment is the master switch for all remote
                                          ///< self-enrollment. Defaults to enabled.
} authd_flags_t;

typedef struct authd_config_t {
    unsigned short port;
    authd_flags_t flags;
    authd_force_options_t force_options;
    char *ciphers;
    char *agent_ca;
    char *manager_cert;
    char *manager_key;
    long timeout_sec;
    long timeout_usec;
    bool worker_node;
    bool ipv6;
    bool allow_higher_versions;
    unsigned int max_agents;
    /// Seconds a deletion waits before its indexer purge may run (internal option
    /// `authd.purge_delay`). It is the deletion task's initial NEXT_ATTEMPT_AT offset; 0 makes the
    /// purge eligible immediately, which is only meant for tests.
    int purge_delay;
    /// Seconds authd allows for one wazuh-db round trip (internal option `authd.wdb_timeout`).
    ///
    /// It exists because the writer thread creates the deletion rows, and the writer is the thread
    /// that persists client.keys: with an unbounded client a wedged wazuh-db would HANG it, and a
    /// stuck writer has no next cycle to self-heal from. Bounded, the same failure is a phase that
    /// simply did not complete, which the journal makes recoverable.
    int wdb_timeout;
    /// Deletion tasks that may be outstanding before authd refuses new deletions at the request
    /// (`wazuh_modules.manager_task_max_pending_deletes`). 0 disables the bound.
    ///
    /// Read from the Task Manager's namespace rather than authd's on purpose: it is ONE bound on
    /// ONE queue, enforced authoritatively by wazuh-db at creation and pre-checked here so the
    /// caller gets a refusal instead of a deletion that half-succeeds. Two keys would let the two
    /// halves drift.
    int max_pending_deletes;
} authd_config_t;

/**
 * @brief It converts a time string with the format <time><unit>, where the unit could be
 *        d (days), h (hours), m (minutes), or s (seconds), to a representation in seconds saved
 *        in a `time_t` variable.
 *        The time unit is optional. If not provided, it is assumed as seconds.
 *
 * @param syscheck String with the format <time><unit>.
 * @param interval The variable to save the time conversion.
 * @retval OS_INVALID in case of error. OS_SUCCES otherways.
 */
int get_time_interval(char *source, time_t *interval);

/**
 * @brief Validates that a colon-separated string only contains TLS 1.3 ciphersuite names
 *        accepted by SSL_CTX_set_ciphersuites().
 *
 * @param ciphers Colon-separated list of TLS 1.3 ciphersuite names.
 * @retval OS_INVALID if any token is not a recognized TLS 1.3 ciphersuite name. 0 otherwise.
 */
int w_authd_validate_ciphers(const char *ciphers);

#endif
