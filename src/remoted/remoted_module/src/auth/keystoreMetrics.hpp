/*
 * Wazuh remoted module - Keystore metrics
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_AUTH_KEYSTORE_METRICS_HPP
#define _REMOTED_AUTH_KEYSTORE_METRICS_HPP

namespace remoted::auth
{
    // The remoted.auth.keystore.* name catalog: the pulls the facade registers over Keystore's
    // health accessors (registerKeystorePulls()). The class itself stays metrics-library-free.
    // Levels describing the file as last loaded (see Keystore::agentsLoaded() / entriesSkipped()):
    constexpr auto METRIC_KEYSTORE_AGENTS {"remoted.auth.keystore.agents"};
    constexpr auto METRIC_KEYSTORE_ENTRIES_SKIPPED {"remoted.auth.keystore.entries_skipped"};
    // Load outcomes since start:
    constexpr auto METRIC_KEYSTORE_RELOADS_TOTAL {"remoted.auth.keystore.reloads.total"};
    constexpr auto METRIC_KEYSTORE_RELOAD_FAILURES_TOTAL {"remoted.auth.keystore.reload_failures.total"};
    // Credentials adopted from accepted POST /enroll answers (Keystore::upsert()): how many were
    // taken, how many the file has not caught up with yet (a level), how many it never caught up
    // with within the grace.
    constexpr auto METRIC_KEYSTORE_ADOPTIONS_TOTAL {"remoted.auth.keystore.adoptions.total"};
    constexpr auto METRIC_KEYSTORE_ADOPTIONS_PENDING {"remoted.auth.keystore.adoptions_pending"};
    constexpr auto METRIC_KEYSTORE_ADOPTION_EXPIRIES_TOTAL {"remoted.auth.keystore.adoption_expiries.total"};
} // namespace remoted::auth

#endif // _REMOTED_AUTH_KEYSTORE_METRICS_HPP
