/*
 * Wazuh remoted module - client.keys keystore metrics
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_AUTH_KEYSTORE_METRICS_HPP
#define _REMOTED_AUTH_KEYSTORE_METRICS_HPP

/**
 * @file keystoreMetrics.hpp
 * @brief Names of the client.keys keystore pulls (`remoted.auth.keystore.*`) on the shared
 *        `wazuh_metrics` registry.
 *
 * Registered by the facade (registerKeystoreDiagnostics()) over the atomics Keystore::reload()
 * maintains, on a weak target repointed per start. `agents` and `entries_skipped` are LEVELS of
 * the adopted load (a failed load leaves both untouched); the two totals count loads.
 */

namespace remoted::auth
{
    constexpr auto METRIC_KEYSTORE_AGENTS {"remoted.auth.keystore.agents"};
    constexpr auto METRIC_KEYSTORE_ENTRIES_SKIPPED {"remoted.auth.keystore.entries_skipped"};
    constexpr auto METRIC_KEYSTORE_RELOADS_TOTAL {"remoted.auth.keystore.reloads.total"};
    constexpr auto METRIC_KEYSTORE_RELOAD_FAILURES_TOTAL {"remoted.auth.keystore.reload_failures.total"};
} // namespace remoted::auth

#endif // _REMOTED_AUTH_KEYSTORE_METRICS_HPP
