/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// Compiled only into indexer_client_testing (INDEXER_CLIENT_TESTING): the record of runtime thread ids and the
// counters the component tests read.

#include <atomic>
#include <mutex>

#include "testing/hooks.hpp"
#include "transport/seams.hpp"

namespace
{
    std::mutex g_registryMutex;
    std::vector<pid_t> g_runtimeThreads;
    std::atomic<std::uint64_t> g_postsRejected {0};
} // namespace

namespace indexer_client::detail::seams
{
    void onRuntimeThreadStart(pid_t tid)
    {
        std::lock_guard<std::mutex> lock(g_registryMutex);
        g_runtimeThreads.push_back(tid);
    }

    void onPostRejected()
    {
        g_postsRejected.fetch_add(1);
    }
} // namespace indexer_client::detail::seams

namespace indexer_client::testing_hooks
{
    std::vector<pid_t> runtimeThreads()
    {
        std::lock_guard<std::mutex> lock(g_registryMutex);
        return g_runtimeThreads;
    }

    void clearRuntimeThreads()
    {
        std::lock_guard<std::mutex> lock(g_registryMutex);
        g_runtimeThreads.clear();
    }

    std::uint64_t postsRejected()
    {
        return g_postsRejected.load();
    }
} // namespace indexer_client::testing_hooks
