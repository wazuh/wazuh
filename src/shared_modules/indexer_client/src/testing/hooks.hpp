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

#ifndef _INDEXER_CLIENT_TESTING_HOOKS_HPP
#define _INDEXER_CLIENT_TESTING_HOOKS_HPP

// Test-only (INDEXER_CLIENT_TESTING): installs the hooks behind detail::seams and reads the test registry. Each
// setter replaces the previous hook; an empty function restores the default (no-op / identity). resetAll() is meant
// for test fixtures' TearDown.

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include <sys/types.h>

namespace indexer_client::testing_hooks
{
    void setAfterAdmissionCheck(std::function<void()> hook);
    void setInjectMultiError(std::function<int(int)> hook);
    void setThrowOnAdd(std::function<void()> hook);
    void setBeforeRetryAfterParse(std::function<void()> hook);
    void setOnTimerHandler(std::function<void(std::uint64_t, std::uint64_t)> hook);
    void setOpenSocket(std::function<std::optional<int>()> hook);
    void resetAll();

    /// Kernel tids of the runtime threads started since the last clearRuntimeThreads().
    std::vector<pid_t> runtimeThreads();
    void clearRuntimeThreads();

    /// Posts refused because their loop had closed, since process start.
    std::uint64_t postsRejected();
} // namespace indexer_client::testing_hooks

#endif // _INDEXER_CLIENT_TESTING_HOOKS_HPP
