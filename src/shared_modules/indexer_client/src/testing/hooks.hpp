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

#include <cstddef>
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
    void setAfterAdmission(std::function<void()> hook); ///< E3a: between reserve and enqueue in Writer::submit.
    /// E3b-2: the bulk sender's submit is refused (InvalidState) while the hook returns true.
    void setRefuseSubmit(std::function<bool()> hook);
    /// G-diff E3b-2: runs in every bulk completion after the slot was released; a throw exercises its fallback.
    void setBeforeCompletion(std::function<void()> hook);
    /// E3c-2: runs in the bulk sender's pool task before the cancelled ops are dropped and the body assembled.
    void setBeforeAssembly(std::function<void()> hook);
    /// G-diff E3b-2: runs in the bulk sender's NodeSet hook before the Down mirror is refreshed; blocking delays it.
    void setBeforeSenderMirror(std::function<void()> hook);
    /// E3b-1: capacity of the calling thread's bulk-response parser (0 before its first use); I65 caps it at 4 MiB.
    std::size_t parserCapacity();
    /// false makes RuntimeOwner::start create the NodeSet and the Prober without starting the probe (no round, no
    /// timer; probeNow() still arms a single round): for the suites that count the transport's own traffic (E2a).
    /// Read once per start(); resetAll() restores the default, true.
    void setProbeAutoStart(bool enabled);
    /// Clears every hook above and restores the probe's auto start.
    void resetAll();

    /// Kernel tids of the runtime threads started since the last clearRuntimeThreads().
    std::vector<pid_t> runtimeThreads();
    void clearRuntimeThreads();

    /// Posts refused because their loop had closed, since process start.
    std::uint64_t postsRejected();
} // namespace indexer_client::testing_hooks

#endif // _INDEXER_CLIENT_TESTING_HOOKS_HPP
