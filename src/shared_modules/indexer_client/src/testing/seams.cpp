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

// Compiled only into indexer_client_testing (INDEXER_CLIENT_TESTING). Hooks are read under a mutex and copied before
// the call, so a test may replace them while runtime threads run.

#include <mutex>
#include <utility>

#include "testing/hooks.hpp"
#include "transport/seams.hpp"

namespace
{
    std::mutex g_hooksMutex;
    std::function<void()> g_afterAdmissionCheck;
    std::function<int(int)> g_injectMultiError;
    std::function<void()> g_throwOnAdd;
    std::function<void()> g_beforeRetryAfterParse;
    std::function<void(std::uint64_t, std::uint64_t)> g_onTimerHandler;
    std::function<std::optional<int>()> g_openSocket;

    template<class F>
    F copyOf(const F& hook)
    {
        std::lock_guard<std::mutex> lock(g_hooksMutex);
        return hook;
    }

    template<class F>
    void store(F& slot, F hook)
    {
        std::lock_guard<std::mutex> lock(g_hooksMutex);
        slot = std::move(hook);
    }
} // namespace

namespace indexer_client::detail::seams
{
    void afterAdmissionCheck()
    {
        if (auto hook = copyOf(g_afterAdmissionCheck))
        {
            hook();
        }
    }

    int injectMultiError(int rc)
    {
        auto hook = copyOf(g_injectMultiError);
        return hook ? hook(rc) : rc;
    }

    void throwOnAdd()
    {
        if (auto hook = copyOf(g_throwOnAdd))
        {
            hook();
        }
    }

    void beforeRetryAfterParse()
    {
        if (auto hook = copyOf(g_beforeRetryAfterParse))
        {
            hook();
        }
    }

    void onTimerHandler(std::uint64_t generation, std::uint64_t current)
    {
        if (auto hook = copyOf(g_onTimerHandler))
        {
            hook(generation, current);
        }
    }

    std::optional<int> openSocket()
    {
        auto hook = copyOf(g_openSocket);
        return hook ? hook() : std::nullopt;
    }
} // namespace indexer_client::detail::seams

namespace indexer_client::testing_hooks
{
    void setAfterAdmissionCheck(std::function<void()> hook)
    {
        store(g_afterAdmissionCheck, std::move(hook));
    }
    void setInjectMultiError(std::function<int(int)> hook)
    {
        store(g_injectMultiError, std::move(hook));
    }
    void setThrowOnAdd(std::function<void()> hook)
    {
        store(g_throwOnAdd, std::move(hook));
    }
    void setBeforeRetryAfterParse(std::function<void()> hook)
    {
        store(g_beforeRetryAfterParse, std::move(hook));
    }
    void setOnTimerHandler(std::function<void(std::uint64_t, std::uint64_t)> hook)
    {
        store(g_onTimerHandler, std::move(hook));
    }
    void setOpenSocket(std::function<std::optional<int>()> hook)
    {
        store(g_openSocket, std::move(hook));
    }
    void resetAll()
    {
        {
            std::lock_guard<std::mutex> lock(g_hooksMutex);
            g_afterAdmissionCheck = {};
            g_injectMultiError = {};
            g_throwOnAdd = {};
            g_beforeRetryAfterParse = {};
            g_onTimerHandler = {};
            g_openSocket = {};
        }
        setProbeAutoStart(true);
    }
} // namespace indexer_client::testing_hooks
