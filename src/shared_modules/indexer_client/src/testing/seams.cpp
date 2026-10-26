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
// the call, so a test may replace them while runtime threads run. A seam with no hook installed reads only its slot's
// atomic flag (acquire) and never takes the mutex (G-diff E6e r2 P3-1): otherwise every seam on a hot path (stage(),
// the stripe flush) would serialize all producers through g_hooksMutex — a full barrier between a stripe's store of
// `oldest` and its load of the armed deadline, and a happens-before edge TSAN would see between unrelated producers.

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <utility>

#include "testing/hooks.hpp"
#include "transport/seams.hpp"

namespace
{
    /// A hook slot: `set` mirrors whether `fn` is installed, so a seam with none skips the mutex.
    template<class F>
    struct Hook final
    {
        F fn;
        std::atomic<bool> set {false};
    };

    std::mutex g_hooksMutex;
    Hook<std::function<void()>> g_afterAdmissionCheck;
    Hook<std::function<int(int)>> g_injectMultiError;
    Hook<std::function<void()>> g_throwOnAdd;
    Hook<std::function<void()>> g_beforeRetryAfterParse;
    Hook<std::function<void(std::uint64_t, std::uint64_t)>> g_onTimerHandler;
    Hook<std::function<std::optional<int>()>> g_openSocket;
    Hook<std::function<bool()>> g_refuseSubmit;
    Hook<std::function<void()>> g_beforeCompletion;
    Hook<std::function<void()>> g_beforeSenderMirror;
    Hook<std::function<void()>> g_beforeAssembly;
    std::optional<std::int64_t> g_queryConflictBaseMs;
    Hook<std::function<void()>> g_inCallbackGate;
    Hook<std::function<void()>> g_afterPayloadReleased;
    Hook<std::function<void()>> g_midBulkSettle;
    Hook<std::function<void()>> g_beforeStagePush;
    Hook<std::function<void()>> g_beforeArmedDueLoad;
    Hook<std::function<void()>> g_beforePublishArmedDue;
    Hook<std::function<void()>> g_midAdmitBatch;
    Hook<std::function<void()>> g_inSettleBulk;

    template<class F>
    F copyOf(const Hook<F>& hook)
    {
        if (!hook.set.load(std::memory_order_acquire))
        {
            return {}; // Fast path: no hook, no mutex.
        }
        std::lock_guard<std::mutex> lock(g_hooksMutex);
        return hook.fn;
    }

    template<class F>
    void store(Hook<F>& slot, F hook)
    {
        std::lock_guard<std::mutex> lock(g_hooksMutex);
        slot.fn = std::move(hook);
        slot.set.store(static_cast<bool>(slot.fn), std::memory_order_release);
    }

    /// g_hooksMutex held (resetAll).
    template<class F>
    void clear(Hook<F>& slot)
    {
        slot.set.store(false, std::memory_order_release);
        slot.fn = {};
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

    bool refuseSubmit()
    {
        auto hook = copyOf(g_refuseSubmit);
        return hook ? hook() : false;
    }

    void beforeCompletion()
    {
        if (auto hook = copyOf(g_beforeCompletion))
        {
            hook();
        }
    }

    void beforeSenderMirror()
    {
        if (auto hook = copyOf(g_beforeSenderMirror))
        {
            hook();
        }
    }

    void beforeAssembly()
    {
        if (auto hook = copyOf(g_beforeAssembly))
        {
            hook();
        }
    }

    std::optional<std::int64_t> queryConflictBaseMs()
    {
        std::lock_guard<std::mutex> lock(g_hooksMutex);
        return g_queryConflictBaseMs;
    }

    void inCallbackGate()
    {
        if (auto hook = copyOf(g_inCallbackGate))
        {
            hook();
        }
    }

    void afterPayloadReleased()
    {
        if (auto hook = copyOf(g_afterPayloadReleased))
        {
            hook();
        }
    }

    void midBulkSettle()
    {
        if (auto hook = copyOf(g_midBulkSettle))
        {
            hook();
        }
    }

    void beforeStagePush()
    {
        if (auto hook = copyOf(g_beforeStagePush))
        {
            hook();
        }
    }

    void beforeArmedDueLoad()
    {
        if (auto hook = copyOf(g_beforeArmedDueLoad))
        {
            hook();
        }
    }

    void beforePublishArmedDue()
    {
        if (auto hook = copyOf(g_beforePublishArmedDue))
        {
            hook();
        }
    }

    void midAdmitBatch()
    {
        if (auto hook = copyOf(g_midAdmitBatch))
        {
            hook();
        }
    }

    void inSettleBulk()
    {
        if (auto hook = copyOf(g_inSettleBulk))
        {
            hook();
        }
    }

    std::optional<std::size_t> stripeCount()
    {
        static const std::optional<std::size_t> fixed = []() -> std::optional<std::size_t>
        {
            const char* raw = std::getenv("INDEXER_CLIENT_TEST_STRIPES");
            if (raw == nullptr || *raw == '\0')
            {
                return std::nullopt;
            }
            std::size_t value = 0;
            for (const char* c = raw; *c != '\0'; ++c)
            {
                if (*c < '0' || *c > '9' || (value = value * 10 + static_cast<std::size_t>(*c - '0')) > 64)
                {
                    value = 0;
                    break;
                }
            }
            if (value == 0)
            {
                std::fprintf(stderr, "INDEXER_CLIENT_TEST_STRIPES='%s' is not an integer 1-64\n", raw);
                std::abort();
            }
            return value;
        }();
        return fixed;
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
    void setRefuseSubmit(std::function<bool()> hook)
    {
        store(g_refuseSubmit, std::move(hook));
    }
    void setBeforeCompletion(std::function<void()> hook)
    {
        store(g_beforeCompletion, std::move(hook));
    }
    void setBeforeSenderMirror(std::function<void()> hook)
    {
        store(g_beforeSenderMirror, std::move(hook));
    }
    void setBeforeAssembly(std::function<void()> hook)
    {
        store(g_beforeAssembly, std::move(hook));
    }
    void setInCallbackGate(std::function<void()> hook)
    {
        store(g_inCallbackGate, std::move(hook));
    }
    void setAfterPayloadReleased(std::function<void()> hook)
    {
        store(g_afterPayloadReleased, std::move(hook));
    }
    void setMidBulkSettle(std::function<void()> hook)
    {
        store(g_midBulkSettle, std::move(hook));
    }
    void setBeforeStagePush(std::function<void()> hook)
    {
        store(g_beforeStagePush, std::move(hook));
    }
    void setBeforeArmedDueLoad(std::function<void()> hook)
    {
        store(g_beforeArmedDueLoad, std::move(hook));
    }
    void setBeforePublishArmedDue(std::function<void()> hook)
    {
        store(g_beforePublishArmedDue, std::move(hook));
    }
    void setMidAdmitBatch(std::function<void()> hook)
    {
        store(g_midAdmitBatch, std::move(hook));
    }
    void setInSettleBulk(std::function<void()> hook)
    {
        store(g_inSettleBulk, std::move(hook));
    }

    void setQueryConflictBaseMs(std::optional<std::int64_t> milliseconds)
    {
        std::lock_guard<std::mutex> lock(g_hooksMutex);
        g_queryConflictBaseMs = milliseconds;
    }
    void resetAll()
    {
        {
            std::lock_guard<std::mutex> lock(g_hooksMutex);
            clear(g_afterAdmissionCheck);
            clear(g_injectMultiError);
            clear(g_throwOnAdd);
            clear(g_beforeRetryAfterParse);
            clear(g_onTimerHandler);
            clear(g_openSocket);
            clear(g_refuseSubmit);
            clear(g_beforeCompletion);
            clear(g_beforeSenderMirror);
            clear(g_beforeAssembly);
            g_queryConflictBaseMs.reset();
            clear(g_inCallbackGate);
            clear(g_afterPayloadReleased);
            clear(g_midBulkSettle);
            clear(g_beforeStagePush);
            clear(g_beforeArmedDueLoad);
            clear(g_beforePublishArmedDue);
            clear(g_midAdmitBatch);
            clear(g_inSettleBulk);
        }
        setProbeAutoStart(true);
    }
} // namespace indexer_client::testing_hooks
