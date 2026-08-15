/*
 * Wazuh remoted module - Control and /scan/vd metrics unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "control/metrics.hpp"
#include "scanvd/scanVdMetrics.hpp"

#include <wazuh_metrics/jsonDump.hpp>
#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <string>
#include <thread>
#include <vector>

using namespace remoted::control;
using namespace remoted::scanvd;

// Null-object contract: a default-constructed struct (all counters null) must stay a valid
// collaborator -- every inc* is a silent no-op. Production never builds one (the facade resolves
// from its manager), but the client/handler tests rely on this to skip metric plumbing.
TEST(ControlMetricsTest, DefaultConstructedCountsNothing)
{
    ControlMetrics m;
    incStartup(m);
    incNotify(m);
    incShutdown(m);
    incWdbError(m);
    incTaskFetch(m);
    incTaskFetchError(m);
    // Nothing to observe -- not crashing IS the contract.
    EXPECT_EQ(m.startup, nullptr);
    EXPECT_EQ(m.taskFetchError, nullptr);
}

// makeControlMetrics() registers the whole remoted.control.* family on the manager, all
// counters starting at 0. Guards against a member/name mismatch slipping into the catalog.
TEST(ControlMetricsTest, MakeRegistersFamilyAtZero)
{
    wazuh::metrics::Manager manager;
    const ControlMetrics m {makeControlMetrics(manager)};

    for (const auto* name :
         {METRIC_STARTUP, METRIC_NOTIFY, METRIC_SHUTDOWN, METRIC_WDB_ERROR, METRIC_TASK_FETCH, METRIC_TASK_FETCH_ERROR})
    {
        EXPECT_TRUE(manager.exists(name)) << name;
    }
    EXPECT_EQ(manager.count(), 6U);
    EXPECT_EQ(m.startup->get(), 0U);
    EXPECT_EQ(m.taskFetchError->get(), 0U);
}

// Each inc helper touches exactly its own counter; a regression in the wrong counter
// (copy-paste bug) would break exactly one of the six sub-cases. Counts are asserted through
// the MANAGER (not the struct) to prove the struct's shared_ptrs and the registry agree.
TEST(ControlMetricsTest, IncHelpersEachTouchOneCounter)
{
    wazuh::metrics::Manager manager;
    ControlMetrics m {makeControlMetrics(manager)};

    const auto valueOf = [&manager](const char* name)
    {
        return static_cast<uint64_t>(manager.get(name)->value());
    };

    incStartup(m);
    EXPECT_EQ(valueOf(METRIC_STARTUP), 1U);
    EXPECT_EQ(valueOf(METRIC_NOTIFY) + valueOf(METRIC_SHUTDOWN) + valueOf(METRIC_WDB_ERROR) +
                  valueOf(METRIC_TASK_FETCH) + valueOf(METRIC_TASK_FETCH_ERROR),
              0U);
    incNotify(m);
    EXPECT_EQ(valueOf(METRIC_NOTIFY), 1U);
    incShutdown(m);
    EXPECT_EQ(valueOf(METRIC_SHUTDOWN), 1U);
    incWdbError(m);
    EXPECT_EQ(valueOf(METRIC_WDB_ERROR), 1U);
    incTaskFetch(m);
    EXPECT_EQ(valueOf(METRIC_TASK_FETCH), 1U);
    incTaskFetchError(m);
    EXPECT_EQ(valueOf(METRIC_TASK_FETCH_ERROR), 1U);
}

// Resolving the family twice on the same manager yields the SAME counters (dedupe by name), so
// totals accumulate across re-makes -- the property the facade relies on for HTTP-server restart
// retries (counters survive in the manager; a fresh struct keeps counting where the old one left).
TEST(ControlMetricsTest, RemakeOnSameManagerKeepsTotals)
{
    wazuh::metrics::Manager manager;
    ControlMetrics first {makeControlMetrics(manager)};
    incStartup(first);

    ControlMetrics second {makeControlMetrics(manager)};
    incStartup(second);

    EXPECT_EQ(second.startup.get(), first.startup.get());
    EXPECT_EQ(second.startup->get(), 2U);
}

// The counters are documented as thread-safe (lock-free relaxed atomics underneath). This test
// makes that contract explicit: 8 threads each incrementing 1000 times must not lose a single
// write. If the backing metric ever stops being atomic, this fires under -fsanitize=thread.
TEST(ControlMetricsTest, IncIsThreadSafe)
{
    constexpr int threads = 8;
    constexpr int perThread = 1000;

    wazuh::metrics::Manager manager;
    ControlMetrics m {makeControlMetrics(manager)};
    std::vector<std::thread> ts;
    ts.reserve(threads);
    for (int i = 0; i < threads; ++i)
    {
        ts.emplace_back(
            [&m]
            {
                for (int j = 0; j < perThread; ++j)
                {
                    incStartup(m);
                }
            });
    }
    for (auto& t : ts)
    {
        t.join();
    }

    EXPECT_EQ(m.startup->get(), static_cast<uint64_t>(threads * perThread));
}

// Null-object contract for the /scan/vd set, same rationale as the control one.
TEST(ScanVdMetricsTest, DefaultConstructedCountsNothing)
{
    ScanVdMetrics m;
    incRequests(m);
    incVersionMismatch(m);
    incQueueFull(m);
    incInvalidAgent(m);
    incAccepted(m);
    incScanSucceeded(m);
    incScanRetried(m);
    incScanRetriesExhausted(m);
    incScanPermanentFailure(m);
    incScanDiscarded(m);
    EXPECT_EQ(m.requests, nullptr);
    EXPECT_EQ(m.scanDiscarded, nullptr);
}

// makeScanVdMetrics() registers the whole remoted.scanvd.* family, and each inc helper touches
// exactly its own counter (asserted through the manager, as above). One test for both because
// the family is bigger and the interesting property is the member<->name pairing.
TEST(ScanVdMetricsTest, MakeRegistersFamilyAndIncHelpersEachTouchOneCounter)
{
    wazuh::metrics::Manager manager;
    ScanVdMetrics m {makeScanVdMetrics(manager)};

    const std::vector<std::pair<void (*)(ScanVdMetrics&), const char*>> pairs {
        {incRequests, METRIC_REQUESTS_TOTAL},
        {incVersionMismatch, METRIC_VERSION_MISMATCH},
        {incQueueFull, METRIC_QUEUE_FULL},
        {incInvalidAgent, METRIC_INVALID_AGENT},
        {incAccepted, METRIC_ACCEPTED},
        {incScanSucceeded, METRIC_SCANS_SUCCEEDED},
        {incScanRetried, METRIC_SCANS_RETRIED},
        {incScanRetriesExhausted, METRIC_SCANS_RETRIES_EXHAUSTED},
        {incScanPermanentFailure, METRIC_SCANS_PERMANENT_FAILURE},
        {incScanDiscarded, METRIC_SCANS_DISCARDED}};
    EXPECT_EQ(manager.count(), pairs.size());

    uint64_t expected = 0;
    for (const auto& [inc, name] : pairs)
    {
        ASSERT_TRUE(manager.exists(name)) << name;
        EXPECT_EQ(static_cast<uint64_t>(manager.get(name)->value()), 0U) << name;
        // Distinct increment counts (1, 2, 3...) so two swapped names cannot cancel out.
        ++expected;
        for (uint64_t i = 0; i < expected; ++i)
        {
            inc(m);
        }
        EXPECT_EQ(static_cast<uint64_t>(manager.get(name)->value()), expected) << name;
    }
}

// Both families resolve on ONE manager in production (the facade's), so the dump must show them
// side by side under their remoted.* namespaces -- that dump is the only observation path today.
TEST(RemotedMetricsTest, DumpJsonShowsBothFamilies)
{
    wazuh::metrics::Manager manager;
    ControlMetrics control {makeControlMetrics(manager)};
    ScanVdMetrics scanVd {makeScanVdMetrics(manager)};

    incStartup(control);
    incAccepted(scanVd);

    const std::string dump = wazuh::metrics::dumpJson(manager, {"remoted"});
    EXPECT_NE(dump.find("\"name\":\"remoted\""), std::string::npos) << dump;
    EXPECT_NE(dump.find(METRIC_STARTUP), std::string::npos) << dump;
    EXPECT_NE(dump.find(METRIC_ACCEPTED), std::string::npos) << dump;
}
