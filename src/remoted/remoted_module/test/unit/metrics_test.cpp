/*
 * Wazuh remoted module - Metric catalog unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "common/requestOutcomeMetrics.hpp"
#include "control/metrics.hpp"
#include "endpoints/endpoint.hpp"
#include "scanvd/scanVdMetrics.hpp"

#include <wazuh_metrics/jsonDump.hpp>
#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <string>
#include <string_view>
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

    for (const auto* name : {METRIC_STARTUP,
                             METRIC_NOTIFY,
                             METRIC_SHUTDOWN,
                             METRIC_WDB_ERROR,
                             METRIC_TASK_FETCH,
                             METRIC_TASK_FETCH_ERROR,
                             METRIC_REJECTED,
                             METRIC_WDB_LATENCY})
    {
        EXPECT_TRUE(manager.exists(name)) << name;
    }
    EXPECT_EQ(manager.count(), 8U);
    EXPECT_EQ(m.startup->get(), 0U);
    EXPECT_EQ(m.taskFetchError->get(), 0U);
    EXPECT_EQ(m.rejected->get(), 0U);
    EXPECT_EQ(m.wdbLatency->snapshot().count, 0U);
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
    incRejected(m);
    EXPECT_EQ(valueOf(METRIC_REJECTED), 1U);

    // The histogram helper records exactly one observation with the given value -- and, like
    // every helper here, is a safe no-op on the null object.
    observeWdbLatency(m, 2500U);
    const auto snapshot = m.wdbLatency->snapshot();
    EXPECT_EQ(snapshot.count, 1U);
    EXPECT_EQ(snapshot.sum, 2500U);
    ControlMetrics nullObject;
    incRejected(nullObject);
    observeWdbLatency(nullObject, 1U); // not crashing IS the contract
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
    incVdError(m);
    incIndexerUnavailable(m);
    EXPECT_EQ(m.requests, nullptr);
    EXPECT_EQ(m.vdError, nullptr);
    EXPECT_EQ(m.indexerUnavailable, nullptr);
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
        {incVdError, METRIC_VD_ERROR},
        {incIndexerUnavailable, METRIC_INDEXER_UNAVAILABLE}};
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

// Null-object contract for the per-endpoint response set, same rationale as the control one.
TEST(ResponseCountersTest, DefaultConstructedCountsNothing)
{
    remoted::metrics::ResponseCounters c;
    c.count(200);
    c.count(503);
    c.count(101);
    EXPECT_EQ(c.c2xx, nullptr);
    EXPECT_EQ(c.other, nullptr);
}

// make() registers the whole remoted.http.<endpoint>.responses.* family at zero. Guards the
// member<->name pairing and the fixed 8-cell vocabulary every endpoint must share.
TEST(ResponseCountersTest, MakeRegistersFamilyAtZero)
{
    wazuh::metrics::Manager manager;
    const auto c = remoted::metrics::ResponseCounters::make(manager, "stateless");

    for (const auto* code : {"2xx", "400", "403", "409", "413", "500", "503", "other"})
    {
        const std::string name = std::string {"remoted.http.stateless.responses."} + code;
        EXPECT_TRUE(manager.exists(name)) << name;
        EXPECT_EQ(static_cast<uint64_t>(manager.get(name)->value()), 0U) << name;
    }
    EXPECT_EQ(manager.count(), 8U);
    EXPECT_EQ(c.c2xx->get(), 0U);
}

// count() maps each status to exactly one cell: the whole 2xx range collapses into one counter,
// each cataloged code hits its own, and everything else (1xx, 3xx, uncataloged 4xx/5xx) lands in
// "other". Distinct increment counts so two swapped cells cannot cancel out.
TEST(ResponseCountersTest, CountMapsStatusToExactlyOneCell)
{
    wazuh::metrics::Manager manager;
    const auto c = remoted::metrics::ResponseCounters::make(manager, "stateful");

    c.count(200);
    c.count(202);
    c.count(299);
    EXPECT_EQ(c.c2xx->get(), 3U);

    const std::vector<std::pair<int, std::shared_ptr<wazuh::metrics::ICounter>>> cells {
        {400, c.c400}, {403, c.c403}, {409, c.c409}, {413, c.c413}, {500, c.c500}, {503, c.c503}};
    uint64_t expected = 0;
    for (const auto& [status, cell] : cells)
    {
        ++expected;
        for (uint64_t i = 0; i < expected; ++i)
        {
            c.count(status);
        }
        EXPECT_EQ(cell->get(), expected) << status;
    }

    c.count(101);
    c.count(304);
    c.count(404);
    c.count(504);
    EXPECT_EQ(c.other->get(), 4U);
    EXPECT_EQ(c.c2xx->get(), 3U); // untouched by the non-2xx traffic above
}

// makeEndpointHttpMetrics() resolves the latency histogram only on request: /stateless and
// /stateful pay for one, /stats and /config do not -- and observeLatency() stays a safe no-op
// on the histogram-less (and on the default-constructed) struct.
TEST(EndpointHttpMetricsTest, LatencyHistogramIsOptInAndObserveIsNullSafe)
{
    wazuh::metrics::Manager manager;

    const auto withLatency = remoted::metrics::makeEndpointHttpMetrics(manager, "stateless", true);
    ASSERT_NE(withLatency.latency, nullptr);
    EXPECT_TRUE(manager.exists("remoted.http.stateless.latency"));
    remoted::metrics::observeLatency(withLatency, 1500U);
    EXPECT_EQ(withLatency.latency->snapshot().count, 1U);
    EXPECT_EQ(withLatency.latency->snapshot().sum, 1500U);

    const auto withoutLatency = remoted::metrics::makeEndpointHttpMetrics(manager, "stats", false);
    EXPECT_EQ(withoutLatency.latency, nullptr);
    EXPECT_FALSE(manager.exists("remoted.http.stats.latency"));
    remoted::metrics::observeLatency(withoutLatency, 1500U); // not crashing IS the contract

    remoted::metrics::observeLatency(remoted::metrics::EndpointHttpMetrics {}, 1U);
}

// makeAuthRejectMetrics() registers the whole remoted.auth.reject.* family at zero. Guards the
// member<->name pairing, like the control/scanvd equivalents.
TEST(AuthRejectMetricsTest, MakeRegistersFamilyAtZero)
{
    wazuh::metrics::Manager manager;
    const auto m = remoted::endpoints::makeAuthRejectMetrics(manager);

    for (const auto* name : {remoted::endpoints::METRIC_AUTH_REJECT_UNKNOWN_AGENT,
                             remoted::endpoints::METRIC_AUTH_REJECT_INVALID_SIGNATURE,
                             remoted::endpoints::METRIC_AUTH_REJECT_BAD_TOKEN,
                             remoted::endpoints::METRIC_AUTH_REJECT_IDENTITY_MISMATCH,
                             remoted::endpoints::METRIC_AUTH_REJECT_CLOCK_SKEW,
                             remoted::endpoints::METRIC_AUTH_REJECT_UNUSABLE_KEY,
                             remoted::endpoints::METRIC_AUTH_REJECT_ADDRESS_NOT_ALLOWED,
                             remoted::endpoints::METRIC_AUTH_REJECT_ENROLLMENT_KEY,
                             remoted::endpoints::METRIC_AUTH_REJECT_PAYLOAD_MISMATCH,
                             remoted::endpoints::METRIC_AUTH_REJECT_BODY_TOO_LARGE,
                             remoted::endpoints::METRIC_AUTH_REJECT_BAD_ENCODING,
                             remoted::endpoints::METRIC_AUTH_REJECT_MALFORMED})
    {
        EXPECT_TRUE(manager.exists(name)) << name;
    }
    EXPECT_EQ(manager.count(), 12U);
    EXPECT_EQ(m.unknownAgent->get(), 0U);
    EXPECT_EQ(m.malformed->get(), 0U);
}

// errorResponseFor() is the single funnel every client-visible auth rejection passes through;
// once a family is installed, each AuthError must land in exactly one cell -- with the
// PRE-collapse cause, not classify()'s coarser who-must-act folding. Every enum value is fed
// through so a new AuthError can never silently fall out of the accounting.
TEST(AuthRejectMetricsTest, ErrorResponseForCountsEveryAuthErrorInItsCell)
{
    using remoted::auth::AuthError;

    wazuh::metrics::Manager manager;
    remoted::endpoints::installAuthRejectMetrics(remoted::endpoints::makeAuthRejectMetrics(manager));

    // The set of AuthErrors is DISCOVERED, not hand-listed, and that is the whole point: a
    // hand-written list has now failed twice. AddressNotAllowed (static-IP agents) and
    // EnrollmentKeyUnavailable (/enroll) each arrived upstream, each fell into the `malformed`
    // cell, and no test noticed -- the second time even though a static_assert was guarding the
    // enum, because it was anchored to a fixed enumerator and the new value was APPENDED past it.
    //
    // toString() is the registry that cannot go stale: it switches over AuthError with no
    // default, so -Wswitch forces whoever adds a value to extend it, and it answers "unknown"
    // for anything not yet named. So: probe well past the current size, treat every named value
    // as live, feed it through the funnel, and require the cells to account for all of them.
    // Append a value without giving it a cell and this test fails on the total.
    std::vector<AuthError> live;
    for (int i = 1; i <= 128; ++i)
    {
        const auto err = static_cast<AuthError>(i);
        if (std::string_view {remoted::auth::toString(err)} != "unknown")
        {
            live.push_back(err);
        }
    }
    // Sanity floor: if the probe stopped finding values, the discovery itself broke.
    ASSERT_GE(live.size(), 15U) << "AuthError discovery via toString() found implausibly few values";

    for (const auto err : live)
    {
        (void)remoted::endpoints::errorResponseFor(err);
    }

    const auto valueOf = [&manager](const char* name)
    {
        return static_cast<uint64_t>(manager.get(name)->value());
    };
    EXPECT_EQ(valueOf(remoted::endpoints::METRIC_AUTH_REJECT_UNKNOWN_AGENT), 1U);
    EXPECT_EQ(valueOf(remoted::endpoints::METRIC_AUTH_REJECT_INVALID_SIGNATURE), 1U);
    EXPECT_EQ(valueOf(remoted::endpoints::METRIC_AUTH_REJECT_BAD_TOKEN), 1U);
    EXPECT_EQ(valueOf(remoted::endpoints::METRIC_AUTH_REJECT_IDENTITY_MISMATCH), 1U);
    EXPECT_EQ(valueOf(remoted::endpoints::METRIC_AUTH_REJECT_CLOCK_SKEW), 1U); // StaleToken (both profiles)
    EXPECT_EQ(valueOf(remoted::endpoints::METRIC_AUTH_REJECT_UNUSABLE_KEY), 1U);
    EXPECT_EQ(valueOf(remoted::endpoints::METRIC_AUTH_REJECT_ADDRESS_NOT_ALLOWED), 1U);
    EXPECT_EQ(valueOf(remoted::endpoints::METRIC_AUTH_REJECT_ENROLLMENT_KEY), 1U);
    EXPECT_EQ(valueOf(remoted::endpoints::METRIC_AUTH_REJECT_PAYLOAD_MISMATCH), 1U);
    EXPECT_EQ(valueOf(remoted::endpoints::METRIC_AUTH_REJECT_BODY_TOO_LARGE), 1U);
    EXPECT_EQ(valueOf(remoted::endpoints::METRIC_AUTH_REJECT_BAD_ENCODING), 2U); // both encoding causes
    EXPECT_EQ(valueOf(remoted::endpoints::METRIC_AUTH_REJECT_MALFORMED), 4U);    // the four header faults

    // The tripwire: every discovered AuthError landed in exactly one cell. A value appended to
    // the enum without a cell of its own lands in `malformed`, which makes that cell exceed the
    // four header faults asserted above AND keeps this total honest -- so the failure names
    // itself instead of hiding as a silently widened bucket.
    const auto total = valueOf(remoted::endpoints::METRIC_AUTH_REJECT_UNKNOWN_AGENT) +
                       valueOf(remoted::endpoints::METRIC_AUTH_REJECT_INVALID_SIGNATURE) +
                       valueOf(remoted::endpoints::METRIC_AUTH_REJECT_BAD_TOKEN) +
                       valueOf(remoted::endpoints::METRIC_AUTH_REJECT_IDENTITY_MISMATCH) +
                       valueOf(remoted::endpoints::METRIC_AUTH_REJECT_CLOCK_SKEW) +
                       valueOf(remoted::endpoints::METRIC_AUTH_REJECT_UNUSABLE_KEY) +
                       valueOf(remoted::endpoints::METRIC_AUTH_REJECT_ADDRESS_NOT_ALLOWED) +
                       valueOf(remoted::endpoints::METRIC_AUTH_REJECT_ENROLLMENT_KEY) +
                       valueOf(remoted::endpoints::METRIC_AUTH_REJECT_PAYLOAD_MISMATCH) +
                       valueOf(remoted::endpoints::METRIC_AUTH_REJECT_BODY_TOO_LARGE) +
                       valueOf(remoted::endpoints::METRIC_AUTH_REJECT_BAD_ENCODING) +
                       valueOf(remoted::endpoints::METRIC_AUTH_REJECT_MALFORMED);
    EXPECT_EQ(total, live.size()) << "an AuthError is not accounted for in any remoted.auth.reject.* cell";

    // Uninstall (back to the null object): the instance is process-wide, so leaving these
    // counters live would leak this test's accounting into any later test that rejects.
    remoted::endpoints::installAuthRejectMetrics(remoted::endpoints::AuthRejectMetrics {});
    (void)remoted::endpoints::errorResponseFor(AuthError::InvalidSignature);          // not crashing IS the contract
    EXPECT_EQ(valueOf(remoted::endpoints::METRIC_AUTH_REJECT_INVALID_SIGNATURE), 1U); // unchanged after uninstall
}

// All families resolve on ONE manager in production (the facade's), so the dump must show them
// side by side under their remoted.* namespaces -- that dump is the only observation path today.
TEST(RemotedMetricsTest, DumpJsonShowsBothFamilies)
{
    wazuh::metrics::Manager manager;
    ControlMetrics control {makeControlMetrics(manager)};
    ScanVdMetrics scanVd {makeScanVdMetrics(manager)};
    const auto http = remoted::metrics::makeEndpointHttpMetrics(manager, "stateless", true);

    incStartup(control);
    incAccepted(scanVd);
    http.responses.count(202);

    const std::string dump = wazuh::metrics::dumpJson(manager, {"remoted"});
    EXPECT_NE(dump.find("\"name\":\"remoted\""), std::string::npos) << dump;
    EXPECT_NE(dump.find(METRIC_STARTUP), std::string::npos) << dump;
    EXPECT_NE(dump.find(METRIC_ACCEPTED), std::string::npos) << dump;
    EXPECT_NE(dump.find("remoted.http.stateless.responses.2xx"), std::string::npos) << dump;
    EXPECT_NE(dump.find("remoted.http.stateless.latency"), std::string::npos) << dump;
}
