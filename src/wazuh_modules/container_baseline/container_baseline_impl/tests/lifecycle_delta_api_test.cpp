/*
 * Wazuh container_baseline — lifecycle delta and per-container scan C API
 * (#37532 / #37203 O3, O14).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * These pin the ONE property that, if wrong, destroys data: what each entry
 * point does when it could not reach the connector.
 *
 * Every function here returns "nothing" on failure, and "nothing" is also what
 * a node with no containers legitimately returns. A caller that cannot tell
 * those apart deletes every stored row the moment the connector blips and
 * re-creates them on the next cycle — the mass false-delete this module's
 * headers warn about throughout. So the failure path must be a DISTINCT value,
 * and the cursor must not move when nothing was learned, or the caller would
 * skip whatever it missed when the connector came back.
 */

#include "container_baseline.h"
#include "container_baseline_scanner.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace wazuh::container_baseline;

namespace
{

/// A path nothing is listening on. Not merely absent — an unreachable connector
/// and an absent one must be indistinguishable to these entry points, because
/// to a caller they mean the same thing: it learned nothing.
const char* const kDeadSocket = "/tmp/cb-lifecycle-test-no-such-socket";

struct Collected
{
    std::vector<std::string> ids;
    std::vector<int> kinds;
    std::vector<unsigned int> masks;
};

void CollectEvent(const cb_lifecycle_event_t* event, void* user_data)
{
    auto* out = static_cast<Collected*>(user_data);
    out->ids.emplace_back(event->container_id ? event->container_id : "");
    out->kinds.push_back(event->kind);
    out->masks.push_back(event->changed);
}

void CountRow(const char*, const char*, const char*, void*) {}

} // namespace

TEST(LifecycleDeltaApiTest, AnUnreachableConnectorIsUnavailableNotEmpty)
{
    unsigned long long epoch = 7;
    unsigned long long seq = 42;
    Collected collected;

    const auto result = cbaseline_lifecycle_since(kDeadSocket, &epoch, &seq, CollectEvent, &collected);

    EXPECT_EQ(CB_DELTA_UNAVAILABLE, result)
        << "returning 0 would be indistinguishable from 'nothing changed' and would authorise a sweep";
    EXPECT_TRUE(collected.ids.empty());
}

TEST(LifecycleDeltaApiTest, TheCursorDoesNotMoveWhenNothingWasLearned)
{
    // If it advanced on failure, the transitions that happened while the
    // connector was away would be skipped when it came back — silently, and
    // with no way for the caller to notice it had a hole.
    unsigned long long epoch = 7;
    unsigned long long seq = 42;

    static_cast<void>(cbaseline_lifecycle_since(kDeadSocket, &epoch, &seq, CollectEvent, nullptr));

    EXPECT_EQ(7u, epoch);
    EXPECT_EQ(42u, seq);
}

TEST(LifecycleDeltaApiTest, ANullCursorIsRefusedRatherThanAssumedToBeCold)
{
    // Treating a null cursor as 0/0 would quietly re-baseline everything on
    // every call, which looks like it is working.
    EXPECT_EQ(CB_DELTA_UNAVAILABLE, cbaseline_lifecycle_since(kDeadSocket, nullptr, nullptr, CollectEvent, nullptr));

    unsigned long long epoch = 0;
    EXPECT_EQ(CB_DELTA_UNAVAILABLE, cbaseline_lifecycle_since(kDeadSocket, &epoch, nullptr, CollectEvent, nullptr));
    EXPECT_EQ(CB_DELTA_UNAVAILABLE, cbaseline_lifecycle_since(nullptr, &epoch, &epoch, CollectEvent, nullptr));
}

TEST(LifecycleDeltaApiTest, ThePerContainerScanReportsUnreachableDistinctlyFromScannedNothing)
{
    const char* ids[] = {"container-a", "container-b"};

    EXPECT_EQ(-1, cbaseline_run_syscollector_dbsync_for(kDeadSocket, ids, 2, CountRow, nullptr, nullptr))
        << "-1 so the caller cannot read 'I could not ask' as 'those containers are gone'";

    // A missing socket path is the same statement about the connector, so it
    // gets the same answer rather than a caller-bug code.
    EXPECT_EQ(-1, cbaseline_run_syscollector_dbsync_for(nullptr, ids, 2, CountRow, nullptr, nullptr));
}

TEST(LifecycleDeltaApiTest, AnEmptyIdListIsACallerBugNotAConnectorFailure)
{
    // 0, not -1: nothing was asked for, and that says nothing about whether the
    // connector is reachable. Returning -1 here would make a caller suppress a
    // sweep it was entitled to perform.
    const char* ids[] = {"x"};

    EXPECT_EQ(0, cbaseline_run_syscollector_dbsync_for(kDeadSocket, ids, 0, CountRow, nullptr, nullptr));
    EXPECT_EQ(0, cbaseline_run_syscollector_dbsync_for(kDeadSocket, nullptr, 2, CountRow, nullptr, nullptr));

    const char* blanks[] = {"", nullptr};
    EXPECT_EQ(0, cbaseline_run_syscollector_dbsync_for(kDeadSocket, blanks, 2, CountRow, nullptr, nullptr));
}

TEST(LifecycleDeltaApiTest, TheScannerLayerAlsoReportsUnreachableAsMinusOne)
{
    // Same contract one layer down, where syscollector's delta path will call
    // it. Worth pinning separately: the C wrapper could be made correct while
    // the function it wraps quietly returned 0.
    const std::vector<std::string> ids {"container-a"};

    EXPECT_EQ(-1, RunSyscollectorDbsyncBaselineForContainers(kDeadSocket, ids, [](const DbsyncRow&) {}));

    // ...and an empty selection still short-circuits to 0 without asking.
    EXPECT_EQ(0, RunSyscollectorDbsyncBaselineForContainers(kDeadSocket, {}, [](const DbsyncRow&) {}));
}
