/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * D16's settle in the staging buffer (#37532, WP1 of 14-spike-integration-plan).
 *
 * RT_EV_FILE_OPEN fires on open-with-write-intent, so the event precedes the
 * modification: reconciling immediately re-reads the PRE-write file and stores
 * it as the new state (C23), and an 8-second-deferred write was measured as
 * never reported at all. The settle holds a staged path until either the pid
 * that triggered it has exited or a bounded delay has elapsed.
 *
 * Seven properties, each of which a plausible refactor would break:
 *
 *   1. A zero delay behaves exactly as before the settle existed. This is what
 *      keeps tests/unit/container_event_staging_test.cpp's fourteen cases
 *      honest — they all drain with a zero timeout and expect their paths at
 *      once.
 *   2. A live writer's path is withheld until the deadline.
 *   3. A dead writer's path is released immediately, however long the delay.
 *   4. Suspect work bypasses the settle: a re-walk reads whole directories, so
 *      there is no single write for it to be racing.
 *   5. A repeat event takes the newer pid but does NOT extend the deadline —
 *      extending it per write is how an append-heavy log starves.
 *   6. Only settled paths leave; the rest stay pending rather than being
 *      served early or dropped.
 *   7. nextBatch() does not return "no work" while work is settling. It has to
 *      re-arm its own wait, because the consumer's loop calls straight back in
 *      and would otherwise spin a core.
 *
 * Standalone, like tests/txn/ and tests/alert/: `make check`. Needs nothing
 * built — the staging buffer is header-only — and spawns no processes, because
 * pid liveness is injected.
 */

#include "container_event_staging.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <set>
#include <string>
#include <thread>

using fim_container_events::Batch;
using fim_container_events::ContainerEventStaging;
using Clock = std::chrono::steady_clock;

namespace {

int g_failures = 0;

void Check(bool condition, const char* what)
{
    std::printf("  %-70s %s\n", what, condition ? "OK" : "FAIL");
    if (!condition) ++g_failures;
}

long ElapsedMs(const Clock::time_point& from)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - from).count();
}

/// Which pids the injected liveness probe should call alive.
std::set<unsigned int> g_alive;

fim_container_events::PidAliveFn AliveSet()
{
    return [](unsigned int pid) { return g_alive.count(pid) != 0; };
}

// -------------------------------------------------------------------- cases --

void CaseZeroDelayIsTheOldBehaviour()
{
    std::printf("case 1: a zero settle delay serves a path at once\n");

    // pid 7 is ALIVE, so only the zero delay can be releasing this.
    g_alive = {7};
    ContainerEventStaging staging(1024, 128, 0, AliveSet());
    staging.release();
    staging.onEvent("c1", "/etc/passwd", 7);

    Batch batch;
    Check(staging.nextBatch(batch, 0), "served with a zero timeout");
    Check(batch.paths.size() == 1 && batch.paths[0] == "/etc/passwd", "the staged path");
    Check(!staging.nextBatch(batch, 0), "and nothing is left");
}

void CaseLiveWriterIsHeldUntilTheDeadline()
{
    std::printf("case 2: a live writer's path waits for the deadline\n");

    g_alive = {7};
    ContainerEventStaging staging(1024, 128, 300, AliveSet());
    staging.release();
    staging.onEvent("c1", "/etc/passwd", 7);

    Batch batch;
    Check(!staging.nextBatch(batch, 0), "not served immediately");
    Check(!staging.nextBatch(batch, 100), "still not served 100ms in");

    const auto start = Clock::now();
    Check(staging.nextBatch(batch, 2000), "served once the deadline passes");
    Check(batch.paths.size() == 1 && batch.paths[0] == "/etc/passwd", "the staged path");

    // It waited rather than returning at once, and did not wait the full 2s.
    const auto waited = ElapsedMs(start);
    Check(waited < 1000, "released on the deadline, not on the caller's timeout");

    Check(staging.stats().settle_expired >= 1, "counted as a deadline release");
    Check(staging.stats().settle_early == 0, "not counted as an early release");
}

void CaseDeadWriterIsReleasedImmediately()
{
    std::printf("case 3: a dead writer's path is released at once\n");

    // pid 7 is NOT alive. The delay is 5s, so only the early release can serve.
    g_alive.clear();
    ContainerEventStaging staging(1024, 128, 5000, AliveSet());
    staging.release();
    staging.onEvent("c1", "/etc/passwd", 7);

    const auto start = Clock::now();
    Batch batch;
    Check(staging.nextBatch(batch, 2000), "served well inside the 5s delay");
    Check(ElapsedMs(start) < 500, "and promptly");
    Check(batch.paths.size() == 1 && batch.paths[0] == "/etc/passwd", "the staged path");
    Check(staging.stats().settle_early == 1, "counted as an early release");
}

void CaseSuspectBypassesTheSettle()
{
    std::printf("case 4: suspect work is not held by the settle\n");

    g_alive = {7};
    ContainerEventStaging staging(1024, 128, 5000, AliveSet());
    staging.release();

    staging.onEvent("c1", "/etc/passwd", 7); // would be held for 5s
    staging.onDrops("c1");                    // supersedes it with a re-walk

    Batch batch;
    Check(staging.nextBatch(batch, 0), "served with a zero timeout");
    Check(batch.suspect, "as a re-walk");
    Check(batch.container_id == "c1", "for the right container");
    Check(batch.paths.empty(), "with no paths");
}

void CaseRepeatEventTakesThePidNotTheDeadline()
{
    std::printf("case 5: a repeat event updates the pid and keeps the deadline\n");

    // First writer alive, second gone: the repeat must make the path releasable.
    g_alive = {7};
    ContainerEventStaging staging(1024, 128, 5000, AliveSet());
    staging.release();

    staging.onEvent("c1", "/var/log/app.log", 7);

    Batch batch;
    Check(!staging.nextBatch(batch, 0), "held while pid 7 is alive");

    staging.onEvent("c1", "/var/log/app.log", 8); // pid 8 is not in g_alive
    Check(staging.nextBatch(batch, 1000), "released once the newer pid is gone");
    Check(staging.stats().deduplicated == 1, "the repeat was still de-duplicated");

    // And the deadline is not pushed out by a stream of writes. This has to be
    // observed WHILE the writes are still arriving: draining after they stop
    // passes either way, because the last write's deadline has also passed by
    // then. A live pid keeps the early release out of it, so the 250ms bound is
    // the only thing that can serve this path.
    g_alive = {9};
    ContainerEventStaging hammered(1024, 128, 250, AliveSet());
    hammered.release();

    std::atomic<bool> writing{true};
    const auto start = Clock::now();

    std::thread writer([&hammered, &writing] {
        while (writing.load(std::memory_order_relaxed))
        {
            hammered.onEvent("c2", "/var/log/busy.log", 9);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });

    Batch busy;
    const bool served = hammered.nextBatch(busy, 800);
    const auto waited = ElapsedMs(start);

    writing.store(false, std::memory_order_relaxed);
    writer.join();

    Check(served, "an append-heavy path is served while still being written");
    Check(served && waited < 700, "on its ORIGINAL deadline, not one pushed out per write");
}

void CaseOnlySettledPathsLeave()
{
    std::printf("case 6: unsettled paths stay pending\n");

    // pid 7 alive (held), pid 8 gone (releasable).
    g_alive = {7};
    ContainerEventStaging staging(1024, 128, 400, AliveSet());
    staging.release();

    staging.onEvent("c1", "/etc/held", 7);
    staging.onEvent("c1", "/etc/ready", 8);

    Batch batch;
    Check(staging.nextBatch(batch, 1000), "the container is served");
    Check(batch.paths.size() == 1, "with exactly one path");
    Check(batch.paths.size() == 1 && batch.paths[0] == "/etc/ready", "the settled one");
    Check(staging.pendingContainers() == 1, "the container is still pending");

    Check(staging.nextBatch(batch, 2000), "the held path follows on its deadline");
    Check(batch.paths.size() == 1 && batch.paths[0] == "/etc/held", "as its own batch");
    Check(staging.pendingContainers() == 0, "and nothing is left");
}

void CaseSettlingWorkDoesNotReturnEarly()
{
    std::printf("case 7: nextBatch waits instead of reporting no work\n");

    g_alive = {7};
    ContainerEventStaging staging(1024, 128, 150, AliveSet());
    staging.release();
    staging.onEvent("c1", "/etc/passwd", 7);

    // The consumer's own loop is `while (...) if (!nextBatch(b, 500)) continue;`
    // so a false return here with work pending spins a core. It must wait out
    // the settle within the caller's timeout instead.
    const auto start = Clock::now();
    Batch batch;
    const bool served = staging.nextBatch(batch, 600);

    Check(served, "served within the caller's timeout");
    Check(ElapsedMs(start) >= 140, "having actually waited for the settle");
    Check(batch.paths.size() == 1 && batch.paths[0] == "/etc/passwd", "the staged path");
}

} // namespace

int main()
{
    CaseZeroDelayIsTheOldBehaviour();
    CaseLiveWriterIsHeldUntilTheDeadline();
    CaseDeadWriterIsReleasedImmediately();
    CaseSuspectBypassesTheSettle();
    CaseRepeatEventTakesThePidNotTheDeadline();
    CaseOnlySettledPathsLeave();
    CaseSettlingWorkDoesNotReturnEarly();

    std::printf("\n%s\n", g_failures == 0 ? "ALL OK" : "FAILURES");
    return g_failures == 0 ? 0 : 1;
}
