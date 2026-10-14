/*
 * Wazuh Syscheckd — when the container FIM stale-row sweep may run (#40329).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Split out of the drain for the same reason as resolver_wait.hpp: the drain
 * owns threads and sockets and cannot be unit tested, so the decision lives
 * here and only the staging call stays there.
 *
 * This one is worth separating even more than the pacing next to it, because
 * what it guards is a DELETION. The sweep removes a container's rows because
 * the container is absent from a list, so a wrong "yes" does not cost latency,
 * it costs a live container its whole FIM baseline.
 *
 * TWO TRIGGERS, AND THEY MUST NOT BE COLLAPSED.
 *
 * 1. The cadence. Every `interval`, settle what the lifecycle notifications
 *    could not report — a container removed while the agent was down, a
 *    removal swallowed by a cursor resync, one the producer never saw. By the
 *    time this fires the connector has been answering for an interval, so its
 *    list can be believed.
 *
 * 2. A debt left by container_instances restarting. Its lifecycle journal is
 *    in memory, so a restart takes with it every record of what was removed
 *    meanwhile, and the resync that follows reports what EXISTS and never what
 *    has gone. A sweep is the only thing that can settle it.
 *
 * Trigger 2 may not simply run when the resync is seen, and that is the whole
 * reason this file exists. The module answers `list` as soon as its socket is
 * bound, BEFORE its first enumeration has finished, so the obvious moment to
 * sweep is exactly the moment its answer is least complete. Measured on a real
 * node: the connector replied 8 ms after the module came back with 5 of 11
 * containers, and the sweep deleted SIX containers' rows — 801 of them
 * belonging to containers that were still running.
 *
 * A stability check inside the sweep does not save it: polled twice 500 ms
 * apart, the connector returned the same incomplete list both times and agreed
 * with itself. Nor do the warm-up and quiescence guards in
 * container_baseline_scanner.cpp, which look like they would — they are
 * process-global latches, deliberately spent on the FIRST discovery of the
 * process so a recurring caller does not pay their latency for ever.
 *
 * So the debt waits for the producer to go QUIET rather than for a guessed
 * number of seconds: while it is still discovering, each newly reported
 * container moves the list and pushes the deadline out.
 *
 * The asymmetry is deliberate. Only the debt waits for silence. Making the
 * CADENCE wait for it too would starve the sweep on any node with steady
 * container churn — which is precisely the node whose stale rows fill the
 * table — and the cadence does not need it, because it meets a connector that
 * warmed up long ago.
 */

#ifndef _RECONCILE_FLOOR_HPP
#define _RECONCILE_FLOOR_HPP

#include <chrono>

namespace fim_container_events
{

/// How long container_instances must have reported an unchanged list before a
/// sweep owed to its restart may run. Matches the producer's own removal grace:
/// 60 s is already the scale on which it decides a container is gone, so it is
/// the right scale on which to believe the list it serves.
constexpr auto RESYNC_SETTLE = std::chrono::seconds {60};

/// What the resolver loop should do about the floor this pass.
struct FloorDecision
{
    /// Ask the consumer for a stale-container sweep.
    bool sweep {false};

    /// The resync debt has been paid; stop carrying it.
    bool clear_resync_debt {false};

    /// When the cadence next falls due. Always set, so the caller can assign it
    /// unconditionally rather than remembering which branches move it.
    std::chrono::steady_clock::time_point next_floor {};
};

/// Decides whether the stale-container sweep runs now.
///
/// @param enabled            <reconcile_interval> is non-zero.
/// @param owed_after_resync  container_instances restarted and the sweep it
///                           made necessary has not run yet.
/// @param now                the loop's current instant.
/// @param next_floor         when the cadence is next due.
/// @param last_list_change   when the container list last moved.
/// @param interval           the configured cadence.
/// @param resync_settle      silence required before paying a resync debt.
///
/// A sweep is asked for at most once per call: the debt and the cadence can
/// both be ready at the same instant, and two sweeps back to back would read
/// the same list twice. Paying the debt therefore re-arms the cadence as well.
[[nodiscard]] inline FloorDecision planReconcileFloor(bool enabled,
                                                      bool owed_after_resync,
                                                      std::chrono::steady_clock::time_point now,
                                                      std::chrono::steady_clock::time_point next_floor,
                                                      std::chrono::steady_clock::time_point last_list_change,
                                                      std::chrono::milliseconds interval,
                                                      std::chrono::milliseconds resync_settle)
{
    FloorDecision decision;
    decision.next_floor = next_floor;

    if (!enabled)
    {
        /* 0 disables the sweep outright. The debt is deliberately left
         * outstanding rather than cleared: if the interval is ever made
         * non-zero without restarting the loop, it is still owed. */
        return decision;
    }

    if (owed_after_resync && (now - last_list_change) >= resync_settle)
    {
        decision.sweep = true;
        decision.clear_resync_debt = true;
        decision.next_floor = now + interval;
        return decision;
    }

    if (now >= next_floor)
    {
        /* No silence requirement here — see this file's header. */
        decision.sweep = true;
        decision.next_floor = now + interval;
    }

    return decision;
}

} // namespace fim_container_events

#endif /* _RECONCILE_FLOOR_HPP */
