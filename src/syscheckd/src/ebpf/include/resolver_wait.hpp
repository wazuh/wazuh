/*
 * Wazuh Syscheckd — how long the container resolver waits between passes
 * (#37532 / #37396).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Split out of the drain for the same reason as everything else it drives: the
 * drain owns threads and sockets and cannot be unit tested, so the decision
 * lives here and only the poll() call stays there.
 *
 * The decision is small but it is the one that can go wrong in two expensive
 * ways. Too long and a cgroup that nobody will announce — one waiting on an IPC
 * round-trip rather than on a container_instances event — sits unresolved for
 * an interval. Too short, or zero on a loop that cannot make progress, and the
 * resolver spins a core doing nothing.
 */

#ifndef _RESOLVER_WAIT_HPP
#define _RESOLVER_WAIT_HPP

#include <algorithm>
#include <chrono>

namespace fim_container_events
{

/* Pacing for unresolved cgroups. They are waiting on container_instances to
 * answer a query, not to announce anything, so no notification will arrive for
 * them and they need a cadence of their own. */
constexpr int RESOLVE_PACING_MS = 200;

/// Milliseconds to block before the next resolver pass.
///
/// @param until_refresh  time left before the scheduled full refresh is due.
/// @param has_unresolved whether any cgroup is still awaiting identification.
///
/// Never negative: a deadline already passed means "wake immediately", and
/// handing poll() a negative timeout would make it block forever — the one
/// mistake here that would look like a hang rather than a slowdown.
[[nodiscard]] inline int resolverWaitMs(std::chrono::milliseconds until_refresh, bool has_unresolved)
{
    if (until_refresh.count() < 0)
    {
        until_refresh = std::chrono::milliseconds {0};
    }

    if (has_unresolved)
    {
        until_refresh = std::min(until_refresh, std::chrono::milliseconds {RESOLVE_PACING_MS});
    }

    return static_cast<int>(until_refresh.count());
}

} // namespace fim_container_events

#endif /* _RESOLVER_WAIT_HPP */
