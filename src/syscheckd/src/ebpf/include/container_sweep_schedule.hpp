/*
 * Wazuh Syscheckd — when the container reconciliation floor comes round
 * (#37532 / #37396).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Split out of the drain for the same reason as resolver_wait.hpp beside it:
 * the drain owns threads and sockets and cannot be unit tested, so the decision
 * lives here and only the clock reading stays there.
 *
 * What it schedules is the whole-node sweep (ReconcileMode::sweepAbsent): list
 * the containers that exist, refresh the admission set from that list, delete
 * the rows and contexts of the ones that do not. The per-container cleanup
 * driven by a reported removal needs none of this — it rides the container
 * list refresh that already runs every resolver_interval_ms — so the only thing
 * scheduled here is the backstop for what no notification can report:
 *
 *   - a removal that happened across a resync, since a full-list reply carries
 *     no removal events at all;
 *   - a container the module never learned about in the first place (D19).
 *
 * This is a DEADLINE AND NOTHING ELSE. The drain also requests a sweep out of
 * band — on a resync, and on a container it had not seen — and those requests
 * deliberately do not pass through this class: they raise the staging marker
 * directly and then restart() the period here. That costs one extra call at
 * each site and buys the property worth having:
 *
 *   **No value of the interval can suppress an out-of-band sweep**, because
 *   the interval is not on that path at all.
 *
 * Which is the inverse of syscollector's shape, where
 * `container_baseline_interval == 0` — the DEFAULT — takes a branch whose wait
 * predicate ignores the lifecycle notification entirely
 * (syscollectorImp.cpp:3300), so leaving the floor unset silently switches the
 * event-driven path off as well. A floor must never be able to turn off the
 * thing it is a floor under.
 */

#ifndef _CONTAINER_SWEEP_SCHEDULE_HPP
#define _CONTAINER_SWEEP_SCHEDULE_HPP

#include <chrono>
#include <optional>

namespace fim_container_events
{

class SweepSchedule
{
    public:
        using Clock = std::chrono::steady_clock;
        using TimePoint = Clock::time_point;

        /* Zero or less means no periodic deadline — see the header. */
        explicit SweepSchedule(int interval_ms) noexcept
            : m_interval_ms(interval_ms)
        {
        }

        /* Begin a period. Called when the resolver loop starts, and again after
         * every sweep however it was triggered, so the interval measures time
         * since the last sweep rather than since the last scheduled one. An
         * out-of-band sweep is a sweep; following it with another one an
         * instant later would be a whole-node pass for nothing.
         *
         * Until the first call there is no deadline and due() is false, which
         * is why the loop restarts it before its first iteration rather than
         * relying on the constructor: a deadline measured from whenever the
         * Impl happened to be built would be wrong by however long start()
         * took to open the engine. */
        void restart(TimePoint now)
        {
            m_next = periodic() ? std::optional<TimePoint> {now + std::chrono::milliseconds {m_interval_ms}}
                                : std::nullopt;
        }

        /* Whether the floor is due. Deliberately const: it does not consume
         * anything, so a sweep that is due and not performed stays due. The
         * failure that buys is a repeated sweep — visible, and cheap — rather
         * than a skipped one, which is invisible and leaves a removed
         * container's rows in place indefinitely. */
        [[nodiscard]] bool due(TimePoint now) const
        {
            return m_next.has_value() && now >= *m_next;
        }

        /* The earlier of `other` and the next sweep, for bounding a poll().
         * Returns `other` unchanged when there is no periodic deadline.
         *
         * Needed because the resolver blocks until its container list refresh
         * is due, and nothing guarantees that deadline is the sooner of the
         * two: a resolver_interval_ms longer than this interval would
         * otherwise let the sweep run late by however much it overshot. */
        [[nodiscard]] TimePoint soonerOf(TimePoint other) const
        {
            return (m_next.has_value() && *m_next < other) ? *m_next : other;
        }

        [[nodiscard]] bool periodic() const noexcept
        {
            return m_interval_ms > 0;
        }

    private:
        int m_interval_ms;
        std::optional<TimePoint> m_next;
};

} // namespace fim_container_events

#endif /* _CONTAINER_SWEEP_SCHEDULE_HPP */
