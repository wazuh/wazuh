/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "cadence.hpp"

#include <ctime>

namespace task_manager::schedule
{
    Timestamp nextIntervalRun(const Timestamp previous, const Timestamp now, const std::chrono::seconds interval)
    {
        const auto seconds {interval.count()};
        if (seconds <= 0)
        {
            return 0;
        }

        // Never run: the first slot is one interval out.
        if (previous <= 0)
        {
            return now + seconds;
        }

        if (previous > now)
        {
            return previous;
        }

        // Coalescing, in one step rather than a loop.
        const auto behind {now - previous};
        return previous + ((behind / seconds) + 1) * seconds;
    }

    Timestamp nextDailyRun(const Timestamp now, const std::chrono::seconds dayWait)
    {
        auto offset {dayWait.count() > 0 ? dayWait.count() : 0};
        if (offset >= DAY_SECONDS)
        {
            offset = DAY_SECONDS - 1;
        }

        const auto stamp {static_cast<std::time_t>(now)};
        std::tm broken {};

        if (::localtime_r(&stamp, &broken) == nullptr)
        {
            // Only reachable on a timestamp the C library cannot break down at all. One day out is
            // the honest answer: the schedule stays alive and retries tomorrow.
            return now + DAY_SECONDS;
        }

        broken.tm_sec = 0;
        broken.tm_min = 0;
        broken.tm_hour = 0;
        broken.tm_isdst = -1;

        const auto slot {static_cast<Timestamp>(std::mktime(&broken)) + offset};
        if (slot > now)
        {
            return slot;
        }

        // Today's slot has passed. Re-break tomorrow rather than adding a day to `slot`: letting
        // mktime() normalise an out-of-range tm_mday is what keeps the offset anchored to local
        // midnight across a DST transition.
        broken.tm_mday += 1;
        broken.tm_isdst = -1;

        return static_cast<Timestamp>(std::mktime(&broken)) + offset;
    }

    Timestamp nextRun(const Schedule& schedule, const Timestamp previous, const Timestamp now)
    {
        if (schedule.definition.cadence == Cadence::Daily)
        {
            return nextDailyRun(now, schedule.dayWait);
        }

        return nextIntervalRun(previous, now, schedule.interval);
    }

    Timestamp startupNextRun(const Schedule& schedule,
                             const bool hadRow,
                             const Timestamp storedNextRun,
                             const bool storedEnabled,
                             const Timestamp now)
    {
        const auto fresh {nextRun(schedule, 0, now)};

        if (!hadRow || storedNextRun <= 0)
        {
            return fresh;
        }

        // Disabled to enabled.
        if (schedule.enabled && !storedEnabled)
        {
            return fresh;
        }

        // An interval that SHRANK. The interval is not persisted -- it belongs to the code, not to
        // the row -- so it is detected by its consequence: a stored slot further out than one whole
        // interval from now cannot have been produced by the interval configured today. Without
        // this, an operator who lowers agents_disconnection_time still waits out the old, longer
        // one.
        //
        // An interval that GREW needs no handling: the stored slot merely falls sooner than the new
        // interval would place it, so it fires once early and re-anchors on the next advance.
        if (schedule.definition.cadence == Cadence::Interval && schedule.interval.count() > 0 &&
            storedNextRun > now + schedule.interval.count())
        {
            return fresh;
        }

        // A daily slot is derived from the calendar on every advance, so a stored value that no
        // longer matches the configured offset is corrected the same way.
        if (schedule.definition.cadence == Cadence::Daily && storedNextRun > fresh)
        {
            return fresh;
        }

        return storedNextRun;
    }

    bool nodeAllows(const NodeScope scope, const int workerState)
    {
        if (scope == NodeScope::Any)
        {
            return true;
        }

        // Only an explicit "this node is the master" passes. Unknown (-1) does not.
        return workerState == 0;
    }
} // namespace task_manager::schedule
