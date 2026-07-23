/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_FAKE_SYS_SEAMS_HPP
#define _HC_FAKE_SYS_SEAMS_HPP

#include "stopToken.hpp"
#include "sysSeams.hpp"

#include <cstdint>
#include <deque>
#include <initializer_list>
#include <vector>

/// Deterministic clock: tests advance it explicitly; no real sleeps anywhere.
class FakeClock final : public IClock
{
    public:
        std::time_t wallSeconds() const override
        {
            return m_baseWall + static_cast<std::time_t>(m_elapsedMs / 1000);
        }

        std::chrono::steady_clock::time_point steadyNow() const override
        {
            return m_baseSteady + std::chrono::milliseconds {m_elapsedMs};
        }

        void advance(std::chrono::milliseconds delta)
        {
            m_elapsedMs += delta.count();
        }

        void setWall(std::time_t wall)
        {
            m_baseWall = wall;
            m_elapsedMs = 0;
        }

    private:
        std::time_t m_baseWall {1700000000};
        std::chrono::steady_clock::time_point m_baseSteady {};
        int64_t m_elapsedMs {0};
};

/// Scripted randomness: yields the queued values in order, then repeats the
/// last one (0.5 when never scripted).
class ScriptedRandom final : public IRandom
{
    public:
        explicit ScriptedRandom(std::vector<double> values = {})
            : m_values(std::move(values))
        {
        }

        double uniform01() override
        {
            if (m_values.empty())
            {
                return 0.5;
            }

            const double value = m_values[m_index];

            if (m_index + 1 < m_values.size())
            {
                m_index++;
            }

            return value;
        }

    private:
        std::vector<double> m_values;
        size_t m_index {0};
};

/// Waiter that never sleeps: records every requested delay and answers each
/// waitFor() from a script (true = keep running). When the script runs dry it
/// returns false, so loops under test always terminate.
class FakeWaiter final : public Waiter
{
    public:
        bool waitFor(std::chrono::milliseconds timeout) override
        {
            m_requestedDelays.push_back(timeout);

            if (m_script.empty())
            {
                return false;
            }

            const bool keepRunning = m_script.front();
            m_script.pop_front();
            return keepRunning;
        }

        void notify() override
        {
            m_notifyCount++;
        }

        void script(std::initializer_list<bool> answers)
        {
            m_script.assign(answers);
        }

        const std::vector<std::chrono::milliseconds>& requestedDelays() const
        {
            return m_requestedDelays;
        }

        int notifyCount() const
        {
            return m_notifyCount;
        }

    private:
        std::deque<bool> m_script;
        std::vector<std::chrono::milliseconds> m_requestedDelays;
        int m_notifyCount {0};
};

#endif // _HC_FAKE_SYS_SEAMS_HPP
