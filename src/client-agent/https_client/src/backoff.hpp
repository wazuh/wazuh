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

#ifndef _HC_BACKOFF_HPP
#define _HC_BACKOFF_HPP

#include "sysSeams.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>

/**
 * @brief Full-jitter exponential backoff (D9): each delay is uniform in
 *        [0, min(cap, base * 2^attempt)]; reset on success. One instance per
 *        stream so streams back off independently.
 */
class Backoff final
{
    public:
        Backoff(uint32_t baseMs, uint32_t capMs, IRandom& random)
            : m_baseMs(baseMs)
            , m_capMs(capMs)
            , m_random(random)
        {
        }

        std::chrono::milliseconds next()
        {
            const auto delay = std::chrono::milliseconds
            {
                static_cast<int64_t>(m_random.uniform01() * static_cast<double>(currentCeilingMs()))};

            if (m_attempt < MAX_ATTEMPT_SHIFT)
            {
                m_attempt++;
            }

            return delay;
        }

        /// The current window ceiling; also the floor back-pressure compares against.
        uint64_t currentCeilingMs() const
        {
            const uint64_t exponential = static_cast<uint64_t>(m_baseMs) << m_attempt;
            return std::min<uint64_t>(exponential, m_capMs);
        }

        void reset()
        {
            m_attempt = 0;
        }

    private:
        static constexpr uint32_t MAX_ATTEMPT_SHIFT = 20; ///< Overflow guard; cap rules anyway.

        uint32_t m_baseMs;
        uint32_t m_capMs;
        IRandom& m_random;
        uint32_t m_attempt {0};
};

#endif // _HC_BACKOFF_HPP
