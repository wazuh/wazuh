/*
 * Wazuh - Indexer Connector exponential backoff.
 * Copyright (C) 2015, Wazuh Inc.
 * July 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef INDEXER_EXPONENTIAL_BACKOFF_HPP
#define INDEXER_EXPONENTIAL_BACKOFF_HPP

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <random>

class IndexerExponentialBackoff final
{
public:
    explicit IndexerExponentialBackoff(std::chrono::milliseconds baseDelay)
        : IndexerExponentialBackoff(baseDelay, baseDelay)
    {
    }

    explicit IndexerExponentialBackoff(std::chrono::milliseconds baseDelay, std::chrono::milliseconds maxDelay)
        : m_baseDelay(std::max(baseDelay, std::chrono::milliseconds {0}))
        , m_maxDelay(std::max(maxDelay, m_baseDelay))
        , m_rng(std::random_device {}())
    {
    }

    std::chrono::milliseconds nextDelay()
    {
        const auto failures = m_failures++;
        const auto cap = cappedDelay(failures);

        if (cap.count() <= 0)
        {
            return std::chrono::milliseconds {0};
        }

        if (failures == 0)
        {
            return cap;
        }

        const auto lowerBound = previousExponentialDelay(cap);
        std::uniform_int_distribution<int64_t> distribution {static_cast<int64_t>(lowerBound.count()),
                                                             static_cast<int64_t>(cap.count())};
        return std::chrono::milliseconds {distribution(m_rng)};
    }

    void reset()
    {
        m_failures = 0;
    }

private:
    std::chrono::milliseconds cappedDelay(size_t failures) const
    {
        auto delay = m_baseDelay;

        for (size_t i = 0; i < failures && delay < m_maxDelay; ++i)
        {
            if (delay.count() > m_maxDelay.count() / 2)
            {
                return m_maxDelay;
            }
            delay *= 2;
        }

        return std::min(delay, m_maxDelay);
    }

    std::chrono::milliseconds previousExponentialDelay(std::chrono::milliseconds cap) const
    {
        if (cap <= m_baseDelay || m_baseDelay.count() <= 0)
        {
            return std::chrono::milliseconds {0};
        }

        auto delay = m_baseDelay;
        auto previousDelay = m_baseDelay;

        while (delay < cap)
        {
            previousDelay = delay;
            if (delay.count() > cap.count() / 2)
            {
                break;
            }
            delay *= 2;
        }

        return previousDelay;
    }

    std::chrono::milliseconds m_baseDelay;
    std::chrono::milliseconds m_maxDelay;
    size_t m_failures {0};
    std::mt19937_64 m_rng;
};

/**
 * @brief Bounds one operation's retry loop by attempts and by wall-clock time.
 *
 * exhausted() is called after each failed request with the delay the next retry would sleep;
 * it returns true once the failure count reaches the attempts cap, or when sleeping that delay
 * would cross the deadline. A cap of 0 disables that bound, so {0, 0} retries forever.
 */
class IndexerRetryBudget final
{
public:
    IndexerRetryBudget(size_t maxAttempts, std::chrono::milliseconds maxDuration)
        : m_maxAttempts(maxAttempts)
        , m_deadline(std::chrono::steady_clock::now() + maxDuration)
        , m_timeBounded(maxDuration.count() > 0)
    {
    }

    bool exhausted(std::chrono::milliseconds nextDelay)
    {
        ++m_failedAttempts;
        if (m_maxAttempts > 0 && m_failedAttempts >= m_maxAttempts)
        {
            return true;
        }
        return m_timeBounded && (std::chrono::steady_clock::now() + nextDelay >= m_deadline);
    }

private:
    size_t m_maxAttempts;
    std::chrono::steady_clock::time_point m_deadline;
    bool m_timeBounded;
    size_t m_failedAttempts {0};
};

#endif // INDEXER_EXPONENTIAL_BACKOFF_HPP
