/*
 * Wazuh inventory sync
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * It is used to:
 * - Track out-of-order or missing `Data` messages.
 * - Efficiently detect session completion.
 * - Generate ranges of missing sequences (used in End message handling).
 *
 * This class is a core part of the agent sync protocol and must be efficient and scalable.
 */
#ifndef _GAP_SET_HPP
#define _GAP_SET_HPP

#include <chrono>
#include <cstdint>
#include <vector>

/**
 * @brief The GapSet class tracks the receipt of expected sequence numbers.
 * It uses a bitmap for memory efficiency and a dirty flag to optimize gap range queries.
 */
class GapSet final
{
public:
    /**
     * @brief Constructs a new GapSet instance.
     * @param size The total number of expected chunks.
     */
    explicit GapSet(const uint64_t size)
        : m_size(size)
        , m_observed(size, false)
    {
    }

    /**
     * @brief Marks a sequence number as observed.
     * @param seq The sequence number to mark.
     *
     * If the number is out of bounds or already seen, the call is a no-op.
     * Updates last activity timestamp and invalidates the gap cache.
     */
    void observe(const uint64_t seq)
    {
        if (seq >= m_size || m_observed[seq])
        {
            return;
        }

        m_lastUpdate = std::chrono::steady_clock::now();
        m_observed[seq] = true;
        ++m_observedCount;
        m_gapCacheDirty = true;
    }

    /**
     * @brief Checks whether all expected values have been observed.
     * @return true if all values from 0 to size-1 have been seen.
     */
    bool empty() const
    {
        return m_observedCount == m_size;
    }

    /**
     * @brief Checks whether a specific sequence number has been observed.
     * @param seq The sequence number to query.
     * @return true if it has been marked as received.
     */
    bool contains(const uint64_t seq) const
    {
        return seq < m_size && m_observed[seq];
    }

    /**
     * @brief Returns the ranges of missing sequence numbers.
     * Uses cached result unless invalidated by a new observation.
     * @return A vector of (start, end) pairs of missing ranges.
     */
    const std::vector<std::pair<uint64_t, uint64_t>>& ranges()
    {
        if (!m_gapCacheDirty)
        {
            return m_cachedRanges;
        }

        m_cachedRanges.clear();
        bool inGap = false;
        uint64_t gapStart = 0;

        for (uint64_t i = 0; i < m_size; ++i)
        {
            if (!m_observed[i])
            {
                if (!inGap)
                {
                    inGap = true;
                    gapStart = i;
                }
            }
            else if (inGap)
            {
                m_cachedRanges.emplace_back(gapStart, i - 1);
                inGap = false;
            }
        }

        if (inGap)
        {
            m_cachedRanges.emplace_back(gapStart, m_size - 1);
        }

        m_gapCacheDirty = false;
        return m_cachedRanges;
    }

    /**
     * @brief Returns the last update time.
     * @return The last update time set
     */
    std::chrono::time_point<std::chrono::steady_clock> lastUpdate() const
    {
        return m_lastUpdate;
    }

private:
    uint64_t m_size {0};          ///< Total expected number of entries
    std::vector<bool> m_observed; ///< Observed entries (bitmap)
    uint64_t m_observedCount {0}; ///< Count of observed entries
    std::chrono::time_point<std::chrono::steady_clock> m_lastUpdate {
        std::chrono::steady_clock::now()};                     ///< Last update time
    bool m_gapCacheDirty {true};                               ///< Whether the gap cache is dirty
    std::vector<std::pair<uint64_t, uint64_t>> m_cachedRanges; ///< Cached result of gap ranges
};

#endif // _GAP_SET_HPP