/*
 * Wazuh inventory sync
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _GAP_SET_HPP
#define _GAP_SET_HPP

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <set>
#include <stdexcept>
#include <vector>

/**
 * @brief Efficient GapSet for sparse sequence number tracking.
 * Maintains sorted intervals of observed ranges for O(log n) operations.
 */
class GapSet final
{
private:
    // Represents a closed interval [start, end]
    struct Interval
    {
        uint64_t start;
        uint64_t end;

        Interval(uint64_t startValue, uint64_t endValue)
            : start(startValue)
            , end(endValue)
        {
        }

        // Proper strict weak ordering by start, then by end
        bool operator<(const Interval& other) const
        {
            if (start != other.start)
            {
                return start < other.start;
            }
            return end < other.end;
        }

        bool contains(uint64_t seq) const
        {
            return seq >= start && seq <= end;
        }

        bool canMergeWith(const Interval& other) const
        {
            // Adjacent or overlapping intervals can be merged
            return start <= other.end + 1 && other.start <= end + 1;
        }

        Interval mergeWith(const Interval& other) const
        {
            return {std::min(start, other.start), std::max(end, other.end)};
        }
    };

public:
    explicit GapSet(uint64_t size)
        : m_size(size)
    {
        if (size == 0)
        {
            m_allObserved = true;
        }
        m_lastUpdate = std::chrono::steady_clock::now();
    }

    /**
     * @brief Marks a sequence number as observed.
     * O(log n) complexity where n is number of intervals.
     */
    void observe(uint64_t seq)
    {
        if (seq >= m_size)
        {
            throw std::out_of_range("Sequence number out of range");
        }

        if (m_allObserved)
        {
            return;
        }

        // Find the first interval that starts at or after seq
        auto it = m_intervals.lower_bound(Interval(seq, seq));

        // Check if seq is already covered by the previous interval
        if (it != m_intervals.begin())
        {
            auto prev = std::prev(it);
            if (prev->contains(seq))
            {
                return; // Already observed
            }
        }

        // Check if seq is covered by current interval
        if (it != m_intervals.end() && it->contains(seq))
        {
            return; // Already observed
        }

        m_lastUpdate = std::chrono::steady_clock::now();
        ++m_observedCount;

        // Create new interval for this sequence
        Interval newInterval(seq, seq);

        // Collect intervals to merge with
        std::vector<std::set<Interval>::iterator> toErase;

        // Check if we can merge with previous interval
        if (it != m_intervals.begin())
        {
            auto prev = std::prev(it);
            if (prev->canMergeWith(newInterval))
            {
                newInterval = prev->mergeWith(newInterval);
                toErase.push_back(prev);
            }
        }

        // Check if we can merge with following intervals
        while (it != m_intervals.end() && newInterval.canMergeWith(*it))
        {
            newInterval = newInterval.mergeWith(*it);
            toErase.push_back(it);
            ++it;
        }

        // Remove intervals that were merged
        for (auto eraseIt : toErase)
        {
            m_intervals.erase(eraseIt);
        }

        // Insert the merged interval
        m_intervals.insert(newInterval);

        // Check if we've observed everything
        if (m_intervals.size() == 1 && m_intervals.begin()->start == 0 && m_intervals.begin()->end == m_size - 1)
        {
            m_allObserved = true;
        }
    }

    /**
     * @brief Checks if all sequences are observed.
     * O(1) complexity.
     */
    bool empty() const
    {
        if (m_size == 0)
        {
            return true;
        }
        return m_allObserved;
    }

    /**
     * @brief Checks if a sequence is observed.
     * O(log n) complexity.
     */
    bool contains(uint64_t seq) const
    {
        if (seq >= m_size)
        {
            return false;
        }
        if (m_allObserved)
        {
            return true;
        }

        // Find first interval starting at or after seq
        auto it = m_intervals.lower_bound(Interval(seq, seq));

        // Check if seq is in current interval
        if (it != m_intervals.end() && it->contains(seq))
        {
            return true;
        }

        // Check if seq is in previous interval
        if (it != m_intervals.begin())
        {
            --it;
            return it->contains(seq);
        }

        return false;
    }

    /**
     * @brief Returns gap ranges.
     * O(k) where k is number of intervals.
     */
    std::vector<std::pair<uint64_t, uint64_t>> ranges() const
    {
        std::vector<std::pair<uint64_t, uint64_t>> gaps;

        if (m_size == 0 || m_allObserved)
        {
            return gaps;
        }

        if (m_intervals.empty())
        {
            gaps.emplace_back(0, m_size - 1);
            return gaps;
        }

        uint64_t pos = 0;
        for (const auto& interval : m_intervals)
        {
            if (pos < interval.start)
            {
                gaps.emplace_back(pos, interval.start - 1);
            }
            pos = interval.end + 1;
        }

        if (pos < m_size)
        {
            gaps.emplace_back(pos, m_size - 1);
        }

        return gaps;
    }

    std::chrono::time_point<std::chrono::steady_clock> lastUpdate() const
    {
        return m_lastUpdate;
    }

    // Debug/monitoring methods
    size_t intervalCount() const
    {
        return m_intervals.size();
    }
    uint64_t observedCount() const
    {
        return m_observedCount;
    }

private:
    uint64_t m_size;                                                 ///< Total size of the observed sequence
    uint64_t m_observedCount {0};                                    ///< Total count of observed elements
    bool m_allObserved {false};                                      ///< Flag to indicate if all elements are observed
    std::set<Interval> m_intervals;                                  ///< Set of observed intervals
    std::chrono::time_point<std::chrono::steady_clock> m_lastUpdate; ///< Last update time
};

#endif // _GAP_SET_HPP
