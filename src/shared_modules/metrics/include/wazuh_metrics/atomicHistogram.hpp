/*
 * Wazuh shared metrics
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WAZUH_METRICS_ATOMIC_HISTOGRAM_HPP
#define _WAZUH_METRICS_ATOMIC_HISTOGRAM_HPP

#include <array>
#include <atomic>
#include <cstdint>
#include <limits>
#include <string>

#include <wazuh_metrics/iMetric.hpp>

namespace wazuh::metrics
{

    /**
     * @brief Lock-free distribution metric over log-linear buckets.
     *
     * Design: 32 octaves (one per bit of the observed value) split into 4
     * sub-buckets each -- 128 buckets, ~1.1 KiB per histogram. Values above the
     * last octave clamp into the last bucket.
     *
     * Hot path (observe): one CLZ, three relaxed fetch_add, and two min/max CAS
     * loops that all but never retry once the range settles -- no locks, no
     * allocations, no floating point. Roughly the cost of two counter increments.
     *
     * Cold path (snapshot): reads the 128 buckets with relaxed loads and walks
     * them to the requested percentile ranks. The estimate it returns is the
     * midpoint of the bucket the rank lands in, so the relative error is bounded
     * by the bucket width: at 4 sub-buckets per octave, ~12.5% -- plenty for
     * operational p50/p99. Like every read here it is best-effort under
     * concurrent observes: consistent enough for metrics, not for accounting.
     *
     * Values are unit-agnostic unsigned integers (the unit is registration
     * metadata). uint64_t on purpose: C++17 has no fetch_add for atomic<double>,
     * and an integer sum stays exact.
     */
    class AtomicHistogram : public IHistogram
    {
    private:
        static constexpr unsigned kSubBits {2U};                   ///< 4 sub-buckets per octave.
        static constexpr unsigned kOctaves {32U};                  ///< Distinct value magnitudes tracked.
        static constexpr unsigned kBuckets {kOctaves << kSubBits}; ///< 128.

        std::string m_name;
        std::array<std::atomic<uint64_t>, kBuckets> m_counts {};
        std::atomic<uint64_t> m_count {0};
        std::atomic<uint64_t> m_sum {0};
        std::atomic<uint64_t> m_min {std::numeric_limits<uint64_t>::max()};
        std::atomic<uint64_t> m_max {0};
        std::atomic_bool m_enabled {true};

        /**
         * @brief Map a value to its bucket: octave = MSB position, then the next
         * two bits pick the sub-bucket. Everything past the last octave clamps.
         */
        static unsigned bucketIndex(uint64_t value) noexcept
        {
            // `| 1` so CLZ never sees 0 (undefined); it also maps 0 into octave 0.
            const auto octave = 63U - static_cast<unsigned>(__builtin_clzll(value | 1U));
            const auto sub = (octave >= kSubBits) ? static_cast<unsigned>((value >> (octave - kSubBits)) & 3U)
                                                  : static_cast<unsigned>(value & 3U);
            const auto index = (octave << kSubBits) | sub;
            return (index < kBuckets) ? index : (kBuckets - 1U);
        }

        /**
         * @brief Representative value for a bucket: the midpoint of its range
         * (for the first two octaves the mapping is exact -- the value itself).
         */
        static uint64_t bucketMid(unsigned index) noexcept
        {
            const auto octave = index >> kSubBits;
            const auto sub = static_cast<uint64_t>(index & 3U);
            if (octave < kSubBits)
            {
                return sub;
            }
            const auto lower = (4U + sub) << (octave - kSubBits);
            const auto width = uint64_t {1} << (octave - kSubBits);
            return lower + (width / 2U);
        }

    public:
        explicit AtomicHistogram(std::string name)
            : m_name(std::move(name))
        {
        }

        ~AtomicHistogram() override = default;

        AtomicHistogram(const AtomicHistogram&) = delete;
        AtomicHistogram& operator=(const AtomicHistogram&) = delete;
        AtomicHistogram(AtomicHistogram&&) = delete;
        AtomicHistogram& operator=(AtomicHistogram&&) = delete;

        /** @copydoc wazuh::metrics::IMetric::name() */
        const std::string& name() const override
        {
            return m_name;
        }

        /** @copydoc wazuh::metrics::IMetric::type() */
        MetricType type() const override
        {
            return MetricType::HISTOGRAM;
        }

        /** @copydoc wazuh::metrics::IMetric::isEnabled() */
        bool isEnabled() const override
        {
            return m_enabled.load(std::memory_order_relaxed);
        }

        /** @copydoc wazuh::metrics::IMetric::enable() */
        void enable() override
        {
            m_enabled.store(true, std::memory_order_relaxed);
        }

        /** @copydoc wazuh::metrics::IMetric::disable() */
        void disable() override
        {
            m_enabled.store(false, std::memory_order_relaxed);
        }

        /** @copydoc wazuh::metrics::IMetric::reset() */
        void reset() override
        {
            for (auto& bucket : m_counts)
            {
                bucket.store(0, std::memory_order_relaxed);
            }
            m_count.store(0, std::memory_order_relaxed);
            m_sum.store(0, std::memory_order_relaxed);
            m_min.store(std::numeric_limits<uint64_t>::max(), std::memory_order_relaxed);
            m_max.store(0, std::memory_order_relaxed);
        }

        /** @copydoc wazuh::metrics::IMetric::value() -- the observation count. */
        double value() const override
        {
            if (!m_enabled.load(std::memory_order_relaxed))
            {
                return 0.0;
            }
            return static_cast<double>(m_count.load(std::memory_order_relaxed));
        }

        /** @copydoc wazuh::metrics::IHistogram::observe() */
        void observe(uint64_t value) override
        {
            if (!m_enabled.load(std::memory_order_relaxed))
            {
                return;
            }

            m_counts[bucketIndex(value)].fetch_add(1, std::memory_order_relaxed);
            m_count.fetch_add(1, std::memory_order_relaxed);
            m_sum.fetch_add(value, std::memory_order_relaxed);

            auto current = m_max.load(std::memory_order_relaxed);
            while (value > current && !m_max.compare_exchange_weak(current, value, std::memory_order_relaxed))
            {
            }
            current = m_min.load(std::memory_order_relaxed);
            while (value < current && !m_min.compare_exchange_weak(current, value, std::memory_order_relaxed))
            {
            }
        }

        /** @copydoc wazuh::metrics::IHistogram::snapshot() */
        Snapshot snapshot() const override
        {
            // One pass copying the buckets, so the three ranks are computed over
            // the SAME picture even while observes keep landing.
            std::array<uint64_t, kBuckets> counts {};
            uint64_t total {0};
            for (unsigned index = 0; index < kBuckets; ++index)
            {
                counts[index] = m_counts[index].load(std::memory_order_relaxed);
                total += counts[index];
            }

            Snapshot out;
            out.count = m_count.load(std::memory_order_relaxed);
            out.sum = m_sum.load(std::memory_order_relaxed);
            if (total == 0)
            {
                return out; // all zeros; min stays 0 rather than leaking the sentinel
            }
            out.min = m_min.load(std::memory_order_relaxed);
            out.max = m_max.load(std::memory_order_relaxed);

            const auto percentile = [&counts, total](double quantile) -> uint64_t
            {
                // Rank of the quantile among `total` ordered observations, 1-based.
                auto rank = static_cast<uint64_t>(quantile * static_cast<double>(total));
                if (rank < total)
                {
                    ++rank; // ceil for non-exact ranks; never past the last observation
                }
                uint64_t accumulated {0};
                for (unsigned index = 0; index < kBuckets; ++index)
                {
                    accumulated += counts[index];
                    if (accumulated >= rank)
                    {
                        return bucketMid(index);
                    }
                }
                return bucketMid(kBuckets - 1U);
            };

            out.p50 = percentile(0.50);
            out.p90 = percentile(0.90);
            out.p99 = percentile(0.99);
            return out;
        }
    };

} // namespace wazuh::metrics

#endif // _WAZUH_METRICS_ATOMIC_HISTOGRAM_HPP
