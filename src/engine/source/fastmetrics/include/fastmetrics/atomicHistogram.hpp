#ifndef _FASTMETRICS_ATOMIC_HISTOGRAM_HPP
#define _FASTMETRICS_ATOMIC_HISTOGRAM_HPP

#include <algorithm>
#include <array>
#include <atomic>
#include <limits>
#include <string>

#include <fastmetrics/iMetric.hpp>

namespace fastmetrics
{

/**
 * @brief Lock-free atomic histogram with fixed exponential buckets
 *
 * Default buckets for latency measurement (microseconds):
 * [1, 10, 100, 1k, 10k, 100k, 1M, 10M, +inf]
 *
 * Template parameter NumBuckets includes the infinity bucket.
 */
template<size_t NumBuckets = 9>
class AtomicHistogram : public IHistogram
{
    static_assert(NumBuckets > 1 && NumBuckets <= 32, "NumBuckets must be between 2 and 32");

private:
    std::string m_name;
    std::array<std::atomic<uint64_t>, NumBuckets> m_buckets; ///< Bucket counters
    std::array<uint64_t, NumBuckets - 1> m_boundaries;       ///< Upper boundaries (sorted)
    std::atomic<uint64_t> m_count;                           ///< Total count
    std::atomic<uint64_t> m_sum;                             ///< Sum of all values
    std::atomic<uint64_t> m_min;                             ///< Minimum value
    std::atomic<uint64_t> m_max;                             ///< Maximum value
    std::atomic_bool m_enabled;

    /**
     * @brief Find bucket index using binary search
     */
    size_t findBucket(uint64_t value) const
    {
        auto it = std::lower_bound(m_boundaries.begin(), m_boundaries.end(), value);
        return std::distance(m_boundaries.begin(), it);
    }

    /**
     * @brief Update min atomically
     */
    void updateMin(uint64_t value)
    {
        uint64_t oldMin = m_min.load(std::memory_order_relaxed);
        while (value < oldMin && !m_min.compare_exchange_weak(oldMin, value, std::memory_order_relaxed))
        {
        }
    }

    /**
     * @brief Update max atomically
     */
    void updateMax(uint64_t value)
    {
        uint64_t oldMax = m_max.load(std::memory_order_relaxed);
        while (value > oldMax && !m_max.compare_exchange_weak(oldMax, value, std::memory_order_relaxed))
        {
        }
    }

public:
    /**
     * @brief Construct with default exponential boundaries for latency (microseconds)
     * Buckets: [1, 10, 100, 1k, 10k, 100k, 1M, 10M, +inf]
     */
    explicit AtomicHistogram(std::string name)
        : m_name(std::move(name))
        , m_count(0)
        , m_sum(0)
        , m_min(std::numeric_limits<uint64_t>::max())
        , m_max(0)
        , m_enabled(true)
    {
        // Initialize buckets
        for (auto& bucket : m_buckets)
        {
            bucket.store(0, std::memory_order_relaxed);
        }

        // Default exponential boundaries for latency (microseconds)
        // [1, 10, 100, 1k, 10k, 100k, 1M, 10M]
        uint64_t boundary = 1;
        for (size_t i = 0; i < NumBuckets - 1; ++i)
        {
            m_boundaries[i] = boundary;
            boundary *= 10;
        }
    }

    ~AtomicHistogram() override = default;

    AtomicHistogram(const AtomicHistogram&) = delete;
    AtomicHistogram& operator=(const AtomicHistogram&) = delete;
    AtomicHistogram(AtomicHistogram&&) = delete;
    AtomicHistogram& operator=(AtomicHistogram&&) = delete;

    // IMetric interface
    const std::string& name() const override { return m_name; }

    MetricType type() const override { return MetricType::HISTOGRAM; }

    bool isEnabled() const override { return m_enabled.load(std::memory_order_relaxed); }

    void enable() override { m_enabled.store(true, std::memory_order_relaxed); }

    void disable() override { m_enabled.store(false, std::memory_order_relaxed); }

    void reset() override
    {
        for (auto& bucket : m_buckets)
        {
            bucket.store(0, std::memory_order_relaxed);
        }
        m_count.store(0, std::memory_order_relaxed);
        m_sum.store(0, std::memory_order_relaxed);
        m_min.store(std::numeric_limits<uint64_t>::max(), std::memory_order_relaxed);
        m_max.store(0, std::memory_order_relaxed);
    }

    double value() const override { return static_cast<double>(count()); }

    // IHistogram interface
    void record(uint64_t value) override
    {
        if (!m_enabled.load(std::memory_order_relaxed)) [[unlikely]]
        {
            return;
        }

        // Find and increment bucket
        size_t bucketIdx = findBucket(value);
        m_buckets[bucketIdx].fetch_add(1, std::memory_order_relaxed);

        // Update statistics
        m_count.fetch_add(1, std::memory_order_relaxed);
        m_sum.fetch_add(value, std::memory_order_relaxed);
        updateMin(value);
        updateMax(value);
    }

    uint64_t count() const override { return m_count.load(std::memory_order_relaxed); }

    uint64_t sum() const override { return m_sum.load(std::memory_order_relaxed); }

    uint64_t min() const override
    {
        uint64_t minVal = m_min.load(std::memory_order_relaxed);
        return (minVal == std::numeric_limits<uint64_t>::max()) ? 0 : minVal;
    }

    uint64_t max() const override { return m_max.load(std::memory_order_relaxed); }

    uint64_t mean() const override
    {
        uint64_t cnt = m_count.load(std::memory_order_relaxed);
        if (cnt == 0)
        {
            return 0;
        }
        return m_sum.load(std::memory_order_relaxed) / cnt;
    }

    /**
     * @brief Get bucket count at index (for exporting)
     */
    uint64_t bucketCount(size_t idx) const
    {
        if (idx >= NumBuckets)
        {
            return 0;
        }
        return m_buckets[idx].load(std::memory_order_relaxed);
    }

    /**
     * @brief Get bucket boundary at index (for exporting)
     */
    uint64_t bucketBoundary(size_t idx) const
    {
        if (idx >= NumBuckets - 1)
        {
            return std::numeric_limits<uint64_t>::max();
        }
        return m_boundaries[idx];
    }

    size_t numBuckets() const { return NumBuckets; }
};

} // namespace fastmetrics

#endif // _FASTMETRICS_ATOMIC_HISTOGRAM_HPP
