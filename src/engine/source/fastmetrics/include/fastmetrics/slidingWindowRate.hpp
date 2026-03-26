#ifndef _FASTMETRICS_SLIDING_WINDOW_RATE_HPP
#define _FASTMETRICS_SLIDING_WINDOW_RATE_HPP

#include <algorithm>
#include <chrono>
#include <deque>
#include <functional>
#include <mutex>

namespace fastmetrics
{

/**
 * @brief Sliding window rate calculator for EPS (events per second)
 *
 * Samples a counter value on each read and computes the average
 * rate over configurable time windows (e.g., 1m, 5m, 30m).
 *
 * Thread-safe. Designed for pull-metric usage (sampled on read).
 *
 * Usage:
 *   auto rate = std::make_shared<SlidingWindowRate>(
 *       []() { return myCounter->get(); });
 *
 *   // Read EPS over last minute:
 *   double eps1m = rate->getRate(std::chrono::minutes(1));
 */
class SlidingWindowRate
{
    struct Sample
    {
        std::chrono::steady_clock::time_point time;
        uint64_t value;
    };

    mutable std::mutex m_mutex;
    std::deque<Sample> m_samples;
    std::function<uint64_t()> m_valueGetter;

    static constexpr auto MAX_RETENTION = std::chrono::minutes(31); ///< Keep slightly more than max window

public:
    explicit SlidingWindowRate(std::function<uint64_t()> valueGetter)
        : m_valueGetter(std::move(valueGetter))
    {
    }

    ~SlidingWindowRate() = default;

    SlidingWindowRate(const SlidingWindowRate&) = delete;
    SlidingWindowRate& operator=(const SlidingWindowRate&) = delete;

    /**
     * @brief Record a sample of the current counter value
     *
     * Called automatically by getRate(), but can also be called
     * externally for more frequent sampling.
     */
    void sample()
    {
        auto now = std::chrono::steady_clock::now();
        uint64_t value = 0;
        try
        {
            value = m_valueGetter();
        }
        catch (...)
        {
            return;
        }

        std::lock_guard<std::mutex> lock(m_mutex);
        m_samples.push_back({now, value});

        // Purge samples older than MAX_RETENTION
        while (!m_samples.empty() && (now - m_samples.front().time) > MAX_RETENTION)
        {
            m_samples.pop_front();
        }
    }

    /**
     * @brief Calculate average events per second over the given window
     *
     * Samples the current counter value first, then computes the rate
     * from the oldest sample within the window to the newest.
     *
     * @param window Time window (e.g., std::chrono::minutes(1))
     * @return Average events per second over the window
     */
    double getRate(std::chrono::seconds window)
    {
        sample();

        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_samples.size() < 2)
        {
            return 0.0;
        }

        const auto& newest = m_samples.back();
        auto windowStart = newest.time - window;

        // Find the oldest sample that is >= windowStart (binary search on sorted timestamps)
        auto it = std::lower_bound(m_samples.begin(),
                                   m_samples.end(),
                                   windowStart,
                                   [](const Sample& s, const std::chrono::steady_clock::time_point& t)
                                   { return s.time < t; });

        // If all samples are within window, use the oldest available
        if (it == m_samples.end())
        {
            it = m_samples.begin();
        }

        // If the found sample IS the newest, try one before
        if (it == std::prev(m_samples.end()) && m_samples.size() >= 2)
        {
            it = m_samples.begin();
        }

        auto elapsedSec = std::chrono::duration<double>(newest.time - it->time).count();
        if (elapsedSec < 0.5)
        {
            return 0.0;
        }

        auto delta = newest.value - it->value;
        return static_cast<double>(delta) / elapsedSec;
    }

    /**
     * @brief Get the number of stored samples (for testing)
     */
    size_t sampleCount() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_samples.size();
    }
};

} // namespace fastmetrics

#endif // _FASTMETRICS_SLIDING_WINDOW_RATE_HPP
