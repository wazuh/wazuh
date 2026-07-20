#ifndef FASTMETRICS_SLIDING_WINDOW_RATE_HPP
#define FASTMETRICS_SLIDING_WINDOW_RATE_HPP

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>

namespace fastmetrics
{

/**
 * @brief Sliding window rate calculator for EPS (events per second).
 *
 * Resolution: 1 second.
 * Maximum window: 31 minutes.
 *
 * Design:
 * - Uses a circular buffer of buckets, one per second.
 * - Each bucket contains:
 *      - timestamp of the second it belongs to
 *      - event count for that second
 * - When a bucket is reused for a new second, only one thread
 *   can recycle it by temporarily marking the bucket with a sentinel timestamp.
 *
 * Notes:
 * - It is lock-free at the atomic level, but reads are "best effort":
 *   consistent enough for metrics, not for exact accounting.
 * - Small deviations may happen under high concurrency.
 */
class SlidingWindowRate
{
private:
    static constexpr std::size_t MAX_WINDOW_SEC = 31 * 60; // 31 minutes
    static constexpr uint64_t RECYCLING_TS = std::numeric_limits<uint64_t>::max();

    struct Bucket
    {
        std::atomic<uint64_t> timestamp {0};
        std::atomic<uint64_t> count {0};
    };

    std::array<Bucket, MAX_WINDOW_SEC> m_buckets {};

    static uint64_t currentSecond()
    {
        using namespace std::chrono;
        return static_cast<uint64_t>(duration_cast<seconds>(steady_clock::now().time_since_epoch()).count());
    }

public:
    SlidingWindowRate() = default;
    ~SlidingWindowRate() = default;

    SlidingWindowRate(const SlidingWindowRate&) = delete;
    SlidingWindowRate& operator=(const SlidingWindowRate&) = delete;

    /**
     * @brief Increments the counter for the current second.
     */
    void increment()
    {
        const uint64_t now = currentSecond();
        Bucket& bucket = m_buckets[now % MAX_WINDOW_SEC];

        while (true)
        {
            const uint64_t ts = bucket.timestamp.load(std::memory_order_acquire);

            if (ts == now)
            {
                bucket.count.fetch_add(1, std::memory_order_relaxed);
                return;
            }

            // Another thread is currently recycling this bucket.
            if (ts == RECYCLING_TS)
            {
                continue;
            }

            // Try to claim the bucket for recycling by moving it into a
            // temporary "recycling" state.
            uint64_t expected = ts;
            if (bucket.timestamp.compare_exchange_weak(
                    expected, RECYCLING_TS, std::memory_order_acq_rel, std::memory_order_acquire))
            {
                // We now own the recycle process.
                //
                // Publish order matters:
                // 1. initialize count for the new second
                // 2. publish timestamp = now
                //
                // Readers/writers only treat the bucket as belonging to 'now'
                // after the timestamp is published.
                bucket.count.store(1, std::memory_order_release);
                bucket.timestamp.store(now, std::memory_order_release);
                return;
            }

            // CAS failed: retry.
        }
    }

    /**
     * @brief Computes the average EPS over the requested window.
     * @param window time window, for example std::chrono::seconds(60)
     * @return average events per second over that window
     */
    double getRate(std::chrono::seconds window) const
    {
        const uint64_t now = currentSecond();

        uint64_t win = static_cast<uint64_t>(window.count());
        if (win == 0)
        {
            return 0.0;
        }

        if (win > MAX_WINDOW_SEC)
        {
            win = MAX_WINDOW_SEC;
        }

        uint64_t sum = 0;

        for (uint64_t offset = 0; offset < win; ++offset)
        {
            // Defensive guard against unsigned underflow in extremely early
            // process lifetime scenarios.
            if (offset > now)
            {
                break;
            }

            const uint64_t sec = now - offset;
            const Bucket& bucket = m_buckets[sec % MAX_WINDOW_SEC];

            // Stable bucket snapshot:
            // read timestamp, then count, then timestamp again.
            const uint64_t ts1 = bucket.timestamp.load(std::memory_order_acquire);

            // Ignore buckets currently being recycled.
            if (ts1 == RECYCLING_TS)
            {
                continue;
            }

            const uint64_t cnt = bucket.count.load(std::memory_order_acquire);
            const uint64_t ts2 = bucket.timestamp.load(std::memory_order_acquire);

            // Accept the bucket only if it remained stable during the read
            // and actually corresponds to the expected second.
            if (ts1 == ts2 && ts1 == sec)
            {
                sum += cnt;
            }
        }

        return static_cast<double>(sum) / static_cast<double>(win);
    }
};

} // namespace fastmetrics

#endif // FASTMETRICS_SLIDING_WINDOW_RATE_HPP
