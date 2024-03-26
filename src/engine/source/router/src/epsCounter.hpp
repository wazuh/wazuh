#ifndef _ROUTER_EPS_COUNTER_HPP
#define _ROUTER_EPS_COUNTER_HPP

#include <atomic>
#include <chrono>

namespace router
{
constexpr auto DEFAULT_EPS = 1000;
constexpr auto DEFAULT_INTERVAL = 10;
constexpr auto DEFAULT_STATE = false;

/**
 * @brief Class to count events per second and reset the counter after a given interval
 *
 */
class Orchestrator::EpsCounter
{
private:
    std::atomic_uint m_count;     ///< Counter for the number of events
    std::atomic_bool m_canReset;  ///< Flag to ensure only one thread resets the counter
    std::atomic_uint m_limit;     ///< Limit for the number of events per interval
    std::atomic_ulong m_interval; ///< Interval windows size in nanoseconds
    std::chrono::time_point<std::chrono::steady_clock> m_lastReset; ///< Last time the counter was reset
    std::atomic_bool active;                                        ///< Flag to indicate if the counter is active

    void checkSettings(uint eps, uint intervalSec)
    {
        if (eps < 1)
        {
            throw std::runtime_error("EPS Limit must be greater than 0");
        }

        if (intervalSec < 1)
        {
            throw std::runtime_error("EPS Interval must be greater than 0");
        }
    }

public:
    EpsCounter()
        : m_count(0)
        , m_canReset(true)
        , m_limit(DEFAULT_EPS * DEFAULT_INTERVAL)
        , m_interval(1e9 * DEFAULT_INTERVAL)
        , m_lastReset(std::chrono::steady_clock::now())
        , active(DEFAULT_STATE)
    {
    }

    /**
     * @brief Construct a new Eps Counter object
     *
     * @param eps Maximum number of events per second
     * @param intervalSec Interval window size in seconds
     */
    EpsCounter(uint eps, uint intervalSec, bool state)
        : m_count(0)
        , m_lastReset(std::chrono::steady_clock::now())
        , m_canReset(true)
        , active(state)
    {
        checkSettings(eps, intervalSec);
        m_limit.store(eps * intervalSec, std::memory_order_relaxed);
        m_interval.store(1e9 * intervalSec, std::memory_order_relaxed);
    }

    bool limitReached()
    {
        // Preemptively check the limit, only then check and reset the counter
        auto current = m_count.fetch_add(1, std::memory_order_relaxed);
        if (++current <= m_limit.load(std::memory_order_relaxed))
        {
            return false;
        }

        auto now = std::chrono::steady_clock::now();
        auto especulativeElapsedTime = std::chrono::duration_cast<std::chrono::nanoseconds>(now - m_lastReset).count();

        if (especulativeElapsedTime >= m_interval.load(std::memory_order_relaxed))
        {
            // Ensure only one thread resets the counter
            bool expected = true;
            if (m_canReset.compare_exchange_strong(expected, false, std::memory_order_acquire))
            {
                auto realElapsedTime = std::chrono::duration_cast<std::chrono::nanoseconds>(now - m_lastReset).count();
                if (realElapsedTime >= m_interval.load(std::memory_order_relaxed))
                {
                    m_lastReset = now;
                    m_count.store(0, std::memory_order_relaxed);
                }

                m_canReset.store(true, std::memory_order_release);
            }
        }

        return true;
    }

    void stop() { active.store(false, std::memory_order_relaxed); }

    void start() { active.store(true, std::memory_order_relaxed); }

    bool isActive() const { return active.load(std::memory_order_relaxed); }

    void changeSettings(uint eps, uint intervalSec)
    {
        checkSettings(eps, intervalSec);

        m_limit.store(eps * intervalSec, std::memory_order_relaxed);
        m_interval.store(1e9 * intervalSec, std::memory_order_relaxed);
    }

    uint getEps() const
    {
        return m_limit.load(std::memory_order_relaxed) / (m_interval.load(std::memory_order_relaxed) / 1e9);
    }
    uint getRefreshInterval() const { return m_interval.load(std::memory_order_relaxed) / 1e9; }
};
} // namespace router

#endif // _ROUTER_EPS_COUNTER_HPP
