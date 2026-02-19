#ifndef _FASTQUEUE_RATELIMITE
#define _FASTQUEUE_RATELIMITE

#include <atomic>
#include <chrono>
#include <stdexcept>
#include <thread>


namespace fastqueue
{

/**
 * @brief Token Bucket rate limiter for controlling dequeue rate
 *
 * Uses a token bucket algorithm to limit the rate at which elements can be dequeued.
 * Thread-safe using atomics. Lockess design to minimize contention.
 */
class RateLimiter
{
private:
    std::atomic<double> m_tokens;          ///< Current available tokens
    std::atomic<int64_t> m_lastRefillTime; ///< Last time tokens were refilled (microseconds)
    const double m_maxTokens;              ///< Maximum tokens (burst size)
    const double m_refillRate;             ///< Tokens added per microsecond

public:
    /**
     * @brief Construct a new Rate Limiter
     *
     * @param maxElementsPerSecond Maximum elements that can be dequeued per second
     * @param burstSize Maximum burst size (window). Default: maxElementsPerSecond
     */
    RateLimiter(size_t maxElementsPerSecond, size_t burstSize = 0)
        : m_tokens(0.0)
        , m_lastRefillTime(0)
        , m_maxTokens(burstSize > 0 ? static_cast<double>(burstSize) : static_cast<double>(maxElementsPerSecond))
        , m_refillRate(static_cast<double>(maxElementsPerSecond) / 1000000.0) // per microsecond
    {
        if (maxElementsPerSecond == 0)
        {
            throw std::runtime_error("maxElementsPerSecond must be greater than 0");
        }

        // Initialize with full tokens
        m_tokens.store(m_maxTokens, std::memory_order_relaxed);

        auto now = std::chrono::steady_clock::now().time_since_epoch();
        m_lastRefillTime.store(std::chrono::duration_cast<std::chrono::microseconds>(now).count(),
                               std::memory_order_relaxed);
    }

    /**
     * @brief Try to acquire tokens for dequeuing elements
     *
     * @param count Number of tokens to acquire
     * @return true if tokens were acquired, false if rate limit exceeded
     */
    bool tryAcquire(size_t count = 1)
    {
        refillTokens();
        return consumeTokens(count);
    }

    /**
     * @brief Wait to acquire tokens for dequeuing elements
     *
     * Waits until enough tokens are available or timeout expires.
     * Avoids busy waiting by sleeping until tokens should be available.
     *
     * @param count Number of tokens to acquire
     * @param timeoutMicros Maximum time to wait in microseconds
     * @return true if tokens were acquired, false if timeout expired
     */
    bool waitAcquire(size_t count, int64_t timeoutMicros)
    {
        auto startTime = std::chrono::steady_clock::now();
        auto timeoutDuration = std::chrono::microseconds(timeoutMicros);

        while (true)
        {
            // Try to acquire tokens
            if (tryAcquire(count))
            {
                return true;
            }

            // Check if timeout expired
            auto elapsed = std::chrono::steady_clock::now() - startTime;
            if (elapsed >= timeoutDuration)
            {
                return false; // Timeout
            }

            // Calculate how long to wait for tokens to refill
            double currentTokens = m_tokens.load(std::memory_order_relaxed);
            double tokensNeeded = static_cast<double>(count) - currentTokens;

            if (tokensNeeded > 0)
            {
                // Time needed for tokens to refill (in microseconds)
                int64_t waitTimeMicros = static_cast<int64_t>(tokensNeeded / m_refillRate);

                // Don't wait longer than remaining timeout
                int64_t remainingMicros =
                    std::chrono::duration_cast<std::chrono::microseconds>(timeoutDuration - elapsed).count();
                waitTimeMicros = std::min(waitTimeMicros, remainingMicros);

                // Sleep to avoid busy waiting (minimum 1ms to avoid spinning)
                if (waitTimeMicros > 1000)
                {
                    std::this_thread::sleep_for(std::chrono::microseconds(waitTimeMicros));
                }
                else
                {
                    // Very short wait - just yield
                    std::this_thread::yield();
                }
            }
            else
            {
                // Tokens should be available, try again immediately
                std::this_thread::yield();
            }
        }
    }

private:
    /**
     * @brief Refill tokens based on elapsed time
     */
    void refillTokens()
    {
        auto now = std::chrono::steady_clock::now().time_since_epoch();
        int64_t currentTime = std::chrono::duration_cast<std::chrono::microseconds>(now).count();
        int64_t lastTime = m_lastRefillTime.load(std::memory_order_relaxed);

        int64_t elapsed = currentTime - lastTime;
        if (elapsed > 0)
        {
            double tokensToAdd = elapsed * m_refillRate;
            double currentTokens = m_tokens.load(std::memory_order_relaxed);
            double newTokens = std::min(currentTokens + tokensToAdd, m_maxTokens);

            // Update tokens and time atomically (best effort)
            m_tokens.store(newTokens, std::memory_order_relaxed);
            m_lastRefillTime.store(currentTime, std::memory_order_relaxed);
        }
    }

    /**
     * @brief Try to consume tokens atomically
     *
     * @param count Number of tokens to consume
     * @return true if tokens were consumed, false otherwise
     */
    bool consumeTokens(size_t count)
    {
        double currentTokens = m_tokens.load(std::memory_order_relaxed);
        if (currentTokens >= static_cast<double>(count))
        {
            // Atomic subtraction
            double expected = currentTokens;
            double desired = currentTokens - static_cast<double>(count);

            // Use compare_exchange to ensure atomicity
            while (!m_tokens.compare_exchange_weak(
                expected, desired, std::memory_order_release, std::memory_order_relaxed))
            {
                if (expected < static_cast<double>(count))
                {
                    return false; // Not enough tokens
                }
                desired = expected - static_cast<double>(count);
            }
            return true;
        }

        return false;
    }
};
} // namespace fastqueue

#endif // _FASTQUEUE_RATELIMITE
