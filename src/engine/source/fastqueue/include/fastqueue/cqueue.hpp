#ifndef _FASTQUEUE_CQUEUE
#define _FASTQUEUE_CQUEUE

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <thread>

#include <blockingconcurrentqueue.h>

#include <fastqueue/iqueue.hpp>

namespace
{
/**
 * @brief Optimized traits for large queues (2^17 to 2^20 elements)
 *
 * BLOCK_SIZE: 4096 elements per block
 *   - For 131K elements (2^17): ~32 blocks
 *   - For 1M elements (2^20): ~256 blocks
 *   - Larger blocks = fewer allocations, better cache locality for sequential access
 *
 * IMPLICIT_INITIAL_INDEX_SIZE: 512 entries
 *   - Covers up to ~2M elements without index reallocation
 *   - Memory overhead: ~4KB (negligible for queues of this size)
 *   - Zero reallocations for queues up to 2^20 elements
 */
struct WQueueTraits : public moodycamel::ConcurrentQueueDefaultTraits
{
    static constexpr size_t BLOCK_SIZE = 4096;                 // Optimal for large queues
    static constexpr size_t IMPLICIT_INITIAL_INDEX_SIZE = 512; // Supports up to 2^21 elements
};
} // namespace

namespace fastqueue
{

constexpr int64_t WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 100000; ///< Timeout for the wait_dequeue_timed method
constexpr size_t MIN_QUEUE_CAPACITY = 8192; ///< Minimum queue capacity (2x BLOCK_SIZE for optimal performance)

/**
 * @brief Token Bucket rate limiter for controlling dequeue rate
 *
 * Uses a token bucket algorithm to limit the rate at which elements can be dequeued.
 * Thread-safe using atomics.
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

/**
 * @brief A thread-safe queue that can be used to pass messages between threads.
 *
 * This class is a wrapper of the BlockingConcurrentQueue class from the moodycamel library.
 * It provides a simple interface to use the queue with optimized block size and index settings.
 *
 * @note IMPORTANT: Minimum queue capacity is MIN_QUEUE_CAPACITY (8192 elements).
 *       This is required for optimal performance with BLOCK_SIZE=4096.
 *       Attempting to create a queue with smaller capacity will throw std::runtime_error.
 *
 * @tparam T The type of the data to be stored in the queue.
 * @tparam D The traits class for the queue (default: WQueueTraits with optimized settings).
 */
template<typename T, typename D = WQueueTraits>
class CQueue : public IQueue<T>
{
private:
    static_assert(std::is_base_of_v<moodycamel::ConcurrentQueueDefaultTraits, D>,
                  "The template parameter D must be a subclass of ConcurrentQueueDefaultTraits");

    moodycamel::BlockingConcurrentQueue<T, D> m_queue {}; ///< The queue itself.
    std::size_t m_minCapacity;                            ///< The minimum capacity of the queue.
    std::unique_ptr<RateLimiter> m_rateLimiter;           ///< Optional rate limiter (nullptr = no limiting)

public:
    /**
     * @brief Construct a new Concurrent Queue object
     *
     * @param capacity The capacity of the queue. (Approximate)
     * @throw std::runtime_error if the capacity is less than or equal to 0 or less than MIN_QUEUE_CAPACITY
     */
    explicit CQueue(int capacity)
        : m_queue(capacity)
        , m_minCapacity(capacity)
        , m_rateLimiter(nullptr)
    {
        if (capacity <= 0)
        {
            throw std::runtime_error("The capacity of the queue must be greater than 0");
        }
        if (static_cast<size_t>(capacity) < MIN_QUEUE_CAPACITY)
        {
            throw std::runtime_error("The capacity of the queue must be at least " + std::to_string(MIN_QUEUE_CAPACITY)
                                     + " elements");
        }
    }

    /**
     * @brief Construct a new Concurrent Queue object with rate limiting
     *
     * @param capacity The capacity of the queue. (Approximate)
     * @param maxElementsPerSecond Maximum elements per second that can be dequeued (0 = no limit)
     * @param burstSize Maximum burst size (tokens that can accumulate). Defaults to maxElementsPerSecond.
     * @throw std::runtime_error if the capacity is less than or equal to 0 or less than MIN_QUEUE_CAPACITY
     * @throw std::runtime_error if maxElementsPerSecond is negative
     * @throw std::runtime_error if burstSize is less than 1
     */
    CQueue(int capacity, double maxElementsPerSecond, double burstSize = 0.0)
        : m_queue(capacity)
        , m_minCapacity(capacity)
        , m_rateLimiter(nullptr)
    {
        if (capacity <= 0)
        {
            throw std::runtime_error("The capacity of the queue must be greater than 0");
        }
        if (static_cast<size_t>(capacity) < MIN_QUEUE_CAPACITY)
        {
            throw std::runtime_error("The capacity of the queue must be at least " + std::to_string(MIN_QUEUE_CAPACITY)
                                     + " elements");
        }
        if (maxElementsPerSecond < 0.0)
        {
            throw std::runtime_error("maxElementsPerSecond must be non-negative");
        }

        // Only create rate limiter if rate limiting is requested
        if (maxElementsPerSecond > 0.0)
        {
            const double actualBurstSize = (burstSize <= 0.0) ? maxElementsPerSecond : burstSize;
            if (actualBurstSize < 1.0)
            {
                throw std::runtime_error("burstSize must be at least 1");
            }
            m_rateLimiter = std::make_unique<RateLimiter>(maxElementsPerSecond, actualBurstSize);
        }
    }

    /**
     * @copydoc IQueue::push
     */
    inline bool push(T&& element) override { return m_queue.try_enqueue(std::move(element)); }

    /**
     * @copydoc IQueue::tryPush
     */
    inline bool tryPush(const T& element) override { return m_queue.try_enqueue(element); }

    /**
     * @copydoc IQueue::waitPop
     * @note The timeout is in microseconds.
     * @note If rate limiting is enabled, this method will wait for both:
     *       1) Tokens to become available (rate limiter)
     *       2) Elements to become available in the queue
     *       The effective timeout applies to the total operation.
     */
    inline bool waitPop(T& element, int64_t timeout) override
    {
        if (m_rateLimiter)
        {
            auto startTime = std::chrono::steady_clock::now();

            // Wait for rate limiter token
            if (!m_rateLimiter->waitAcquire(1, timeout))
            {
                return false; // Rate limiter timeout
            }

            // Calculate remaining timeout for queue operation
            auto elapsed =
                std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - startTime);
            int64_t remainingTimeout = timeout - elapsed.count();

            if (remainingTimeout <= 0)
            {
                return false; // No time left
            }

            return m_queue.wait_dequeue_timed(element, remainingTimeout);
        }

        return m_queue.wait_dequeue_timed(element, timeout);
    }

    /**
     * @copydoc IQueue::tryPop
     * @note If rate limiting is enabled, this method will return false if the rate limit is exceeded.
     */
    inline bool tryPop(T& element) override
    {
        if (m_rateLimiter && !m_rateLimiter->tryAcquire(1))
        {
            return false;
        }
        return m_queue.try_dequeue(element);
    }

    /**
     * @copydoc IQueue::empty
     * @note The size is approximate.
     */
    inline bool empty() const noexcept override { return m_queue.size_approx() == 0; }

    /**
     * @copydoc IQueue::size
     * @note The size is approximate.
     */
    inline size_t size() const noexcept override { return m_queue.size_approx(); }

    /**
     * @copydoc IQueue::aproxFreeSlots
     * @note The free slots is approximate.
     * @note The free slots is calculated as the minimum capacity minus the approximate size of the queue.
     * @note Returns 0 if the queue size exceeds the minimum capacity.
     */
    inline size_t aproxFreeSlots() const noexcept override
    {
        const auto currentSize = m_queue.size_approx();
        return (currentSize >= m_minCapacity) ? 0 : (m_minCapacity - currentSize);
    }

    /**
     * @copydoc IQueue::tryPopBulk
     * @note This is significantly more efficient than calling tryPop in a loop.
     * @note If rate limiting is enabled, this method will acquire tokens for ALL requested elements
     *       or return 0 if insufficient tokens are available. This maintains the atomicity of bulk operations.
     */
    inline std::size_t tryPopBulk(T* elements, std::size_t max) override
    {
        if (m_rateLimiter && !m_rateLimiter->tryAcquire(max))
        {
            return 0;
        }
        return m_queue.try_dequeue_bulk(elements, max);
    }
};

} // namespace fastqueue

#endif // _QUEUES_CONCURRENTQUEUE_HPP
