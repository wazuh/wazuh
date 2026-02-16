#ifndef _FASTQUEUE_STDQUEUE_HPP
#define _FASTQUEUE_STDQUEUE_HPP

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>

#include <fastqueue/iqueue.hpp>
#include <fastqueue/ratelimiter.hpp>

namespace fastqueue
{

/**
 * @brief A thread-safe queue using std::queue with rate limiting support
 *
 * This class provides a thread-safe wrapper around std::queue with:
 * - Mutex-based synchronization
 * - Condition variable for blocking operations
 * - Optional rate limiting for dequeue operations
 * - Capacity limits with overflow protection
 *
 * @note This implementation uses locks, unlike CQueue which is lock-free.
 *       Use CQueue for better performance in high-contention scenarios.
 *
 * @note IMPORTANT: Minimum queue capacity is MIN_QUEUE_CAPACITY (8192 elements).
 *       Attempting to create a queue with smaller capacity will throw std::runtime_error.
 *
 * @tparam T The type of the data to be stored in the queue.
 */
template<typename T>
class StdQueue : public IQueue<T>
{
private:
    std::queue<T> m_queue;                      ///< The underlying queue
    mutable std::mutex m_mutex;                 ///< Mutex for thread-safe access
    std::condition_variable m_condVar;          ///< Condition variable for blocking operations
    const std::size_t m_capacity;               ///< Maximum capacity of the queue
    std::unique_ptr<RateLimiter> m_rateLimiter; ///< Optional rate limiter (nullptr = no limiting)

public:
    /**
     * @brief Construct a new StdQueue object
     *
     * @param capacity The maximum capacity of the queue
     * @throw std::runtime_error if the capacity is less than or equal to 0 or less than MIN_QUEUE_CAPACITY
     */
    explicit StdQueue(int capacity)
        : m_capacity(capacity)
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
     * @brief Construct a new StdQueue object with rate limiting
     *
     * @param capacity The maximum capacity of the queue
     * @param maxElementsPerSecond Maximum elements per second that can be dequeued (0 = no limit)
     * @param burstSize Maximum burst size (tokens that can accumulate). Defaults to maxElementsPerSecond.
     * @throw std::runtime_error if the capacity is less than or equal to 0 or less than MIN_QUEUE_CAPACITY
     * @throw std::runtime_error if maxElementsPerSecond is negative
     * @throw std::runtime_error if burstSize is less than 1
     */
    StdQueue(int capacity, double maxElementsPerSecond, double burstSize = 0.0)
        : m_capacity(capacity)
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
    bool push(T&& element) override
    {
        std::unique_lock<std::mutex> lock(m_mutex);

        if (m_queue.size() >= m_capacity)
        {
            return false; // Queue is full
        }

        m_queue.push(std::move(element));
        lock.unlock();
        m_condVar.notify_one();
        return true;
    }

    /**
     * @copydoc IQueue::tryPush
     */
    bool tryPush(const T& element) override
    {
        std::unique_lock<std::mutex> lock(m_mutex);

        if (m_queue.size() >= m_capacity)
        {
            return false; // Queue is full
        }

        m_queue.push(element);
        lock.unlock();
        m_condVar.notify_one();
        return true;
    }

    /**
     * @copydoc IQueue::waitPop
     * @note The timeout is in microseconds.
     * @note If rate limiting is enabled, this method will wait for both:
     *       1) Tokens to become available (rate limiter)
     *       2) Elements to become available in the queue
     *       The effective timeout applies to the total operation.
     */
    bool waitPop(T& element, int64_t timeout = 0) override
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

            return waitPopInternal(element, remainingTimeout);
        }

        return waitPopInternal(element, timeout);
    }

    /**
     * @copydoc IQueue::tryPop
     * @note If rate limiting is enabled, this method will return false if the rate limit is exceeded.
     */
    bool tryPop(T& element) override
    {
        if (m_rateLimiter && !m_rateLimiter->tryAcquire(1))
        {
            return false;
        }

        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_queue.empty())
        {
            return false;
        }

        element = std::move(m_queue.front());
        m_queue.pop();
        return true;
    }

    /**
     * @copydoc IQueue::empty
     */
    bool empty() const noexcept override
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.empty();
    }

    /**
     * @copydoc IQueue::size
     */
    std::size_t size() const noexcept override
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.size();
    }

    /**
     * @copydoc IQueue::aproxFreeSlots
     * @note Returns the exact number of free slots (not approximate for this implementation).
     */
    std::size_t aproxFreeSlots() const noexcept override
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto currentSize = m_queue.size();
        return (currentSize >= m_capacity) ? 0 : (m_capacity - currentSize);
    }

    /**
     * @copydoc IQueue::tryPopBulk
     * @note If rate limiting is enabled, this method will acquire tokens for ALL requested elements
     *       or return 0 if insufficient tokens are available. This maintains the atomicity of bulk operations.
     */
    std::size_t tryPopBulk(T* elements, std::size_t max) override
    {
        if (m_rateLimiter && !m_rateLimiter->tryAcquire(max))
        {
            return 0;
        }

        std::lock_guard<std::mutex> lock(m_mutex);

        std::size_t count = 0;
        while (count < max && !m_queue.empty())
        {
            elements[count] = std::move(m_queue.front());
            m_queue.pop();
            ++count;
        }

        return count;
    }

private:
    /**
     * @brief Internal implementation of waitPop without rate limiting
     *
     * @param element Reference to store the popped element
     * @param timeout Timeout in microseconds
     * @return true if element was popped, false if timeout occurred
     */
    bool waitPopInternal(T& element, int64_t timeout)
    {
        std::unique_lock<std::mutex> lock(m_mutex);

        if (timeout < 0)
        {
            // Infinite wait
            m_condVar.wait(lock, [this] { return !m_queue.empty(); });
        }
        else if (timeout == 0)
        {
            // No wait
            if (m_queue.empty())
            {
                return false;
            }
        }
        else
        {
            // Wait with timeout
            auto timeoutDuration = std::chrono::microseconds(timeout);
            if (!m_condVar.wait_for(lock, timeoutDuration, [this] { return !m_queue.empty(); }))
            {
                return false; // Timeout
            }
        }

        element = std::move(m_queue.front());
        m_queue.pop();
        return true;
    }
};

} // namespace fastqueue

#endif // _FASTQUEUE_STDQUEUE_HPP
