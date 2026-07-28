#ifndef _FASTQUEUE_BYTELIMITER_HPP
#define _FASTQUEUE_BYTELIMITER_HPP

#include <atomic>
#include <cstddef>
#include <functional>

namespace fastqueue
{

/**
 * @brief Lock-free byte-based capacity limiter for queues.
 *
 * Tracks accumulated byte sizes of enqueued elements and rejects pushes that
 * would exceed the configured budget. All operations are lock-free (atomic),
 * so ByteLimiter can be embedded in both mutex-based and lock-free queue
 * implementations without extra synchronization cost.
 *
 * Usage pattern (push side):
 *   const size_t sz = limiter.measure(element);  // before moving element
 *   if (!limiter.tryAcquireBytes(sz)) return false;
 *   if (!underlying_enqueue(std::move(element))) {
 *       limiter.releaseBytes(sz);                // roll back on enqueue failure
 *       return false;
 *   }
 *
 * Usage pattern (pop side):
 *   const size_t sz = limiter.measure(queue.front()); // before moving
 *   element = std::move(queue.front());
 *   limiter.releaseBytes(sz);
 *
 * @tparam T Element type stored in the owning queue.
 */
template<typename T>
class ByteLimiter
{
    std::size_t m_maxBytes {0};
    std::atomic<std::size_t> m_currentBytes {0};
    std::function<std::size_t(const T&)> m_sizeOf;

public:
    bool isEnabled() const noexcept { return static_cast<bool>(m_sizeOf); }

    void configure(std::size_t maxBytes, std::function<std::size_t(const T&)> sizeOf)
    {
        m_maxBytes = maxBytes;
        m_sizeOf = std::move(sizeOf);
        m_currentBytes.store(0, std::memory_order_relaxed);
    }

    std::size_t measure(const T& element) const noexcept { return m_sizeOf ? m_sizeOf(element) : 0; }

    /**
     * @brief Attempt to reserve @p sz bytes from the budget.
     *
     * @return true  Bytes reserved; caller MUST call releaseBytes(sz) if the
     *               element is ultimately not enqueued.
     * @return false Quota would be exceeded; no bytes reserved.
     */
    bool tryAcquireBytes(std::size_t sz) noexcept
    {
        if (!m_sizeOf)
            return true;
        if (m_maxBytes > 0)
        {
            if (sz > m_maxBytes)
                return false;
            const std::size_t prev = m_currentBytes.fetch_add(sz, std::memory_order_relaxed);
            if (prev >= m_maxBytes || sz > m_maxBytes - prev)
            {
                m_currentBytes.fetch_sub(sz, std::memory_order_relaxed);
                return false;
            }
        }
        else
        {
            m_currentBytes.fetch_add(sz, std::memory_order_relaxed);
        }
        return true;
    }

    void releaseBytes(std::size_t sz) noexcept
    {
        if (!m_sizeOf || sz == 0)
            return;
        const std::size_t prev = m_currentBytes.fetch_sub(sz, std::memory_order_relaxed);
        if (prev < sz)
        {
            // Compensate underflow without clobbering concurrent increments.
            // store(0) would destroy any fetch_add that landed between our fetch_sub and here.
            m_currentBytes.fetch_add(sz - prev, std::memory_order_relaxed);
        }
    }

    std::size_t bytesUsed() const noexcept { return m_currentBytes.load(std::memory_order_relaxed); }
    std::size_t maxBytes() const noexcept { return m_maxBytes; }
};

} // namespace fastqueue

#endif // _FASTQUEUE_BYTELIMITER_HPP
