#ifndef _FASTQUEUE_CQUEUE
#define _FASTQUEUE_CQUEUE

#include <cstddef>
#include <stdexcept>

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

/**
 * @brief A thread-safe queue that can be used to pass messages between threads.
 *
 * This class is a wrapper of the BlockingConcurrentQueue class from the moodycamel library.
 * It provides a simple interface to use the queue with optimized block size and index settings.
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

public:
    /**
     * @brief Construct a new Concurrent Queue object
     *
     * @param capacity The capacity of the queue. (Approximate)
     * @throw std::runtime_error if the capacity is less than or equal to 0
     */
    explicit CQueue(int capacity)
        : m_queue(capacity)
        , m_minCapacity(capacity)
    {
        if (capacity <= 0)
        {
            throw std::runtime_error("The capacity of the queue must be greater than 0");
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
     */
    inline bool waitPop(T& element, int64_t timeout) override { return m_queue.wait_dequeue_timed(element, timeout); }

    /**
     * @copydoc IQueue::tryPop
     */
    inline bool tryPop(T& element) override { return m_queue.try_dequeue(element); }

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
     */
    inline std::size_t tryPopBulk(T* elements, std::size_t max) override
    {
        return m_queue.try_dequeue_bulk(elements, max);
    }
};

} // namespace fastqueue

#endif // _QUEUES_CONCURRENTQUEUE_HPP
