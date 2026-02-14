#ifndef _FASTQUEUE_CQUEUE
#define _FASTQUEUE_CQUEUE

#include <cassert>
#include <cstddef>
#include <memory>
#include <stdexcept>

#include <blockingconcurrentqueue.h>

#include <fastqueue/iqueue.hpp>

namespace
{
struct WQueueTraits : public moodycamel::ConcurrentQueueDefaultTraits
{
    static constexpr size_t BLOCK_SIZE = 2048;
    static constexpr size_t IMPLICIT_INITIAL_INDEX_SIZE = 8192;
};
} // namespace

namespace fastqueue
{

constexpr int64_t WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 100000; ///< Timeout for the wait_dequeue_timed method

/**
 * @brief A thread-safe queue that can be used to pass messages between threads.
 *
 * This class is a wrapper of the BlockingConcurrentQueue class from the moodycamel library.
 * It provides a simple interface to use the queue.
 * It also provides a way to flood the queue when it is full.
 * The queue will be flooded when the push method is called and the queue is full
 * and the pathFloodedFile is provided.
 * @tparam T The type of the data to be stored in the queue.
 */
template<typename T, typename D = moodycamel::ConcurrentQueueDefaultTraits>
class CQueue : public IQueue<T>
{
private:
    static_assert(std::is_base_of_v<moodycamel::ConcurrentQueueDefaultTraits, D>,
                  "The template parameter D must be a subclass of ConcurrentQueueDefaultTraits");

    moodycamel::BlockingConcurrentQueue<T, D> m_queue {}; ///< The queue itself.
    std::size_t m_minCapacity;                            ///< The minimum capacity of the queue.
    bool m_discard; ///< If true, the queue will discard the events when it is full instead of flooding the file or
                    ///< blocking.

public:
    /**
     * @brief Construct a new Concurrent Queue object
     *
     * @param capacity The capacity of the queue. (Approximate)
     * @throw std::runtime_error if the capacity is less than or equal to 0
     */
    explicit CQueue(int capacity, bool discard = false)
        : m_queue()
        , m_minCapacity(capacity)
        , m_discard(discard)
    {
        if (capacity <= 0)
        {
            throw std::runtime_error("The capacity of the queue must be greater than 0");
        }
        m_minCapacity = capacity;

        m_queue = moodycamel::BlockingConcurrentQueue<T, D>(capacity);
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
    * / inline bool waitPop(T& element, int64_t timeout) override
    {
        return m_queue.wait_dequeue_timed(element, timeout);
    }

    /**
     * @brief Tries to pop an element from the queue.
     *
     * @param element The element to be popped, it will be modified.
     * @return true if the element was popped.
     * @return false if the queue is empty.
     * @note If the queue is empty, the element will not be modified.
     */
    inline bool tryPop(T& element) override { return m_queue.try_dequeue(element); }

    /**
     * @copydoc IQueue::empty
     * @note The size is approximate.
     */
    inline bool empty() const override { return m_queue.size_approx() == 0; }

    /**
     * @copydoc IQueue::size
     * @note The size is approximate.
     */
    inline size_t size() const override { return m_queue.size_approx(); }

    /**
     * @copydoc IQueue::aproxFreeSlots
     * @note The free slots is approximate.
     * @note The free slots is calculated as the minimum capacity minus the approximate size of the queue.
     */
    inline size_t aproxFreeSlots() const override { return m_minCapacity - m_queue.size_approx(); }
};

} // namespace fastqueue

#endif // _QUEUES_CONCURRENTQUEUE_HPP
