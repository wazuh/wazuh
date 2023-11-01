#ifndef _BLOCKING_CONCURRENT_IQUEUE_HPP
#define _BLOCKING_CONCURRENT_IQUEUE_HPP

namespace base::queue
{

/**
 * @brief An interface for a blocking concurrent queue with priority support.
 *
 * This interface defines the common operations for a blocking concurrent queue.
 * Implementations should provide methods for pushing, waiting for a pop operation,
 * checking if the queue is empty, and getting the size of the queue. The "priority"
 * parameter can be used to specify whether the element should be treated as high priority (true)
 * or low priority (false).
 *
 * @tparam T The type of elements to be stored in the queue.
 */
template <typename T>
class iBlockingConcurrentQueue
{
public:
    /**
     * @brief Destructor for the interface.
     */
    virtual ~iBlockingConcurrentQueue() = default;

    /**
     * @brief Push an element into the queue.
     *
     * @param element The element to push into the queue.
     * @param priority (Optional) Set to true for high-priority elements, false for low-priority.
     */
    virtual void push(T&& element, bool priority = false) = 0;

    /**
     * @brief Wait for and pop an element from the queue.
     *
     * @param element A reference to store the popped element.
     * @param timeout (Optional) The maximum time to wait for an element (in milliseconds).
     */
    virtual bool waitPop(T& element, int64_t timeout = 0) = 0;

    /**
     * @brief Check if the queue is empty.
     *
     * @param priority (Optional) Set to true to check the emptiness of the high-priority queue,
     * or false to check the low-priority queue.
     * @return true if the specified queue is empty, false otherwise.
     */
    virtual bool empty(bool priority = false) const = 0;

    /**
     * @brief Get the size of the queue.
     *
     * @param priority (Optional) Set to true to get the size of the high-priority queue,
     * or false to get the size of the low-priority queue.
     * @return The number of elements in the specified queue.
     */
    virtual size_t size(bool priority = false) const = 0;
};
}

#endif // _BLOCKING_CONCURRENT_IQUEUE_HPP
