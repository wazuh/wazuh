#ifndef _QUEUE_IQUEUE_HPP
#define _QUEUE_IQUEUE_HPP

namespace base::queue
{

/**
 * @brief An interface for a blocking concurrent queue
 *
 * This interface defines the common operations for a blocking concurrent queue.
 * Implementations should provide methods for pushing, waiting for a pop operation,
 *
 * @tparam T The type of elements to be stored in the queue.
 */
template<typename T>
class iQueue
{
public:
    /**
     * @brief Destructor for the interface.
     */
    virtual ~iQueue() = default;

    /**
     * @brief Push an element into the queue if fails to push, flush element to file.
     *
     * @param element The element to push into the queue
     */
    virtual void push(T&& element) = 0;

    /**
     * @brief Try to push an element into the queue
     *
     * @param element
     * @return true if the element was pushed successfully, false otherwise.
     */
    virtual bool tryPush(const T& element) = 0;

    /**
     * @brief Wait for and pop an element from the queue.
     *
     * @param element A reference to store the popped element.
     * @param timeout (Optional) The maximum time to wait for an element (in milliseconds).
     */
    virtual bool waitPop(T& element, int64_t timeout = 0) = 0;

    /**
     * @brief Try to pop an element from the queue.
     *
     * @param element A reference to store the popped element.
     * @return true if an element was popped successfully, false otherwise.
     */
    virtual bool tryPop(T& element) = 0;

    /**
     * @brief Check if the queue is empty.
     *
     * @param priority (Optional) Set to true to check the emptiness of the high-priority queue,
     * or false to check the low-priority queue.
     * @return true if the specified queue is empty, false otherwise.
     */
    virtual bool empty() const = 0;

    /**
     * @brief Get the size of the queue.
     *
     * @param priority (Optional) Set to true to get the size of the high-priority queue,
     * or false to get the size of the low-priority queue.
     * @return The number of elements in the specified queue.
     */
    virtual size_t size() const = 0;

    /**
     * @brief Get the approximate free aproxFreeSlots of the queue.
     *
     * @return The approximate number of elements that can be pushed into the queue.
     */
    virtual size_t aproxFreeSlots() const = 0;
};

} // namespace base::queue

#endif // _QUEUE_IQUEUE_HPP
