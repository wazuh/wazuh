#ifndef _FASTQUEUE_IQUEUE_HPP
#define _FASTQUEUE_IQUEUE_HPP

#include <cstddef>

namespace fastqueue
{

/**
 * @brief An interface for a fast concurrent queue
 *
 * This interface defines the common operations for a concurrent queue.
 * Implementations should provide methods for pushing, waiting for a pop operation,
 *
 * @tparam T The type of elements to be stored in the queue.
 * @note The methods of this interface are thread-safe and can be called from multiple threads concurrently.
 */
template<typename T>
class IQueue
{
public:
    /**
     * @brief Destructor for the interface.
     */
    virtual ~IQueue() = default;

    /**
     * @brief Push an element into the queue if fails to push, flush element to file.
     *
     * @param element The element to push into the queue
     */
    virtual bool push(T&& element) = 0;

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
     * @param timeout The maximum time to wait for an element (in milliseconds, 0 for no wait, negative for infinite
     * wait).
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
     * @return true if the specified queue is empty, false otherwise.
     */
    virtual bool empty() const = 0;

    /**
     * @brief Get the size of the queue.
     *
     * @return The number of elements in the specified queue.
     */
    virtual std::size_t size() const = 0;

    /**
     * @brief Get the approximate free aproxFreeSlots of the queue.
     *
     * @return The approximate number of elements that can be pushed into the queue.
     */
    virtual std::size_t aproxFreeSlots() const = 0;
};

} // namespace fastqueue

#endif // _FASTQUEUE_IQUEUE_HPP
