#ifndef _FASTQUEUE_IQUEUE_HPP
#define _FASTQUEUE_IQUEUE_HPP

#include <cstddef>
#include <cstdint>

namespace fastqueue
{

constexpr int64_t WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 100000; ///< Timeout for the wait_dequeue_timed method
constexpr size_t MIN_QUEUE_CAPACITY = 8192; ///< Minimum queue capacity (2x BLOCK_SIZE for optimal performance)

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
     * @brief Push an element into the queue.
     *
     * @param element The element to push into the queue (moved)
     * @return true if the element was pushed successfully, false otherwise.
     * @note Does not allocate additional memory, fails if queue is full.
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
     * @param timeout The maximum time to wait for an element in microseconds (0 for no wait, negative for infinite
     * wait).
     * @return true if an element was popped successfully, false if timeout occurred or queue is empty.
     */
    virtual bool waitPop(T& element, int64_t timeout) = 0;

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
    virtual bool empty() const noexcept = 0;

    /**
     * @brief Get the size of the queue.
     *
     * @return The number of elements in the specified queue.
     */
    virtual std::size_t size() const noexcept = 0;

    /**
     * @brief Get the approximate free aproxFreeSlots of the queue.
     *
     * @return The approximate number of elements that can be pushed into the queue.
     */
    virtual std::size_t aproxFreeSlots() const noexcept = 0;

    /**
     * @brief Try to pop multiple elements from the queue at once (bulk operation).
     *
     * @param elements Pointer to array where elements will be stored.
     * @param max Maximum number of elements to pop.
     * @return The actual number of elements popped.
     * @note This is more efficient than calling tryPop multiple times.
     */
    virtual std::size_t tryPopBulk(T* elements, std::size_t max) = 0;
};

} // namespace fastqueue

#endif // _FASTQUEUE_IQUEUE_HPP
