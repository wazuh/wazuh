#ifndef _QUEUE_CONCURRENTQUEUE_HPP
#define _QUEUE_CONCURRENTQUEUE_HPP

#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>

#include <blockingconcurrentqueue.h>

#include <logging/logging.hpp>

namespace base::queue
{

constexpr int64_t WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 1000000; ///< Timeout for the wait_dequeue_timed method

/**
 * @brief Provides a wrapper for the flooding file
 *
 * @warning this is thread safe for the write operation
 */
class FloodingFile
{
private:
    std::ofstream m_file; ///< File stream for the flooding file
    std::string m_error;  ///< Error message if the file is not good
    std::mutex m_mutex;   ///< Mutex for the write operation

public:
    /**
     * @brief Construct a new FloodingFile object
     *
     * The file will be opened in append mode, and the file pointer will be set at the end of the file.
     * @param path (const std::string&) Path to the flooding file
     */
    explicit FloodingFile(const std::string& path)
        : m_file(path, std::ios::out | std::ios::app | std::ios::ate)
        , m_error {}
        , m_mutex {}
    {
        if (!m_file.good())
        {
            m_error = strerror(errno);
        }
    }

    /**
     * @brief Checks if the file is open and ready to write
     *
     * @return std::optional<std::string> containing an error message if the file is not good
     */
    std::optional<std::string> getError() const
    {
        if (m_file.good())
        {
            return std::nullopt;
        }
        else if (m_error.empty())
        {
            return "Unknown error";
        }
        return m_error;
    }

    /**
     * @brief Writes a message to the flooding file
     *
     * @param message (const std::string&) Message to write
     *
     * @return true if the write operation was successful, false otherwise
     */
    bool write(const std::string& message)
    {
        if (m_file.is_open())
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            m_file << message << std::endl;
            return true;
        }
        return false;
    }
};

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
template<typename T>
class ConcurrentQueue
{
private:
    moodycamel::BlockingConcurrentQueue<T> m_queue {}; ///< The queue itself.
    std::shared_ptr<FloodingFile> m_floodingFile;      ///< The flooding file.

public:
    /**
     * @brief Construct a new Concurrent Queue object
     *
     * @param capacity The capacity of the queue. (Approximate)
     * @param pathFloodedFile The path to the file where the queue will be flooded.
     *
     * @note If the pathFloodedFile is not provided, the queue will not be flooded,and the
     * push method will block until there is space in the queue.
     */
    explicit ConcurrentQueue(const std::size_t capacity, const std::string& pathFloodedFile = {})
        : m_queue {moodycamel::BlockingConcurrentQueue<T>(capacity)}
        , m_floodingFile {nullptr}
    {
        // Verify if T has a toString method (for flooding the queue)
        static_assert(std::is_same<decltype(std::declval<T>()->str()), std::string>::value,
                      "T must have a toString method");

        // Verify if the pathFloodedFile is provided
        if (!pathFloodedFile.empty())
        {
            m_floodingFile = std::make_shared<FloodingFile>(pathFloodedFile);
            if (m_floodingFile->getError())
            {
                throw std::runtime_error("Error opening the flooding file: " + m_floodingFile->getError().value());
            }
            else
            {
                WAZUH_LOG_INFO("The queue will be flooded in the file: {}", pathFloodedFile);
            }
        }
        else
        {
            WAZUH_LOG_INFO("No flooding file provided, the queue will not be flooded.");
        }
        // Disable buffering for the flooding file
    }

    /**
     * @brief Pushes a new element to the queue.
     *
     * @param element The element to be pushed, it will be moved.
     * @throw std::runtime_error if the queue is flooded and the file is not good.
     * @note If the pathFloodedFile is not provided, the queue will not be flooded,and the
     * push method will block until there is space in the queue.
     */
    void push(T&& element)
    {
        if (!m_floodingFile)
        {
            while (!m_queue.try_enqueue(std::move(element)))
            {
                // Right now we process 1 event for ~0.1ms, we sleep by a factor
                // of 5 because we are saturating the queue and we don't want to.
                std::this_thread::sleep_for(std::chrono::microseconds(500));
            }
        }
        else
        {
            const std::size_t maxAttempts {3}; // TODO Shoul be a macro with the time in ms?
            for (std::size_t attempts {0}; attempts < maxAttempts; ++attempts)
            {
                if (m_queue.try_enqueue(std::move(element)))
                {
                    return;
                }
                // TODO: Benchmarks to find the best value.... (0.1ms)
                // 3.3K events per second (In the worst case)
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
            m_floodingFile->write(element->str());
        }
    }

    /**
     * @brief Pops an element from the queue.
     *
     * @param element The element to be popped, it will be modified.
     * @param timeout The timeout in microseconds.
     * @return true if the element was popped.
     * @return false if the timeout was reached.
     * @note If the timeout is reached, the element will not be modified.
     * @note If the timeout is not provided, the default timeout will be used.
     * @note If the timeout is 0, the method will return immediately.
     * @note If the timeout is negative, the method will block until an element is popped.
     */
    bool waitPop(T& element, int64_t timeout = WAIT_DEQUEUE_TIMEOUT_USEC)
    {
        return m_queue.wait_dequeue_timed(element, timeout);
    }

    /**
     * @brief Checks if the queue is empty.
     *
     * @note The size is approximate.
     * @return true if the queue is empty.
     * @return false otherwise.
     */
    bool empty() const { return m_queue.size_approx() == 0; }

    /**
     * @brief Gets the size of the queue.
     *
     * @note The size is approximate.
     * @return size_t The size of the queue.
     */
    size_t size() const { return m_queue.size_approx(); }
};
} // namespace base::queue

#endif // _QUEUES_CONCURRENTQUEUE_HPP
