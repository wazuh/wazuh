#ifndef _QUEUE_CONCURRENTQUEUE_HPP
#define _QUEUE_CONCURRENTQUEUE_HPP

#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>

#include <concurrentqueue-1.0.4/blockingconcurrentqueue.h>
// TODO: Until the indexer connector is unified with the rest of wazuh-manager
// #include <metrics/imanager.hpp>
#include <queue/iqueue.hpp>

#include <base/logging.hpp>

namespace base::queue
{

constexpr int64_t WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 100000; ///< Timeout for the wait_dequeue_timed method

// Check if T has a str method
template<typename T, typename = std::void_t<>>
struct has_str_method : std::false_type
{
};

template<typename T>
struct has_str_method<T, std::void_t<decltype(std::declval<T>()->str())>> : std::true_type
{
};

template<typename T>
inline constexpr bool has_str_method_v = has_str_method<T>::value;
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
template<typename T, typename D = moodycamel::ConcurrentQueueDefaultTraits>
class ConcurrentQueue : public iQueue<T>
{
private:
    static_assert(std::is_base_of_v<moodycamel::ConcurrentQueueDefaultTraits, D>,
                  "The template parameter D must be a subclass of ConcurrentQueueDefaultTraits");

    // TODO: Until the indexer connector is unified with the rest of wazuh-manager
    // struct Metrics
    // {
    //     std::shared_ptr<metrics::IMetric> m_used;               ///< Counter for the used queue
    //     std::shared_ptr<metrics::IMetric> m_queued;             ///< Counter for the queued events
    //     std::shared_ptr<metrics::IMetric> m_flooded;            ///< Counter for the flooded events
    //     std::shared_ptr<metrics::IMetric> m_consumed;           ///< Counter for the consumed events
    //     std::shared_ptr<metrics::IMetric> m_consumendPerSecond; ///< Counter for the used queue
    // };

    moodycamel::BlockingConcurrentQueue<T, D> m_queue {}; ///< The queue itself.
    std::size_t m_minCapacity;                            ///< The minimum capacity of the queue.
    std::shared_ptr<FloodingFile> m_floodingFile;         ///< The flooding file.
    std::size_t m_maxAttempts;            ///< The maximum number of attempts to push an element to the queue.
    std::chrono::microseconds m_waitTime; ///< The time to wait for the queue to be not full.
    bool m_discard; ///< If true, the queue will discard the events when it is full instead of flooding the file or
                    ///< blocking.

    // Metrics m_metrics; ///< Metrics for the queue

    template<typename U = T>
    std::enable_if_t<has_str_method_v<U>, void> pushWithStr(U&& element)
    {
        if (m_discard)
        {
            for (std::size_t attempts {0}; attempts < m_maxAttempts; ++attempts)
            {
                if (m_queue.try_enqueue(std::move(element)))
                {
                    // m_metrics.m_queued->update(1UL);
                    // m_metrics.m_used->update(1L);
                    return;
                }
                std::this_thread::sleep_for(std::chrono::microseconds(500));
            }
           // m_metrics.m_flooded->update(1UL);
            return;
        }

        if (!m_floodingFile)
        {
            while (!m_queue.try_enqueue(std::move(element))) // TODO Wait whats? Move more than once?
            {
                // Right now we process 1 event for ~0.1ms, we sleep by a factor
                // of 5 because we are saturating the queue and we don't want to.
                std::this_thread::sleep_for(std::chrono::microseconds(500));
            }
            // m_metrics.m_queued->update(1UL);
            // m_metrics.m_used->update(1L);
        }
        else
        {
            for (std::size_t attempts {0}; attempts < m_maxAttempts; ++attempts)
            {
                if (m_queue.try_enqueue(std::move(element))) // TODO Wait whats? Move more than once?
                {
                    // TODO: Until the indexer connector is unified with the rest of wazuh-manager
                    // m_metrics.m_queued->update(1UL);
                    // m_metrics.m_used->update(1L);
                    return;
                }
                std::this_thread::sleep_for(m_waitTime);
            }
            if (element != nullptr)
            {
                m_floodingFile->write(element->str());
            }
            // TODO: Until the indexer connector is unified with the rest of wazuh-manager
            // m_metrics.m_flooded->update(1UL);
        }
    }

    template<typename U = T>
    std::enable_if_t<!has_str_method_v<U>, void> pushWithoutStr(U&& element)
    {
        throw std::logic_error("The type T must have a ->str() method");
    }

public:
    /**
     * @brief Construct a new Concurrent Queue object
     *
     * @param capacity The capacity of the queue. (Approximate)
     * @param metricModuleName The name of the module for the metrics.
     * @param pathFloodedFile The path to the file where the queue will be flooded.
     * @param maxAttempts The maximum number of attempts to push an element to the queue. (ignored if
     * pathFloodedFile is not provided)
     * @param waitTime The time to wait for the queue to be not full. (ignored if pathFloodedFile is not provided)
     *
     * @throw std::runtime_error if the capacity is less than or equal to 0
     * @throw std::runtime_error if the pathFloodedFile is provided and the maxAttempts is less than or equal to 0
     * @throw std::runtime_error if the pathFloodedFile is provided and the waitTime is less than or equal to 0
     * @note If the pathFloodedFile is not provided, the queue will not be flooded,and the
     * push method will block until there is space in the queue.
     */
    explicit ConcurrentQueue(const int capacity,
                             const std::string& metricModuleName,
                             const std::string& pathFloodedFile = {},
                             const int maxAttempts = 3,
                             const int waitTime = -1,
                             const bool discard = false)
        : m_floodingFile {nullptr}
        , m_discard {discard}
    {
        if (capacity <= 0)
        {
            throw std::runtime_error("The capacity of the queue must be greater than 0");
        }
        m_minCapacity = capacity;

        if (maxAttempts <= 0)
        {
            throw std::runtime_error("The maximum number of attempts must be greater than 0");
        }
        m_maxAttempts = maxAttempts;
        m_queue = moodycamel::BlockingConcurrentQueue<T, D>(capacity);

        // Verify if the pathFloodedFile is provided
        if (!pathFloodedFile.empty())
        {
            if (waitTime <= 0)
            {
                throw std::runtime_error("The wait time must be greater than 0");
            }

            m_waitTime = std::chrono::microseconds(waitTime);

            m_floodingFile = std::make_shared<FloodingFile>(pathFloodedFile);
            if (m_floodingFile->getError())
            {
                throw std::runtime_error("Error opening the flooding file: " + m_floodingFile->getError().value());
            }
            else
            {
                LOG_INFO("The queue will be flooded in the file: {}", pathFloodedFile);
            }
        }
        else
        {
            LOG_INFO("No flooding file provided, the queue will not be flooded.");
        }

        /*
        m_metrics = Metrics {};
        m_metrics.m_queued = metrics::getManager().addMetric(metrics::MetricType::UINTCOUNTER,
                                                             metricModuleName + ".QueuedEvents",
                                                             "Number of events queued in the queue",
                                                             "events");
        m_metrics.m_used = metrics::getManager().addMetric(metrics::MetricType::INTUPDOWNCOUNTER,
                                                           metricModuleName + ".UsedQueue",
                                                           "Number of used slots in the queue",
                                                           "slots");
        m_metrics.m_consumed = metrics::getManager().addMetric(metrics::MetricType::UINTCOUNTER,
                                                               metricModuleName + ".ConsumedEvents",
                                                               "Number of consumed events from the queue",
                                                               "events");
        m_metrics.m_flooded = metrics::getManager().addMetric(metrics::MetricType::UINTCOUNTER,
                                                              metricModuleName + ".FloodedEvents",
                                                              "Number of flooded events from the queue",
                                                              "events");
        */
        // TODO: Add rate metric once implemented
        // m_metrics.m_metricsScopeDelta = std::move(metricsScopeDelta);
        // m_metrics.m_consumendPerSecond =
        // m_metrics.m_metricsScopeDelta->getCounterUInteger("ConsumedEventsPerSecond");
    }

    void push(T&& element) override
    {
        if constexpr (has_str_method_v<T>)
        {
            pushWithStr(std::move(element));
        }
        else
        {
            pushWithoutStr(std::move(element));
        }
    }

    /**
     * @brief Pushes a new element to the queue.
     *
     * @param element The element to be pushed, it will be moved.
     * @throw std::runtime_error if the queue is flooded and the file is not good.
     * @note If the pathFloodedFile is not provided, the queue will not be flooded,and the
     * push method will block until there is space in the queue.
     */

    /**
     * @brief Tries to push an element to the queue.
     *
     * @param element The element to be pushed, it will be copied.
     * @return true if the element was pushed.
     * @return false if the queue is full.
     */
    bool tryPush(const T& element) override
    {
        auto result = m_queue.try_enqueue(element);
        // TODO: Until the indexer connector is unified with the rest of wazuh-manager
        // if (result)
        // {
        //     m_metrics.m_queued->update(1UL);
        //     m_metrics.m_used->update(1L);
        // }
        return result;
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
    bool waitPop(T& element, int64_t timeout = WAIT_DEQUEUE_TIMEOUT_USEC) override
    {
        auto result = m_queue.wait_dequeue_timed(element, timeout);
        // TODO: Until the indexer connector is unified with the rest of wazuh-manager
        // if (result)
        // {
        //     m_metrics.m_consumed->update(1UL);
        //     m_metrics.m_used->update(-1L);
        //     // m_metrics.m_consumendPerSecond->update(1UL);
        // }

        return result;
    }

    bool tryPop(T& element) override
    {
        auto result = m_queue.try_dequeue(element);
        // TODO: Until the indexer connector is unified with the rest of wazuh-manager
        // if (result)
        // {
        //     m_metrics.m_consumed->update(1UL);
        //     m_metrics.m_used->update(-1L);
        //     // m_metrics.m_consumendPerSecond->update(1UL);
        // }
        return result;
    }

    /**
     * @brief Checks if the queue is empty.
     *
     * @note The size is approximate.
     * @return true if the queue is empty.
     * @return false otherwise.
     */
    bool empty() const override { return m_queue.size_approx() == 0; }
    /**
     * @brief Gets the size of the queue.
     *
     * @note The size is approximate.
     * @return size_t The size of the queue.
     */
    inline size_t size() const override { return m_queue.size_approx(); }

    /**
     * @brief Gets the approximate free capacity of the queue.
     *
     * @return size_t The approximate number of elements that can be pushed into the queue.
     */
    inline size_t aproxFreeSlots() const override { return m_minCapacity - m_queue.size_approx(); }
};

} // namespace base::queue

#endif // _QUEUES_CONCURRENTQUEUE_HPP
