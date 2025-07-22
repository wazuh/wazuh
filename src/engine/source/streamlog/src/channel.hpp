#ifndef _STREAMLOG_LOGGER_CHANNEL_HPP
#define _STREAMLOG_LOGGER_CHANNEL_HPP


#include <atomic>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <regex>
#include <sstream>
#include <thread>

#include <streamlog/logger.hpp>

#include <base/logging.hpp>
#include <queue/concurrentQueue.hpp>

namespace streamlog
{



/***********************************************************************************************************************
 * @brief Concrete implementation of WriterEvent for log channels
 **********************************************************************************************************************/
class ChannelWriter : public WriterEvent
{
private:
    std::shared_ptr<base::queue::ConcurrentQueue<std::string>> m_queue;
    std::shared_ptr<std::atomic<bool>> m_closedChannel;

public:
    ChannelWriter(std::shared_ptr<base::queue::ConcurrentQueue<std::string>> queue,
                  std::shared_ptr<std::atomic<bool>> channelClosedDueToError)
        : m_queue(std::move(queue))
        , m_closedChannel(std::move(channelClosedDueToError))
    {
        if (!m_queue || !m_closedChannel)
        {
            throw std::invalid_argument("Queue and channelClosedDueToError must not be null");
        }
    }

    void operator()(std::string&& message) override
    {
        if (!m_closedChannel->load(std::memory_order_relaxed))
        {
            m_queue->push(std::move(message));
        }
    }
};

/***********************************************************************************************************************
 * @brief High-performance internal implementation that manages the async processing
 * Each channel gets its own dedicated worker thread for maximum throughput
 * TODO: Move to channel.h/cpp
 **********************************************************************************************************************/
class ChannelHandler
{
private:
    RotationConfig m_config;   ///< The rotation configuration for the log channel.
    std::string m_channelName; ///< The name of the log channel.

    struct AsyncChannelData
    {
        // Stream flow handling
        std::shared_ptr<base::queue::ConcurrentQueue<std::string>> queue; ///< Thread-safe queue for log messages.
        std::ofstream outputFile;                ///< Output file stream for writing log messages.
        std::thread workerThread;                ///< Thread that processes log messages asynchronously.
        std::atomic<bool> stopRequested {false}; ///< Atomic flag to signal the worker thread to stop.

        // File path
        std::filesystem::path currentFile; ///< Current log file being written to.
        std::filesystem::path latestLink;  ///< Path to the latest log file link. (Hard link to currentFile)

        // State and performance optimization
        std::chrono::system_clock::time_point lastRotation;      ///< The last time the log file was rotated.
        std::chrono::system_clock::time_point lastRotationCheck; ///< Timestamp of the last rotation check.
        size_t currentSize {0};                                  ///< Current size of the log file in bytes.
        size_t counter {0}; ///< Counter for the number of rotations (max size rotations).

        /// @brief Flag indicating if the channel is closed due to an error.
        std::shared_ptr<std::atomic<bool>> channelClosedDueToError {std::make_shared<std::atomic<bool>>(false)};

    } m_stateData; ///< State data for the channel.

    /**
     * @brief Replaces placeholders in a pattern string with corresponding values.
     * @see ChannelHandler::replacePlaceholders for details.
     */
    std::string replacePlaceholders(const std::chrono::system_clock::time_point& timePoint) const;

    /**
     * @brief Rotation check
     * @see ChannelHandler::needsRotation for details.
     */
    bool needsRotation(size_t messageSize);

    /**
     * @brief Rotates the log file for the current channel based
     * @see ChannelHandler::rotateFile for details.
     */
    void rotateFile();

    /**
     * @brief Opens the output file for the current channel and creates or updates a hard link to the latest file.
     * @see ChannelHandler::updateOutputFileAndLink for details.
     */
    void updateOutputFileAndLink();

    void stopWorkerThread();
    void startWorkerThread();

    /**
     * @brief Writes a message to the output file associated with the channel.
     * @see ChannelHandler::writeMessage for details.
     */
    void writeMessage(const std::string& message);

    /**
     * @brief Worker thread, each channel has its own dedicated worker thread for maximum throughput
     * @see ChannelHandler::workerThreadFunc for details.
     */
    void workerThreadFunc();

public:
    ChannelHandler(RotationConfig config, std::string channelName);
};


} // namespace streamlog

#endif // _STREAMLOG_LOGGER_CHANNEL_HPP
