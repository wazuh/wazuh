#ifndef _STREAMLOG_LOGGER_CHANNEL_HPP
#define _STREAMLOG_LOGGER_CHANNEL_HPP

#include <atomic>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <memory>
#include <mutex>
#include <regex>
#include <sstream>
#include <thread>

#include <streamlog/logger.hpp>

#include <base/logging.hpp>
#include <queue/concurrentQueue.hpp>

namespace streamlog
{

enum class ChannelState : int
{
    Running = 0,
    StopRequested = 1,
    ErrorClosed = 2
};

// Forward declaration
class ChannelHandler;

/***********************************************************************************************************************
 * @brief Concrete implementation of WriterEvent for log channels
 **********************************************************************************************************************/
class ChannelWriter : public WriterEvent
{
private:
    std::shared_ptr<base::queue::ConcurrentQueue<std::string>> m_queue;
    std::shared_ptr<std::atomic<ChannelState>> m_channelState;
    std::weak_ptr<ChannelHandler> m_channelHandler; // Weak reference to avoid circular dependency

public:
    ChannelWriter(std::shared_ptr<base::queue::ConcurrentQueue<std::string>> queue,
                  std::shared_ptr<std::atomic<ChannelState>> channelState,
                  std::weak_ptr<ChannelHandler> channelHandler)
        : m_queue(std::move(queue))
        , m_channelState(std::move(channelState))
        , m_channelHandler(std::move(channelHandler))
    {
        if (!m_queue || !m_channelState)
        {
            throw std::invalid_argument("Queue and channelState must not be null");
        }
    }

    // Make ChannelWriter non-copyable to prevent issues with writer counting
    ChannelWriter(const ChannelWriter&) = delete;
    ChannelWriter& operator=(const ChannelWriter&) = delete;

    // Also disable move to keep the design simple and safe
    ChannelWriter(ChannelWriter&&) = delete;
    ChannelWriter& operator=(ChannelWriter&&) = delete;

    // Destructor that notifies when the writer is destroyed
    ~ChannelWriter();

    void operator()(std::string&& message) override
    {
        if (m_channelState->load(std::memory_order_relaxed) == ChannelState::Running)
        {
            m_queue->push(std::move(
                message)); // TODO Handle error and print message for changing the buffer size, maybe trypush con &&
        }
    }
};

/***********************************************************************************************************************
 * @brief High-performance internal implementation that manages the async processing
 * Each channel gets its own dedicated worker thread for maximum throughput
 **********************************************************************************************************************/
class ChannelHandler : public std::enable_shared_from_this<ChannelHandler>
{
private:
    const RotationConfig m_config;           ///< The rotation configuration for the log channel.
    const std::string m_channelName;         ///< The name of the log channel.
    mutable std::mutex m_writersMutex;       ///< Mutex to protect the writers reference count
    std::atomic<size_t> m_activeWriters {0}; ///< Count of active ChannelWriter instances

    struct AsyncChannelData
    {
        // Stream flow handling
        std::shared_ptr<base::queue::ConcurrentQueue<std::string>> queue; ///< Thread-safe queue for log messages.
        std::ofstream outputFile; ///< Output file stream for writing log messages.
        std::thread workerThread; ///< Thread that processes log messages asynchronously.
        std::shared_ptr<std::atomic<ChannelState>> channelState {
            std::make_shared<std::atomic<ChannelState>>(ChannelState::Running)};

        // File path
        std::filesystem::path currentFile; ///< Current log file being written to.
        std::filesystem::path latestLink;  ///< Path to the latest log file link. (Hard link to currentFile)

        // State and performance optimization
        std::chrono::system_clock::time_point lastRotation;      ///< The last time the log file was rotated.
        std::chrono::system_clock::time_point lastRotationCheck; ///< Timestamp of the last rotation check.
        size_t currentSize {0};                                  ///< Current size of the log file in bytes.
        size_t counter {0}; ///< Counter for the number of rotations (max size rotations).

    } m_stateData; ///< State data for the channel.

    /**
     * @brief Replaces placeholders in a pattern string with corresponding values.
     */
    std::string replacePlaceholders(const std::chrono::system_clock::time_point& timePoint) const;

    /**
     * @brief Rotation check
     */
    bool needsRotation(size_t messageSize);

    /**
     * @brief Rotates the log file for the current channel based
     */
    void rotateFile();

    /**
     * @brief Opens the output file for the current channel and creates or updates a hard link to the latest file.
     */
    void updateOutputFileAndLink();

    void stopWorkerThread();
    void startWorkerThread();

    /**
     * @brief Writes a message to the output file associated with the channel.
     */
    void writeMessage(const std::string& message);

    /**
     * @brief Worker thread, each channel has its own dedicated worker thread for maximum throughput
     */
    void workerThreadFunc();

    /**
     * @brief Called when a ChannelWriter is destroyed
     */
    void onWriterDestroyed();

    /**
     * @brief Private constructor - use create() instead
     */
    ChannelHandler(RotationConfig config, std::string channelName);

public:
    /**
     * @brief Validates the channel name according to naming rules
     * @param channelName The channel name to validate
     * @throws std::runtime_error if the name is invalid
     */
    static void validateChannelName(const std::string& channelName);

    /**
     * @brief Validates and normalizes the rotation configuration
     * @param config The configuration to validate and modify
     * @throws std::runtime_error if the configuration is invalid
     */
    static void validateAndNormalizeConfig(RotationConfig& config);

    /**
     * @brief Factory method to create a ChannelHandler as a shared_ptr
     * @param config The rotation configuration for the log channel
     * @param channelName The name of the log channel
     * @return A shared_ptr to the newly created ChannelHandler
     * @throws std::runtime_error if the configuration is invalid or initialization fails
     */
    static std::shared_ptr<ChannelHandler> create(RotationConfig config, std::string channelName);

    /**
     * @brief Creates a new ChannelWriter and starts the worker thread if it's the first writer
     * @return A shared_ptr to a new ChannelWriter instance
     */
    std::shared_ptr<ChannelWriter> createWriter();

    /**
     * @brief Gets the current rotation configuration
     * @return A const reference to the rotation configuration
     */
    const RotationConfig& getConfig() const { return m_config; }

    /**
     * @brief Destructor - ensures worker thread is properly stopped
     */
    ~ChannelHandler();

    // Make the class non-copyable and non-movable for safety
    ChannelHandler(const ChannelHandler&) = delete;
    ChannelHandler& operator=(const ChannelHandler&) = delete;
    ChannelHandler(ChannelHandler&&) = delete;
    ChannelHandler& operator=(ChannelHandler&&) = delete;

    // Allow ChannelWriter to start and stop the worker thread
    friend class ChannelWriter;
};

} // namespace streamlog

#endif // _STREAMLOG_LOGGER_CHANNEL_HPP
