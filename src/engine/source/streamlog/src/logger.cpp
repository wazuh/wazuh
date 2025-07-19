
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

public:
    ChannelWriter(std::shared_ptr<base::queue::ConcurrentQueue<std::string>> queue)
        : m_queue(std::move(queue))
    {
        if (!m_queue)
        {
            throw std::invalid_argument("Queue cannot be null");
        }
    }

    void operator()(std::string&& message) override { m_queue->push(std::move(message)); }
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
        std::ostream::ofstream outputFile;       ///< Output file stream for writing log messages.
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

        bool channelClosedDueToError {false}; ///< Indicate if the channel discarted messages due to an error on files

    } m_stateData; ///< State data for the channel.

    /**
     * @brief Replaces placeholders in a pattern string with corresponding values.
     * @see ChannelHandler::replacePlaceholders for details.
     */
    std::string replacePlaceholders(const std::chrono::system_clock::time_point& timePoint) const;

    /**
     * @brief Rotation check with aggressive caching
     * @see ChannelHandler::needsRotation for details.
     */
    bool needsRotation(size_t messageSize);

    /**
     * @brief Rotates the log file for the current channel based on size or other criteria.
     * @see ChannelHandler::rotateFile for details.
     */
    void rotateFile();

    /**
     * @brief Opens the output file for the current channel and creates or updates a hard link to the latest file.
     * @throws std::runtime_error If the output file cannot be opened or the hard link cannot be created.
     * @see ChannelHandler::updateOutputFileAndLink for details.
     */
    void updateOutputFileAndLink();

    void stopWorkerThread()
    {
        if (m_stateData.workerThread.joinable())
        {
            m_stateData.stopRequested.store(true, std::memory_order_relaxed);
            m_stateData.workerThread.join();
        }
    }

    void startWorkerThread()
    {
        m_stateData.stopRequested.store(false, std::memory_order_relaxed);
        m_stateData.workerThread = std::thread(&ChannelHandler::workerThreadFunc, this);
    }

    void writeMessage(const std::string& message)
    {
        m_stateData.currentSize += message.size() + 1; // +1 for newline character
        m_stateData.outputFile << message << std::endl;
        if (m_stateData.outputFile.fail())
        {
            LOG_ERROR("Failed to write message to output file for channel: {}", m_channelName);
            m_stateData.channelClosedDueToError = true;
            return;
        }
        m_stateData.outputFile.flush();
    }

    /**
     * @brief High-performance worker thread function with minimized lock contention
     * Each channel has its own dedicated worker thread for maximum throughput
     * File is opened once and kept open until rotation or thread termination
     */
    void workerThreadFunc()
    {

        // Main processing loop with minimal lock contention
        std::string message;
        while (true)
        {
            // Fast atomic check without mutex
            if (m_stateData.stopRequested.load(std::memory_order_relaxed))
            {
                break; // Exit if stop requested
                LOG_INFO("Stopping writer thread for channel: {}", m_channelName);
            }

            // Check if we need to rotate the file
            if (m_stateData.queue->waitPop(message, 1000) && !message.empty())
            {
                if (needsRotation(message.size()))
                {
                    rotateFile();
                }
                if (m_stateData.channelClosedDueToError)
                {
                    // Skip writing if channel is closed due to error
                    // In practice, this should not happend
                    continue;
                }
                writeMessage(message);
            }
        }
    }

public:
    ChannelHandler(RotationConfig config, std::string channelName)
        : m_config(std::move(config))
        , m_channelName(std::move(channelName))
        , m_stateData()
    {
        if (m_config.basePath.empty() || !std::filesystem::exists(m_config.basePath)
            || !std::filesystem::is_directory(m_config.basePath))
        {
            throw std::runtime_error("Base path does not exist or is not a directory: " + m_config.basePath.string());
        }
        if (m_config.pattern.empty())
        {
            throw std::runtime_error("Log pattern cannot be empty");
        }
        // Assign default maxSize if not set
        if (m_config.bufferSize == 0)
        {
            m_config.bufferSize = 1 << 20; // Default to 1 MiB events if not specified
        }
        // Ajust the pattern if needed
        if (m_config.maxSize > 0 && m_config.pattern.find("${counter}") == std::string::npos)
        {
            auto lastDot = m_config.pattern.find_last_of('.');
            if (lastDot != std::string::npos)
            {
                m_config.pattern.insert(lastDot, "-${counter}"); // Insert before the file extension
            }
            else
            {
                m_config.pattern += "-${counter}"; // Append counter if no extension
            }

            if (m_config.maxSize < 0x1 << 20)
            {
                m_config.maxSize = 0x1 << 20; // Default to 1 MiB if maxSize is too small
            }
        }

        // Set up the initial files and counters
        m_stateData.latestLink = m_config.basePath / m_channelName ".json";
        m_stateData.currentFile = [&]() -> std::filesystem::path
        {
            const auto now = std::chrono::system_clock::now();
            if (m_config.maxSize > 0)
            {
                auto candidate = m_config.basePath / replacePlaceholders(now);
                while (std::filesystem::exists(candidate))
                {
                    m_stateData.counter++;
                    candidate = m_config.basePath / replacePlaceholders(now);
                }
                if (m_stateData.counter > 0)
                {
                    m_stateData.counter--;
                    candidate = m_config.basePath / replacePlaceholders(now);
                }
                return candidate;
            }
            return m_config.basePath / replacePlaceholders(now);
        }();

        // Initialize Stream flow handling
        m_stateData.queue = std::make_shared<base::queue::ConcurrentQueue<std::string>>(m_config.bufferSize);
    }
};

std::string ChannelHandler::replacePlaceholders(const std::chrono::system_clock::time_point& timePoint) const
{
    const auto time_t = std::chrono::system_clock::to_time_t(timePoint);
    const auto tmPtr = std::localtime(&time_t);
    if (!tmPtr)
    {
        throw std::runtime_error("Error remplacing placeholders: localtime failed");
    }
    const auto& tm = *tmPtr;

    std::string result = m_config.pattern;

    // Replace time placeholders
    result = std::regex_replace(result, std::regex(R"(\$\{YYYY\})"), std::to_string(tm.tm_year + 1900));
    result = std::regex_replace(result, std::regex(R"(\$\{YY\})"), std::to_string((tm.tm_year + 1900) % 100));
    result = std::regex_replace(
        result, std::regex(R"(\$\{MM\})"), (tm.tm_mon + 1 < 10 ? "0" : "") + std::to_string(tm.tm_mon + 1));
    result = std::regex_replace(
        result, std::regex(R"(\$\{DD\})"), (tm.tm_mday < 10 ? "0" : "") + std::to_string(tm.tm_mday));
    result = std::regex_replace(
        result, std::regex(R"(\$\{HH\})"), (tm.tm_hour < 10 ? "0" : "") + std::to_string(tm.tm_hour));
    result =
        std::regex_replace(result, std::regex(R"(\$\{mm\})"), (tm.tm_min < 10 ? "0" : "") + std::to_string(tm.tm_min));
    result =
        std::regex_replace(result, std::regex(R"(\$\{ss\})"), (tm.tm_sec < 10 ? "0" : "") + std::to_string(tm.tm_sec));

    // Replace channel name
    result = std::regex_replace(result, std::regex(R"(\$\{name\})"), m_channelName);

    // Replace counter if maxSize is set
    if (m_config.maxSize > 0)
    {
        result = std::regex_replace(result, std::regex(R"(\$\{counter\})"), std::to_string(m_config.counter));
    }

    return result;
}

/**
 * @brief Determines whether the log channel requires rotation based on size or time.
 *
 * This function checks if the log file needs to be rotated. Rotation is triggered if:
 * - The new log file size (current size plus incoming message size) exceeds the configured maximum size.
 * - The hour boundary has changed since the last rotation, and the log file path pattern (based on time) has
 * changed.
 *
 * @param messageSize The size of the incoming log message to be written.
 * @return true If rotation is required due to size or time pattern change.
 * @return false If no rotation is needed.
 */
bool ChannelHandler::needsRotation(const size_t messageSize)
{
    try
    {
        m_stateData.lastRotationCheck = std::chrono::system_clock::now();
        const auto& now = m_stateData.lastRotationCheck;

        // Fast path: check size first (most common rotation trigger)
        size_t newSize = m_stateData.currentSize + messageSize;
        if (m_config.maxSize >= 0 && newSize >= m_config.maxSize)
        {
            return true;
        }

        // Check if date pattern actually changed by comparing hour boundaries (minimum granularity)
        auto nowHour = std::chrono::duration_cast<std::chrono::hours>(now.time_since_epoch());
        auto lastHour = std::chrono::duration_cast<std::chrono::hours>(m_stateData.lastRotation.time_since_epoch());

        if (nowHour != lastHour)
        {
            // More precise check: only generate paths if hour actually changed
            auto candidatePath = std::filesystem::path(replacePlaceholders(now));
            return (m_stateData.currentFile != candidatePath);
        }
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Error checking rotation for channel '{}': {}", m_channelName, e.what());
        m_stateData.channelClosedDueToError = true;
    }

    return false;
}

/**
 * @brief Rotates the log file for the current channel based on size or other criteria.
 *
 * This function handles log file rotation by generating a new file path according to the configured pattern,
 * updating counters for size-based rotation, creating necessary directories, and managing file handles.
 * It also updates the symbolic or hard link to the latest log file and resets internal state data.
 *
 * Rotation is triggered when the current file size exceeds the configured maximum size.
 * The function ensures that the new log file is opened for writing and logs any errors encountered during
 * directory creation, file opening, or link updates.
 *
 * @note The function assumes that m_config, m_stateData, and m_channelName are properly initialized.
 *       Error handling is performed via logging, but some TODOs remain for more robust error management.
 */
void ChannelHandler::rotateFile()
{
    const auto& now = m_stateData.lastRotationCheck;

    // Set the counter based on size rotation
    m_stateData.counter = [&]() -> size_t
    {
        if (m_config.maxSize > 0 && m_stateData.currentSize >= m_config.maxSize)
        {
            return m_stateData.counter + 1;
        }
        return 0; // Reset counter if not rotating by size
    }();

    // Try update the file path with the current time and counter
    try
    {
        auto newFilePath = m_config.basePath / replacePlaceholders(now);
        // Only create directories if path changed and they don't exist
        auto newParentPath = newFilePath.parent_path();
        if (newParentPath != m_stateData.currentFile.parent_path() && !std::filesystem::exists(newParentPath))
        {
            std::error_code ec;
            std::filesystem::create_directories(newParentPath, ec);
            if (ec)
            {
                LOG_WARNING("Failed to create directories for {}: {}", newParentPath.string(), ec.message());
            }
        }
        m_stateData.currentFile = newFilePath;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to generate new file path for channel '{}': {}", m_channelName, e.what());
        m_stateData.channelClosedDueToError = true;
        return;
    }
    m_stateData.currentSize = 0;
    m_stateData.lastRotation = now;

    // Rotate the file by closing the current output file and opening a new one
    try
    {
        updateOutputFileAndLink();
    }
    catch (const std::runtime_error& e)
    {
        LOG_ERROR("Failed to rotate file for channel '{}': {}. Closing channel and discarding messages.",
                  m_channelName,
                  e.what());
        m_stateData.channelClosedDueToError = true;
        return;
    }

    LOG_INFO("Rotated the channel '{}' to new file: {}", m_channelName, m_stateData.currentFile.string());
}

/**
 * @brief Opens the output file for the current channel and creates or updates a hard link to the latest file.
 *
 * This function checks if the output file is already open for the channel and closes it if necessary.
 * It then attempts to open the output file in append mode. If the file cannot be opened, an exception is thrown.
 * After successfully opening the file, the function creates or updates a hard link pointing to the current file.
 * If the hard link cannot be created, the output file is closed and an exception is thrown.
 * Debug and error messages are logged throughout the process.
 *
 * @throws std::runtime_error If the output file cannot be opened or the hard link cannot be created.
 */
void ChannelHandler::updateOutputFileAndLink()
{
    if (m_stateData.outputFile.is_open())
    {
        m_stateData.outputFile.flush();
        m_stateData.outputFile.close();
    }

    m_stateData.outputFile.open(m_stateData.currentFile, std::ios::out | std::ios::app);
    if (!m_stateData.outputFile.is_open())
    {
        throw std::runtime_error("Failed to open output file for channel: " + m_channelName + " at "
                                 + m_stateData.currentFile.string());
    }

    // Create or update the latest link to the current file
    std::error_code ec;
    std::filesystem::create_hard_link(m_stateData.currentFile, m_stateData.latestLink, ec);
    if (ec)
    {
        m_stateData.outputFile.close();
        throw std::runtime_error("Failed to create hard link for latest file: " + m_stateData.latestLink.string() + ": "
                                 + ec.message());
    }
    LOG_DEBUG("Opened output file for channel: {} at {}", m_channelName, m_stateData.currentFile.string());
}

} // namespace streamlog
