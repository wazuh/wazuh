#include "channel.hpp"

#include <base/process.hpp>

namespace streamlog
{

/**
 * @brief Replaces placeholders in the log pattern with actual values based on the provided time point and channel
 * configuration.
 *
 * This function processes the pattern string defined in the channel configuration (`m_config.pattern`)
 * and replaces the following placeholders with their corresponding values:
 * - `${YYYY}`: 4-digit year (e.g., 2024)
 * - `${YY}`: 2-digit year (e.g., 24)
 * - `${MM}`: 2-digit month (01-12)
 * - `${DD}`: 2-digit day of the month (01-31)
 * - `${HH}`: 2-digit hour (00-23)
 * - `${name}`: Channel name (`m_channelName`)
 * - `${counter}`: Counter value (`m_config.counter`), only if `m_config.maxSize > 0`
 *
 * @param timePoint The time point to use for formatting date and time placeholders.
 * @return A string with all placeholders replaced by their corresponding values.
 * @throws std::runtime_error If conversion of timePoint to local time fails.
 */
std::string ChannelHandler::replacePlaceholders(const std::chrono::system_clock::time_point& timePoint) const
{
    const auto time_t = std::chrono::system_clock::to_time_t(timePoint);
    const auto tmPtr = std::localtime(&time_t);
    if (!tmPtr)
    {
        throw std::runtime_error("Error remplacing placeholders: localtime failed");
    }
    const auto& tm = *tmPtr;

    auto result = m_config.pattern;

    // Replace time placeholders
    result = std::regex_replace(result, std::regex(R"(\$\{YYYY\})"), std::to_string(tm.tm_year + 1900));
    result = std::regex_replace(result, std::regex(R"(\$\{YY\})"), std::to_string((tm.tm_year + 1900) % 100));
    result = std::regex_replace(
        result, std::regex(R"(\$\{MM\})"), (tm.tm_mon + 1 < 10 ? "0" : "") + std::to_string(tm.tm_mon + 1));
    result = std::regex_replace(
        result, std::regex(R"(\$\{DD\})"), (tm.tm_mday < 10 ? "0" : "") + std::to_string(tm.tm_mday));
    result = std::regex_replace(
        result, std::regex(R"(\$\{HH\})"), (tm.tm_hour < 10 ? "0" : "") + std::to_string(tm.tm_hour));

    // Replace channel name
    result = std::regex_replace(result, std::regex(R"(\$\{name\})"), m_channelName);

    // Replace counter if maxSize is set
    if (m_config.maxSize > 0)
    {
        result = std::regex_replace(result, std::regex(R"(\$\{counter\})"), std::to_string(m_stateData.counter));
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

        // Fast path: check size first
        const size_t newSize = m_stateData.currentSize + messageSize;
        if (m_config.maxSize >= 0 && newSize >= m_config.maxSize)
        {
            return true;
        }

        // Check if date pattern actually changed by comparing hour boundaries
        const auto nowHour = std::chrono::duration_cast<std::chrono::hours>(now.time_since_epoch());
        const auto lastHour =
            std::chrono::duration_cast<std::chrono::hours>(m_stateData.lastRotation.time_since_epoch());

        if (nowHour != lastHour)
        {
            auto candidatePath = std::filesystem::path(replacePlaceholders(now));
            return (m_stateData.currentFile != candidatePath);
        }
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Error checking rotation for channel '{}': {}", m_channelName, e.what());
        m_stateData.channelState->store(ChannelState::ErrorClosed, std::memory_order_relaxed);
    }

    return false;
}

/**
 * @brief Rotates the log file for the current channel based on size or date criteria.
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
        m_stateData.channelState->store(ChannelState::ErrorClosed, std::memory_order_relaxed);
        return;
    }
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
        m_stateData.channelState->store(ChannelState::ErrorClosed, std::memory_order_relaxed);
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

    // Open the output file in append mode, if not existing, it will be created
    m_stateData.outputFile.clear();
    m_stateData.outputFile.open(m_stateData.currentFile, std::ios::out | std::ios::app);

    // Check if any error occurred while opening the file
    if (!m_stateData.outputFile.is_open() || m_stateData.outputFile.fail())
    {
        throw std::runtime_error(fmt::format("Failed to open output file for channel '{}' ({}) due to: {}",
                                             m_channelName,
                                             m_stateData.currentFile.string(),
                                             std::strerror(errno)));
    }
    m_stateData.currentSize = std::filesystem::file_size(m_stateData.currentFile);

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

/**
 * @brief Worker thread function for processing log messages in a channel.
 *
 * This function runs in a dedicated thread and continuously processes messages from the channel's queue.
 * It performs the following tasks in a loop:
 *   - Checks if a stop has been requested and exits if so.
 *   - Waits for new messages to arrive in the queue with a timeout.
 *   - Checks if log file rotation is needed based on the incoming message size and rotates the file if necessary.
 *   - Skips writing messages if the channel has been closed due to an error, and requests the thread to stop.
 *   - Writes valid messages to the log file.
 *
 */
void ChannelHandler::workerThreadFunc()
{

    LOG_DEBUG("Starting writer thread for channel: {}", m_channelName);

    base::process::setThreadName("ChannelWriter-" + m_channelName);

    std::string message;
    while (m_stateData.channelState->load(std::memory_order_relaxed) == ChannelState::Running)
    {
        // Check if we need to rotate the file
        if (m_stateData.queue->waitPop(message, 1000) && !message.empty())
        {
            if (needsRotation(message.size()))
            {
                rotateFile();
            }
            if (m_stateData.channelState->load(std::memory_order_relaxed) != ChannelState::Running)
            {
                // Skip writing if channel is closed due to error
                break;
            }
            writeMessage(message);
        }
    }

    LOG_INFO("Stopping writer thread for channel: {}", m_channelName);
}

void ChannelHandler::stopWorkerThread()
{
    if (m_stateData.workerThread.joinable())
    {
        // Request the worker thread to stop
        m_stateData.channelState->store(ChannelState::StopRequested, std::memory_order_relaxed);
        m_stateData.workerThread.join();

        // Reset the state back to Running for potential future use
        m_stateData.channelState->store(ChannelState::Running, std::memory_order_relaxed);

        // Discard any pending messages in the queue
        std::string discardedMessage;
        size_t discardedCount = 0;
        while (m_stateData.queue->tryPop(discardedMessage))
        {
            discardedCount++;
        }

        if (discardedCount > 0)
        {
            LOG_WARNING("Discarded {} pending messages for channel: {}", discardedCount, m_channelName);
        }

        LOG_DEBUG("Worker thread stopped for channel: {}", m_channelName);
    }
}

void ChannelHandler::startWorkerThread()
{
    m_stateData.channelState->store(ChannelState::Running, std::memory_order_relaxed);
    m_stateData.workerThread = std::thread(&ChannelHandler::workerThreadFunc, this);
}

/**
 * @brief Writes a message to the output file associated with the channel.
 *
 * This function appends the given message, followed by a newline character, to the output file.
 * It updates the current size of the written data accordingly. If writing to the file fails,
 * an error is logged, the channel is marked as closed due to error, and the function returns early.
 * After writing, the output file is flushed to ensure data is written to disk.
 *
 * @param message The message string to be written to the output file.
 */
void ChannelHandler::writeMessage(const std::string& message)
{
    m_stateData.currentSize += message.size() + 1; // +1 for newline character
    m_stateData.outputFile << message << "\n";
    if (m_stateData.outputFile.fail())
    {
        LOG_ERROR("Failed to write message to output file for channel: {}", m_channelName);
        m_stateData.channelState->store(ChannelState::ErrorClosed, std::memory_order_relaxed);
        return;
    }
    m_stateData.outputFile.flush();
}

ChannelHandler::ChannelHandler(RotationConfig config, std::string channelName)
    : m_config(std::move(config))
    , m_channelName(std::move(channelName))
    , m_stateData()
{
    // Validate the configuration
    if (m_channelName.empty())
    {
        throw std::runtime_error("Channel name cannot be empty");
    }

    // Ensure the base path is absolute, exist and is a dir
    if (!m_config.basePath.is_absolute() || m_config.basePath.empty())
    {
        throw std::runtime_error("Base path must be an absolute path");
    }
    if (!std::filesystem::exists(m_config.basePath) || !std::filesystem::is_directory(m_config.basePath))
    {
        throw std::runtime_error("Base path must exist and be a directory: " + m_config.basePath.string());
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
        // Add the counter placeholder to the pattern if maxSize is set and counter is not already present
        auto lastDot = m_config.pattern.find_last_of('.');
        if (lastDot != std::string::npos)
        {
            m_config.pattern.insert(lastDot, "-${counter}");
        }
        else
        {
            m_config.pattern += "-${counter}";
        }

        if (m_config.maxSize < 0x1 << 20)
        {
            // Default to 1 MiB if maxSize is too small
            m_config.maxSize = 0x1 << 20;
        }
    }

    // Initial state data: File paths
    m_stateData.latestLink = m_config.basePath / (m_channelName + ".json");
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
    m_stateData.queue = std::make_shared<base::queue::ConcurrentQueue<std::string>>(m_config.bufferSize);
    m_stateData.lastRotation = std::chrono::system_clock::now();
    m_stateData.lastRotationCheck = m_stateData.lastRotation;

    // Check if need to create the directories
    auto parentPath = m_stateData.currentFile.parent_path();
    if (!std::filesystem::exists(parentPath))
    {
        std::error_code ec;
        std::filesystem::create_directories(parentPath, ec);
        if (ec)
        {
            throw std::runtime_error("Failed to create directories for " + parentPath.string() + ": " + ec.message());
        }
    }

    // Open the output file and create the latest link
    try
    {
        updateOutputFileAndLink();
    }
    catch (const std::runtime_error& e)
    {
        throw std::runtime_error("Failed to initialize channel '" + m_channelName + "': " + e.what());
    }

    LOG_DEBUG("ChannelHandler '{}' initialized. Worker thread will start on first writer creation.", m_channelName);
}

/**
 * @brief Factory method to create a ChannelHandler as a shared_ptr
 */
std::shared_ptr<ChannelHandler> ChannelHandler::create(RotationConfig config, std::string channelName)
{
    return std::shared_ptr<ChannelHandler>(new ChannelHandler(std::move(config), std::move(channelName)));
}

/**
 * @brief Destructor - ensures worker thread is properly stopped
 */
ChannelHandler::~ChannelHandler()
{
    LOG_DEBUG("Destroying ChannelHandler for channel: {}", m_channelName);

    if (m_stateData.workerThread.joinable())
    {
        LOG_WARNING("ChannelHandler '{}' being destroyed with active worker thread. Forcing stop.", m_channelName);
        stopWorkerThread();
    }

    if (m_stateData.outputFile.is_open())
    {
        m_stateData.outputFile.flush();
        m_stateData.outputFile.close();
    }

    LOG_DEBUG("ChannelHandler '{}' destroyed", m_channelName);
}

/**
 * @brief Creates a new ChannelWriter instance for the channel.
 *
 * This method is thread-safe and ensures that the worker thread is started if this is the first writer.
 *
 * @return A shared pointer to the newly created ChannelWriter.
 */
std::shared_ptr<ChannelWriter> ChannelHandler::createWriter()
{
    std::lock_guard<std::mutex> lock(m_writersMutex);

    const auto currentState = m_stateData.channelState->load(std::memory_order_relaxed);
    if (currentState == ChannelState::ErrorClosed)
    {
        throw std::runtime_error("Cannot create writer for channel '" + m_channelName
                                 + "' - channel is in error state");
    }

    // Check if we need to start the worker thread (first writer)
    if (m_activeWriters.load(std::memory_order_relaxed) == 0)
    {
        LOG_DEBUG("Starting worker thread for channel '{}' - first writer created", m_channelName);
        startWorkerThread();
    }

    // Increment the active writers count
    m_activeWriters.fetch_add(1, std::memory_order_relaxed);

    auto writer = std::make_shared<ChannelWriter>(m_stateData.queue, m_stateData.channelState, weak_from_this());

    LOG_DEBUG("Created ChannelWriter for channel '{}'. Active writers: {}",
              m_channelName,
              m_activeWriters.load(std::memory_order_relaxed));

    return writer;
}

/**
 * @brief Called when a ChannelWriter is destroyed.
 *
 * This method updates the active writers count and stops the worker thread if there are no more active writers.
 */
void ChannelHandler::onWriterDestroyed()
{
    std::lock_guard<std::mutex> lock(m_writersMutex);

    size_t currentWriters = m_activeWriters.fetch_sub(1, std::memory_order_relaxed) - 1;

    LOG_DEBUG("ChannelWriter destroyed for channel '{}'. Active writers: {}", m_channelName, currentWriters);

    // If this was the last writer, stop the worker thread
    if (currentWriters == 0)
    {
        LOG_DEBUG("Stopping worker thread for channel '{}' - no more active writers", m_channelName);
        stopWorkerThread();
    }
}

// Implementation of ChannelWriter destructor
ChannelWriter::~ChannelWriter()
{
    if (auto handler = m_channelHandler.lock())
    {
        handler->onWriterDestroyed();
    }
}

} // namespace streamlog
