#include "channel.hpp"

#include <zlibHelper.hpp>

#include <base/process.hpp>

namespace streamlog
{

constexpr const char* STORE_POSFIX_PATH_TO_CURRENT = "/last_current"; ///< JSON path to the last current file path
constexpr const char* MONTHS[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
constexpr size_t MONTHS_COUNT = sizeof(MONTHS) / sizeof(MONTHS[0]);

/**
 * @brief Replaces placeholders in the log pattern with actual values based on the provided time point and channel
 * configuration.
 *
 * This function processes the pattern string defined in the channel configuration (`m_config.pattern`)
 * and replaces the following placeholders with their corresponding values:
 * - `${YYYY}`: 4-digit year (e.g., 2024)
 * - `${YY}`: 2-digit year (e.g., 24)
 * - `${MM}`: 2-digit month (01-12)
 * - `${MMM}`: 3-letter month abbreviation (Jan, Feb, etc.)
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

    if (tm.tm_mon >= 0 && static_cast<size_t>(tm.tm_mon) < MONTHS_COUNT)
    {
        result = std::regex_replace(result, std::regex(R"(\$\{MMM\})"), MONTHS[tm.tm_mon]);
    }

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
 * @return `RotationRequirement` indicating whether rotation is needed and what type (size or time).
 */
ChannelHandler::RotationRequirement ChannelHandler::needsRotation(const size_t messageSize) const
{
    try
    {
        m_stateData.lastRotationCheck = std::chrono::system_clock::now();
        const auto& now = m_stateData.lastRotationCheck;

        // Fast path: check size first
        const size_t newSize = m_stateData.currentSize + messageSize;
        if (m_config.maxSize > 0 && newSize >= m_config.maxSize)
        {
            LOG_DEBUG("Channel '{}' needs rotation due to size: {} > {}", m_channelName, newSize, m_config.maxSize);
            return RotationRequirement::Size;
        }

        // Check if date pattern actually changed by comparing hour boundaries
        const auto nowHour = std::chrono::duration_cast<std::chrono::hours>(now.time_since_epoch());
        const auto lastHour =
            std::chrono::duration_cast<std::chrono::hours>(m_stateData.lastRotation.time_since_epoch());

        if (nowHour != lastHour)
        {
            auto candidatePath = std::filesystem::path(replacePlaceholders(now));
            return (m_stateData.currentFile != candidatePath) ? RotationRequirement::Time : RotationRequirement::No;
        }
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Error checking rotation for channel '{}': {}", m_channelName, e.what());
        m_stateData.channelState->store(ChannelState::ErrorClosed, std::memory_order_relaxed);
    }

    return RotationRequirement::No;
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
 * @param rotationType The type of rotation needed (size or time).
 * @throws std::runtime_error If an error occurs during file path generation, file opening, or link creation.
 * @throws std::logic_error If an invalid rotation type is provided.
 * @note The function assumes that m_config, m_stateData, and m_channelName are properly initialized.
 *       Error handling is performed via logging, but some TODOs remain for more robust error management.
 */
void ChannelHandler::rotateFile(RotationRequirement rotationType)
{
    const auto& now = m_stateData.lastRotationCheck;

    // Set the counter based on size rotation
    m_stateData.counter = [&]() -> size_t
    {
        switch (rotationType)
        {
            case RotationRequirement::Size: return m_stateData.counter + 1; // Increment counter for size-based rotation
            case RotationRequirement::Time: return 0;                       // Reset counter for time-based rotation
            default: std::logic_error("Invalid rotation type for counter update"); return 0; // Fallback
        }
    }();

    // Try update the file path with the current time and counter
    const auto previousFile = m_stateData.currentFile;
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

    // Schedule compression of the previous file if needed
    if (previousFile != m_stateData.currentFile && m_config.shouldCompress)
    {
        // Schedule compression of the previous file if needed
        if (auto schedulerPtr = m_scheduler.lock())
        {
            const auto taskName = "CompressLog-" + m_channelName + "-" + previousFile.filename().string();
            auto config = createCompressionTaskConfig(previousFile);
            schedulerPtr->scheduleTask(taskName, std::move(config));
            LOG_DEBUG("Scheduled compression for rotated log file: {}", previousFile.string());
        }
        else
        {
            LOG_WARNING("Scheduler is no longer available; cannot schedule compression for channel '{}'",
                        m_channelName);
        }
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

    // Remove existing hard link if it exists
    if (std::filesystem::exists(m_stateData.latestLink, ec))
    {
        std::filesystem::remove(m_stateData.latestLink, ec);
        if (ec)
        {
            LOG_WARNING("Failed to remove existing hard link {}: {}", m_stateData.latestLink.string(), ec.message());
        }
    }

    // Create new hard link
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
            if (const auto rType = needsRotation(message.size()); rType != RotationRequirement::No)
            {
                rotateFile(rType);
                if (m_config.shouldCompress)
                {
                    // Save the current file path to the store for future compression in next start
                    savePreviousCurrentFilePathFromStore();
                }
            }
            if (m_stateData.channelState->load(std::memory_order_relaxed) != ChannelState::Running)
            {
                // Skip writing if channel is closed due to error
                break;
            }
            writeMessage(message);
        }
    }

    LOG_DEBUG("Stopping writer thread for channel: {}", m_channelName);
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

/**
 * @brief Validates the channel name according to naming rules
 * @param channelName The channel name to validate
 * @throws std::runtime_error if the name is invalid
 */
void ChannelHandler::validateChannelName(const std::string& channelName)
{
    // Validate length
    if (channelName.empty())
    {
        throw std::runtime_error("Channel name cannot be empty");
    }
    else if (channelName.length() > 255)
    {
        throw std::runtime_error("Channel name cannot exceed 255 characters");
    }

    // Only allow alphanumeric characters, underscores, and dashes in channel names
    if (!std::regex_match(channelName, std::regex("^[a-zA-Z0-9_-]+$")))
    {
        throw std::runtime_error("Channel name can only contain alphanumeric characters, underscores, and dashes");
    }
}

/**
 * @brief Validates and normalizes the rotation configuration
 * @param config The configuration to validate and modify
 * @throws std::runtime_error if the configuration is invalid
 */
void ChannelHandler::validateAndNormalizeConfig(RotationConfig& config)
{
    // Validate the base path
    if (!config.basePath.is_absolute() || config.basePath.empty())
    {
        throw std::runtime_error("Base path must be an absolute path");
    }
    if (!std::filesystem::exists(config.basePath) || !std::filesystem::is_directory(config.basePath))
    {
        throw std::runtime_error("Base path must exist and be a directory: " + config.basePath.string());
    }
    // Check if the base path is writable, avoiding check mode_t
    {
        // File test
        auto testPath = config.basePath / ".wazuh_test_write_permission";
        std::ofstream testFile(testPath);
        if (!testFile)
        {
            throw std::runtime_error("Cannot write to base path: " + config.basePath.string() + ": "
                                     + std::strerror(errno));
        }
        testFile.close();
        std::filesystem::remove(testPath);

        // Dir test
        auto testDirPath = config.basePath / ".wazuh_test_dir_permission";
        std::error_code ec;
        std::filesystem::create_directory(testDirPath, ec);
        if (ec)
        {
            throw std::runtime_error("Cannot create directory in base path: " + config.basePath.string() + ": "
                                     + ec.message());
        }
        std::filesystem::remove(testDirPath, ec);
    }

    // Validate compression level
    if (config.shouldCompress && (config.compressionLevel < 1 || config.compressionLevel > 9))
    {
        throw std::runtime_error("Compression level must be between 1 (fastest) and 9 (best)");
    }

    // Validate the pattern
    if (config.pattern.empty())
    {
        throw std::runtime_error("Log pattern cannot be empty");
    }
    else if (config.pattern.size() > 255)
    {
        throw std::runtime_error("Log pattern cannot exceed 255 characters");
    }
    else if (config.pattern.find("../") != std::string::npos)
    {
        throw std::runtime_error("Log pattern cannot contain parent directory references (../): " + config.pattern);
    }

    // Add counter placeholder if maxSize is set and not already present
    if (config.maxSize > 0 && config.pattern.find("${counter}") == std::string::npos)
    {
        auto lastDot = config.pattern.find_last_of('.');
        if (lastDot != std::string::npos)
        {
            config.pattern.insert(lastDot, "-${counter}");
        }
        else
        {
            config.pattern += "-${counter}";
        }
    }

    // Ensure the pattern contains at least one time placeholder or maxSize placeholder if maxSize is set
    if (config.pattern.find("${YYYY}") == std::string::npos && config.pattern.find("${YY}") == std::string::npos
        && config.pattern.find("${MM}") == std::string::npos && config.pattern.find("${DD}") == std::string::npos
        && config.pattern.find("${HH}") == std::string::npos && config.maxSize == 0)
    {
        throw std::runtime_error("Log pattern must contain at least one time placeholder (${YYYY}, ${YY}, ${MM}, "
                                 "${DD}, or ${HH}) or a counter placeholder if maxSize is set");
    }

    // Assign default bufferSize if not set
    if (config.bufferSize == 0)
    {
        config.bufferSize = 0x1 << 20; // Default to 1 MiB events if not specified
    }

    // Adjust maxSize if too small
    if (config.maxSize > 0 && config.maxSize < 0x1 << 20)
    {
        // Default to 1 MiB if maxSize is too small
        config.maxSize = 0x1 << 20;
    }
}

ChannelHandler::ChannelHandler(RotationConfig config,
                               std::string channelName,
                               const std::shared_ptr<store::IStore>& store,
                               std::weak_ptr<scheduler::IScheduler> scheduler,
                               std::string_view ext)
    : m_config(
          [&config]()
          {
              validateAndNormalizeConfig(config);
              return std::move(config);
          }())
    , m_channelName(
          [&channelName]()
          {
              validateChannelName(channelName);
              return std::move(channelName);
          }())
    , m_stateData()
    , m_store(store)
    , m_scheduler(std::move(scheduler))
    , m_fileExtension(ext)
{

    // Initial state data: File paths
    m_stateData.latestLink = m_config.basePath / (m_channelName + "." + m_fileExtension);
    m_stateData.currentFile = [&]() -> std::filesystem::path
    {
        const auto now = std::chrono::system_clock::now();
        if (m_config.maxSize > 0)
        {
            auto candidate = m_config.basePath / replacePlaceholders(now);
            std::optional<std::filesystem::path> compressionCandidate = std::nullopt;

            if (m_config.shouldCompress)
            {
                compressionCandidate = candidate.string() + ".gz";
            }

            // Increment counter until we find a non-existing file, considering compression if enabled
            m_stateData.counter = 0;
            while (std::filesystem::exists(candidate)
                   || (compressionCandidate && std::filesystem::exists(*compressionCandidate)))
            {
                m_stateData.counter++;
                candidate = m_config.basePath / replacePlaceholders(now);
                if (compressionCandidate)
                {
                    compressionCandidate = candidate.string() + ".gz";
                }
            }

            // The candidate cannot be existing here, so we decrement the counter to start from the last existing
            if (m_stateData.counter > 0)
            {
                m_stateData.counter--;
                candidate = m_config.basePath / replacePlaceholders(now);
                if (compressionCandidate)
                {
                    compressionCandidate = candidate.string() + ".gz";
                }
            }

            // Corner case: if the .json|.log does not exist but the .gz does, we increment the counter again,
            // so the new file will not overwrite the compressed one
            // This only happens if an external process deleted the .json but not the .gz
            if (compressionCandidate && std::filesystem::exists(*compressionCandidate))
            {
                m_stateData.counter++;
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

    // Check for previous current file in the store, to schedule compression if needed
    if (m_config.shouldCompress)
    {
        if (auto previousFilePath = getPreviousCurrentFilePathFromStore(); previousFilePath)
        {
            // If the previous current file is different from the current one, schedule compression
            if (*previousFilePath != m_stateData.currentFile)
            {
                if (std::filesystem::exists(*previousFilePath))
                {
                    if (auto schedulerPtr = m_scheduler.lock())
                    {
                        const auto taskName =
                            "CompressLog-" + m_channelName + "-" + previousFilePath->filename().string();
                        auto config = createCompressionTaskConfig(*previousFilePath);
                        schedulerPtr->scheduleTask(taskName, std::move(config));
                        LOG_DEBUG("Scheduled compression for previous log file from store: {}",
                                  previousFilePath->string());
                    }
                    else
                    {
                        LOG_WARNING("Scheduler is no longer available; cannot schedule compression for channel '{}'",
                                    m_channelName);
                    }
                }
                else
                {
                    LOG_DEBUG("Previous current file from store does not exist on disk: {}",
                              previousFilePath->string());
                }
            }
        }
        // Save the current file path to the store
        savePreviousCurrentFilePathFromStore();
    }
    else
    {
        // Clear any previous current file path from the store to avoid compressing old files
        clearPreviousCurrentFilePathFromStore();
    }
}

/**
 * @brief Factory method to create a ChannelHandler as a shared_ptr
 */
std::shared_ptr<ChannelHandler> ChannelHandler::create(RotationConfig config,
                                                       std::string channelName,
                                                       const std::shared_ptr<store::IStore>& store,
                                                       std::weak_ptr<scheduler::IScheduler> scheduler,
                                                       std::string_view ext)
{
    return std::shared_ptr<ChannelHandler>(
        new ChannelHandler(std::move(config), std::move(channelName), store, std::move(scheduler), ext));
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
    std::lock_guard<std::mutex> lock(m_activeWriters.mutex);

    const auto currentState = m_stateData.channelState->load(std::memory_order_relaxed);
    if (currentState == ChannelState::ErrorClosed)
    {
        throw std::runtime_error("Cannot create writer for channel '" + m_channelName
                                 + "' - channel is in error state");
    }

    // Check if we need to start the worker thread (first writer)
    if (m_activeWriters.count == 0)
    {
        LOG_DEBUG("Starting worker thread for channel '{}' - first writer created", m_channelName);
        startWorkerThread();
    }

    // Increment the active writers count
    ++m_activeWriters.count;

    auto writer = std::make_shared<ChannelWriter>(m_stateData.queue, m_stateData.channelState, weak_from_this());

    LOG_DEBUG("Created ChannelWriter for channel '{}'. Active writers: {}", m_channelName, m_activeWriters.count);

    return writer;
}

/**
 * @brief Called when a ChannelWriter is destroyed.
 *
 * This method updates the active writers count and stops the worker thread if there are no more active writers.
 */
void ChannelHandler::onWriterDestroyed()
{
    std::lock_guard<std::mutex> lock(m_activeWriters.mutex);

    --m_activeWriters.count;
    size_t currentWriters = m_activeWriters.count;

    LOG_DEBUG("ChannelWriter destroyed for channel '{}'. Active writers: {}", m_channelName, currentWriters);

    // If this was the last writer, stop the worker thread
    if (currentWriters == 0)
    {
        LOG_DEBUG("Stopping worker thread for channel '{}' - no more active writers", m_channelName);
        stopWorkerThread();
    }
}

// CompressLogFile static method
void ChannelHandler::compressLogFile(std::filesystem::path filePath, int compressionLevel)
{
    try
    {
        Utils::ZlibHelper::gzipCompress(filePath, filePath.string() + ".gz", compressionLevel);
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("Failed to compress log file '{}': {}", filePath.string(), e.what());
        return;
    }
    // Remove the original
    std::error_code ec;
    std::filesystem::remove(filePath, ec);
    if (ec)
    {
        LOG_WARNING("Failed to remove original log file '{}' after compression: {}", filePath.string(), ec.message());
    }
    else
    {
        LOG_DEBUG("Successfully compressed log file '{}'", filePath.string());
    }
}

scheduler::TaskConfig ChannelHandler::createCompressionTaskConfig(std::filesystem::path filePath) const
{
    return scheduler::TaskConfig {
        .interval = 0, // One-time task
        .CPUPriority = 0,
        .timeout = 0,
        .taskFunction = [filePath, compressionLevel = m_config.compressionLevel]()
        { compressLogFile(filePath, compressionLevel); },
    };
}

std::optional<std::filesystem::path> ChannelHandler::getPreviousCurrentFilePathFromStore() const
{
    if (!m_store)
    {
        LOG_ERROR("Store is not available for channel '{}'", m_channelName);
        return std::nullopt;
    }

    try
    {
        // Get the last state document from the store
        const auto state = m_store->readInternalDoc(getStoreBaseName());
        if (base::isError(state))
        {
            // Missing document is not an error, just means no previous state, fist time run
            LOG_DEBUG("Failed to read last state for channel '{}' from store: {}",
                      m_channelName,
                      base::getError(state).message);

            return std::nullopt;
        }

        // Get the path if it exists
        const auto& jState = base::getResponse(state);
        const auto path = jState.getString(STORE_POSFIX_PATH_TO_CURRENT);

        if (path)
        {
            return std::filesystem::path(*path);
        }
        LOG_DEBUG("No previous current file path found in store for channel '{}'", m_channelName);
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("Failed to retrieve last state for channel '{}': {}", m_channelName, e.what());
    }
    return std::nullopt;
}

void ChannelHandler::savePreviousCurrentFilePathFromStore() const
{
    if (!m_store)
    {
        LOG_ERROR("Store is not available for channel '{}'", m_channelName);
        return;
    }

    try
    {
        // Get the last state document from the store
        auto state = m_store->readInternalDoc(getStoreBaseName());

        if (base::isError(state))
        {
            // Missing document is not an error, just means no previous state, fist time run
            LOG_DEBUG("Failed to read last state for channel '{}' from store: {}. Creating new state.",
                      m_channelName,
                      base::getError(state).message);
            state = json::Json();
        }

        // Update the path
        auto jState = base::getResponse(state);
        jState.setString(m_stateData.currentFile.string(), STORE_POSFIX_PATH_TO_CURRENT);

        // Save the updated document back to the store
        const auto res = m_store->upsertInternalDoc(getStoreBaseName(), jState);
        if (base::isError(res))
        {
            LOG_WARNING(
                "Failed to save last state for channel '{}' to store: {}", m_channelName, base::getError(res).message);
        }
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("Failed to save last state for channel '{}': {}", m_channelName, e.what());
    }
}

void ChannelHandler::clearPreviousCurrentFilePathFromStore() const
{
    if (!m_store)
    {
        LOG_ERROR("Store is not available for channel '{}'", m_channelName);
        return;
    }

    try
    {
        // Remove the document from the store
        // Get the last state document from the store
        auto state = m_store->readInternalDoc(getStoreBaseName());

        if (base::isError(state))
        {
            // Missing document is not an error, just means no previous state, fist time run
            LOG_DEBUG("Failed to read last state for channel '{}' from store: {}. Creating new state.",
                      m_channelName,
                      base::getError(state).message);
            state = json::Json();
        }
        auto jState = base::getResponse(state);
        jState.erase(STORE_POSFIX_PATH_TO_CURRENT);

        // Save the updated document back to the store
        const auto res = m_store->upsertInternalDoc(getStoreBaseName(), jState);
        if (base::isError(res))
        {
            LOG_WARNING(
                "Failed to clear last state for channel '{}' in store: {}", m_channelName, base::getError(res).message);
        }
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("Failed to clear last state for channel '{}': {}", m_channelName, e.what());
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
