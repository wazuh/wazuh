#ifndef _STREAMLOG_LOGGER_HPP
#define _STREAMLOG_LOGGER_HPP

#include <chrono>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>

/**
 * @brief Asynchronous, rotating log management module. Handles named, rotating log channels with asynchronous writes.
 *
 * This module provides:
 *   - Registration of named log channels with rotation configuration.
 *   - Retrieval of lightweight writer functors for application code.
 *   - Asynchronous, thread-safe writes into date- and size-rotated files via a dedicated I/O thread.
 *   - Runtime reconfiguration and on-demand rotation.
 *   - Hard-link “latest” pointer to the current log file for each channel.
 *
 * ## Concepts
 *
 * - **Channel Registration**
 *   Clients call `registerLog(name, config)` to declare a log stream,
 *
 * - **RotationConfig**
 *   Defines `basePath`, `pattern`, optional `maxSize`, and `bufferSize`.
 *   E.g.
 *   ```cpp
 *   RotationConfig cfg {
 *     "/var/ossec/logs",         // basePath
 *     "${YYYY}/${MMM}/wazuh-${name}-${DD}.json",
 *     10*1024*1024,              // rotate after 10 MiB
 *     1<<20                      // 1 MiB write buffer
 *   };
 *   ```
 *
 * - **Writer Functor**
 *   `auto writer = logManager.getWriter("alerts");`
 *   `writer(jsonString);` enqueues one line (JSON string + ‘\n’) to the log.
 *
 * - **Asynchronous I/O**
 *   A dedicated thread per channel flushes buffered lines on each write.
 *
 * - **Rotation Mechanics**
 *   When any date placeholder in `pattern` changes (e.g., new day, month, year),
 *   a new file is created and the channel’s hard-link `<basePath>/<name>.json` is updated
 *   to point at it.
 *   If `maxSize` is set, rotation also occurs when the file exceeds this size and a new file is created.
 *   The file is rotated by renaming it to `<basePath>/${pattern}-${counter}.json`,
 *   where `${counter}` is a monotonically increasing number to avoid overwriting.
 *
 * - **File Naming**
 *   The log files are named according to the `pattern` provided in the `RotationConfig`.
 *   Placeholders like `${YYYY}`, `${MMM}`, `${DD}`, and `${name}` are
 *   replaced with the current date and the log channel name.
 *   For example, if the pattern is `"${YYYY}/${MMM}/wazuh-${name}-${DD}.json"`,
 *   and the channel name is `"alerts"`, the log file might be named
 *   `"2025/Jul/wazuh-alerts-01.json"` for logs written on July 1, 2025.
 *
 * - **Suported Patterns**
 *  The following placeholders are supported in the `pattern`:
 *   - `${YYYY}`: 4-digit year
 *   - `${YY}`: 2-digit year
 *   - `${MMM}`: 3-letter month abbreviation (e.g., Jan, Feb, Mar)
 *   - `${MM}`: 2-digit month (01-12)
 *   - `${DD}`: 2-digit day of the month (01-31)
 *   - `${HH}`: 2-digit hour (00-23)
 *   - `${name}`: The name of the log channel
 *   - `${counter}`: A monotonically increasing number to avoid overwriting files, is mandatory if `maxSize` is set.
 *  The pattern can also include static text and directory separators, if not existing in the `basePath` can be created.
 *  The pattern no supports obsolute paths nor relative paths with `..` segments.
 *  If the file exists, it will be appended to, otherwise a new file will be created.
 *
 * - **Buffering**
 *  Each log channel uses a buffer of size `bufferSize` (default 1 MiB) to accumulate log entries.
 * This buffer allows for efficient asynchronous writes, reducing the number of I/O operations.
 *
 *  When the buffer is full or when a write operation occurs, the buffered entries are flushed to the log file.
 * * - **Error Handling**
 *  If an I/O operation fails (e.g., due to disk issues), the write is discarded,
 * and an emergency error log is emitted to ensure that the application can continue running without crashing.
 * * - **Thread Safety**
 *
 * ## Features
 *
 * - **Support for Multiple Channels**
 *  Each channel can have its own configuration and operates independently.
 *  This allows for flexible logging setups where different parts of the application
 *  can log to different files with their own rotation policies.
 *  Each channel is identified by a unique name, and the `LogManager`
 *  handles the registration and management of these channels.
 *
 * - **Hard-Link Latest**
 *  Each channel maintains a hard link `<basePath>/<name>.json` that always points
 *  to the current log file.
 *
 * - **Runtime API**
 *   - `updateConfig(name, newConfig)` modifies rotation parameters on the fly.
 *   - `rotateNow(name)` forces immediate rotation.
 *
 * - **Error Handling**
 *   - On I/O failure, writes are discarded and an emergency error log is emitted.
 *
 * @see RotationConfig
 * @see LogManager
 * @ingroup LogManagerModule
 */
namespace streamlog
{

class WriterEvent
{
public:
    void operator()(std::string&& message);
};

/**
 * @brief Configuration structure for the streamlog logger.
 *
 * Contains parameters for log file management, including base path, file naming pattern,
 * optional maximum file size, optional maximum file age, and buffer size.
 */
struct RotationConfig
{
    std::filesystem::path basePath; ///< The base directory path where log files will be stored, should be an absolute
                                    ///< path and must exist and be writable.
    std::string pattern;            ///< The pattern used for naming log files, which can include placeholders.
    std::optional<size_t> maxSize;  ///< Optional maximum size (in bytes) for a log file before rotation.
    size_t bufferSize = 1 << 20;    ///<  The size (in events) of the buffer used for logging operations.
};

/**
 * @brief Manages multiple log channels with rotation and asynchronous writes.
 *
 * The `LogManager` class provides methods to register log channels, update their configurations,
 * retrieve writer functors for logging, and manage log file rotation.
 * It handles the asynchronous writing of log entries to files, ensuring thread safety and
 * efficient I/O operations.
 */
class LogManager
{

private:
    struct ChannelState
    {
        RotationConfig config;               ///< The configuration for the log channel.
        std::filesystem::path currentFile;   ///< The current log file being written to.
        size_t currentSize = 0;              ///< The current size of the log file in bytes.
        size_t counter = 0;                  ///< A counter for the number of rotations performed.
        std::shared_ptr<WriterEvent> writer; ///< A shared pointer to the writer event for this channel, only can
                                             ///< destroy the channel if nobody has a writer for it.
        std::filesystem::path latestLink;                   ///< The hard link to the latest log file
        std::chrono::system_clock::time_point lastRotation; ///< The last time the log file was rotated.
    };

    std::unordered_map<std::string, ChannelState> channels;

public:
    /**
     * @brief Registers a new log channel with the specified name and rotation configuration.
     *
     * @param name The name of the log channel.
     * @param cfg The rotation configuration for the log channel.
     * @throws std::runtime_error if the log channel cannot be registered due to an existing channel with the same name,
     *         invalid configuration, or if the base path does not exist or is not writable.
     */
    void registerLog(std::string_view name, const RotationConfig& cfg);

    /**
     * @brief Updates the configuration of an existing log channel.
     *
     * @param name The name of the log channel to update.
     * @param cfg The new rotation configuration for the log channel.
     * @throws std::runtime_error if the log channel does not exist or if the new configuration is invalid.
     */
    void updateConfig(std::string_view name, const RotationConfig& cfg);

    /**
     * @brief Retrieves a writer functor for the specified log channel.
     *
     * @param name The name of the log channel for which to retrieve the writer.
     * @return A function that takes a string (the log entry) and writes it to
     * the log channel asynchronously.
     * @throws std::runtime_error if the log channel does not exist.
     */
    std::shared_ptr<WriterEvent> getWriter(const std::string& name);

    /**
     * @brief Gets the current configuration of a log channel.
     *
     * @param name The name of the log channel.
     * @return The current rotation configuration of the log channel.
     * @throws std::runtime_error if the log channel does not exist.
     */
    RotationConfig getConfig(const std::string& name) const;

    /**
     * @brief Check is someone has a writer for the channel.
     * 
     */
    bool hasWriter(const std::string& name) const;

    /**
     * @brief Destroys the specified log channel, releasing its resources.
     *
     * @param name The name of the log channel to destroy.
     * @throws std::runtime_error if the log channel does not exist or if in use. (Somebody has a writer for it)
     */
    void destroyChannel(std::string_view name);


    ~LogManager();
};

} // namespace streamlog

#endif // _STREAMLOG_LOGGER_HPP
