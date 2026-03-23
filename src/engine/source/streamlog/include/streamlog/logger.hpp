#ifndef _STREAMLOG_LOGGER_HPP
#define _STREAMLOG_LOGGER_HPP

#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include <scheduler/ischeduler.hpp>
#include <store/istore.hpp>
#include <streamlog/ilogger.hpp>

/**
 * @brief Asynchronous, rotating log management module. Handles named, rotating log channels with asynchronous writes.
 *
 * This module provides:
 *   - Registration of named log channels with rotation configuration.
 *   - Retrieval of lightweight writer functors for application code.
 *   - Asynchronous, thread-safe writes into date- and size-rotated files via a dedicated I/O thread.
 *   - Runtime configuration and on-demand rotation.
 *   - Hard-link “latest” pointer to the current log file for each channel.
 *   - Compression of rotated files asynchronously.
 *
 * ## Concepts
 *
 * - **Channel Registration**
 *   Clients call `registerLog(name, config)` to declare a log stream,
 *
 * - **RotationConfig**
 *   Defines `basePath`, `pattern`, optional `maxSize`, `bufferSize`, and optional compression settings.
 *   E.g.
 *   ```cpp
 *   RotationConfig cfg {
 *     "/var/wazuh-manager/logs",         // basePath
 *     "${YYYY}/${MMM}/wazuh-${name}-${DD}.json",
 *     10*1024*1024,              // rotate after 10 MiB
 *     1<<20,                     // 1 MiB write buffer
 *     true,                      // compress rotated files
 *      5                         // compression level (1-9)
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

class ChannelHandler; // Forward declaration of ChannelHandler

/**
 * @brief Configuration for a single log channel's rotation and compression policy.
 *
 * A `RotationConfig` is passed to `LogManager::registerLog()` (or `updateConfig()`) and
 * fully describes **where** log files are written, **how** they are named, and **when**
 * they are rotated and optionally compressed.
 *
 * ### Validation & Normalisation
 * `ChannelHandler::validateAndNormalizeConfig()` is called automatically during channel
 * creation. It enforces the following rules:
 * - `basePath` must be an existing, writable, absolute directory.
 * - `pattern` must contain at least one time placeholder unless `maxSize > 0`.
 * - If `maxSize > 0` and the pattern lacks `${counter}`, it is inserted before the last dot.
 * - `bufferSize` of 0 is promoted to the default (1 Mi events).
 * - `maxSize` below 1 MiB is clamped to 1 MiB.
 * - `compressionLevel` must be in [1, 9] when `shouldCompress` is `true`.
 *
 * @see LogManager::registerLog
 * @see ChannelHandler::validateAndNormalizeConfig
 * @ingroup StreamlogModule
 */
struct RotationConfig
{
    std::filesystem::path basePath; ///< Absolute directory where log files are written. Must exist and be writable.
    std::string pattern;            ///< File-name pattern with placeholders (see namespace docs for the full list).
    size_t maxSize;              ///< Maximum file size in bytes before size-based rotation. `0` disables size rotation.
    size_t bufferSize = 1 << 20; ///< Queue capacity in events (default 1 Mi). `0` is promoted to the default.
    bool shouldCompress {true};  ///< Compress rotated files with gzip when `true`.
    size_t compressionLevel {5}; ///< Gzip compression level: 1 (fastest) – 9 (best). Only used when `shouldCompress`.
};

/**
 * @brief Manages multiple named log channels with rotation and asynchronous writes.
 *
 * `LogManager` is the concrete implementation of `ILogManager`. It owns a set of
 * `ChannelHandler` instances (one per registered channel), each backed by a
 * dedicated worker thread for zero-contention writes.
 *
 * ### Ownership Model
 * - `LogManager` **owns** `ChannelHandler`s via `shared_ptr`.
 * - `ChannelWriter`s hold a `weak_ptr` back to their handler to avoid preventing
 *   handler destruction.
 * - Writer creation increments an `ActiveWriters` counter; destruction decrements it.
 *   When the count reaches zero the worker thread is joined.
 *
 * ### Thread Safety
 * All public methods are protected by a `shared_mutex`:
 * - Read operations (`hasChannel`, `getConfig`, `getWriter`, `getActiveWritersCount`)
 *   take a shared (read) lock.
 * - Write operations (`registerLog`, `updateConfig`, `destroyChannel`, `cleanup`)
 *   take a unique (write) lock.
 *
 * @see RotationConfig
 * @see WriterEvent
 * @see ChannelHandler
 * @ingroup StreamlogModule
 */
class LogManager : public ILogManager
{

private:
    std::unordered_map<std::string, std::shared_ptr<ChannelHandler>> m_channels; ///< Channel names to ChannelHandler
    mutable std::shared_mutex m_channelsMutex;        ///< Mutex to protect access to m_channels
    std::weak_ptr<scheduler::IScheduler> m_scheduler; ///< Scheduler for compressing log writes
    std::shared_ptr<store::IStore> m_store;           ///< Store for managing last state

public:
    LogManager(const std::shared_ptr<store::IStore>& store, std::weak_ptr<scheduler::IScheduler> scheduler = {})
        : m_scheduler(std::move(scheduler))
        , m_channels()
        , m_channelsMutex()
        , m_store(store) {};

    /**
     * @brief Register a new named log channel.
     *
     * Creates a `ChannelHandler`, validates and normalises `cfg`, opens the initial output
     * file, and creates the hard-link shortcut `<basePath>/<name>.<ext>`. The worker
     * thread is **not** started until the first `getWriter()` call.
     *
     * @param name Unique channel name (alphanumeric, dashes, underscores; max 255 chars).
     * @param cfg  Rotation and compression configuration.
     * @param ext  File extension for the "latest" hard-link (e.g. `"json"`, `"log"`).
     *
     * @throws std::runtime_error If `name` is already registered, `cfg` is invalid,
     *         the base path does not exist, or the initial file cannot be opened.
     */
    void registerLog(const std::string& name, const RotationConfig& cfg, std::string_view ext);

    /**
     * @brief Checks if a log channel with the specified name exists.
     *
     * @param name The name of the log channel to check.
     * @return true if the channel exists, false otherwise.
     */
    bool hasChannel(const std::string& name) const
    {
        std::shared_lock lock(m_channelsMutex);
        return m_channels.find(name) != m_channels.end();
    }

    /**
     * @brief Replace the configuration of an existing log channel.
     *
     * The channel is destroyed and re-created with the new configuration. This is only
     * allowed when there are **no active writers**; otherwise an exception is thrown.
     *
     * @param name Existing channel name.
     * @param cfg  New rotation and compression configuration.
     * @param ext  File extension for the "latest" hard-link.
     *
     * @throws std::runtime_error If the channel does not exist, has active writers, or
     *         the new configuration is invalid.
     */
    void updateConfig(const std::string& name, const RotationConfig& cfg, std::string_view ext);

    /**
     * @brief Obtain a writer handle for asynchronous log writing.
     *
     * The first call for a channel starts its worker thread. The returned handle
     * is reference-counted; when the last copy is destroyed the active-writer
     * counter is decremented and the worker thread may be joined.
     *
     * @param name A previously registered channel name.
     * @return Shared pointer to a `WriterEvent` bound to the channel.
     * @throws std::runtime_error If the channel does not exist or is in error state.
     */
    [[nodiscard]] std::shared_ptr<WriterEvent> getWriter(const std::string& name) override;

    /**
     * @brief Gets the current configuration of a log channel.
     *
     * @param name The name of the log channel.
     * @return The current rotation configuration of the log channel.
     * @throws std::runtime_error if the log channel does not exist.
     */
    const RotationConfig& getConfig(const std::string& name) const;

    /**
     * @brief Get the Active Writers Count for a specific channel.
     *
     * @param name The name of the log channel.
     * @return The number of active writers for the specified channel.
     * @throws std::runtime_error if the log channel does not exist.
     */
    std::size_t getActiveWritersCount(const std::string& name) const;

    /**
     * @brief Destroy a channel, stopping its worker thread and releasing resources.
     *
     * The channel must have **zero** active writers; otherwise the call throws.
     *
     * @param name Channel to destroy.
     * @throws std::runtime_error If the channel does not exist or has active writers.
     */
    void destroyChannel(const std::string& name);

    /**
     * @brief Creates and validates the base directory path for a log channel.
     *
     * This method creates a subdirectory within the configured base path using the provided
     * channel name. It performs validation on both the channel name and configuration,
     * ensures the target path doesn't conflict with existing files, and creates the
     * necessary directory structure.
     *
     * @param channelName The name of the log channel to create a directory for
     * @param config The rotation configuration containing the base path and other settings
     *
     * @return Reference to the modified RotationConfig with updated base path
     *
     * @throws std::runtime_error If the channel name is invalid, configuration is invalid,
     *                           the target path exists but is not a directory, or
     *                           directory creation fails
     *
     * @note The method modifies the basePath field in the provided config to point to
     *       the newly created subdirectory (basePath/channelName)
     */
    static RotationConfig& isolatedBasePath(const std::string& channelName, RotationConfig& config);

    /**
     * @brief Clean up the logger, releasing all resources.
     *
     * @warning After calling this method, the LogManager instance should not be used again.
     */
    void cleanup();

    /**
     * @brief Destructor
     */
    ~LogManager() = default;
};

} // namespace streamlog

#endif // _STREAMLOG_LOGGER_HPP
