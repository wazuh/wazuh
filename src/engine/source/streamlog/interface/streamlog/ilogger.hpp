
#ifndef STREAMLOG_ILOGGER_HPP
#define STREAMLOG_ILOGGER_HPP

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

namespace streamlog
{

/**
 * @brief Configuration for a single log channel's rotation and compression policy.
 *
 * Describes **where** log files are written, **how** they are named, and **when**
 * they are rotated and optionally compressed.
 *
 * @see ILogManager::ensureChannel
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
 * @brief Abstract base class for writer event handlers.
 *
 * A `WriterEvent` represents a handle for writing log messages into a specific channel.
 * Each instance is bound to a single channel and is **not copyable or movable** in the
 * concrete implementation (`ChannelWriter`). Multiple `WriterEvent` instances can coexist
 * for the same channel; the underlying channel starts its I/O worker thread when the first
 * writer is created and stops it when the last writer is destroyed.
 *
 * ### Thread Safety
 * The `operator()` is thread-safe: multiple threads may call it concurrently on the same
 * `WriterEvent` instance.
 *
 * ### Lifetime
 * The writer holds a weak reference to its channel handler. Destroying the writer
 * decrements the channel's active-writer count and may trigger worker-thread shutdown.
 *
 * @see ILogManager::ensureAndGetWriter
 * @ingroup StreamlogModule
 */
class WriterEvent
{
public:
    virtual ~WriterEvent() = default;

    /**
     * @brief Enqueue a log message for asynchronous writing.
     *
     * The message is moved into the channel's internal lock-free queue and will be
     * written to the output file by the dedicated worker thread.
     *
     * @param message The log entry to write (typically a JSON string).
     * @return `true` if the message was successfully enqueued, `false` if the channel
     *         is no longer running (e.g., error-closed) or the queue is full.
     */
    virtual bool operator()(std::string&& message) = 0;
};

/**
 * @brief Abstract interface for the log channel manager.
 *
 * `ILogManager` is the entry point for application code that needs to write structured logs.
 * It provides a single method to obtain a `WriterEvent` for a named channel. The concrete
 * implementation (`LogManager`) adds channel registration, configuration updates, and
 * lifecycle management.
 *
 * ### Typical Usage
 * @code
 * // Ensure the channel exists and obtain a writer in one call
 * auto writer = logManager->ensureAndGetWriter("mySpace-wazuh-events-v5", cfg, "json");
 *
 * // Write log entries from any thread
 * (*writer)(R"({"level":"warning","msg":"disk usage 90%"})");
 * @endcode
 *
 * @see LogManager
 * @ingroup StreamlogModule
 */
class ILogManager
{
public:
    virtual ~ILogManager() = default;

    /**
     * @brief Ensure the channel exists and return a writer in a single operation.
     *
     * Creates the channel on first use and otherwise reuses the existing one.
     * The returned `WriterEvent` can be used from any thread to enqueue messages.
     * The caller owns the shared pointer; when the last copy is destroyed the channel's
     * active-writer count is decremented.
     *
     * @param name   Unique channel name.
     * @param cfg    Rotation and compression configuration (used only on first creation).
     * @param ext    File extension for the "latest" hard-link (e.g. `"json"`).
     * @return A shared pointer to a `WriterEvent` bound to the channel.
     * @throws std::runtime_error If the configuration is invalid or directory creation fails.
     */
    [[nodiscard]] virtual std::shared_ptr<WriterEvent>
    ensureAndGetWriter(const std::string& name, const RotationConfig& cfg, std::string_view ext) = 0;
};

} // namespace streamlog

#endif // STREAMLOG_ILOGGER_HPP
