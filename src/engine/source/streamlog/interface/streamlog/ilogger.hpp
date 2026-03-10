
#ifndef STREAMLOG_ILOGGER_HPP
#define STREAMLOG_ILOGGER_HPP

#include <memory>
#include <string>

namespace streamlog
{

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
 * @see ILogManager::getWriter
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
 * // Obtain a writer (channel must already be registered)
 * auto writer = logManager->getWriter("alerts");
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
     * @brief Retrieve a writer handle for the specified log channel.
     *
     * The returned `WriterEvent` can be used from any thread to enqueue messages.
     * The caller owns the shared pointer; when the last copy is destroyed the channel's
     * active-writer count is decremented.
     *
     * @param name The unique name of a previously registered log channel.
     * @return A shared pointer to a `WriterEvent` bound to the channel.
     * @throws std::runtime_error If the channel does not exist.
     */
    virtual std::shared_ptr<WriterEvent> getWriter(const std::string& name) = 0;
};

} // namespace streamlog

#endif // STREAMLOG_ILOGGER_HPP
