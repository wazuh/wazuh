#ifndef _STREAMLOG_LOGGER_CHANNEL_HPP
#define _STREAMLOG_LOGGER_CHANNEL_HPP

#include <atomic>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <memory>
#include <mutex>
#include <regex>
#include <shared_mutex>
#include <sstream>
#include <thread>
#include <unordered_map>

#include <streamlog/logger.hpp>

#include <base/logging.hpp>
#include <fastqueue/stdqueue.hpp>
#include <scheduler/ischeduler.hpp>
#include <store/istore.hpp>

namespace streamlog
{

constexpr const char* STORE_STREAMLOG_BASE_NAME = "streamlog/"; ///< Document base name for storing last state
using FastQueueType = fastqueue::StdQueue<std::string>;         ///< Type alias for the fast queue used in channels

/**
 * @brief State machine for a channel's lifecycle.
 *
 * | State            | Description |
 * |------------------|-------------|
 * | `Running`        | Normal operation – messages are accepted and written. |
 * | `StopRequested`  | Graceful shutdown in progress; worker thread is draining and exiting. |
 * | `ErrorClosed`    | An I/O error occurred; all subsequent writes are silently dropped. |
 *
 * Transitions are performed via `std::atomic` with relaxed ordering (sufficient because
 * the only consequence of a stale read is one extra write attempt).
 *
 * @ingroup StreamlogModule
 */
enum class ChannelState : int
{
    Running = 0,       ///< Channel is active and accepting messages.
    StopRequested = 1, ///< Worker thread was asked to stop (last writer destroyed).
    ErrorClosed = 2    ///< An irrecoverable I/O error closed the channel.
};

// Forward declaration
class ChannelHandler;

/**
 * @brief Concrete `WriterEvent` implementation for log channels.
 *
 * A `ChannelWriter` is the user-facing write handle. It pushes messages into the
 * channel's `FastQueueType` (a lock-free queue), where the `ChannelHandler` worker
 * thread picks them up for file I/O.
 *
 * ### Ownership & Lifetime
 * - Holds a `shared_ptr` to the queue and the atomic channel state so that writes
 *   remain valid even if the `ChannelHandler` is being destroyed concurrently.
 * - Holds a `weak_ptr` to the owning `ChannelHandler` solely for the destructor
 *   callback (`onWriterDestroyed()`).
 * - Non-copyable and non-movable to guarantee a 1 1 mapping between writer objects
 *   and the active-writer reference count.
 *
 * ### Thread Safety
 * `operator()` is safe to call from any thread. The queue provides its own internal
 * synchronisation.
 *
 * @see ChannelHandler::createWriter
 * @ingroup StreamlogModule
 */
class ChannelWriter : public WriterEvent
{
private:
    std::shared_ptr<FastQueueType> m_queue;                    ///< Thread-safe queue for log messages.
    std::shared_ptr<std::atomic<ChannelState>> m_channelState; ///< State to check if it's running or closed.
    std::weak_ptr<ChannelHandler> m_channelHandler;            // Weak reference to avoid circular dependency

public:
    ChannelWriter(decltype(m_queue) queue,
                  decltype(m_channelState) channelState,
                  decltype(m_channelHandler) channelHandler)
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

    bool operator()(std::string&& message) override
    {
        if (m_channelState->load(std::memory_order_relaxed) == ChannelState::Running)
        {
            return m_queue->push(std::move(message));
        }
        return false; // Indicate that the message was not accepted (channel not running)
    }
};

/**
 * @brief Internal engine that manages one log channel's asynchronous I/O pipeline.
 *
 * Each `ChannelHandler` owns:
 * - A **rotation configuration** (`RotationConfig`) – immutable after construction.
 * - A **lock-free queue** (`FastQueueType`) – shared with all its `ChannelWriter`s.
 * - A **worker thread** – started on the first `createWriter()` call, joined when
 *   the last writer is destroyed.
 * - State for **file rotation**: current output file, hard-link to "latest", file
 *   size counter, rotation counter, and last-rotation timestamps.
 * - Optional **store persistence** to survive restarts (tracks the current file path
 *   so a pending compression can be resumed).
 *
 * ### Worker Thread Loop
 * 1. `waitPop` from the queue (1 s timeout).
 * 2. Check `needsRotation()` – if yes, `rotateFile()` and schedule compression.
 * 3. `writeMessage()` – append + newline + flush.
 * 4. Repeat until `ChannelState != Running`.
 *
 * ### Factory Pattern
 * The constructor is private. Use the static `create()` method which returns a
 * `shared_ptr` (required because `ChannelWriter` stores a `weak_ptr` back via
 * `enable_shared_from_this`).
 *
 * @see ChannelWriter
 * @see LogManager
 * @ingroup StreamlogModule
 */
class ChannelHandler : public std::enable_shared_from_this<ChannelHandler>
{
public:
    /**
     * @brief Enum to indicate if rotation is needed based on size or time.
     */
    enum class RotationRequirement
    {
        No,   ///< No rotation needed.
        Size, ///< Rotation needed due to size limit.
        Time  ///< Rotation needed due to time pattern change.
    };

private:
    const RotationConfig m_config;   ///< The rotation configuration for the log channel.
    const std::string m_channelName; ///< The name of the log channel.

    std::weak_ptr<scheduler::IScheduler> m_scheduler; ///< Scheduler for compressing log writes
    const std::string m_fileExtension;                ///< The file extension for log files.
    std::shared_ptr<store::IStore> m_store;           ///< Store for managing last state

    struct ActiveWriters
    {
        mutable std::mutex mutex; ///< Mutex to protect the writers reference count
        size_t count {0};         ///< Count of active ChannelWriter instances (protected by m_writersMutex)
    } m_activeWriters;            ///< Active writers count, protected by m_writersMutex

    /// @brief Per-channel mutex serialising concurrent retention cleanup calls.
    ///
    /// Using a shared_ptr so that compression task lambdas (which may outlive the
    /// ChannelHandler) can capture it by value and keep it alive.
    std::shared_ptr<std::mutex> m_retentionMutex {std::make_shared<std::mutex>()};

    /// @brief Thread-safe registry of files currently in the compression pipeline.
    ///
    /// Tracks both the source (.log/.json) and destination (.gz) paths so that
    /// concurrent retention cleanup skips files that are mid-compression.
    /// Uses refcounting to handle the (unlikely) case of duplicate registrations.
    /// Wrapped in a shared_ptr so task lambdas can capture it by value.
    class InFlightRegistry
    {
    public:
        /// Register a path as in-flight. Thread-safe.
        void add(const std::filesystem::path& path)
        {
            std::unique_lock lock(m_mutex);
            ++m_paths[path.string()];
        }

        /// Unregister a path. Removes the entry when refcount reaches 0. Thread-safe.
        void remove(const std::filesystem::path& path)
        {
            std::unique_lock lock(m_mutex);
            auto it = m_paths.find(path.string());
            if (it != m_paths.end() && --it->second == 0)
            {
                m_paths.erase(it);
            }
        }

        /// Check if a path is currently in-flight. Thread-safe (shared lock).
        bool contains(const std::filesystem::path& path) const
        {
            std::shared_lock lock(m_mutex);
            return m_paths.count(path.string()) > 0;
        }

    private:
        mutable std::shared_mutex m_mutex;
        std::unordered_map<std::string, size_t> m_paths; ///< path.string() → refcount
    };

    // In shared_ptr so task lambdas that outlive ChannelHandler keep it alive.
    std::shared_ptr<InFlightRegistry> m_inFlightFiles {std::make_shared<InFlightRegistry>()};

    struct AsyncChannelData
    {
        // Stream flow handling
        std::shared_ptr<FastQueueType> queue; ///< Thread-safe queue for log messages.
        std::ofstream outputFile;             ///< Output file stream for writing log messages.
        std::thread workerThread;             ///< Thread that processes log messages asynchronously.
        std::shared_ptr<std::atomic<ChannelState>> channelState {
            std::make_shared<std::atomic<ChannelState>>(ChannelState::Running)};

        // File path
        std::filesystem::path currentFile; ///< Current log file being written to.
        std::filesystem::path latestLink;  ///< Path to the latest log file link. (Hard link to currentFile)

        // State and performance optimization
        std::chrono::system_clock::time_point lastRotation;              ///< The last time the log file was rotated.
        mutable std::chrono::system_clock::time_point lastRotationCheck; ///< Timestamp of the last rotation check.
        size_t currentSize {0};                                          ///< Current size of the log file in bytes.
        size_t counter {0}; ///< Counter for the number of rotations (max size rotations).
    } m_stateData;          ///< State data for the channel.

    /**
     * @brief Replaces placeholders in a pattern string with corresponding values.
     */
    std::string replacePlaceholders(const std::chrono::system_clock::time_point& timePoint) const;

    /**
     * @brief Rotation check
     */
    RotationRequirement needsRotation(size_t messageSize) const;

    /**
     * @brief Rotates the log file for the current channel based
     */
    void rotateFile(RotationRequirement rotationType);

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
     * @brief Compresses a rotated log file using gzip in a background task.
     *
     * On success the original file is removed and only the `.gz` remains.
     * On failure (gzipCompress throws) a warning is logged and the function
     * returns early — the original file is left on disk and a partial `.gz`
     * artefact may also remain.  The caller receives no indication of
     * success or failure; post-compression steps (in-flight unregister,
     * retention cleanup) always execute regardless of the outcome.
     *
     * @note Static method to allow scheduling without needing an instance.
     */
    static void compressLogFile(std::filesystem::path filePath, int compressionLevel);

    /**
     * @brief Creates a TaskConfig for compressing a log file.
     *
     * The returned task lambda executes three steps unconditionally:
     *   1. `compressLogFile()` — may fail silently (see its doc).
     *   2. Unregister both source and `.gz` paths from the in-flight registry.
     *   3. Run retention cleanup (`deleteOldFilesStatic`) if any policy is active.
     *
     * Steps 2-3 run regardless of whether compression succeeded.  On failure
     * the retention cleanup operates in best-effort mode on whatever state
     * remains on disk (original uncompressed file and/or partial `.gz`).
     *
     * @param filePath The path of the log file to compress.
     * @return A TaskConfig configured for compressing the specified log file.
     */
    scheduler::TaskConfig createCompressionTaskConfig(std::filesystem::path filePath) const;

    /**
     * @brief Delete old files from the channel directory according to retention rules (maxFiles and
     * maxAccumulatedSize).
     *
     * Scans basePath recursively for all regular files belonging to this channel
     * (excluding the current active file and the latest hard-link). Files are sorted
     * by mtime (oldest first) so that the cleanup is pattern-agnostic — it works
     * correctly even if the naming pattern was changed after files were already written.
     *
     * Cleanup algorithm:
     *   1) Scan basePath recursively for regular files (both .ext and .ext.gz)
     *   2) Exclude the current active file and the latest link
     *   3) Sort by mtime ascending (oldest first)
     *   4) Apply maxAccumulatedSize: delete oldest until total size fits the limit
     *   5) Apply maxFiles: delete oldest until count fits the limit
     */
    void deleteOldFiles();

    /**
     * @brief Static version of deleteOldFiles for use in scheduled tasks (compression callbacks).
     *
     * Because compression tasks run asynchronously via the scheduler and may outlive
     * the ChannelHandler instance, this static method captures all needed state by value.
     *
     * Active-file exclusion uses a two-layer strategy to minimise the TOCTOU window
     * between when the directory is scanned and when each file is actually deleted:
     *
     *   1. `::stat(latestLink)` is called once before the scan to obtain the initial active
     *      inode. Files matching this inode are removed from the candidate list after the
     *      scan (not inside the scan loop), keeping the loop itself filter-free.
     *
     *   2. `::stat(latestLink)` is called again immediately before every individual
     *      `remove()` call. This catches any rotation that occurred between the initial
     *      read and the deletion attempt — the fresh inode will reflect the new active
     *      file, preventing its accidental deletion.
     *
     * Callers are responsible for holding `m_retentionMutex` before invoking this method
     * to prevent concurrent retention runs on the same channel from both the worker thread
     * and scheduler threads.
     */
    static void deleteOldFilesStatic(const std::filesystem::path& basePath,
                                     const std::filesystem::path& latestLink,
                                     size_t maxFiles,
                                     size_t maxAccumulatedSize,
                                     const std::string& channelName,
                                     const std::shared_ptr<InFlightRegistry>& inFlightFiles);

    base::Name getStoreBaseName() const { return base::Name(STORE_STREAMLOG_BASE_NAME) + m_channelName + "/0"; }

    /**
     * @brief Get the last file used to write logs from the store
     * @return The last file path if it exists in the store, std::nullopt
     */
    std::optional<std::filesystem::path> getPreviousCurrentFilePathFromStore() const;

    /**
     * @brief Save the current file used to write logs to the store
     */
    void savePreviousCurrentFilePathFromStore() const;

    /**
     * @brief Clear the last file used to write logs from the store, avoid compression of old files
     */
    void clearPreviousCurrentFilePathFromStore() const;

    /**
     * @brief Private constructor - use create() instead
     */
    ChannelHandler(RotationConfig config,
                   std::string channelName,
                   const std::shared_ptr<store::IStore>& store,
                   std::weak_ptr<scheduler::IScheduler> scheduler,
                   std::string_view ext);

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
     * @param store The store for managing the last state
     * @param scheduler Optional scheduler for handling compression tasks
     * @param ext The file extension for log files
     * @return A shared_ptr to the newly created ChannelHandler
     * @throws std::runtime_error if the configuration is invalid or initialization fails
     */
    static std::shared_ptr<ChannelHandler> create(RotationConfig config,
                                                  std::string channelName,
                                                  const std::shared_ptr<store::IStore>& store,
                                                  std::weak_ptr<scheduler::IScheduler> scheduler = {},
                                                  std::string_view ext = "json");

    /**
     * @brief Creates a new ChannelWriter and starts the worker thread if it's the first writer
     * @return A shared_ptr to a new ChannelWriter instance
     */
    std::shared_ptr<ChannelWriter> createWriter();

    /**
     * @brief Gets the name of the channel
     * @return The name of the channel
     */
    const std::string& getChannelName() const { return m_channelName; }

    /**
     * @brief Get the current file path being written to
     * @return The current log file path
     */
    std::filesystem::path getCurrentFilePath() const { return m_stateData.currentFile; }

    /**
     * @brief Gets the number of active writers for this channel
     * @return The number of active ChannelWriter instances
     */
    size_t getActiveWritersCount() const
    {
        std::lock_guard<std::mutex> lock(m_activeWriters.mutex);
        return m_activeWriters.count;
    }

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
