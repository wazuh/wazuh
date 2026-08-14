#pragma once

#include "iagent_sync_protocol.hpp"
#include "sysInfoInterface.h"

#include <commonDefs.h>
#include <idbsync.hpp>
#include <ifile_io_utils.hpp>
#include <ifilesystem_wrapper.hpp>
#include <ipersistent_queue.hpp>

#include <json.hpp>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

// Type definition for module query callback function
// Returns 0 on success, -1 on error. Response must be freed by caller.
using module_query_callback_t = std::function<int(const std::string& module_name, const std::string& query, char** response)>;

// Type definition for the handshake query callback function.
// Queries agentd for fresh cluster_name/agent_groups into the given buffers.
// Returns true if the query succeeded (buffers may still be empty if legitimately unset).
using handshake_query_callback_t =
    std::function<bool(char* cluster_name, size_t cluster_name_size,
                       char* agent_groups, size_t agent_groups_size)>;

class AgentInfoImpl
{
    public:
        /// @brief Structure to represent a module query response
        struct ModuleResponse
        {
            bool success;              ///< True if operation succeeded (error code 0)
            std::string response;      ///< Raw response string
            int errorCode;             ///< Parsed error code (0 if success)
            bool isModuleUnavailable;  ///< True if error indicates module is unavailable (50-53)
        };

        /// @brief Durable VD feed offset + pending-rescan state, backed by the `vd_feed_state`
        /// table in agent_info.db. `hasOffset` distinguishes "never observed" from "observed 0"
        /// (a manager legitimately reporting offset 0 -- e.g. VD not enabled -- must not be
        /// treated as unset).
        struct VdFeedState
        {
            bool hasOffset{false};
            uint64_t offset{0};
            bool pending{false};
            uint64_t pendingOffset{0};
        };

        /// @brief Result of observeVdFeedOffset().
        struct VdOffsetObserveResult
        {
            bool changed{false};       ///< True if offset advanced (was newer than the stored value)
            bool pending{false};       ///< True if a /scan/vd request is now outstanding for pendingOffset
            uint64_t pendingOffset{0}; ///< Valid when pending is true
        };

        /// @brief Constructor
        /// @param dbPath Path to the database file
        /// @param reportDiffFunction Function to report stateless diffs
        /// @param logFunction Function to log messages
        /// @param queryModuleFunction Function to query other modules
        /// @param dbSync Pointer to IDBSync for database synchronization
        /// @param sysInfo Pointer to ISysInfo for system information gathering
        /// @param fileIO Pointer to IFileIOUtils for file I/O operations
        /// @param fileSystem Pointer to IFileSystemWrapper for file system operations
        /// @param handshakeQueryFunction Function to query agentd for fresh handshake data on every cycle
        AgentInfoImpl(std::string dbPath,
                      std::function<void(const std::string&)> reportDiffFunction = nullptr,
                      std::function<void(const modules_log_level_t, const std::string&)> logFunction = nullptr,
                      module_query_callback_t queryModuleFunction = nullptr,
                      std::shared_ptr<IDBSync> dbSync = nullptr,
                      std::shared_ptr<ISysInfo> sysInfo = nullptr,
                      std::shared_ptr<IFileIOUtils> fileIO = nullptr,
                      std::shared_ptr<IFileSystemWrapper> fileSystem = nullptr,
                      handshake_query_callback_t handshakeQueryFunction = nullptr);
        ~AgentInfoImpl();

        void start(int interval, int integrityInterval = 86400, std::function<bool()> shouldContinue = nullptr);
        void stop();

        /// @brief Override the flush poll delay (milliseconds). Only used in unit tests to avoid real sleeps.
        /// Negative values are clamped to 0.
        void setFlushPollDelayMs(int delayMs)
        {
            m_flushPollDelayMs = clampNonNegative(delayMs);
        }

        /// @brief Override the FIM pause-completion poll delay (milliseconds). Only used in unit tests
        /// to avoid real sleeps. Negative values are clamped to 0.
        void setPausePollDelayMs(int delayMs)
        {
            m_pausePollDelayMs = clampNonNegative(delayMs);
        }

        /// @brief Initialize the synchronization protocol with only in-memory synchronization
        /// @param moduleName Name of the module
        void initSyncProtocol(const std::string& moduleName);

        /// @brief Set the predicate used to detect that a shutdown is in progress.
        /// It complements the module's own stop flag so that failures caused by the global agent
        /// shutdown (which happens before this module receives its own stop) are logged at a lower
        /// level (DEBUG or INFO, depending on the message) instead of WARNING.
        /// @param isShuttingDown Predicate returning true while a shutdown is requested
        void setIsShuttingDownFunction(std::function<bool()> isShuttingDown);

        /// @brief Parse sync protocol response buffer
        /// @param data Pointer to the response data buffer
        /// @param length Size of the response data buffer
        /// @return true if parsing succeeds, false otherwise
        bool parseResponseBuffer(const uint8_t* data, size_t length);

        /// @brief Process a database event and emit notifications
        /// @param result Type of change (INSERTED, MODIFIED, DELETED)
        /// @param data Event data
        /// @param table Table name
        void processEvent(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table);

        /// @brief Convert data to ECS format
        /// @param data Original data
        /// @param table Table name
        /// @return ECS-formatted data
        nlohmann::json ecsData(const nlohmann::json& data, const std::string& table) const;

        /// @brief Durable /control task_id dedup guard, backed by the `tasks` table in
        /// this same agent_info.db (rather than a private flat file), keyed by task_id.
        /// Atomically checks whether taskId was already recorded and, if not, records it.
        /// @param taskId The task_id to check and record
        /// @return true when taskId was new and is now recorded (dispatch it); false when it is
        ///         a duplicate, or when the check/insert itself failed (fail closed -- callers
        ///         must not dispatch a task whose durability could not be confirmed).
        bool checkAndRecordTask(const std::string& taskId);

        /// @brief Prune the `tasks` table: entries older than ttlSeconds, then (if still over
        /// maxEntries) the oldest surplus entries. Safe to call periodically.
        /// @param ttlSeconds Entries last recorded more than this many seconds ago are deleted.
        /// @param maxEntries Entries beyond this count (oldest first) are deleted; 0 is treated as 1.
        void cleanupExpiredTasks(uint32_t ttlSeconds, uint32_t maxEntries);

        /// @brief Current number of remembered task_ids in the `tasks` table. For tests and
        /// .state metrics.
        size_t countTasks();

        /// @brief Configure the bounds cleanupExpiredTasks() enforces on its own periodic call
        /// from within start()'s loop. Runs on that loop rather than a dedicated cleanup thread,
        /// which would otherwise race with this instance's destruction since nothing
        /// synchronizes the two.
        /// @param ttlSeconds Entries older than this are pruned.
        /// @param maxEntries Entries beyond this count (oldest first) are pruned.
        void setTaskRegistryLimits(uint32_t ttlSeconds, uint32_t maxEntries)
        {
            m_taskRegistryTtlSeconds = ttlSeconds;
            m_taskRegistryMaxEntries = maxEntries == 0 ? 1 : maxEntries;
        }

        /// @brief Observe a VD feed offset reported by the manager (via /control notify).
        /// Monotonic: a value not newer than the currently stored offset is a no-op. When the
        /// offset advances, it is persisted immediately; a re-scan is marked pending only if
        /// syscollector's VDFirst has already completed (queried live via
        /// get_vd_first_sync_completed) -- otherwise VDFirst's own full scan will cover the new
        /// offset (see Start.feed_offset), so no /scan/vd request is needed.
        /// @param offset The offset value received from the manager.
        /// @return changed=true if the offset advanced; pending/pendingOffset reflect the
        ///         resulting state regardless of whether this call itself changed anything.
        VdOffsetObserveResult observeVdFeedOffset(uint64_t offset);

        /// @brief Clear the pending re-scan flag, but only if it is still pending for exactly
        /// this offset. A stale confirmation (nothing pending, or a newer offset has since
        /// superseded this one) is a no-op -- the pending flag must only ever be cleared by a
        /// matching /scan/vd 200 OK, never by a 409 or transport failure.
        /// @param offset The offset the caller's /scan/vd request succeeded for.
        /// @return true if the pending flag was actually cleared.
        bool clearVdRescanPending(uint64_t offset);

        /// @brief Current durable VD feed state. Used both to answer an IPC recovery query
        /// (agentd resuming a pending re-scan after its own restart) and internally by
        /// populateAgentMetadata() to feed Start.feed_offset.
        VdFeedState getVdFeedState();

    private:
        /// @brief Determine if a stateless event should be generated based on changed fields
        /// @param result Type of change (INSERTED, MODIFIED, DELETED)
        /// @param data Event data
        /// @param table Table name
        /// @return true if stateless event should be generated, false otherwise
        bool shouldGenerateStatelessEvent(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table) const;

        /// @brief Categorize metadata changes to determine sync flag routing
        /// Sets m_clusterNameChanged as side effect; returns true if non-cluster metadata changed
        /// @param result Type of change (INSERTED, MODIFIED, DELETED)
        /// @param data Event data from DBSync callback
        /// @return true if non-cluster-name, non-cluster-node metadata changed
        bool categorizeMetadataChanges(ReturnTypeCallback result, const nlohmann::json& data);

        /// @brief Update the global metadata provider with current agent metadata
        /// @param agentMetadata Agent metadata JSON
        /// @param groups List of agent groups
        void updateMetadataProvider(const nlohmann::json& agentMetadata, const std::vector<std::string>& groups);

        /// @brief Clamp a delay value to be non-negative (shared by the poll-delay setters).
        static int clampNonNegative(int delayMs)
        {
            return delayMs < 0 ? 0 : delayMs;
        }

        /// @brief Result of probing FIM for pause completion
        /// Deferred means FIM's first sync is still in progress: the caller must not
        /// treat this as an error, must resume FIM, and must retry next cycle.
        enum class PauseProbeResult { Completed, Deferred, Failed };

        /// @brief Result of a module coordination cycle. Deferred is distinct from
        /// Failed so the caller can retry quietly (no WARNING) and keep the sync flag set.
        enum class CoordinationResult { Success, Deferred, Failed };

        /// @brief Result of pausing the coordination modules.
        enum class PauseCoordinationResult { Success, Deferred, Failed };

        /// @brief Coordinate modules for version synchronization
        /// This method manages the coordination process: pause, flush, sync versions, set version, sync table, resume
        /// @param table Table name (AGENT_METADATA_TABLE or AGENT_GROUPS_TABLE)
        /// @return CoordinationResult: Success, Deferred (FIM first sync in progress, retry), or Failed
        CoordinationResult coordinateModules(const std::string& table);

        /// @brief Get the create statement for the database
        std::string GetCreateStatement() const;

        /// @brief Populate agent metadata table
        void populateAgentMetadata();

        /// @brief Read agent ID and name from client.keys file
        /// @param agentId Output parameter for agent ID
        /// @param agentName Output parameter for agent name
        /// @return true if successful, false otherwise
        bool readClientKeys(std::string& agentId, std::string& agentName) const;

        /// @brief Read agent groups from merged.mg file
        /// @return Vector of group names
        std::vector<std::string> readAgentGroups() const;

        /// @brief Update changes in database and emit events
        /// @param table Table name
        /// @param values Values to sync
        /// @return true if changes detected, false otherwise
        bool updateChanges(const std::string& table, const nlohmann::json& values);

        /// @brief Update db_metadata table with current in-memory state
        void updateDbMetadata();

        /// @brief Set sync flag in database for a specific table
        /// @param table Table name (AGENT_METADATA_TABLE or AGENT_GROUPS_TABLE)
        /// @param value Flag value (true/false)
        void setSyncFlag(const std::string& table, bool value);

        /// @brief Load sync flags from database to memory
        void loadSyncFlags();

        /// @brief Reset sync flag for a specific table in database and memory
        /// @param table Table name (AGENT_METADATA_TABLE or AGENT_GROUPS_TABLE)
        void resetSyncFlag(const std::string& table);

        /// @brief Check if integrity check should be performed for a table
        /// @param table Table name (AGENT_METADATA_TABLE or AGENT_GROUPS_TABLE)
        /// @param integrityInterval Integrity check interval in seconds
        /// @return true if integrity check should be performed
        bool shouldPerformIntegrityCheck(const std::string& table, int integrityInterval);

        /// @brief Update last integrity check time for a table
        /// @param table Table name (AGENT_METADATA_TABLE or AGENT_GROUPS_TABLE)
        void updateLastIntegrityTime(const std::string& table);

        /// @brief Perform delta synchronization for a table
        /// @param table Table name (AGENT_METADATA_TABLE or AGENT_GROUPS_TABLE)
        /// @return true if successful
        bool performDeltaSync(const std::string& table);

        /// @brief Perform integrity check synchronization for a table
        /// @param table Table name (AGENT_METADATA_TABLE or AGENT_GROUPS_TABLE)
        /// @return true if successful
        bool performIntegritySync(const std::string& table);

        /// @brief Helper to create JSON command messages
        /// @param command Command name
        /// @param params Optional parameters map
        /// @return JSON command string
        std::string createJsonCommand(const std::string& command,
                                      const std::map<std::string, nlohmann::json>& params = {}) const;

        /// @brief Helper to query module with retries and error handling
        /// @param moduleName Module name
        /// @param jsonMessage JSON message to send
        /// @return Module response with parsed information
        ModuleResponse queryModuleWithRetry(const std::string& moduleName, const std::string& jsonMessage);

        /// @brief Helper to resume all paused modules
        /// @param pausedModules Set of paused module names to resume
        void resumePausedModules(const std::set<std::string>& pausedModules);

        /// @brief Poll FIM module for pause completion
        /// @param moduleName Module name (should be FIM)
        /// @return Completed (pause acknowledged), Deferred (FIM first sync still running,
        ///         caller should defer coordination), or Failed (timeout/error/shutdown)
        PauseProbeResult pollFimPauseCompletion(const std::string& moduleName);

        /// @brief Query a coordination module for whether its first synchronization has completed.
        /// @param moduleName Module name (e.g. sca, syscollector).
        /// @return false when the module reports first_sync_completed=0 or has not recorded a
        ///         completed first sync yet (metadata unset = still in progress); true otherwise
        ///         (already synced, or sync disabled — the module reports completed — or the module
        ///         did not answer at all), so coordination is never wedged on a module that will not sync.
        bool isModuleFirstSyncCompleted(const std::string& moduleName);

        /// @brief Query syscollector for whether its VD (Vulnerability Detection) VDFirst
        /// synchronization has completed. Mirrors isModuleFirstSyncCompleted's fail-open
        /// contract: an unreachable/unparseable response is treated as "done" so a syscollector
        /// hiccup cannot permanently wedge re-scan requests.
        /// @return false only when syscollector explicitly reports VDFirst not yet completed.
        bool isVDFirstSyncDone();

        /// @brief Read the single-row `vd_feed_state` table. Caller must hold m_dbSyncMutex and
        /// have already verified m_dBSync is non-null. Returns a default-constructed (all-unset)
        /// state if the row does not exist yet (fresh database).
        VdFeedState readVdFeedStateLocked() const;

        /// @brief Upsert the single-row `vd_feed_state` table. Caller must hold m_dbSyncMutex and
        /// have already verified m_dBSync is non-null.
        void writeVdFeedStateLocked(const VdFeedState& state);

        /// @brief Poll all requested module flushes until completion.
        /// @param pendingModules Set of modules with an accepted flush request.
        /// @return true if all flushes completed successfully, false otherwise.
        bool pollFlushCompletion(std::set<std::string> pendingModules);

        /// @brief Pause all coordination modules
        /// @param pausedModules Output parameter for successfully paused modules
        /// @return Success, Deferred (FIM first sync in progress; modules resumed, retry next cycle), or Failed
        PauseCoordinationResult pauseCoordinationModules(std::set<std::string>& pausedModules);

        /// @brief Trigger flush on all paused modules (fire-and-forget, does not wait for completion)
        /// @param pausedModules Set of paused modules to flush
        /// @return true if all flush IPCs were sent successfully, false otherwise
        bool triggerModuleFlush(const std::set<std::string>& pausedModules);

        /// @brief Get versions from all paused modules and calculate new version
        /// @param pausedModules Set of paused modules
        /// @param incrementVersion Whether to increment version (true for metadata, false for groups)
        /// @param moduleVersions Output parameter for module versions
        /// @return Calculated new version, or -1 on error
        int calculateNewVersion(const std::set<std::string>& pausedModules,
                                bool incrementVersion,
                                std::map<std::string, int>& moduleVersions);

        /// @brief Pointer to IDBSync
        std::shared_ptr<IDBSync> m_dBSync;

        /// @brief Pointer to ISysInfo for system information gathering
        std::shared_ptr<ISysInfo> m_sysInfo;

        /// @brief Pointer to IFileIOUtils for file I/O operations
        std::shared_ptr<IFileIOUtils> m_fileIO;

        /// @brief Pointer to IFileSystemWrapper for file system operations
        std::shared_ptr<IFileSystemWrapper> m_fileSystem;

        /// @brief Function to report stateless diffs
        std::function<void(const std::string&)> m_reportDiffFunction;

        /// @brief Function to log messages
        std::function<void(const modules_log_level_t, const std::string&)> m_logFunction;

        /// @brief Function to query other modules
        module_query_callback_t m_queryModuleFunction;

        /// @brief Function to query agentd for fresh handshake data (cluster_name,
        /// agent_groups) on every populateAgentMetadata() cycle, instead of a one-time cached copy.
        /// Only cluster_name is tracked from it - see populateAgentMetadata() for why
        /// agent_groups deliberately keeps its own, separate one-shot-at-startup handling.
        handshake_query_callback_t m_handshakeQueryFunction;

        /// @brief True once a live handshake query has succeeded at least once. Until then,
        /// populateAgentMetadata() falls back to the C-side startup cache; afterwards, a
        /// transient live-query failure falls back to these last-known-good values instead
        /// of reverting all the way back to the (possibly long-stale) startup cache.
        bool m_hasLiveHandshakeSucceededOnce = false;

        /// @brief Last successfully live-queried cluster_name
        std::string m_lastLiveClusterName;

        /// @brief Sync protocol for agent synchronization
        std::unique_ptr<IAgentSyncProtocol> m_spSyncProtocol;

        /// @brief Flag to track if module has been stopped.
        /// Atomic so the poll loops can read it without holding m_mutex while
        /// stop() writes it from another thread (avoids a data race).
        std::atomic<bool> m_stopped{false};

        /// @brief Predicate reporting whether a shutdown is in progress (may be null).
        /// Injected from the module wrapper; reports the *global* agent shutdown, which is
        /// signaled before this module's own stop() runs.
        std::function<bool()> m_isShuttingDown;

        /// @brief True when this module is stopping OR a global shutdown is in progress.
        /// Used to demote expected shutdown-time failures from WARNING to DEBUG.
        bool isShutdownInProgress() const
        {
            return m_stopped || (m_isShuttingDown && m_isShuttingDown());
        }

        /// @brief Delay in milliseconds between flush completion polls (10 seconds in production).
        /// Overridable in unit tests to avoid real sleeps.
        int m_flushPollDelayMs = 10000;

        /// @brief Delay in milliseconds between FIM pause completion polls (1 second in production).
        /// Overridable in unit tests to avoid real sleeps.
        int m_pausePollDelayMs = 1000;

        /// @brief Modules whose current deferral streak has logged its INFO line, so
        /// repeated deferrals during the same first sync stay at DEBUG. Tracked per
        /// module: FIM's probe runs (and ends its episode) every cycle before
        /// SCA/syscollector are evaluated, so a shared flag would be cleared each cycle
        /// and re-emit the INFO for the whole duration of their first sync.
        /// A module is erased when its deferral episode ends: it reports the first sync
        /// is complete, or (FIM) the probe gives up (timeout/IPC failure) without
        /// deferring.
        std::set<std::string> m_deferralLoggedModules;

        /// @brief Condition variable for efficient sleep/wake mechanism
        std::condition_variable m_cv;

        /// @brief Mutex for condition variable synchronization
        std::mutex m_mutex;

        /// @brief Flag indicating if metadata needs to be synchronized
        bool m_shouldSyncMetadata = false;

        /// @brief Flag indicating if groups need to be synchronized
        bool m_shouldSyncGroups = false;

        /// @brief Last metadata integrity check timestamp (Unix epoch seconds)
        int64_t m_lastMetadataIntegrity = 0;

        /// @brief Last groups integrity check timestamp (Unix epoch seconds)
        int64_t m_lastGroupsIntegrity = 0;

        /// @brief Flag indicating if this is the first run (database just created)
        bool m_isFirstRun = true;

        /// @brief Flag indicating if this is the first groups run (first population with data)
        bool m_isFirstGroupsRun = true;

        /// @brief Mutex for synchronizing access to sync flags
        std::mutex m_syncFlagsMutex;

        /// @brief Mutex for synchronizing access to m_dBSync (prevents race conditions during cleanup/transactions)
        std::mutex m_dbSyncMutex;

        /// @brief Serializes destruction of m_spSyncProtocol in stop()
        std::mutex m_syncProtocolMutex;

        /// @brief Clean-stop handshake: stop() blocks until the run loop (start()) has
        /// exited, so the sync-protocol connection can be closed with no other thread
        /// using it.
        std::mutex m_shutdownMutex;
        std::condition_variable m_shutdownCv;
        bool m_runLoopActive = false;

        /// @brief Flag set during updateChanges callback when cluster_name changed
        bool m_clusterNameChanged = false;

        /// @brief Task registry cleanup bounds (see setTaskRegistryLimits()), read once per
        /// start()'s loop iteration. Defaults match the internal_options.conf defaults
        /// (agent_info.ttl / agent_info.max_entries) so a call to start() before
        /// setTaskRegistryLimits() still behaves sanely rather than pruning everything.
        uint32_t m_taskRegistryTtlSeconds = 86400;
        uint32_t m_taskRegistryMaxEntries = 4096;
};
