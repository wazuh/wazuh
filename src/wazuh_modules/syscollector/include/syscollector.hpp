/*
 * Wazuh SysCollector
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYSCOLLECTOR_HPP
#define _SYSCOLLECTOR_HPP
#include <chrono>
#include <thread>
#include <condition_variable>
#include <mutex>
#include <shared_mutex>
#include <memory>
#include <optional>
#include <atomic>
#include <set>

#include "sysInfoInterface.h"
#include "commonDefs.h"
#include "dbsync.hpp"
#include "syscollectorNormalizer.hpp"
#include "syscollector.h"
#include "syscollector_defs.hpp"
#include "asyncFlushController.hpp"
#include "agent_sync_protocol_types.hpp"
#include "iagent_sync_protocol.hpp"

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

/// What a turn of the scan loop should do about the container pass.
struct ContainerPassDecision
{
    bool run{false};
    /// Scan only what changed. False means walk the whole node.
    bool delta_only{false};
    /// Move the scheduled deadline forward.
    bool advance_deadline{false};
};

/// Decides a container pass from the two things that can ask for one.
///
/// Separated from the loop because the rule it encodes is easy to lose in a
/// refactor and expensive to lose in production: a notification must NEVER
/// defer the scheduled pass. That pass is the reconciliation floor — the only
/// thing that re-establishes what is actually on the node, since no delta can
/// report a container the module itself never learned about — and a host with
/// a steady trickle of container churn would otherwise postpone it for ever,
/// which is precisely when it is most wanted.
[[nodiscard]] inline ContainerPassDecision decideContainerPass(bool scheduled, bool requested)
{
    ContainerPassDecision decision;

    decision.run = scheduled || requested;
    // Scheduled wins when both are true: the thorough pass subsumes the
    // targeted one, so doing both would be waste.
    decision.delta_only = !scheduled;
    decision.advance_deadline = scheduled;

    return decision;
}

class EXPORTED Syscollector final
{
    public:
        static Syscollector& instance()
        {
            static Syscollector s_instance;
            return s_instance;
        }

        using AgentdQueryFunc = std::function<bool(const char*, char*, size_t)>;

        void init(const std::shared_ptr<ISysInfo>& spInfo,
                  const std::function<void(const std::string&)> reportDiffFunction,
                  const std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> persistDiffFunction,
                  const std::function<void(const modules_log_level_t, const std::string&)> logFunction,
                  const std::string& dbPath,
                  const std::string& normalizerConfigPath,
                  const std::string& normalizerType,
                  const unsigned int inverval = 3600ul,
                  const bool scanOnStart = true,
                  const bool hardware = true,
                  const bool os = true,
                  const bool network = true,
                  const bool packages = true,
                  const bool ports = true,
                  const bool portsAll = true,
                  const bool processes = true,
                  const bool hotfixes = true,
                  const bool groups = true,
                  const bool users = true,
                  const bool services = true,
                  const bool browserExtensions = true,
                  const bool notifyOnFirstScan = false,
                  // Appended after notifyOnFirstScan, never inserted before it.
                  // Every caller here passes these positionally, so slotting a
                  // new parameter in front of an existing one silently rebinds
                  // every argument after it -- which is exactly how
                  // notifyOnFirstScan once ended up reading containerBaseline's
                  // value and left the first scan reporting no deltas at all.
                  const bool containerBaseline = true,
                  // 0 = share the host scan interval, which is what the
                  // container pass did before it had a cadence of its own.
                  const unsigned int containerBaselineInterval = 0);

        /**
         * @brief Set agentd query function for agentd communication (cross-platform)
         *
         * This function is used to send commands to agentd and receive JSON responses.
         * Works on both Unix/Linux (socket) and Windows (agcom_dispatch).
         * Should be set before calling start().
         *
         * @param queryFunc Function to query agentd (returns JSON string or nullptr)
         */
        void setAgentdQueryFunction(AgentdQueryFunc queryFunc);

        void start();
        void quiesce();
        void releaseResources();

        /**
         * @brief Signal stop, then release resources synchronously if the scan isn't busy.
         *
         * Must be called from the same thread that called start(), since releaseResources()
         * releases per-thread resources (e.g. the Windows hotfixes() COM context) on the
         * calling thread. Calling this from a different thread releases the wrong thread's
         * resources and leaves start()'s thread never explicitly released.
         */
        void destroy();

        /// Waits on container_instances' lifecycle notifications and brings the
        /// next container pass forward when one arrives -- without moving the
        /// host scan, which keeps its own deadline. Runs until m_stopping.
        void containerNotifyLoop();

        /// Inventories only what container_instances reports as changed since
        /// the last read, rather than walking every container.
        ///
        /// Returns false when it could not be used — nothing was learned, or
        /// the cursor could not be served — and the caller must fall back to a
        /// full pass. It deliberately does NOT fall back itself: a full pass is
        /// the expensive thing, and the decision to pay for it belongs where
        /// the cadence is known.
        bool scanContainerBaselineDelta();

        /// Emits DELETED events for exactly these containers' rows.
        /// Counterpart to sweepContainerRowsNotIn(), for when the set that has
        /// gone is known directly rather than by absence from a list.
        std::size_t sweepContainerRows(const std::vector<std::string>& container_ids);

        // Sync protocol methods
        void initSyncProtocol(const std::string& moduleName, const std::string& syncDbPath, const std::string& syncDbPathVD,
                              uint32_t integrityInterval);

        SyncModuleResult syncModule(Mode mode);
        void persistDifference(const std::string& id, Operation operation, const std::string& index, const std::string& data, uint64_t version, bool isDataContext = false);
        bool parseResponseBuffer(const uint8_t* data, size_t length);
        bool parseResponseBufferVD(const uint8_t* data, size_t length);
        bool notifyDataClean(const std::vector<std::string>& indices);
        void deleteDatabase();
        std::string query(const std::string& jsonQuery);
        bool notifyDisableCollectorsDataClean();
        void deleteDisableCollectorsData();

        // Mutex access for external synchronization (e.g., from wm_sync_module)
        void lockScanMutex();
        void unlockScanMutex();
        bool isScanning() const
        {
            return m_scanning.load();
        }

        // Recovery functions
        void runRecoveryProcess();

    private:
        SYSCOLLECTOR_FRIEND_TEST_DECLARATIONS;

        Syscollector();
        ~Syscollector() = default;
        Syscollector(const Syscollector&) = delete;
        Syscollector& operator=(const Syscollector&) = delete;

        std::string getCreateStatement() const;
        nlohmann::json getOSData();
        nlohmann::json getHardwareData();
        nlohmann::json getNetworkData();
        nlohmann::json getPortsData();
        nlohmann::json getGroupsData();
        nlohmann::json getUsersData();
        nlohmann::json getServicesData();
        nlohmann::json getBrowserExtensionsData();

        std::pair<nlohmann::json, uint64_t> ecsData(const nlohmann::json& data, const std::string& table, bool createFields = true);
        nlohmann::json ecsSystemData(const nlohmann::json& originalData, bool createFields = true);

        /**
         * @brief Fetches all items from a VD table (OS, Packages, or Hotfixes) excluding specified IDs
         * @param tableName Name of the table to query ("dbsync_osinfo", "dbsync_packages", "dbsync_hotfixes")
         * @param excludeIds Set of hash IDs to exclude from results (items already in DataValue)
         * @param forceAll If true, fetch all records regardless of document limits (ignores sync flag)
         * @return Vector of JSON objects representing all rows in the table (excluding specified IDs)
         */
        std::vector<nlohmann::json> fetchAllFromTable(const std::string& tableName, const std::set<std::string>& excludeIds, bool forceAll = false);

        /**
         * @brief Determines which DataContext items to include based on platform-specific rules
         * @param operation The operation type (CREATE, MODIFY, DELETE_)
         * @param index The index being modified (system, packages, hotfixes)
         * @return Vector of table names that should be included as DataContext
         */
        std::vector<std::string> getDataContextTables(Operation operation, const std::string& index);

        /**
         * @brief Checks if the first VD sync has been completed.
         * @details The state is persisted in @c table_metadata under the
         *          @c vd_first_sync_completed key as an epoch-seconds timestamp;
         *          any value > 0 means the first VD sync already completed.
         * @return true if first VD sync is done, false if this is the first scan (VDFIRST)
         */
        bool isVDFirstSyncDone();

        /// @brief Body of deleteDatabase() without taking m_resourcesMutex.
        /// @note The caller must already hold m_resourcesMutex. Exists so callers that
        /// already hold it shared do not acquire it a second time on the same thread.
        void deleteDatabaseUnlocked();
        void persistVDFirstSyncIfNeeded(const bool vdResult, const bool firstSyncDone);

        /**
         * @brief Synchronizes the VD tables (system, packages and hotfixes) and persists the
         *        VDFirst marker when the session succeeds.
         * @details Picks the sync option that fits the current state: SYNC when the agent's own
         *          collectors rule VD scanning out, VDFIRST/VDSYNC otherwise. The session is
         *          sent regardless of the VD feed offset the agent has heard about; what to do
         *          with one built against an offset the node does not have is the manager's
         *          decision.
         * @param mode Synchronization mode to use for the session.
         * @return The result of the session.
         */
        SyncModuleResult synchronizeVDTables(const Mode mode);
        /**
         * @brief Processes VD DataContext after scan completes
         * @details Queries the VD sync protocol database for pending DataValue items,
         *          applies platform-specific rules to determine what DataContext to include,
         *          and submits the DataContext items to the sync protocol
         */
        void processVDDataContext();
        nlohmann::json ecsHardwareData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsHotfixesData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsPackageData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsProcessesData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsPortData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsNetworkInterfaceData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsNetworkProtocolData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsNetworkAddressData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsUsersData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsGroupsData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsServicesData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsBrowserExtensionsData(const nlohmann::json& originalData, bool createFields = true);

        std::string getPrimaryKeys(const nlohmann::json& data, const std::string& table);
        std::string calculateHashId(const nlohmann::json& data, const std::string& table);
        nlohmann::json addPreviousFields(nlohmann::json& current, const nlohmann::json& previous);

        // containerId scopes the transaction's delete detection ("" = host rows).
        // notifyOverride, when set, replaces m_notify for this call's stateless
        // alert decision — used to keep a container's first-ever sync quiet
        // (like today's one-shot baseline) even once later intervals have
        // already flipped m_notify to true for everything else.
        // detectDeletions must be false when `values` is known to be an
        // INCOMPLETE view of the scope (a container whose baseline scan was
        // capped, or whose namespace could not be read): the scoped
        // transaction would otherwise report every row the partial scan did
        // not refresh as DELETED, turning a truncated scan into a flood of
        // false deletions.
        void updateChanges(const std::string& table,
                           const nlohmann::json& values,
                           const std::string& containerId = "",
                           std::optional<bool> notifyOverride = std::nullopt,
                           bool detectDeletions = true);
        void notifyChange(ReturnTypeCallback result,
                          const nlohmann::json& data,
                          const std::string& table,
                          bool notify);
        void processEvent(ReturnTypeCallback result,
                          const nlohmann::json& data,
                          const std::string& table,
                          bool notify);

        void scanHardware();
        void scanOs();
        void scanNetwork();
        void scanPackages();
        void scanHotfixes();
        void scanPorts();
        void scanProcesses();
        void scanGroups();
        void scanUsers();
        void scanServices();
        void scanBrowserExtensions();
        /// @brief Baseline inventory for every container currently known to the
        /// container-connector module (spike #37532, Option A: baseline through the
        /// host event flow). Rows are produced by the container_baseline module in
        /// dbsync_* column format and pushed through per-container scoped DBSync
        /// transactions, so the shared notifyChange/processEvent pipeline computes
        /// deltas and emits stateless + stateful events exactly as for host rows.
        /// See container_baseline_scanner.hpp.
        /// @param only_these   Containers to inventory; empty means the whole
        ///                     node. A delta pass names what changed.
        /// @param sweep_absent Whether absence from the connector's list may be
        ///                     read as removal. Only true for a whole-node
        ///                     pass: on a partial one, every container not
        ///                     visited looks absent, which is most of them.
        void scanContainerBaseline(const std::vector<std::string>& only_these = {}, bool sweep_absent = true);

        /// @brief scanContainerBaseline() with the stopping/paused checks and
        /// the ScanGuard that scan() would otherwise have supplied. Used only
        /// by syncLoop(), when <container_baseline_interval> gives the
        /// container pass a cadence of its own.
        /// @param delta_only Scan only what container_instances reports as
        ///                   changed. Falls back to a whole-node pass when the
        ///                   delta cannot be served — declining to read what
        ///                   changed is not evidence that nothing did.
        void runContainerBaselinePass(bool delta_only = false);

        /// @brief Delete the rows of every container in the DB but absent from
        /// `keep`, emitting DELETED events. `keep` is the set that still
        /// EXISTS, never the set that produced rows — a stopped container
        /// produces no rows yet must keep its state. An empty set removes all
        /// container rows.
        /// @return Number of containers swept.
        std::size_t sweepContainerRowsNotIn(const std::set<std::string>& keep);
        void scan();
        void syncLoop(std::unique_lock<std::mutex>& scan_lock);
        bool pause();
        void resume();
        int flush();
        int executeFlushSync();
        int getMaxVersion();
        int setVersion(int version);

        void setJsonField(nlohmann::json& target,
                          const nlohmann::json& source,
                          const std::string& keyPath,
                          const std::string& jsonKey,
                          bool createFields,
                          bool is_boolean = false);
        void setJsonFieldArray(nlohmann::json& target,
                               const nlohmann::json& source,
                               const std::string& destPath,
                               const std::string& sourceKey,
                               bool createFields);
        void setJsonFieldArrayFromJsonString(nlohmann::json& target,
                                             const nlohmann::json& source,
                                             const std::string& destPath,
                                             const std::string& sourceKey,
                                             bool createFields);

        bool hasDataInTable(const std::string& tableName);
        void checkDisabledCollectorsIndicesWithData();
        void clearTablesForIndices(const std::vector<std::string>& indices);
        bool handleNotifyDataClean();

        /**
         * @brief Whether any disabled collector still has data the manager must be told to clean.
         */
        bool hasDisabledCollectorsData();

        // Recovery functions
        /**
         * @brief Checks if a full sync is required by calculating the checksum-of-checksums for a table and comparing it with the manager's
         * @param table_name The table to check
         * @returns MISMATCH if a full sync is required, VALID if a delta sync is sufficient, NOT_CHECKED
         *          (with the reason) if the check did not complete.
         */
        IntegrityCheckResult checkIfFullSyncRequired(const std::string& tableName);

        /**
         * @brief Get a metadata value from table_metadata.
         *
         * @param key Metadata key to query.
         * @param value Output value. Defaults to 0 when the key is absent.
         * @return true on success, false on error.
         */
        bool getMetadataValue(const std::string& key, int64_t& value);

        /**
         * @brief Update a metadata value in table_metadata.
         *
         * @param key Metadata key to update.
         * @param value Value to persist.
         * @return true on success, false on error.
         */
        bool updateMetadataValue(const std::string& key, int64_t value);

        /**
         * @brief Get the last_sync_time for a given table.
         *
         * @param tableName Name of the table to query.
         * @return int64_t The last sync timestamp (UNIX format), or 0 if not found.
         */
        int64_t getLastSyncTime(const std::string& tableName);

        /**
         * @brief Update the last_sync_time for a given table.
         *
         * @param tableName Name of the table to update.
         * @param timestamp The sync timestamp to set (UNIX format).
         */
        void updateLastSyncTime(const std::string& tableName, int64_t timestamp);

        /**
         * @brief Check if the integrity interval has elapsed for a given table.
         *
         * @param tableName Name of the table to check.
         * @param integrityInterval Integrity check interval in seconds.
         * @return true if interval has elapsed, false otherwise.
         */
        bool recoveryIntervalHasEllapsed(const std::string& tableName, int64_t integrityInterval);

        /**
         * @brief Whether a re-send of this index must be restricted to sync=1.
         *
         * The three paths that re-send an index wholesale -- the data-context
         * fetch, the checksum, and the recovery resync -- have to withhold the
         * same rows the scan withheld, or a row that was deliberately never
         * reported reaches the manager by the back door, and the cap holds only
         * until the next checksum mismatch.
         *
         * True when ANY mechanism can leave a row at sync=0: the host budget,
         * the per-container budget, or the container-count cap. Asking only the
         * host budget was the defect -- it ships at 0, so these paths took the
         * unfiltered branch on exactly the default configuration.
         */
        bool syncFilterRequired(const std::string& index);

        /**
         * @brief Which population of rows a document limit applies to.
         *
         * Host rows and container rows land in the SAME sync index, so with one
         * budget a node running fifty containers can spend the whole
         * `processes` cap on container processes and starve the host's own —
         * with which rows survive decided by scan order and the promotion
         * query's ORDER BY. They therefore get separate limits and separate
         * counters, and every count/promote query is scoped to one of them
         * (#37532 / #37534).
         */
        enum class LimitScope
        {
            host,      ///< container_id = '' — the agent's own rows
            container  ///< container_id <> '' — rows attributed to a container
        };

        /**
         * @brief SQL predicate selecting one scope's rows, to be appended to an
         *        existing WHERE clause.
         *
         * A container budget is PER CONTAINER (#37532 / O10), so a query that
         * spends one must name its container. Omitting the id selects every
         * container's rows, which is right for "how many container rows exist"
         * and wrong for anything that spends a budget.
         *
         * @param scope Scope to filter for.
         * @param containerId One container, or empty for the whole scope.
         * @return " AND container_id=''", " AND container_id<>''" or
         *         " AND container_id='<id>'".
         */
        static std::string scopeFilter(LimitScope scope, const std::string& containerId = {});

        /**
         * @brief Record which containers may report, from one connector reply.
         *
         * @param discovered Every known container, mapped to its verdict.
         *
         * Call only when the connector actually answered. A failed query
         * reports no containers, and taking that as "nothing is admitted"
         * would withhold every container's rows on a momentary blip -- the
         * same class of mistake as sweeping against an empty list, differing
         * only in being recoverable.
         */
        void setAdmittedContainers(const std::map<std::string, bool>& discovered);

        /**
         * @brief Whether a container may report. Caller must hold m_limitsMutex.
         *
         * True for the host scope (an empty id is not a container) and true
         * for every container until a connector reply says otherwise.
         */
        bool isContainerAdmittedLocked(const std::string& containerId) const;

        /**
         * @brief The limits map for a scope. Caller must hold m_limitsMutex.
         */
        std::map<std::string, size_t>& limitsFor(LimitScope scope);

        /**
         * @brief One scope's count for one index. Caller must hold m_limitsMutex.
         *
         * Host counts key on the index alone; container counts key on
         * (container, index), because the budget each row spends is its own
         * container's.
         */
        size_t& countFor(LimitScope scope, const std::string& index, const std::string& containerId);

        /**
         * @brief Container ids with at least one row in a table.
         *
         * The set a per-container budget has to iterate: taken from the rows
         * themselves rather than from the live container list, so a container
         * that still holds rows is still accounted for even once it is gone.
         *
         * @param unsyncedOnly Only containers with at least one withheld
         *                     (sync=0) row: the ones post-scan promotion can act on.
         */
        std::set<std::string> containersWithRowsIn(const std::string& tableName, bool unsyncedOnly = false);

        /**
         * @brief How many collected rows are being held back in one scope.
         *
         * Rows with sync=0: collected, stored, and not reported to the manager
         * because the scope is at its limit. Caller must hold m_limitsMutex.
         */
        size_t unsyncedCountFor(const std::string& tableName,
                                LimitScope scope,
                                const std::string& containerId);

        /**
         * @brief Drops a container's document counts once its rows are gone.
         *
         * Takes m_limitsMutex itself, so it must NOT be called with the lock
         * already held.
         */
        void releaseContainerCounts(const std::string& containerId);

        /**
         * @brief Validates a JSON message against schema and logs validation errors
         *
         * This helper function encapsulates the common pattern of schema validation
         * used across different parts of syscollector. It validates the message against
         * the schema for the given index and logs detailed error messages if validation fails.
         *
         * @param data JSON string to validate
         * @param index Index name for schema lookup (e.g., "wazuh-states-inventory-packages")
         * @param context Context string for logging (e.g., "table: dbsync_packages")
         * @return true if validation passed or validator not initialized, false if validation failed
         */
        bool validateSchemaAndLog(const std::string& data, const std::string& index, const std::string& context) const;

        /**
         * @brief Deletes failed items from DBSync in a batch transaction
         *
         * This helper function encapsulates the common pattern of deleting items that failed
         * schema validation. It uses a DBSync transaction to ensure all deletions are atomic
         * and properly committed to disk.
         *
         * @param failedItems Vector of (table_name, json_data) pairs to delete
         */
        void deleteFailedItemsFromDB(const std::vector<std::pair<std::string, nlohmann::json>>& failedItems) const;

        /**
         * @brief Updates sync flag for items in database
         *
         * This helper function updates the sync flag (0 or 1) for all items in the vector.
         * It uses a DBSync transaction to ensure all updates are atomic and properly committed to disk.
         *
         * @param itemsToUpdate Vector of (table_name, json_data) pairs to update
         * @param syncValue Value to set for sync flag (0 or 1)
         */
        void updateSyncFlagInDB(const std::vector<std::pair<std::string, nlohmann::json>>& itemsToUpdate, int syncValue) const;

        /**
         * @brief Promotes unsynced items with deterministic ordering
         *
         * Selects up to maxToPromote items with sync=0, ordered by the table's ordering fields
         * (using ORDER BY with COLLATE NOCASE), generates INSERT events, and marks them as sync=1.
         * Used by both setDocumentLimits and promoteItemsAfterScan to avoid code duplication.
         *
         * @param index Index name (e.g., "packages")
         * @param tableName Table name (e.g., "dbsync_packages")
         * @param maxToPromote Maximum number of items to promote
         * @param reason Descriptive reason for logging purposes
         * @return Number of items actually promoted
         */
        size_t promoteUnsyncedItems(const std::string& index,
                                    const std::string& tableName,
                                    size_t maxToPromote,
                                    const std::string& reason,
                                    LimitScope scope,
                                    const std::string& containerId = {});

        /**
         * @brief Promotes items after scan to fill available slots
         *
         * After a scan completes, calculates available space (limit - currentCount) for each index
         * and promotes unsynced items with deterministic ordering to fill those slots.
         * Uses the database as source of truth for current counts (m_documentCounts already reflects deletes).
         * Generates INSERT events for promoted items and marks them as sync=1.
         */
        void promoteItemsAfterScan();

        /**
         * @brief One scope's half of promoteItemsAfterScan(). Caller must hold
         *        m_limitsMutex.
         */
        void promoteItemsAfterScanLocked(LimitScope scope);

        /**
         * @brief Gets simplified ordering fields for a table
         *
         * Returns the field(s) to use for simplified ordering when managing document limits.
         * Most tables use only the first PK field, but some (like packages) use multiple
         * fields for more stable ordering (e.g., "name, type").
         *
         * @param tableName Name of the table (e.g., "dbsync_packages")
         * @return Ordering field(s) as string (e.g., "name, type"), empty if table unknown
         */
        std::string getFirstPrimaryKeyField(const std::string& tableName) const;

        /**
         * @brief Builds ORDER BY clause with COLLATE NOCASE for case-insensitive ordering
         *
         * Constructs an ORDER BY clause from comma-separated field names with COLLATE NOCASE
         * for case-insensitive ordering. This ensures consistent ordering across different cases.
         *
         * @param fields Comma-separated field names (e.g., "name, type")
         * @param ascending True for ASC order (default), false for DESC order
         * @return ORDER BY clause string (e.g., "name COLLATE NOCASE, type COLLATE NOCASE ASC")
         */
        std::string buildOrderByClause(const std::string& fields, bool ascending = true) const;

        /**
         * @brief Sets document limits for configured indices
         *
         * @param limits JSON object mapping index names to limit values (0 = unlimited)
         * @return true if limits were set successfully, false otherwise
         */
        bool setDocumentLimits(const nlohmann::json& limits);

        /**
         * @brief Applies one index's new limit within one scope: adjusts the
         *        stored count, promotes unsynced rows into new space, and emits
         *        DELETE events for rows a reduced limit no longer admits.
         *
         * Factored out of setDocumentLimits() so the host and container budgets
         * run identical logic against their own rows. Caller must hold
         * m_limitsMutex.
         */
        void applyDocumentLimit(const std::string& index,
                                const std::string& tableName,
                                size_t newLimit,
                                LimitScope scope,
                                const std::string& containerId = {});

        /**
         * @brief Applies one scope's share of agentd's reply.
         *
         * One reply carries both scopes: container caps are spelled
         * `container_<dimension>` and host caps are not, so each pass takes the
         * keys belonging to its own scope and ignores the rest. Short names are
         * then normalised to sync index names and applied to that scope's
         * budget (#37532 / O10).
         */
        bool applyLimitsForScope(const nlohmann::json& limits, LimitScope scope);

        /**
         * @brief Fetches document limits from agentd
         *
         * Queries agentd for document limits configuration for the syscollector module.
         * Sends the command "getdoclimits syscollector" to agentd.
         *
         * Works on both Unix/Linux (via socket) and Windows (via agcom_dispatch).
         *
         * If agentd is not available or limits are not configured for
         * syscollector, returns an empty optional.
         *
         * Expected response format from agentd:
         * "ok {\"wazuh-states-inventory-packages\": 10000, ...}"
         *
         * @return Optional JSON with limits if available, empty optional otherwise
         */
        std::optional<nlohmann::json> fetchDocumentLimitsFromAgentd();

        /**
         * @brief Initializes document counts from database for all tables
         */
        void initializeDocumentCounts();

        /// @brief Picks the sync protocol an index's data belongs on.
        ///
        /// The system, packages and hotfixes indices ride the VD protocol: the manager routes a
        /// VD session through the scan lane, which both indexes the documents and feeds them to
        /// the vulnerability scanner, so sending them on the plain protocol still populates
        /// wazuh-states-inventory-* but silently leaves the scanner with nothing to evaluate.
        /// Every path that hands rows to the manager has to make the same choice, hence one
        /// place to make it.
        ///
        /// @param index Destination index name.
        /// @return The VD protocol for a VD index when one exists, the plain protocol otherwise;
        ///         nullptr if neither is initialized.
        IAgentSyncProtocol* protocolForIndex(const std::string& index) const;

        /// @brief Whether an index's data rides the VD protocol (system, packages, hotfixes).
        static bool isVDIndex(const std::string& index);

        /// @brief Replaces the manager's copy of one table with what this agent currently holds.
        ///
        /// Bumps every row's version, clears the manager's index, re-persists the whole table and
        /// syncs it. Extracted from runRecoveryProcess() so the same work can be driven by more
        /// than one trigger; it makes no decision about *whether* a resync is needed, only about
        /// carrying one out.
        ///
        /// @param tableName Source dbsync table.
        /// @param index Destination index name.
        /// @return false when the table could not be resynced at all (version bump failed, rows
        ///         could not be read, no protocol, or the manager refused the DataClean); when the
        ///         caller tries again is the caller's decision, and @p retryNote says it. A failure
        ///         of the final synchronization itself returns true: the data reached the queue
        ///         and the ordinary sync cycle will drain it.
        /// @param syncNow When false, the table is cleared and re-persisted but no session is
        ///                opened, leaving the caller to send the queue. The identity resync uses
        ///                that for the VD lane: its three indices have to reach the manager in
        ///                one VDFirst session, which is the only one whose scan chain suppresses
        ///                alerts, and each VDFirst session begins by deleting what the previous
        ///                one indexed.
        /// @param retryNote Appended to the message logged when the resync cannot be carried out,
        ///                  saying when the caller will try again.
        bool resyncTableToManager(const std::string& tableName,
                                  const std::string& index,
                                  bool syncNow,
                                  const std::string& retryNote);

        /// @brief Whether the collector that owns a table is enabled in the configuration.
        /// @param tableName dbsync table to check.
        /// @return false when its collector is switched off, so callers iterating INDEX_MAP skip it.
        bool isCollectorEnabledForTable(const std::string& tableName) const;

        /// @brief Re-sends every table when this agent's id has changed since the last sync.
        ///
        /// An agent deleted on the manager re-enrolls under a new id, but its local databases --
        /// including first_sync_completed -- survive untouched, so every later cycle sends a
        /// delta against a baseline the manager no longer has for this identity. Comparing the
        /// id repairs that on the next cycle instead of waiting for integrity_interval to notice
        /// it one table at a time.
        ///
        /// Reads the id from the shared-memory metadata provider, which is the same value, via
        /// the same call, that stamps the outgoing session -- so a resync can never be sent
        /// under an id different from the one it was compared against.
        void checkAgentIdentity();

        /// @brief Whether the agent id differs from the one Syscollector last synchronized as.
        ///
        /// Read-only twin of checkAgentIdentity()'s decision, for the sync thread to poll.
        /// @return 1 when it changed; 0 when it did not, or was never recorded (adopted, not a
        ///         change); -1 when it cannot tell: no id published yet, a failed read, or no sync
        ///         protocol to resend with. The sync thread keeps its retry state on -1.
        int agentIdentityChangeState();

        /// @brief What checkAgentIdentity() and agentIdentityChangeState() both decide on.
        enum class AgentIdentity
        {
            Unknown,    ///< No id published yet, or the marker could not be read.
            Unrecorded, ///< No id recorded yet: adopted, never resynced.
            Unchanged,  ///< Recorded and equal to the current one.
            Changed     ///< Recorded and different: the manager has nothing under this id.
        };

        /// @brief Reads the current and the recorded agent id and classifies them.
        /// @param currentId Set to the id the metadata provider publishes (0 when unknown).
        /// @param syncedId Set to the id last recorded as synchronized (0 when none).
        AgentIdentity readAgentIdentity(long& currentId, int64_t& syncedId);

        /**
         * @brief Checks if document limit has been reached for a given table/index
         *
         * @param table Table name to check
         * @param data JSON data for the record
         * @param result Callback result type (INSERTED, MODIFIED, DELETED)
         * @return true if within limit and should process, false if limit reached
         */
        bool checkDocumentLimit(const std::string& table, const nlohmann::json& data, ReturnTypeCallback result);

        std::shared_ptr<ISysInfo>                                                m_spInfo;
        std::function<void(const std::string&)>                                  m_reportDiffFunction;
        std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> m_persistDiffFunction;
        std::function<void(const modules_log_level_t, const std::string&)>       m_logFunction;

        AgentdQueryFunc                                                          m_agentdQuery;
        unsigned int                                                             m_intervalValue;
        std::atomic<uint32_t>                                                    m_integrityIntervalValue;
        bool                                                                     m_scanOnStart;
        bool                                                                     m_hardware;
        bool                                                                     m_os;
        bool                                                                     m_network;
        bool                                                                     m_packages;
        bool                                                                     m_ports;
        bool                                                                     m_portsAll;
        bool                                                                     m_processes;
        bool                                                                     m_hotfixes;
        std::atomic<bool>                                                        m_stopping;
        bool                                                                     m_initialized;
        bool                                                                     m_notify;
        std::atomic<bool>                                                        m_paused;
        std::atomic<bool>                                                        m_scanning;
        std::atomic<bool>                                                        m_syncing;
        /// @brief Set while a flush sends. syncModule() and runRecoveryProcess() stand back from
        /// it; pause() does not wait for it.
        std::atomic<bool>                                                        m_flushInProgress {false};
        /// @brief Set while runRecoveryProcess() or the start-up DataClean for disabled collectors
        /// runs; each stands back from the other. A flush waits for it: the identity resync, the
        /// integrity recovery and that DataClean clear the manager's indices, which would reset the
        /// flush's session under it.
        std::atomic<bool>                                                        m_recoveryInProgress {false};
        /// @brief Set while the start-up DataClean for disabled collectors sends and deletes, on top
        /// of m_recoveryInProgress. syncModule() stands back from it: it cannot use
        /// m_recoveryInProgress for that, since runRecoveryProcess() calls it while holding the slot.
        std::atomic<bool>                                                        m_startupDataCleanInProgress {false};
        /// @brief Agent id change resends actually started, plus synchronizations that ran and failed
        /// (the resend only follows a successful one). Reported by get_identity_changed so the sync
        /// thread backs off only after a real attempt, not after a cycle that was skipped.
        std::atomic<uint32_t>                                                    m_identityResyncAttempts {0};
        bool                                                                     m_groups;
        bool                                                                     m_users;
        bool                                                                     m_services;
        bool                                                                     m_browserExtensions;
        // Per-container inventory baseline (Linux only). Previously ran
        // unconditionally on every Linux agent, unlike every sibling collector.
        bool                                                                     m_containerBaseline;
        // Independent container-inventory cadence, decoupled from
        // m_intervalValue (the host scan interval). 0 keeps the two coupled.
        // syncLoop() wakes for whichever deadline elapses first, so the
        // container pass is not bounded by the (possibly much longer) host one.
        unsigned int                                                             m_containerBaselineInterval;
        // One-shot guard so a disabled container baseline purges leftover
        // container rows once, not on every scan interval.
        bool                                                                     m_containerRowsPurged;
        // Set by the lifecycle watcher when container_instances reports its
        // list changed, cleared by syncLoop when it acts on it. Lets a new or
        // removed container be inventoried without waiting out the remainder of
        // whichever interval is in force -- m_containerBaselineInterval on the
        // independent cadence, the host interval on the coupled one. BOTH
        // branches of syncLoop consult it; the coupled branch, which is the
        // default, once did not, so the watcher ran and changed nothing.
        std::atomic<bool>                                                        m_containerScanRequested;
        // Blocks on the notification socket. Started only when the container
        // baseline is enabled: with it off there is nothing to bring forward.
        std::thread                                                              m_containerNotifyThread;
        // Where the delta pass has read up to in container_instances' journal.
        // In memory only: on restart the full pass runs first and re-establishes
        // everything, so a persisted cursor would describe a world this process
        // has not seen. 0/0 means "no cursor", which the module answers with the
        // full set.
        unsigned long long                                                       m_containerCursorEpoch;
        unsigned long long                                                       m_containerCursorSeq;
        std::atomic<unsigned int>                                                m_dataCleanRetries;
        std::atomic<bool>                                                        m_allCollectorsDisabled;
        bool                                                                     m_vdSyncEnabled;
        std::unique_ptr<DBSync>                                                  m_spDBSync;
        std::condition_variable                                                  m_cv;
        std::mutex                                                               m_scan_mutex;
        std::condition_variable                                                  m_pauseCv;
        std::mutex                                                               m_pauseMutex;
        std::unique_ptr<SysNormalizer>                                           m_spNormalizer;
        std::unique_ptr<IAgentSyncProtocol>                                      m_spSyncProtocol;
        std::vector<std::string>                                                 m_disabledCollectorsIndicesWithData;
        std::unique_ptr<IAgentSyncProtocol>                                      m_spSyncProtocolVD;
        std::unique_ptr<Utils::AsyncFlushController>                             m_asyncFlushController;
        std::vector<std::pair<std::string, nlohmann::json>>*                     m_failedItems;  // Pointer to list of items that failed validation (for deferred deletion)
        std::vector<std::pair<std::string, nlohmann::json>>*                     m_itemsToUpdateSync;  // Pointer to list of items that passed limit check (for deferred sync=1 update)

        // Document limits configuration (0 = unlimited)
        std::map<std::string, size_t>                                            m_documentLimits;

        // Current document counts per index (tracks items with sync=1)
        std::map<std::string, size_t>                                            m_documentCounts;

        // The same two, for rows attributed to a container. Separate budget, so
        // container inventory cannot consume the host's — see LimitScope.
        std::map<std::string, size_t>                                            m_containerDocumentLimits;
        // Counts key on the CONTAINER first: one budget each (#37532 / O10).
        std::map<std::string, std::map<std::string, size_t>>                     m_containerDocumentCounts;

        // (container, index) pairs already reported as saturated, so the
        // message is emitted once per saturation rather than once per scan.
        std::set<std::pair<std::string, std::string>>                            m_limitReported;

        // Containers container_instances says may report to the manager.
        //
        // A SEPARATE question from the per-dimension budgets beside it: those
        // bound how much one container reports, this bounds how many report at
        // all. Empty means "not told yet", which reads as admit-everything --
        // the connector is queried per pass, and an agent that has not heard an
        // answer must keep reporting rather than go quiet.
        std::set<std::string>                                                    m_admittedContainers;
        bool                                                                     m_admissionKnown {false};

        // True when at least one known container is being withheld, i.e. the
        // cap is actually biting. Kept separately because the re-send paths
        // need to know that SOMETHING can hold a row at sync=0 without having
        // a container id in hand to ask about.
        bool                                                                     m_containerAdmissionWithholding {false};

        // Whether the stored reporting flags have already been reconciled against
        // the admission set in THIS process.
        //
        // The reconciliation has to run once at startup even when no container has
        // just lost admission, because the previous admission set died with the last
        // process and a row reported before a restart carries sync=1 with nothing in
        // memory to say the container may no longer report it. After that first pass
        // only an actual admission loss can create such a row, so this latch keeps a
        // biting cap from re-reading every container row of every table on every scan.
        bool m_admissionReconciled {false};

        // Whether rows are still owed a retraction.
        //
        // Separate from the latch above because the two answer different questions,
        // and the difference is load-bearing: setAdmittedContainers() replaces the
        // admitted set before it retracts anything, so "a container just lost
        // admission" is observable exactly once, while the retraction it demands can
        // fail -- there may be no persistence callback yet. Holding the obligation
        // here means a failed retraction is retried on the next pass instead of being
        // dropped along with the signal that raised it.
        bool m_admissionRetractionPending {false};

        // Mutex for thread-safe access to limits and counts
        std::mutex                                                               m_limitsMutex;

        /// @brief Serializes releaseResources() against the entry points that other threads
        /// keep driving while the module tears down: wcom's dispatcher is detached and never
        /// joined, and agent-info's coordination polls call query() in-process from its own
        /// module thread (e.g. the get_first_sync_completed guard, which reaches
        /// getMetadataValue() and dereferences m_spDBSync). Those entry points take it shared
        /// around each access; initSyncProtocol() publishes the protocols under the exclusive
        /// lock and releaseResources() resets the members under it. The scan and sync workers
        /// do not take it: they are joined before releaseResources() runs. Mirrors
        /// SecurityConfigurationAssessment::m_resourcesMutex, added for the same defect.
        mutable std::shared_mutex                                                m_resourcesMutex;

        // Container ids whose baseline has already been synced at least once
        // (in this process's lifetime). A container_id not in this set is
        // treated as a first-ever sync and kept quiet regardless of m_notify,
        // mirroring the one-shot baseline's original "no alert per row on
        // first seed" behavior now that scanContainerBaseline() runs every
        // interval instead of once. Reset only implicitly, by process
        // restart — same durability as m_notify itself.
        std::set<std::string>                                                    m_knownContainerIds;
};


#endif //_SYSCOLLECTOR_HPP
