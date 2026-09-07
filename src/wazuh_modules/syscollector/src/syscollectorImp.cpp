/*
 * Wazuh SysCollector
 * Copyright (C) 2015, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "syscollector.h"
#include "syscollector.hpp"
#include "json.hpp"
#include "stringHelper.h"
#include "hashHelper.h"
#include "timeHelper.h"
#include <cstdint>
#include <iostream>
#include <stack>
#include <set>
#include <chrono>
#include <thread>

#include "syscollectorTablesDef.hpp"
#if defined(__linux__)
#include "container_baseline.h"
#endif
#include "agent_sync_protocol.hpp"
#include "logging_helper.h"
#include "module_query_errors.h"
#include "defs.h"
#include "schemaValidator.hpp"

#ifndef WIN32
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#endif

// Constants for socket communication
constexpr int SYSCOLLECTOR_OS_MAXSTR = 6144;
constexpr int SYSCOLLECTOR_OS_SOCKTERR = -2;

#define TRY_CATCH_TASK(task)                                            \
do                                                                      \
{                                                                       \
    try                                                                 \
    {                                                                   \
        if (!m_stopping.load())                                         \
        {                                                               \
            task();                                                     \
        }                                                               \
    }                                                                   \
    catch(const std::exception& ex)                                     \
    {                                                                   \
        if(m_logFunction)                                               \
        {                                                               \
            m_logFunction(LOG_ERROR, std::string{ex.what()});           \
        }                                                               \
    }                                                                   \
}while(0)

constexpr auto EMPTY_VALUE {""};
constexpr auto UNKNOWN_VALUE {" "};

// RAII guard to ensure scanning flag is always cleaned up
class ScanGuard
{
    public:
        explicit ScanGuard(std::atomic<bool>& flag, std::condition_variable& cv)
            : m_flag(flag), m_cv(cv)
        {
            m_flag = true;
        }
        ~ScanGuard()
        {
            m_flag = false;
            m_cv.notify_all();
        }
        // Delete copy and move operations
        ScanGuard(const ScanGuard&) = delete;
        ScanGuard& operator=(const ScanGuard&) = delete;
        ScanGuard(ScanGuard&&) = delete;
        ScanGuard& operator=(ScanGuard&&) = delete;
    private:
        std::atomic<bool>& m_flag;
        std::condition_variable& m_cv;
};

constexpr auto QUEUE_SIZE
{
    4096
};

constexpr auto SYSCOLLECTOR_FIRST_SYNC_COMPLETED_METADATA_KEY {"first_sync_completed"};
constexpr auto SYSCOLLECTOR_FIRST_SCAN_COMPLETED_METADATA_KEY {"first_scan_completed"};
constexpr auto SYSCOLLECTOR_VD_FIRST_SYNC_COMPLETED_METADATA_KEY {"vd_first_sync_completed"};

static const std::map<ReturnTypeCallback, std::string> OPERATION_MAP
{
    // LCOV_EXCL_START
    {MODIFIED, "modified"},
    {DELETED, "deleted"},
    {INSERTED, "created"},
    // LCOV_EXCL_STOP
};

static const std::map<ReturnTypeCallback, Operation_t> OPERATION_STATES_MAP
{
    // LCOV_EXCL_START
    {MODIFIED, OPERATION_MODIFY},
    {DELETED, OPERATION_DELETE},
    {INSERTED, OPERATION_CREATE},
    // LCOV_EXCL_STOP
};

static const std::map<std::string, std::string> INDEX_MAP
{
    // LCOV_EXCL_START
    {OS_TABLE, SYSCOLLECTOR_SYNC_INDEX_SYSTEM},
    {HW_TABLE, SYSCOLLECTOR_SYNC_INDEX_HARDWARE},
    {HOTFIXES_TABLE, SYSCOLLECTOR_SYNC_INDEX_HOTFIXES},
    {PACKAGES_TABLE, SYSCOLLECTOR_SYNC_INDEX_PACKAGES},
    {PROCESSES_TABLE, SYSCOLLECTOR_SYNC_INDEX_PROCESSES},
    {PORTS_TABLE, SYSCOLLECTOR_SYNC_INDEX_PORTS},
    {NET_IFACE_TABLE, SYSCOLLECTOR_SYNC_INDEX_INTERFACES},
    {NET_PROTOCOL_TABLE, SYSCOLLECTOR_SYNC_INDEX_PROTOCOLS},
    {NET_ADDRESS_TABLE, SYSCOLLECTOR_SYNC_INDEX_NETWORKS},
    {USERS_TABLE, SYSCOLLECTOR_SYNC_INDEX_USERS},
    {GROUPS_TABLE, SYSCOLLECTOR_SYNC_INDEX_GROUPS},
    {SERVICES_TABLE, SYSCOLLECTOR_SYNC_INDEX_SERVICES},
    {BROWSER_EXTENSIONS_TABLE, SYSCOLLECTOR_SYNC_INDEX_BROWSER_EXTENSIONS},
    // LCOV_EXCL_STOP
};

// Map from agentd names to full index names
// These names must match exactly what agentd sends
static const std::map<std::string, std::string> AGENTD_TO_INDEX_MAP
{
    // LCOV_EXCL_START
    {"os_info", SYSCOLLECTOR_SYNC_INDEX_SYSTEM},
    {"hardware", SYSCOLLECTOR_SYNC_INDEX_HARDWARE},
    {"hotfixes", SYSCOLLECTOR_SYNC_INDEX_HOTFIXES},
    {"packages", SYSCOLLECTOR_SYNC_INDEX_PACKAGES},
    {"processes", SYSCOLLECTOR_SYNC_INDEX_PROCESSES},
    {"ports", SYSCOLLECTOR_SYNC_INDEX_PORTS},
    {"network_iface", SYSCOLLECTOR_SYNC_INDEX_INTERFACES},
    {"network_protocol", SYSCOLLECTOR_SYNC_INDEX_PROTOCOLS},
    {"network_address", SYSCOLLECTOR_SYNC_INDEX_NETWORKS},
    {"users", SYSCOLLECTOR_SYNC_INDEX_USERS},
    {"groups", SYSCOLLECTOR_SYNC_INDEX_GROUPS},
    {"services", SYSCOLLECTOR_SYNC_INDEX_SERVICES},
    {"browser_extensions", SYSCOLLECTOR_SYNC_INDEX_BROWSER_EXTENSIONS},
    // LCOV_EXCL_STOP
};

static void sanitizeJsonValue(nlohmann::json& input)
{
    if (input.is_object())
    {
        for (auto it = input.begin(); it != input.end(); ++it)
        {
            auto& value = it.value();

            sanitizeJsonValue(value);
        }
    }
    else if (input.is_array())
    {
        for (auto& item : input)
        {
            sanitizeJsonValue(item);
        }
    }
    else if (input.is_string())
    {
        const std::string& stringValue = input.get_ref<const std::string&>();

        if (stringValue != " ")
        {
            input = Utils::trim(stringValue);
        }
    }
}

static std::string getItemChecksum(const nlohmann::json& item)
{
    const auto content{item.dump()};
    Utils::HashData hash;
    hash.update(content.c_str(), content.size());
    return Utils::asciiToHex(hash.hash());
}

// The two container-scope columns are row *identity* and row *context*, never row
// content, so neither may reach the checksum:
//
//   container_id   is the leading PRIMARY KEY of every table in
//                  syscollectorTablesDef.hpp, so rows are already told apart by
//                  it. Digesting it changed every host row's checksum against a
//                  pre-container agent ('' is still a value), which would have
//                  re-synced the whole host inventory of every upgraded agent —
//                  including agents that run no containers at all.
//   container_json is a copy of the container's metadata blob stamped onto each
//                  of its rows. Digesting it makes one label or annotation edit
//                  change the checksum of every row of that container, in every
//                  table, and re-emit its entire inventory as MODIFIED.
//
// Strip both here rather than at each call site: nothing about a future caller
// stamping the scope earlier should be able to put them back into the digest.
static std::string getRowChecksum(nlohmann::json item)
{
    item.erase(std::string{CONTAINER_ID_COLUMN});
    item.erase(std::string{CONTAINER_JSON_COLUMN});
    return getItemChecksum(item);
}

// Monotonic counters excluded from dbsync's diff
// NOTE: dbsync's "ignore" only suppresses the diff/callback when ignored fields
// are the *only* thing that changed; it also skips persisting their new value in
// that case (see SQLiteDBEngine::syncTableRowData). These fields will hold whatever
// value they had at the last scan that also changed a non-ignored field.
static const std::vector<std::string> HW_IGNORED_FIELDS { "memory_free", "memory_used", "checksum" };
static const std::vector<std::string> PROCESSES_IGNORED_FIELDS { "utime", "stime", "checksum" };
static const std::vector<std::string> NET_IFACE_IGNORED_FIELDS
{
    "host_network_egress_packages", "host_network_ingress_packages",
    "host_network_egress_errors",   "host_network_ingress_errors",
    "host_network_egress_bytes",    "host_network_ingress_bytes",
    "host_network_egress_drops",    "host_network_ingress_drops",
    "checksum"
};

static std::string getItemId(const nlohmann::json& item, const std::vector<std::string>& idFields)
{
    Utils::HashData hash;

    for (const auto& field : idFields)
    {
        const auto& value{item.at(field)};

        if (value.is_string())
        {
            const auto& valueString{value.get<std::string>()};
            hash.update(valueString.c_str(), valueString.size());
        }
        else
        {
            const auto& valueNumber{value.get<unsigned long>()};
            const auto valueString{std::to_string(valueNumber)};
            hash.update(valueString.c_str(), valueString.size());
        }
    }

    return Utils::asciiToHex(hash.hash());
}

static bool isElementDuplicated(const nlohmann::json& input, const std::pair<std::string, std::string>& keyValue)
{
    const auto it
    {
        std::find_if (input.begin(), input.end(), [&keyValue](const auto & elem)
        {
            return elem.at(keyValue.first) == keyValue.second;
        })
    };
    return it != input.end();
}

// Restricts a DBSync transaction's delete detection to one container's rows
// (or to host rows when containerId is empty), so a scan of one scope cannot
// delete rows belonging to another.
static nlohmann::json scopedTxnTables(const nlohmann::json& tables, const std::string& containerId)
{
    nlohmann::json txnInput;
    txnInput["tables"] = tables.is_array() ? tables : nlohmann::json::array({tables});
    txnInput["scope"] = {{"column", CONTAINER_ID_COLUMN}, {"value", containerId}};
    return txnInput;
}

void Syscollector::notifyChange(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table, bool notify)
{
    if (DB_ERROR == result)
    {
        m_logFunction(LOG_ERROR, data.dump());
    }
    else
    {
        // Deliberately NOT gated on m_stopping: this is the per-row DBSync callback for
        // whichever task is currently in flight (wired up by updateChanges() for every
        // scanX() task, called once per changed row within that task's own transaction).
        // TRY_CATCH_TASK already guarantees no *new* task starts once m_stopping is true;
        // gating here as well would let an already-started task report only part of its
        // own transaction if m_stopping flips mid-transaction, which is a worse outcome
        // than letting the in-flight task finish reporting everything it found.
        if (data.is_array())
        {
            for (const auto& item : data)
            {
                processEvent(result, item, table, notify);
            }
        }
        else
        {
            processEvent(result, data, table, notify);
        }
    }
}

void Syscollector::processEvent(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table, bool notify)
{
    nlohmann::json aux = (result == MODIFIED && data.contains("new")) ? data["new"] : data;

    auto [newData, version] = ecsData(aux, table);

    const auto statefulToSend{newData.dump()};
    auto indexIt = INDEX_MAP.find(table);

    if (indexIt != INDEX_MAP.end())
    {
        // Validate data against schema before queuing
        bool shouldQueue = true;
        std::string dataToQueue = statefulToSend;
        std::string context = "table: " + table;

        // Use helper function to validate and log
        bool validationPassed = validateSchemaAndLog(statefulToSend, indexIt->second, context);

        if (!validationPassed)
        {
            // Don't queue invalid message
            if (m_logFunction)
            {
                m_logFunction(LOG_ERROR, "Discarding invalid Syscollector message (table: " + table + ")");
            }

            // Mark for deferred deletion from DBSync to prevent integrity sync loops
            // We cannot delete here as we are inside a DBSync callback (would cause nested transactions)
            if (result == INSERTED || result == MODIFIED)
            {
                if (m_logFunction)
                {
                    m_logFunction(LOG_DEBUG, "Marking entry from table " + table + " for deferred deletion due to validation failure");
                }

                // Store the failed item for deletion after transaction completes
                if (m_failedItems)
                {
                    m_failedItems->emplace_back(table, aux);
                }
            }

            shouldQueue = false;
        }

        if (shouldQueue && m_persistDiffFunction)
        {
            // Check document limit only for stateful events (events that will be persisted)
            // Stateless events are not subject to document limits
            if (!checkDocumentLimit(table, aux, result))
            {
                // Limit reached, do not persist this record
                // The event will still be sent as stateless (below)
                if (m_logFunction)
                {
                    m_logFunction(LOG_DEBUG_VERBOSE, "Document limit reached for table " + table + ", skipping persistence");
                }
            }
            else
            {
                // Within limit, persist the event
                m_persistDiffFunction(calculateHashId(aux, table), OPERATION_STATES_MAP.at(result), indexIt->second, dataToQueue, version);
            }
        }
    }

    // Remove checksum and state from newData to avoid sending them in the diff
    if (newData.contains("checksum"))
    {
        newData.erase("checksum");
    }

    if (newData.contains("state"))
    {
        newData.erase("state");
    }

    if (notify)
    {
        nlohmann::json stateless;

        stateless["collector"] = table;
        stateless["module"] = "inventory";

        auto [oldData, oldVersion] = (result == MODIFIED) ? ecsData(data["old"], table, false) : std::make_pair(nlohmann::json{}, uint64_t(0));

        auto changedFields = addPreviousFields(newData, oldData);

        stateless["data"] = newData;
        stateless["data"]["event"]["changed_fields"] = changedFields;
        stateless["data"]["event"]["created"] = Utils::getCurrentISO8601();
        stateless["data"]["event"]["type"] = OPERATION_MAP.at(result);

        const auto statelessToSend{stateless.dump()};
        m_reportDiffFunction(statelessToSend);
        m_logFunction(LOG_DEBUG_VERBOSE, "Delta sent: " + statelessToSend);
    }
}

void Syscollector::updateChanges(const std::string& table,
                                 const nlohmann::json& values,
                                 const std::string& containerId,
                                 std::optional<bool> notifyOverride,
                                 bool detectDeletions)
{
    const bool notify = notifyOverride.has_value() ? *notifyOverride : m_notify;
    const auto callback
    {
        [this, table, notify](ReturnTypeCallback result, const nlohmann::json & data)
        {
            if (result == INSERTED || result == MODIFIED || result == DELETED)
            {
                notifyChange(result, data, table, notify);
            }
        }
    };
    DBSyncTxn txn
    {
        m_spDBSync->handle(),
        scopedTxnTables(nlohmann::json{table}, containerId),
        0,
        QUEUE_SIZE,
        callback
    };

    // An empty row set is valid (e.g. a container that no longer has rows in
    // this table): skipping syncTxnRow leaves every scoped row marked for
    // delete, so getDeletedRows reports them all as DELETED.
    if (!values.empty())
    {
        // container_id is part of every table's PK, so each row must carry it
        // explicitly (the engine reads PK values from the row data).
        nlohmann::json stampedValues = values;

        for (auto& row : stampedValues)
        {
            if (!row.contains(CONTAINER_ID_COLUMN))
            {
                row[CONTAINER_ID_COLUMN] = containerId;
            }
        }

        nlohmann::json input;
        input["table"] = table;
        input["data"] = stampedValues;
        input["options"]["return_old_data"] = true;

        if (table == HW_TABLE)
        {
            input["options"]["ignore"] = HW_IGNORED_FIELDS;
        }
        else if (table == NET_IFACE_TABLE)
        {
            input["options"]["ignore"] = NET_IFACE_IGNORED_FIELDS;
        }
        else if (table == PROCESSES_TABLE)
        {
            // The host processes scan applies this list on its own streaming
            // transaction; container rows arrive through here instead, so
            // without this branch every container process whose CPU time moved
            // between scans produced a MODIFIED event carrying only
            // utime/stime — by row count the largest source of churn in a
            // multi-container baseline.
            input["options"]["ignore"] = PROCESSES_IGNORED_FIELDS;
        }

        txn.syncTxnRow(input);
    }

    if (detectDeletions)
    {
        txn.getDeletedRows(callback);
    }
}

Syscollector::Syscollector()
    : m_intervalValue { 0 }
    , m_integrityIntervalValue { 86400 }
    , m_scanOnStart { false }
    , m_hardware { false }
    , m_os { false }
    , m_network { false }
    , m_packages { false }
    , m_ports { false }
    , m_portsAll { false }
    , m_processes { false }
    , m_hotfixes { false }
    , m_stopping { true }
    , m_initialized { false }
    , m_notify { false }
    , m_paused { false }
    , m_scanning { false }
    , m_syncing { false }
    , m_groups { false }
    , m_users { false }
    , m_services { false }
    , m_browserExtensions { false }
    , m_containerBaseline { false }
    , m_containerBaselineInterval { 0 }
    , m_containerRowsPurged { false }
    , m_vdSyncEnabled { false }
    , m_failedItems { nullptr }
    , m_itemsToUpdateSync { nullptr }
{
    m_asyncFlushController = std::make_unique<Utils::AsyncFlushController>(
                                 "Syscollector",
                                 [this]()
    {
        return executeFlushSync();
    },
    [this](modules_log_level_t level, const std::string & message)
    {
        if (m_logFunction)
        {
            m_logFunction(level, message);
        }
    });

    // Initialize document limits to 0 (unlimited) for all indices, in both
    // scopes: a container row must find its own entry rather than fall through
    // to the host's.
    for (const auto& [table, index] : INDEX_MAP)
    {
        m_documentLimits[index] = 0;
        m_documentCounts[index] = 0;
        m_containerDocumentLimits[index] = 0;
        m_containerDocumentCounts[index] = 0;
    }
}

std::string Syscollector::getCreateStatement() const
{
    std::string ret;

    ret += OS_SQL_STATEMENT;
    ret += HW_SQL_STATEMENT;
    ret += PACKAGES_SQL_STATEMENT;
    ret += HOTFIXES_SQL_STATEMENT;
    ret += PROCESSES_SQL_STATEMENT;
    ret += PORTS_SQL_STATEMENT;
    ret += NETIFACE_SQL_STATEMENT;
    ret += NETPROTO_SQL_STATEMENT;
    ret += NETADDR_SQL_STATEMENT;
    ret += GROUPS_SQL_STATEMENT;
    ret += USERS_SQL_STATEMENT;
    ret += SERVICES_SQL_STATEMENT;
    ret += BROWSER_EXTENSIONS_SQL_STATEMENT;
    ret += TABLE_METADATA_SQL_STATEMENT;
    return ret;
}


void Syscollector::init(const std::shared_ptr<ISysInfo>& spInfo,
                        std::function<void(const std::string&)> reportDiffFunction,
                        std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> persistDiffFunction,
                        std::function<void(const modules_log_level_t, const std::string&)> logFunction,
                        const std::string& dbPath,
                        const std::string& normalizerConfigPath,
                        const std::string& normalizerType,
                        const unsigned int interval,
                        const bool scanOnStart,
                        const bool hardware,
                        const bool os,
                        const bool network,
                        const bool packages,
                        const bool ports,
                        const bool portsAll,
                        const bool processes,
                        const bool hotfixes,
                        const bool groups,
                        const bool users,
                        const bool services,
                        const bool browserExtensions,
                        const bool containerBaseline,
                        const bool notifyOnFirstScan,
                        const unsigned int containerBaselineInterval)
{
    auto dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, dbPath, getCreateStatement(), DbManagement::PERSISTENT);
    auto normalizer = std::make_unique<SysNormalizer>(normalizerConfigPath, normalizerType);

    std::unique_lock<std::mutex> lock{m_scan_mutex};

    m_spInfo = spInfo;
    m_reportDiffFunction = std::move(reportDiffFunction);
    m_persistDiffFunction = std::move(persistDiffFunction);
    m_logFunction = std::move(logFunction);
    m_intervalValue = interval;
    m_scanOnStart = scanOnStart;
    m_hardware = hardware;
    m_os = os;
    m_network = network;
    m_packages = packages;
    m_ports = ports;
    m_portsAll = portsAll;
    m_processes = processes;
    m_hotfixes = hotfixes;
    m_notify = notifyOnFirstScan;
    m_groups = groups;
    m_users = users;
    m_services = services;
    m_browserExtensions = browserExtensions;
    m_containerBaseline = containerBaseline;
    m_containerBaselineInterval = containerBaselineInterval;
    m_stopping = false;

    m_spDBSync      = std::move(dbSync);
    m_spNormalizer  = std::move(normalizer);
    m_initialized   = true;

    // Initialize document counts from database
    initializeDocumentCounts();

    m_allCollectorsDisabled = !(m_hardware || m_os || m_network || m_packages || m_ports || m_processes || m_hotfixes || m_groups || m_users || m_services || m_browserExtensions || m_containerBaseline);
    m_dataCleanRetries = 1;  // Default retries for data clean

    // Check disabled collectors with existing data
    checkDisabledCollectorsIndicesWithData();
}

void Syscollector::setAgentdQueryFunction(AgentdQueryFunc queryFunc)
{
    m_agentdQuery = std::move(queryFunc);

    if (m_logFunction)
    {
        m_logFunction(LOG_DEBUG, "Agentd query function set for agentd communication");
    }
}

void Syscollector::start()
{
    // Don't start if initialization failed
    {
        std::scoped_lock<std::mutex> lock{m_scan_mutex};

        if (!m_initialized)
        {
            if (m_logFunction)
            {
                m_logFunction(LOG_ERROR, "Cannot start Syscollector - module initialization failed");
            }

            return;
        }

        m_stopping = false;
    }

    // Reset sync protocol stop flag to allow restarting operations
    if (m_spSyncProtocol)
    {
        m_spSyncProtocol->reset();
    }

    bool notifySuccess = handleNotifyDataClean();

    if (notifySuccess)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, "Syscollector data clean notification for disabled collectors sent successfully, proceeding to delete data.");
        }

        deleteDisableCollectorsData();
    }
    else
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_WARNING, "Syscollector data clean notification for disabled collectors failed, proceeding without deleting data.");
        }
    }

    // If all collectors are disabled, do not start the module
    if (m_allCollectorsDisabled)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_INFO, "All collectors are disabled. Exiting...");
        }

        return;
    }

    // Determine if VD sync should be enabled based on configuration
    // VD-relevant data includes: packages, OS, and hotfixes (Windows only)
    m_vdSyncEnabled = m_packages && m_os;
#ifdef _WIN32
    m_vdSyncEnabled = m_vdSyncEnabled && m_hotfixes;
#endif

    if (!m_vdSyncEnabled)
    {
#ifdef _WIN32
        m_logFunction(LOG_WARNING, "Vulnerability Detector synchronization is disabled. OS, packages, and hotfixes are required to be enabled.");
#else
        m_logFunction(LOG_WARNING, "Vulnerability Detector synchronization is disabled. OS and packages are required to be enabled.");
#endif
    }

    // Try to fetch document limits from agentd before starting syncLoop
    // fetchDocumentLimitsFromAgentd() will retry until success or stop signal
    if (m_logFunction)
    {
        m_logFunction(LOG_DEBUG, "Attempting to fetch document limits from agentd...");
    }

    auto limits = fetchDocumentLimitsFromAgentd();

    if (limits.has_value())
    {
        if (setDocumentLimits(limits.value()))
        {
            if (m_logFunction)
            {
                m_logFunction(LOG_DEBUG, "Document limits successfully configured from agentd");
            }
        }
        else
        {
            if (m_logFunction)
            {
                m_logFunction(LOG_ERROR, "Failed to apply document limits obtained from agentd");
                return;
            }
        }
    }

    // Container-inventory caps, if this manager knows about them. Fetched
    // separately and non-blocking on purpose: a manager older than #37532 has
    // no such agcom module, and "unlimited" is the correct answer there.
    auto containerLimits = fetchContainerDocumentLimitsFromAgentd();

    if (containerLimits.has_value() && !setContainerDocumentLimits(containerLimits.value()))
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Failed to apply container document limits obtained from agentd");
        }
    }

    std::unique_lock<std::mutex> scan_lock{m_scan_mutex};
    syncLoop(scan_lock);
}

bool Syscollector::handleNotifyDataClean()
{
    bool ret = false;
    unsigned int attempt = 0;
    constexpr unsigned int DATACLEAN_RETRY_WAIT_SECONDS = 60;  // Fixed wait time between retries

    // If all collectors are disabled, retry indefinitely until success or stopping
    // Otherwise, respect the configured retry limit
    while (!ret && !m_stopping.load())
    {
        attempt++;

        ret = notifyDisableCollectorsDataClean();

        if (ret)
        {
            if (m_logFunction)
            {
                m_logFunction(LOG_DEBUG, "Data clean notification succeeded on attempt " + std::to_string(attempt) + ".");
            }

            break;
        }

        // LCOV_EXCL_START
        // Check if we should continue retrying
        bool shouldRetry = m_allCollectorsDisabled || (attempt < m_dataCleanRetries);

        if (shouldRetry)
        {

            if (m_logFunction)
            {
                m_logFunction(LOG_WARNING, "Syscollector data clean notification failed, retry in " + std::to_string(DATACLEAN_RETRY_WAIT_SECONDS) + " seconds.");
            }

            // Wait before next retry with fixed interval
            for (unsigned int i = 0; i < DATACLEAN_RETRY_WAIT_SECONDS && !m_stopping.load(); i++)
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            if (m_stopping.load())
            {
                if (m_logFunction)
                {
                    m_logFunction(LOG_DEBUG, "Data clean notification interrupted by module stop.");
                }

                break;
            }
        }
        else
        {
            if (m_logFunction)
            {
                m_logFunction(LOG_WARNING, "Syscollector data clean notification failed after " + std::to_string(m_dataCleanRetries) + " attempts.");
            }

            break;
        }

        // LCOV_EXCL_STOP
    }

    return ret;
}

void Syscollector::quiesce()
{
    {
        // m_pauseMutex must be held here: pause() checks m_stopping and waits on m_pauseCv
        // under this same mutex, so setting the flag and notifying without it would leave a
        // window where pause() reads m_stopping as false and starts waiting right after this
        // notify_all() fires, missing it (lost wakeup) until some other, unrelated notify
        // (e.g. a scan/sync finishing on its own) happens to wake it instead.
        std::lock_guard<std::mutex> lock(m_pauseMutex);
        m_stopping = true;
        m_pauseCv.notify_all();
    }
    m_cv.notify_all();

    if (m_spSyncProtocol)
    {
        m_spSyncProtocol->stop();
    }

    if (m_spSyncProtocolVD)
    {
        m_spSyncProtocolVD->stop();
    }

    if (m_asyncFlushController)
    {
        m_asyncFlushController->waitForFlushToFinish();
    }
}

void Syscollector::releaseResources()
{
    // Exclude the entry points that other threads keep driving while the module tears
    // down. The scan and sync workers are joined before this runs (see wm_syscollector.c),
    // but query() is not: wcom's dispatcher is detached and agent-info polls it in-process,
    // so without this lock a get_first_sync_completed query could be inside
    // getMetadataValue() dereferencing m_spDBSync while it is reset here (issue #38203).
    std::unique_lock<std::shared_mutex> resourcesLock(m_resourcesMutex);

    // Join any in-flight asynchronous flush before the members it uses are reset.
    // The worker runs executeFlushSync() -> synchronizeModule() on its own thread and
    // takes no lock, so quiesce()'s waitForFlushToFinish() misses a flush accepted
    // afterwards (flush() has no m_stopping check). Holding the exclusive lock here also
    // stops a new flush being accepted, because flush() is only reachable through
    // query(), which takes the lock shared.
    //
    // The controller is joined, not destroyed: it is created once in the constructor of
    // this singleton, so destroying it would leave the module permanently unable to flush
    // for the rest of the process lifetime.
    if (m_asyncFlushController)
    {
        m_asyncFlushController->waitForFlushToFinish();
    }

    // Explicitly release all resources to ensure clean state between tests
    // and prevent use-after-free when Syscollector singleton destructs
    // after static dependencies have already been destroyed
    m_spDBSync.reset();
    m_spNormalizer.reset();
    m_spSyncProtocol.reset();
    m_spSyncProtocolVD.reset();

    if (m_spInfo)
    {
        // Release this thread's per-thread resources (Windows: the hotfixes() COM
        // context) explicitly, on this thread, before m_spInfo is destroyed and before
        // this thread exits -- see releaseThreadResources()'s implementation for why
        // this can no longer be left to automatic thread_local teardown at thread exit.
        m_spInfo->releaseThreadResources();
    }

    m_spInfo.reset();
}

void Syscollector::destroy()
{
    quiesce();

    std::unique_lock<std::mutex> lock{m_scan_mutex, std::try_to_lock};
    const bool scanMutexAvailable = lock.owns_lock();

    if (scanMutexAvailable)
    {
        lock.unlock();
    }

    if (!scanMutexAvailable)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_WARNING, "Stop requested while scan mutex is busy; skipping synchronous syscollector resource teardown.");
        }

        return;
    }

    releaseResources();
}

std::pair<nlohmann::json, uint64_t> Syscollector::ecsData(const nlohmann::json& data, const std::string& table, bool createFields)
{
    nlohmann::json ret;
    uint64_t document_version = 0;

    if (table == OS_TABLE)
    {
        ret = ecsSystemData(data, createFields);
    }
    else if (table == HW_TABLE)
    {
        ret = ecsHardwareData(data, createFields);
    }
    else if (table == HOTFIXES_TABLE)
    {
        ret = ecsHotfixesData(data, createFields);
    }
    else if (table == PACKAGES_TABLE)
    {
        ret = ecsPackageData(data, createFields);
    }
    else if (table == PROCESSES_TABLE)
    {
        ret = ecsProcessesData(data, createFields);
    }
    else if (table == PORTS_TABLE)
    {
        ret = ecsPortData(data, createFields);
    }
    else if (table == NET_IFACE_TABLE)
    {
        ret = ecsNetworkInterfaceData(data, createFields);
    }
    else if (table == NET_PROTOCOL_TABLE)
    {
        ret = ecsNetworkProtocolData(data, createFields);
    }
    else if (table == NET_ADDRESS_TABLE)
    {
        ret = ecsNetworkAddressData(data, createFields);
    }
    else if (table == USERS_TABLE)
    {
        ret = ecsUsersData(data, createFields);
    }
    else if (table == GROUPS_TABLE)
    {
        ret = ecsGroupsData(data, createFields);
    }
    else if (table == SERVICES_TABLE)
    {
        ret = ecsServicesData(data, createFields);
    }
    else if (table == BROWSER_EXTENSIONS_TABLE)
    {
        ret = ecsBrowserExtensionsData(data, createFields);
    }

    // Option A (container baseline): container-sourced rows carry their
    // serialized runtime context in the container_json column — surface it as
    // the event's container/kubernetes blocks. Host rows have an empty column
    // and are untouched. DELETED events keep the blocks because the column is
    // part of the stored row, even after the container itself is gone.
    if (data.contains(CONTAINER_JSON_COLUMN) && data[CONTAINER_JSON_COLUMN].is_string())
    {
        const auto& contextBlob = data[CONTAINER_JSON_COLUMN].get_ref<const std::string&>();

        if (!contextBlob.empty())
        {
            const auto context = nlohmann::json::parse(contextBlob, nullptr, false);

            if (context.is_object())
            {
                if (context.contains("container"))
                {
                    ret["container"] = context["container"];
                }

                if (context.contains("kubernetes"))
                {
                    ret["kubernetes"] = context["kubernetes"];
                }
            }
        }
    }

    if (createFields)
    {
        setJsonField(ret, data, "/checksum/hash/sha1", "checksum", true);

        // Add state modified_at and version fields for stateful events only
        nlohmann::json state;
        state["modified_at"] = Utils::getCurrentISO8601();

        // Include document_version field in state for synchronization
        if (data.contains("version"))
        {
            document_version = data["version"].get<uint64_t>();
            state["document_version"] = document_version;
        }

        ret["state"] = state;
    }

    return {ret, document_version};
}

nlohmann::json Syscollector::ecsSystemData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/host/architecture", "architecture", createFields);
    setJsonField(ret, originalData, "/host/hostname", "hostname", createFields);
    setJsonField(ret, originalData, "/host/os/build", "os_build", createFields);
    setJsonField(ret, originalData, "/host/os/codename", "os_codename", createFields);
    setJsonField(ret, originalData, "/host/os/distribution/release", "os_distribution_release", createFields);
    setJsonField(ret, originalData, "/host/os/full", "os_full", createFields);
    setJsonField(ret, originalData, "/host/os/kernel/name", "os_kernel_name", createFields);
    setJsonField(ret, originalData, "/host/os/kernel/release", "os_kernel_release", createFields);
    setJsonField(ret, originalData, "/host/os/kernel/version", "os_kernel_version", createFields);
    setJsonField(ret, originalData, "/host/os/major", "os_major", createFields);
    setJsonField(ret, originalData, "/host/os/minor", "os_minor", createFields);
    setJsonField(ret, originalData, "/host/os/name", "os_name", createFields);
    setJsonField(ret, originalData, "/host/os/type", "os_type", createFields);
    setJsonField(ret, originalData, "/host/os/patch", "os_patch", createFields);
    setJsonField(ret, originalData, "/host/os/platform", "os_platform", createFields);
    setJsonField(ret, originalData, "/host/os/version", "os_version", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsHardwareData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/host/cpu/cores", "cpu_cores", createFields);
    setJsonField(ret, originalData, "/host/cpu/name", "cpu_name", createFields);

    // Convert cpu speed to integer for ECS compliance (in case it comes as float)
    if (createFields || originalData.contains("cpu_speed"))
    {
        const nlohmann::json::json_pointer pointer("/host/cpu/speed");

        if (originalData.contains("cpu_speed") && !originalData["cpu_speed"].is_null())
        {
            const auto& value = originalData["cpu_speed"];

            if (value.is_number() && value.get<double>() != 0.0)
            {
                ret[pointer] = value.get<int64_t>();
            }
            else
            {
                ret[pointer] = nullptr;
            }
        }
        else
        {
            ret[pointer] = nullptr;
        }
    }

    setJsonField(ret, originalData, "/host/memory/free", "memory_free", createFields);
    setJsonField(ret, originalData, "/host/memory/total", "memory_total", createFields);
    setJsonField(ret, originalData, "/host/memory/used", "memory_used", createFields);
    setJsonField(ret, originalData, "/host/serial_number", "serial_number", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsHotfixesData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/package/hotfix/name", "hotfix_name", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsPackageData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/package/architecture", "architecture", createFields);
    setJsonField(ret, originalData, "/package/category", "category", createFields);
    setJsonField(ret, originalData, "/package/description", "description", createFields);
    setJsonField(ret, originalData, "/package/installed", "installed", createFields);
    setJsonField(ret, originalData, "/package/multiarch", "multiarch", createFields);
    setJsonField(ret, originalData, "/package/name", "name", createFields);
    setJsonField(ret, originalData, "/package/path", "path", createFields);
    setJsonField(ret, originalData, "/package/priority", "priority", createFields);
    setJsonField(ret, originalData, "/package/size", "size", createFields);
    setJsonField(ret, originalData, "/package/source", "source", createFields);
    setJsonField(ret, originalData, "/package/type", "type", createFields);
    setJsonField(ret, originalData, "/package/vendor", "vendor", createFields);
    setJsonField(ret, originalData, "/package/version", "version_", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsProcessesData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonFieldArray(ret, originalData, "/process/args", "args", createFields);
    setJsonField(ret, originalData, "/process/args_count", "args_count", createFields);
    setJsonField(ret, originalData, "/process/command_line", "command_line", createFields);
    setJsonField(ret, originalData, "/process/name", "name", createFields);
    setJsonField(ret, originalData, "/process/parent/pid", "parent_pid", createFields);

    // Convert pid from string to integer for ECS compliance
    if (createFields || originalData.contains("pid"))
    {
        const nlohmann::json::json_pointer pointer("/process/pid");

        // LCOV_EXCL_START
        if (originalData.contains("pid") && originalData["pid"] != EMPTY_VALUE && originalData["pid"] != UNKNOWN_VALUE)
        {
            try
            {
                ret[pointer] = std::stoll(originalData["pid"].get<std::string>());
            }
            catch (...)
            {
                ret[pointer] = nullptr;
            }
        }
        else
        {
            ret[pointer] = nullptr;
        }

        // LCOV_EXCL_STOP
    }

    setJsonField(ret, originalData, "/process/start", "start", createFields);
    setJsonField(ret, originalData, "/process/state", "state", createFields);
    setJsonField(ret, originalData, "/process/stime", "stime", createFields);
    setJsonField(ret, originalData, "/process/utime", "utime", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsPortData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonFieldArray(ret, originalData, "/destination/ip", "destination_ip", createFields);
    setJsonField(ret, originalData, "/destination/port", "destination_port", createFields);

    // LCOV_EXCL_START
    // Convert inode from number to string for ECS compliance
    if (createFields || originalData.contains("file_inode"))
    {
        const nlohmann::json::json_pointer pointer("/file/inode");

        if (originalData.contains("file_inode") && !originalData["file_inode"].is_null())
        {
            const auto& value = originalData["file_inode"];

            if (value.is_number())
            {
                ret[pointer] = std::to_string(value.get<int64_t>());
            }
            else if (value.is_string())
            {
                ret[pointer] = value.get<std::string>();
            }
            else
            {
                ret[pointer] = nullptr;
            }
        }
        else
        {
            ret[pointer] = nullptr;
        }
    }

    // LCOV_EXCL_STOP

    setJsonField(ret, originalData, "/host/network/egress/queue", "host_network_egress_queue", createFields);
    setJsonField(ret, originalData, "/host/network/ingress/queue", "host_network_ingress_queue", createFields);
    setJsonField(ret, originalData, "/interface/state", "interface_state", createFields);
    setJsonField(ret, originalData, "/network/transport", "network_transport", createFields);
    setJsonField(ret, originalData, "/process/name", "process_name", createFields);
    setJsonField(ret, originalData, "/process/pid", "process_pid", createFields);
    setJsonFieldArray(ret, originalData, "/source/ip", "source_ip", createFields);
    setJsonField(ret, originalData, "/source/port", "source_port", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsNetworkInterfaceData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonFieldArray(ret, originalData, "/host/mac", "host_mac", createFields);
    setJsonField(ret, originalData, "/host/network/ingress/bytes", "host_network_ingress_bytes", createFields);
    setJsonField(ret, originalData, "/host/network/ingress/drops", "host_network_ingress_drops", createFields);
    setJsonField(ret, originalData, "/host/network/ingress/errors", "host_network_ingress_errors", createFields);
    setJsonField(ret, originalData, "/host/network/ingress/packets", "host_network_ingress_packages", createFields);
    setJsonField(ret, originalData, "/host/network/egress/bytes", "host_network_egress_bytes", createFields);
    setJsonField(ret, originalData, "/host/network/egress/drops", "host_network_egress_drops", createFields);
    setJsonField(ret, originalData, "/host/network/egress/errors", "host_network_egress_errors", createFields);
    setJsonField(ret, originalData, "/host/network/egress/packets", "host_network_egress_packages", createFields);
    setJsonField(ret, originalData, "/interface/alias", "interface_alias", createFields);

    // Discard invalid MTU values: 4294967295 (UINT32_MAX) is reported by Windows and 0 by UNIX
    // when the MTU is not available
    if (createFields || originalData.contains("interface_mtu"))
    {
        const nlohmann::json::json_pointer pointer("/interface/mtu");

        if (originalData.contains("interface_mtu") && originalData["interface_mtu"].is_number() &&
                originalData["interface_mtu"].get<int64_t>() != UINT32_MAX &&
                originalData["interface_mtu"].get<int64_t>() != 0)
        {
            ret[pointer] = originalData["interface_mtu"];
        }
        else
        {
            ret[pointer] = nullptr;
        }
    }

    setJsonField(ret, originalData, "/interface/name", "interface_name", createFields);
    setJsonField(ret, originalData, "/interface/state", "interface_state", createFields);
    setJsonField(ret, originalData, "/interface/type", "interface_type", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsNetworkProtocolData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/interface/name", "interface_name", createFields);
    setJsonField(ret, originalData, "/network/dhcp", "network_dhcp", createFields, true);
    setJsonFieldArray(ret, originalData, "/network/gateway", "network_gateway", createFields);

    // LCOV_EXCL_START
    // Convert metric from string to integer for ECS compliance
    if (createFields || originalData.contains("network_metric"))
    {
        const nlohmann::json::json_pointer pointer("/network/metric");

        if (originalData.contains("network_metric") && !originalData["network_metric"].is_null()
                && originalData["network_metric"] != EMPTY_VALUE && originalData["network_metric"] != UNKNOWN_VALUE)
        {
            const auto& value = originalData["network_metric"];

            if (value.is_string())
            {
                try
                {
                    ret[pointer] = std::stoll(value.get<std::string>());
                }
                catch (...)
                {
                    ret[pointer] = nullptr;
                }
            }
            else if (value.is_number())
            {
                ret[pointer] = value.get<int64_t>();
            }
            else
            {
                ret[pointer] = nullptr;
            }
        }
        else
        {
            ret[pointer] = nullptr;
        }
    }

    // LCOV_EXCL_STOP

    setJsonField(ret, originalData, "/network/type", "network_type", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsNetworkAddressData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/interface/name", "interface_name", createFields);
    setJsonFieldArray(ret, originalData, "/network/broadcast", "network_broadcast", createFields);
    setJsonFieldArray(ret, originalData, "/network/ip", "network_ip", createFields);
    setJsonFieldArray(ret, originalData, "/network/netmask", "network_netmask", createFields);

    // Convert network type from number to string for ECS compliance
    if (createFields || originalData.contains("network_type"))
    {
        const nlohmann::json::json_pointer pointer("/network/type");

        // LCOV_EXCL_START
        if (originalData.contains("network_type") && !originalData["network_type"].is_null())
        {
            const auto& value = originalData["network_type"];

            if (value.is_number())
            {
                ret[pointer] = std::to_string(value.get<int64_t>());
            }
            else if (value.is_string())
            {
                ret[pointer] = value.get<std::string>();
            }
            else
            {
                ret[pointer] = nullptr;
            }
        }
        else
        {
            ret[pointer] = nullptr;
        }

        // LCOV_EXCL_STOP
    }

    return ret;
}

nlohmann::json Syscollector::ecsUsersData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonFieldArray(ret, originalData, "/host/ip", "host_ip", createFields);
    setJsonField(ret, originalData, "/login/status", "login_status", createFields, true);
    setJsonField(ret, originalData, "/login/tty", "login_tty", createFields);
    setJsonField(ret, originalData, "/login/type", "login_type", createFields);
    setJsonField(ret, originalData, "/process/pid", "process_pid", createFields);
    setJsonField(ret, originalData, "/user/auth_failures/count", "user_auth_failed_count", createFields);
    setJsonField(ret, originalData, "/user/auth_failures/timestamp", "user_auth_failed_timestamp", createFields);
    setJsonField(ret, originalData, "/user/created", "user_created", createFields);
    setJsonField(ret, originalData, "/user/full_name", "user_full_name", createFields);
    setJsonField(ret, originalData, "/user/group/id", "user_group_id", createFields);
    setJsonField(ret, originalData, "/user/group/id_signed", "user_group_id_signed", createFields);
    setJsonFieldArray(ret, originalData, "/user/groups", "user_groups", createFields);
    setJsonField(ret, originalData, "/user/home", "user_home", createFields);

    // Convert user_id from number to string for ECS compliance
    if (createFields || originalData.contains("user_id"))
    {
        const nlohmann::json::json_pointer pointer("/user/id");

        if (originalData.contains("user_id"))
        {
            const auto& value = originalData["user_id"];

            if (value.is_number())
            {
                ret[pointer] = std::to_string(value.get<int>());
            }
            else
            {
                ret[pointer] = value;
            }
        }
        else
        {
            ret[pointer] = nullptr;
        }
    }

    setJsonField(ret, originalData, "/user/is_hidden", "user_is_hidden", createFields, true);
    setJsonField(ret, originalData, "/user/is_remote", "user_is_remote", createFields, true);
    setJsonField(ret, originalData, "/user/last_login", "user_last_login", createFields);
    setJsonField(ret, originalData, "/user/name", "user_name", createFields);
    setJsonField(ret, originalData, "/user/password/expiration_date", "user_password_expiration_date", createFields);
    setJsonField(ret, originalData, "/user/password/hash_algorithm", "user_password_hash_algorithm", createFields);
    setJsonField(ret, originalData, "/user/password/inactive_days", "user_password_inactive_days", createFields);
    setJsonField(ret, originalData, "/user/password/last_change", "user_password_last_change", createFields);
    setJsonField(ret, originalData, "/user/password/max_days_between_changes", "user_password_max_days_between_changes", createFields);
    setJsonField(ret, originalData, "/user/password/min_days_between_changes", "user_password_min_days_between_changes", createFields);
    setJsonField(ret, originalData, "/user/password/status", "user_password_status", createFields);
    setJsonField(ret, originalData, "/user/password/warning_days_before_expiration", "user_password_warning_days_before_expiration", createFields);
    setJsonFieldArray(ret, originalData, "/user/roles", "user_roles", createFields);
    setJsonField(ret, originalData, "/user/shell", "user_shell", createFields);
    setJsonField(ret, originalData, "/user/type", "user_type", createFields);
    setJsonField(ret, originalData, "/user/uid_signed", "user_uid_signed", createFields);
    setJsonField(ret, originalData, "/user/uuid", "user_uuid", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsGroupsData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/group/description", "group_description", createFields);
    setJsonField(ret, originalData, "/group/id", "group_id", createFields);
    setJsonField(ret, originalData, "/group/id_signed", "group_id_signed", createFields);
    setJsonField(ret, originalData, "/group/is_hidden", "group_is_hidden", createFields, true);
    setJsonField(ret, originalData, "/group/name", "group_name", createFields);
    setJsonFieldArray(ret, originalData, "/group/users", "group_users", createFields);
    setJsonField(ret, originalData, "/group/uuid", "group_uuid", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsServicesData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/error/log/file/path", "error_log_file_path", createFields);
    setJsonField(ret, originalData, "/file/path", "file_path", createFields);
    setJsonField(ret, originalData, "/log/file/path", "log_file_path", createFields);
    setJsonFieldArray(ret, originalData, "/process/args", "process_args", createFields);
    setJsonField(ret, originalData, "/process/executable", "process_executable", createFields);
    setJsonField(ret, originalData, "/process/group/name", "process_group_name", createFields);
    setJsonField(ret, originalData, "/process/pid", "process_pid", createFields);
    setJsonField(ret, originalData, "/process/root_directory", "process_root_dir", createFields);
    setJsonField(ret, originalData, "/process/user/name", "process_user_name", createFields);
    setJsonField(ret, originalData, "/process/working_directory", "process_working_dir", createFields);
    setJsonField(ret, originalData, "/service/address", "service_address", createFields);
    setJsonField(ret, originalData, "/service/description", "service_description", createFields);
    setJsonField(ret, originalData, "/service/enabled", "service_enabled", createFields);
    setJsonField(ret, originalData, "/service/exit_code", "service_exit_code", createFields);
    setJsonField(ret, originalData, "/service/following", "service_following", createFields);
    setJsonField(ret, originalData, "/service/frequency", "service_frequency", createFields);
    setJsonField(ret, originalData, "/service/id", "service_id", createFields);
    setJsonField(ret, originalData, "/service/inetd_compatibility", "service_inetd_compatibility", createFields, true);
    setJsonField(ret, originalData, "/service/name", "service_name", createFields);
    setJsonField(ret, originalData, "/service/object_path", "service_object_path", createFields);
    setJsonField(ret, originalData, "/service/restart", "service_restart", createFields);
    setJsonField(ret, originalData, "/service/start_type", "service_start_type", createFields);
    setJsonField(ret, originalData, "/service/starts/on_mount", "service_starts_on_mount", createFields, true);
    setJsonFieldArray(ret, originalData, "/service/starts/on_not_empty_directory", "service_starts_on_not_empty_directory", createFields);
    setJsonFieldArray(ret, originalData, "/service/starts/on_path_modified", "service_starts_on_path_modified", createFields);
    setJsonField(ret, originalData, "/service/state", "service_state", createFields);
    setJsonField(ret, originalData, "/service/sub_state", "service_sub_state", createFields);
    setJsonField(ret, originalData, "/service/target/address", "service_target_address", createFields);

    // Convert service_target_ephemeral_id from number to string for ECS compliance
    if (createFields || originalData.contains("service_target_ephemeral_id"))
    {
        const nlohmann::json::json_pointer pointer("/service/target/ephemeral_id");

        if (originalData.contains("service_target_ephemeral_id"))
        {
            const auto& value = originalData["service_target_ephemeral_id"];

            if (value == EMPTY_VALUE || value == UNKNOWN_VALUE)
            {
                ret[pointer] = value;
            }
            else if (value.is_number())
            {
                ret[pointer] = std::to_string(value.get<int>());
            }
            else
            {
                ret[pointer] = value;
            }
        }
        else
        {
            ret[pointer] = nullptr;
        }
    }

    setJsonField(ret, originalData, "/service/target/type", "service_target_type", createFields);
    setJsonField(ret, originalData, "/service/type", "service_type", createFields);
    setJsonField(ret, originalData, "/service/win32_exit_code", "service_win32_exit_code", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsBrowserExtensionsData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/browser/name", "browser_name", createFields);
    setJsonField(ret, originalData, "/browser/profile/name", "browser_profile_name", createFields);
    setJsonField(ret, originalData, "/browser/profile/path", "browser_profile_path", createFields);
    setJsonField(ret, originalData, "/browser/profile/referenced", "browser_profile_referenced", createFields, true);
    setJsonField(ret, originalData, "/file/hash/sha256", "file_hash_sha256", createFields);
    setJsonField(ret, originalData, "/package/autoupdate", "package_autoupdate", createFields, true);
    setJsonField(ret, originalData, "/package/build_version", "package_build_version", createFields);
    setJsonField(ret, originalData, "/package/description", "package_description", createFields);
    setJsonField(ret, originalData, "/package/enabled", "package_enabled", createFields, true);
    setJsonField(ret, originalData, "/package/from_webstore", "package_from_webstore", createFields, true);
    setJsonField(ret, originalData, "/package/id", "package_id", createFields);

    // package_installed is kept as the raw collector string through dbsync (TEXT column,
    // compared/stored as-is) and only converted to an epoch integer here, for ECS compatibility.
    if (createFields || originalData.contains("package_installed"))
    {
        const nlohmann::json::json_pointer pointer("/package/installed");
        nlohmann::json installed;

        if (originalData.contains("package_installed") && originalData["package_installed"].is_string())
        {
            const auto& timestampStr = originalData["package_installed"].get<std::string>();

            if (!timestampStr.empty() && timestampStr != " " && timestampStr != "0")
            {
                try
                {
                    installed = std::stoll(timestampStr);
                }
                catch (const std::exception&)
                {
                    installed = nullptr;
                }
            }
        }

        ret[pointer] = installed;
    }

    setJsonField(ret, originalData, "/package/name", "package_name", createFields);
    setJsonField(ret, originalData, "/package/path", "package_path", createFields);
    setJsonFieldArray(ret, originalData, "/package/permissions", "package_permissions", createFields);
    setJsonField(ret, originalData, "/package/persistent", "package_persistent", createFields, true);
    setJsonField(ret, originalData, "/package/reference", "package_reference", createFields);
    setJsonField(ret, originalData, "/package/type", "package_type", createFields);
    setJsonField(ret, originalData, "/package/vendor", "package_vendor", createFields);
    setJsonField(ret, originalData, "/package/version", "package_version_", createFields);
    setJsonField(ret, originalData, "/package/visible", "package_visible", createFields, true);
    setJsonField(ret, originalData, "/user/id", "user_id", createFields);

    return ret;
}

nlohmann::json Syscollector::getHardwareData()
{
    nlohmann::json ret;
    ret[0] = m_spInfo->hardware();
    sanitizeJsonValue(ret[0]);

    auto checksumInput = ret[0];
    checksumInput.erase("memory_free");
    checksumInput.erase("memory_used");
    ret[0]["checksum"] = getItemChecksum(checksumInput);
    return ret;
}

void Syscollector::scanHardware()
{
    if (m_hardware)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting hardware scan");
        const auto& hwData{getHardwareData()};
        updateChanges(HW_TABLE, hwData);
        m_logFunction(LOG_DEBUG_VERBOSE, "Ending hardware scan");
    }
}

nlohmann::json Syscollector::getOSData()
{
    nlohmann::json ret;
    ret[0] = m_spInfo->os();
    sanitizeJsonValue(ret[0]);
    ret[0]["checksum"] = getItemChecksum(ret[0]);
    return ret;
}

void Syscollector::scanOs()
{
    if (m_os)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting os scan");
        const auto& osData{getOSData()};
        updateChanges(OS_TABLE, osData);
        m_logFunction(LOG_DEBUG_VERBOSE, "Ending os scan");
    }
}

nlohmann::json Syscollector::getNetworkData()
{
    nlohmann::json ret;
    auto networks = m_spInfo->networks();
    nlohmann::json ifaceTableDataList {};
    nlohmann::json protoTableDataList {};
    nlohmann::json addressTableDataList {};
    constexpr auto IPV4 { 0 };
    constexpr auto IPV6 { 1 };
    static const std::map<int, std::string> IP_TYPE
    {
        { IPV4, "ipv4" },
        { IPV6, "ipv6" }
    };

    if (!networks.is_null())
    {
        sanitizeJsonValue(networks);
        const auto& itIface { networks.find("iface") };

        if (networks.end() != itIface)
        {
            for (const auto& item : itIface.value())
            {
                // Split the resulting networks data into the specific DB tables
                // "dbsync_network_iface" table data to update and notify
                nlohmann::json ifaceTableData {};
                ifaceTableData["interface_name"]                = item.at("interface_name");
                ifaceTableData["interface_alias"]               = item.at("interface_alias");
                ifaceTableData["interface_type"]                = item.at("interface_type");
                ifaceTableData["interface_state"]               = item.at("interface_state");
                ifaceTableData["interface_mtu"]                 = item.at("interface_mtu");
                ifaceTableData["host_mac"]                      = item.at("host_mac");
                ifaceTableData["host_network_egress_packages"]  = item.at("host_network_egress_packages");
                ifaceTableData["host_network_ingress_packages"] = item.at("host_network_ingress_packages");
                ifaceTableData["host_network_egress_errors"]    = item.at("host_network_egress_errors");
                ifaceTableData["host_network_ingress_errors"]   = item.at("host_network_ingress_errors");
                ifaceTableData["host_network_egress_bytes"]     = item.at("host_network_egress_bytes");
                ifaceTableData["host_network_ingress_bytes"]    = item.at("host_network_ingress_bytes");
                ifaceTableData["host_network_egress_drops"]     = item.at("host_network_egress_drops");
                ifaceTableData["host_network_ingress_drops"]    = item.at("host_network_ingress_drops");

                auto ifaceChecksumInput = ifaceTableData;

                for (const auto& field : NET_IFACE_IGNORED_FIELDS)
                {
                    ifaceChecksumInput.erase(field);
                }

                ifaceTableData["checksum"] = getItemChecksum(ifaceChecksumInput);
                ifaceTableDataList.push_back(std::move(ifaceTableData));

                if (item.find("IPv4") != item.end())
                {
                    // "dbsync_network_protocol" table data to update and notify
                    nlohmann::json protoTableData {};
                    protoTableData["interface_name"]  = item.at("interface_name");
                    protoTableData["network_gateway"] = item.at("network_gateway");
                    protoTableData["network_type"]    = IP_TYPE.at(IPV4);
                    protoTableData["network_dhcp"]    = item.at("IPv4").begin()->at("network_dhcp");
                    protoTableData["network_metric"]  = item.at("IPv4").begin()->at("network_metric");
                    protoTableData["checksum"]        = getItemChecksum(protoTableData);
                    protoTableDataList.push_back(std::move(protoTableData));

                    for (auto addressTableData : item.at("IPv4"))
                    {
                        // "dbsync_network_address" table data to update and notify
                        addressTableData["interface_name"]   = item.at("interface_name");
                        addressTableData["network_type"] = IPV4;
                        addressTableData["checksum"]         = getItemChecksum(addressTableData);
                        // Remove unwanted fields for dbsync_network_address table
                        addressTableData.erase("network_dhcp");
                        addressTableData.erase("network_metric");

                        addressTableDataList.push_back(std::move(addressTableData));
                    }
                }

                if (item.find("IPv6") != item.end())
                {
                    // "dbsync_network_protocol" table data to update and notify
                    nlohmann::json protoTableData {};
                    protoTableData["interface_name"]  = item.at("interface_name");
                    protoTableData["network_gateway"] = item.at("network_gateway");
                    protoTableData["network_type"]    = IP_TYPE.at(IPV6);
                    protoTableData["network_dhcp"]    = item.at("IPv6").begin()->at("network_dhcp");
                    protoTableData["network_metric"]  = item.at("IPv6").begin()->at("network_metric");
                    protoTableData["checksum"]        = getItemChecksum(protoTableData);
                    protoTableDataList.push_back(std::move(protoTableData));

                    for (auto addressTableData : item.at("IPv6"))
                    {
                        // "dbsync_network_address" table data to update and notify
                        addressTableData["interface_name"]   = item.at("interface_name");
                        addressTableData["network_type"] = IPV6;
                        addressTableData["checksum"]         = getItemChecksum(addressTableData);
                        // Remove unwanted fields for dbsync_network_address table
                        addressTableData.erase("network_dhcp");
                        addressTableData.erase("network_metric");

                        addressTableDataList.push_back(std::move(addressTableData));
                    }
                }
            }

            ret[NET_IFACE_TABLE] = std::move(ifaceTableDataList);
            ret[NET_PROTOCOL_TABLE] = std::move(protoTableDataList);
            ret[NET_ADDRESS_TABLE] = std::move(addressTableDataList);
        }
    }

    return ret;
}

void Syscollector::scanNetwork()
{
    if (m_network)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting network scan");

        const auto networkData(getNetworkData());

        if (!networkData.is_null())
        {
            const auto itIface { networkData.find(NET_IFACE_TABLE) };

            if (itIface != networkData.end())
            {
                updateChanges(NET_IFACE_TABLE, itIface.value());
            }

            const auto itProtocol { networkData.find(NET_PROTOCOL_TABLE) };

            if (itProtocol != networkData.end())
            {
                updateChanges(NET_PROTOCOL_TABLE, itProtocol.value());
            }

            const auto itAddress { networkData.find(NET_ADDRESS_TABLE) };

            if (itAddress != networkData.end())
            {
                updateChanges(NET_ADDRESS_TABLE, itAddress.value());
            }
        }

        m_logFunction(LOG_DEBUG_VERBOSE, "Ending network scan");
    }
}

void Syscollector::scanPackages()
{
    if (m_packages)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting packages scan");

        const auto callback
        {
            [this](ReturnTypeCallback result, const nlohmann::json & data)
            {
                notifyChange(result, data, PACKAGES_TABLE, m_notify);
            }
        };
        DBSyncTxn txn
        {
            m_spDBSync->handle(),
            scopedTxnTables(nlohmann::json{PACKAGES_TABLE}, HOST_CONTAINER_ID),
            0,
            QUEUE_SIZE,
            callback
        };
        m_spInfo->packages([this, &txn](nlohmann::json & rawData)
        {
            nlohmann::json input;

            sanitizeJsonValue(rawData);
            rawData[CONTAINER_ID_COLUMN] = HOST_CONTAINER_ID;
            rawData["checksum"] = getRowChecksum(rawData);

            input["table"] = PACKAGES_TABLE;
            m_spNormalizer->normalize("packages", rawData);
            m_spNormalizer->removeExcluded("packages", rawData);

            if (!rawData.empty())
            {
                input["data"] = nlohmann::json::array( { rawData } );
                input["options"]["return_old_data"] = true;

                txn.syncTxnRow(input);
            }
        });
        txn.getDeletedRows(callback);

        m_logFunction(LOG_DEBUG_VERBOSE, "Ending packages scan");
    }
}

void Syscollector::scanHotfixes()
{
    if (m_hotfixes)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting hotfixes scan");
        auto hotfixes = m_spInfo->hotfixes();

        if (!hotfixes.is_null())
        {
            sanitizeJsonValue(hotfixes);

            for (auto& hotfix : hotfixes)
            {
                hotfix["checksum"] = getItemChecksum(hotfix);
            }

            updateChanges(HOTFIXES_TABLE, hotfixes);
        }

        m_logFunction(LOG_DEBUG_VERBOSE, "Ending hotfixes scan");
    }
}

nlohmann::json Syscollector::getPortsData()
{
    nlohmann::json ret;
    constexpr auto PORT_LISTENING_STATE { "listening" };
    constexpr auto TCP_PROTOCOL { "tcp" };
    constexpr auto UDP_PROTOCOL { "udp" };
    auto data(m_spInfo->ports());

    const std::vector<std::string> PORTS_ITEM_ID_FIELDS {"file_inode", "network_transport", "source_ip", "source_port"};

    if (!data.is_null())
    {
        sanitizeJsonValue(data);

        for (auto& item : data)
        {
            const auto protocol { item.at("network_transport").get_ref<const std::string&>() };

            if (Utils::startsWith(protocol, TCP_PROTOCOL))
            {
                // All ports.
                if (m_portsAll)
                {
                    const auto& itemId { getItemId(item, PORTS_ITEM_ID_FIELDS) };

                    if (!isElementDuplicated(ret, std::make_pair("item_id", itemId)))
                    {
                        item["checksum"] = getItemChecksum(item);
                        item["item_id"] = itemId;
                        ret.push_back(item);
                    }
                }
                else
                {
                    // Only listening ports.
                    const auto isListeningState { item.at("interface_state") == PORT_LISTENING_STATE };

                    if (isListeningState)
                    {
                        const auto& itemId { getItemId(item, PORTS_ITEM_ID_FIELDS) };

                        if (!isElementDuplicated(ret, std::make_pair("item_id", itemId)))
                        {
                            item["checksum"] = getItemChecksum(item);
                            item["item_id"] = itemId;
                            ret.push_back(item);
                        }
                    }
                }
            }
            else if (Utils::startsWith(protocol, UDP_PROTOCOL))
            {
                const auto& itemId { getItemId(item, PORTS_ITEM_ID_FIELDS) };

                if (!isElementDuplicated(ret, std::make_pair("item_id", itemId)))
                {
                    item["checksum"] = getItemChecksum(item);
                    item["item_id"] = itemId;
                    ret.push_back(item);
                }
            }
        }
    }

    return ret;
}

void Syscollector::scanPorts()
{
    if (m_ports)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting ports scan");
        const auto& portsData { getPortsData() };
        updateChanges(PORTS_TABLE, portsData);
        m_logFunction(LOG_DEBUG_VERBOSE, "Ending ports scan");
    }
}

void Syscollector::scanProcesses()
{
    if (m_processes)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting processes scan");

        const auto callback
        {
            [this](ReturnTypeCallback result, const nlohmann::json & data)
            {
                notifyChange(result, data, PROCESSES_TABLE, m_notify);
            }
        };
        DBSyncTxn txn
        {
            m_spDBSync->handle(),
            scopedTxnTables(nlohmann::json{PROCESSES_TABLE}, HOST_CONTAINER_ID),
            0,
            QUEUE_SIZE,
            callback
        };
        m_spInfo->processes([this, &txn](nlohmann::json & rawData)
        {
            nlohmann::json input;

            sanitizeJsonValue(rawData);
            rawData[CONTAINER_ID_COLUMN] = HOST_CONTAINER_ID;

            auto checksumInput = rawData;
            checksumInput.erase("utime");
            checksumInput.erase("stime");
            rawData["checksum"] = getRowChecksum(checksumInput);

            input["table"] = PROCESSES_TABLE;
            input["data"] = nlohmann::json::array( { rawData } );
            input["options"]["return_old_data"] = true;
            input["options"]["ignore"] = PROCESSES_IGNORED_FIELDS;

            txn.syncTxnRow(input);
        });
        txn.getDeletedRows(callback);

        m_logFunction(LOG_DEBUG_VERBOSE, "Ending processes scan");
    }
}

nlohmann::json Syscollector::getGroupsData()
{
    nlohmann::json ret;
    auto groups = m_spInfo->groups();

    if (!groups.is_null())
    {
        for (auto& group : groups)
        {
            sanitizeJsonValue(group);
            group["checksum"] = getItemChecksum(group);
            ret.push_back(std::move(group));
        }
    }

    return ret;
}

nlohmann::json Syscollector::getUsersData()
{
    nlohmann::json ret;
    auto users = m_spInfo->users();

    if (!users.is_null())
    {
        for (auto& user : users)
        {
            sanitizeJsonValue(user);
            user["checksum"] = getItemChecksum(user);
            ret.push_back(std::move(user));
        }
    }

    return ret;
}

nlohmann::json Syscollector::getServicesData()
{
    nlohmann::json ret;
    auto services = m_spInfo->services();

    if (!services.is_null())
    {
        for (auto& service : services)
        {
            sanitizeJsonValue(service);
            service["checksum"] = getItemChecksum(service);
            ret.push_back(std::move(service));
        }
    }

    return ret;
}

nlohmann::json Syscollector::getBrowserExtensionsData()
{
    nlohmann::json ret;
    auto extensions = m_spInfo->browserExtensions();

    if (!extensions.is_null())
    {
        for (auto& extension : extensions)
        {
            sanitizeJsonValue(extension);
            extension["checksum"] = getItemChecksum(extension);
            ret.push_back(std::move(extension));
        }
    }

    return ret;
}

void Syscollector::scanGroups()
{
    if (m_groups)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting groups scan");
        const auto& groupsData { getGroupsData() };
        updateChanges(GROUPS_TABLE, groupsData);
        m_logFunction(LOG_DEBUG_VERBOSE, "Ending groups scan");
    }
}

void Syscollector::scanUsers()
{
    if (m_users)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting users scan");
        const auto& usersData { getUsersData() };
        updateChanges(USERS_TABLE, usersData);
        m_logFunction(LOG_DEBUG_VERBOSE, "Ending users scan");
    }
}

void Syscollector::scanServices()
{
    if (m_services)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting services scan");
        const auto& servicesData { getServicesData() };
        updateChanges(SERVICES_TABLE, servicesData);
        m_logFunction(LOG_DEBUG_VERBOSE, "Ending services scan");
    }
}

void Syscollector::scanBrowserExtensions()
{
    if (m_browserExtensions)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting browser extensions scan");
        const auto& extensionsData { getBrowserExtensionsData() };
        updateChanges(BROWSER_EXTENSIONS_TABLE, extensionsData);
        m_logFunction(LOG_DEBUG_VERBOSE, "Ending browser extensions scan");
    }
}

#if defined(__linux__)
namespace
{
    // Tables the container baseline covers; each container gets one scoped
    // txn per table so absent rows (or absent containers) turn into DELETED
    // events through the same pipeline as host rows.
    const std::vector<std::string> CONTAINER_BASELINE_TABLES
    {
        PROCESSES_TABLE, PORTS_TABLE, USERS_TABLE, GROUPS_TABLE, PACKAGES_TABLE,
        OS_TABLE, NET_IFACE_TABLE, NET_ADDRESS_TABLE, NET_PROTOCOL_TABLE,
        SERVICES_TABLE, HW_TABLE
    };
}
#endif

/// Deletes the rows of every container present in the database but absent from
/// `keep`, emitting their DELETED events through the normal scoped-transaction
/// path. Returns how many containers were swept.
///
/// Callers pass the set of containers that still EXIST (not the set that
/// produced rows this scan) — a container that is merely stopped produces no
/// rows but must keep its state so a restart resumes diffing against it rather
/// than re-seeding from empty. Passing an empty set therefore removes ALL
/// container rows, which is what the disabled-collector path wants.
std::size_t Syscollector::sweepContainerRowsNotIn(const std::set<std::string>& keep)
{
#if defined(__linux__)
    std::set<std::string> staleIds;

    for (const auto& table : CONTAINER_BASELINE_TABLES)
    {
        const auto selectCallback = [&staleIds, &keep](ReturnTypeCallback result, const nlohmann::json & data)
        {
            if (result == SELECTED && data.contains(CONTAINER_ID_COLUMN) && data.at(CONTAINER_ID_COLUMN).is_string())
            {
                const auto& id = data.at(CONTAINER_ID_COLUMN).get_ref<const std::string&>();

                if (!id.empty() && keep.find(id) == keep.end())
                {
                    staleIds.insert(id);
                }
            }
        };

        // DISTINCT so the engine returns at most one row per container instead
        // of one row per stored inventory row.
        auto selectQuery = SelectQuery::builder()
                           .table(table)
                           .columnList({CONTAINER_ID_COLUMN})
                           .rowFilter("WHERE container_id != ''")
                           .distinctOpt(true)
                           .build();
        m_spDBSync->selectRows(selectQuery.query(), selectCallback);
    }

    for (const auto& staleId : staleIds)
    {
        for (const auto& table : CONTAINER_BASELINE_TABLES)
        {
            updateChanges(table, nlohmann::json::array(), staleId);
        }

        m_knownContainerIds.erase(staleId);
    }

    return staleIds.size();
#else
    (void)keep;
    return 0;
#endif
}

void Syscollector::runContainerBaselinePass()
{
    // syncLoop() dispatches the container pass on its own deadline, so it no
    // longer borrows scan()'s stopping/paused checks or its ScanGuard.
    //
    // The guard lives HERE and not inside scanContainerBaseline(), because
    // scan() still calls that directly when the two cadences are coupled
    // (<container_baseline_interval> = 0) and scan() already holds a guard of
    // its own. ScanGuard is a plain set/clear of one flag, so a nested second
    // one would clear m_scanning on the inner exit and let pause() return
    // while the rest of the scan was still writing rows.
    if (m_stopping.load())
    {
        m_logFunction(LOG_DEBUG, "Syscollector is stopping, skipping container baseline.");
        return;
    }

    if (m_paused)
    {
        m_logFunction(LOG_DEBUG, "Syscollector is paused, skipping container baseline.");
        return;
    }

    ScanGuard scanGuard(m_scanning, m_pauseCv);

    // The document-limit bookkeeping scan() does around its collectors has to
    // happen here too, and did not when this cadence was introduced
    // (4b365c11d6). m_itemsToUpdateSync is only non-null inside scan(), so on
    // this path checkDocumentLimit() had nowhere to record the rows it let
    // through: they stayed sync=0 even with everything unlimited, which hid
    // them from every sync=1 query (the counters, and VD's DataContext) and
    // left the next host scan's promotion free to re-emit them as CREATEs it
    // had already sent.
    std::vector<std::pair<std::string, nlohmann::json>> itemsToUpdateSync;
    m_itemsToUpdateSync = &itemsToUpdateSync;

    std::vector<std::pair<std::string, nlohmann::json>> failedItems;
    m_failedItems = &failedItems;

    scanContainerBaseline();

    // Same order scan() uses: mark what passed, then fill any freed slots, then
    // drop the pointers, then delete the rows that failed validation.
    updateSyncFlagInDB(itemsToUpdateSync, 1);
    promoteItemsAfterScan();

    m_failedItems = nullptr;
    m_itemsToUpdateSync = nullptr;

    deleteFailedItemsFromDB(failedItems);
}

void Syscollector::scanContainerBaseline()
{
#if defined(__linux__)

    // Gated like every sibling collector. Previously this ran unconditionally
    // on every Linux agent with no way to turn it off, which also meant paying
    // the connector's cold-start retry on hosts running no containers at all.
    if (!m_containerBaseline)
    {
        // Turning a collector off must not leave its rows behind as permanently
        // stale state, which is what every sibling collector's
        // disabled-with-data cleanup achieves. Container rows share the host
        // tables (scoped by container_id) rather than owning an index of their
        // own, so they are removed here with a one-shot scoped sweep instead.
        if (!m_containerRowsPurged)
        {
            const auto purged = sweepContainerRowsNotIn({});
            m_containerRowsPurged = true;

            if (purged > 0)
            {
                m_logFunction(LOG_DEBUG,
                              "Container baseline is disabled; removed rows of " + std::to_string(purged) +
                              " container(s) left in the database.");
            }
        }

        return;
    }

    m_logFunction(LOG_DEBUG_VERBOSE, "Starting container baseline scan");

    // Rows for one container arrive contiguously and are followed by that
    // container's status callback, so a container can be flushed to the DB as
    // soon as its status arrives. Peak memory is therefore ONE container's
    // rows rather than the whole node's — previously every row of every table
    // of every container was held as parsed nlohmann::json before the first
    // write, which on a large node is hundreds of MB.
    struct Accumulator
    {
        Syscollector* self{nullptr};
        // table -> rows, for the container currently being received.
        std::map<std::string, nlohmann::json> tables;
        std::string current;
        std::size_t rowCount{0};
        std::size_t partialContainers{0};
        std::size_t hostNetnsContainers{0};
        std::size_t unreadableNetnsContainers{0};

        // Why a data class can legitimately have produced no rows, which is
        // never the same fact as "the state was removed".
        struct Absence
        {
            bool partial{false};          // scan truncated / path missing
            bool netnsHostScoped{false};  // shares the host netns; rows are the node's, not the container's
            bool netnsUnreadable{false};  // could not enter the netns (CAP_SYS_ADMIN)
        };

        // Delete detection must be suppressed for exactly the tables whose rows
        // were not collected, and no others. Suppressing all eleven whenever
        // anything was missing would mean that on a host without CAP_SYS_ADMIN
        // no container row could ever be deleted, so stale state would
        // accumulate indefinitely.
        static bool detectDeletionsFor(const std::string& table, const Absence& absence)
        {
            if (absence.partial)
            {
                return false;
            }

            const bool isNetnsScoped = (table == PORTS_TABLE || table == NET_IFACE_TABLE ||
                                        table == NET_ADDRESS_TABLE || table == NET_PROTOCOL_TABLE);

            if (absence.netnsHostScoped && isNetnsScoped)
            {
                return false;
            }

            const bool isInterfaceTable = (table == NET_IFACE_TABLE || table == NET_ADDRESS_TABLE);

            if (absence.netnsUnreadable && isInterfaceTable)
            {
                return false;
            }

            return true;
        }

        void flush(const Absence& absence)
        {
            if (current.empty())
            {
                return;
            }

            // A container's very first sync is forced quiet (no stateless
            // alert), matching the original one-shot baseline's seed
            // behaviour; every sync after that follows m_notify normally.
            const bool isFirstSync = self->m_knownContainerIds.insert(current).second;
            const std::optional<bool> notifyOverride =
                isFirstSync ? std::optional<bool> {false} : std::nullopt;

            for (const auto& table : CONTAINER_BASELINE_TABLES)
            {
                auto it = tables.find(table);
                nlohmann::json tableRows =
                    (it != tables.end()) ? std::move(it->second) : nlohmann::json::array();

                for (auto& row : tableRows)
                {
                    sanitizeJsonValue(row);
                    row["checksum"] = getRowChecksum(row);
                }

                self->updateChanges(table, tableRows, current, notifyOverride,
                                    detectDeletionsFor(table, absence));
            }

            tables.clear();
            current.clear();
        }

        void onRow(const char* containerId, const char* table, const char* rowJson)
        {
            if (!containerId || !table || !rowJson)
            {
                return;
            }

            if (current != containerId)
            {
                // Defensive: the scanner reports a status per container, so this
                // only fires if a container produced rows without a status.
                flush(Absence {});
                current = containerId;
            }

            auto row = nlohmann::json::parse(rowJson, nullptr, false);

            if (row.is_discarded() || !row.is_object())
            {
                return;
            }

            auto& tableRows = tables[table];

            if (!tableRows.is_array())
            {
                tableRows = nlohmann::json::array();
            }

            tableRows.push_back(std::move(row));
            ++rowCount;
        }

        void onStatus(const char* containerId, bool partial, bool hostNetns, bool unreadableNetns)
        {
            if (!containerId)
            {
                return;
            }

            if (current != containerId)
            {
                flush(Absence {});
                current = containerId;
            }

            Absence absence;
            absence.partial = partial;
            absence.netnsHostScoped = hostNetns;
            absence.netnsUnreadable = unreadableNetns;

            if (partial)
            {
                ++partialContainers;
            }

            if (hostNetns)
            {
                ++hostNetnsContainers;
            }

            if (unreadableNetns)
            {
                ++unreadableNetnsContainers;
            }

            flush(absence);
        }
    };

    Accumulator acc;
    acc.self = this;

    const auto sink = [](const char* containerId, const char* table, const char* rowJson, void* userData)
    {
        if (auto* a = static_cast<Accumulator*>(userData))
        {
            a->onRow(containerId, table, rowJson);
        }
    };

    const auto statusSink = [](const cb_container_status_t* status, void* userData)
    {
        if (status == nullptr)
        {
            return;
        }

        if (auto* a = static_cast<Accumulator*>(userData))
        {
            // The individual reasons behind `partial` (row cap, unreadable
            // rootfs, rejected path) are reported per D17 but not consumed
            // here: the inventory accumulator's only decision is whether
            // absence may be read as removal, which is exactly `partial`.
            a->onStatus(status->container_id,
                        status->partial != 0,
                        status->netns_host_scoped != 0,
                        status->netns_unreadable != 0);
        }
    };

    const int baselined =
        cbaseline_run_syscollector_dbsync(CB_DEFAULT_CONNECTOR_SOCKET_PATH, sink, statusSink, &acc);

    acc.flush(Accumulator::Absence {}); // defensive: nothing should remain pending

    if (acc.unreadableNetnsContainers > 0)
    {
        m_logFunction(LOG_DEBUG,
                      "Container baseline: could not enter the network namespace of " +
                      std::to_string(acc.unreadableNetnsContainers) +
                      " container(s) (CAP_SYS_ADMIN missing?); their interface and address rows are absent.");
    }

    if (acc.hostNetnsContainers > 0)
    {
        m_logFunction(LOG_DEBUG_VERBOSE,
                      std::to_string(acc.hostNetnsContainers) +
                      " container(s) share the host network namespace; no container-scoped network rows "
                      "were attributed to them.");
    }

    // Every container currently known to container_instances, independent of
    // whether it has a resolvable live PID right now. A container that's
    // merely stopped is still reported here even though it produced no rows
    // above — this is what lets the stale sweep below tell "stopped" apart
    // from "gone" instead of conflating them.
    std::set<std::string> discoveredIds;
    const auto idSink = [](const char* containerId, void* userData)
    {
        auto* ids = static_cast<std::set<std::string>*>(userData);

        if (ids && containerId)
        {
            ids->insert(containerId);
        }
    };
    const int listed = cbaseline_list_containers(CB_DEFAULT_CONNECTOR_SOCKET_PATH, idSink, &discoveredIds);

    // Containers still in the DB but no longer known to container_instances
    // at all (genuinely removed, not merely stopped): an empty scoped sync
    // per stale id emits their DELETED events — each row's container_json
    // column keeps those self-contained. A container that's still known but
    // just has no live PID right now (stopped) is in `discoveredIds` and is
    // therefore left untouched here, so a later restart resumes diffing
    // against its retained rows instead of re-seeding from empty.
    //
    // Unless the connector never answered (listed < 0), in which case
    // `discoveredIds` is empty for want of a reply rather than for want of
    // containers — sweeping against it would delete every container's rows in
    // every table and re-insert them next cycle. Keeping stale rows for one
    // cycle is strictly cheaper than that false-delete flood.
    std::size_t staleCount = 0;

    if (listed < 0)
    {
        m_logFunction(LOG_WARNING,
                      "Container connector unavailable; skipping stale-container cleanup "
                      "to avoid deleting rows for containers that still exist.");
    }
    else
    {
        staleCount = sweepContainerRowsNotIn(discoveredIds);
    }

    m_logFunction(LOG_DEBUG_VERBOSE,
                  "Container baseline scan finished (" + std::to_string(baselined) + " container(s), " +
                  std::to_string(acc.rowCount) + " row(s), " +
                  std::to_string(acc.partialContainers) + " partial scan(s), " +
                  std::to_string(staleCount) + " stale container(s) cleaned).");
#else
    // Container baseline acquisition (#37532) only runs on Linux - the same
    // Linux-only constraint as container_instances and the eBPF module it
    // depends on.
    m_logFunction(LOG_DEBUG_VERBOSE, "Container baseline scan skipped (Linux-only feature).");
#endif
}

void Syscollector::scan()
{
    if (m_stopping.load())
    {
        m_logFunction(LOG_DEBUG, "Syscollector is stopping, skipping evaluation.");
        return;
    }

    if (m_paused)
    {
        m_logFunction(LOG_DEBUG, "Syscollector is paused, skipping evaluation.");
        return;
    }

    // RAII guard ensures m_scanning is set to false even if function exits early
    ScanGuard scanGuard(m_scanning, m_pauseCv);

    // Vector to accumulate items that fail validation for deferred deletion
    // All scan functions will use this shared vector to collect failed items
    std::vector<std::pair<std::string, nlohmann::json>> failedItems;
    m_failedItems = &failedItems;

    // Vector to accumulate items that passed document limit check for deferred sync=1 update
    // All scan functions will use this shared vector to collect items to update
    std::vector<std::pair<std::string, nlohmann::json>> itemsToUpdateSync;
    m_itemsToUpdateSync = &itemsToUpdateSync;

    int64_t firstScanCompleted = 0;
    const bool isFirstScan = !getMetadataValue(SYSCOLLECTOR_FIRST_SCAN_COMPLETED_METADATA_KEY, firstScanCompleted)
                             || firstScanCompleted == 0;

    if (isFirstScan)
    {
        m_logFunction(LOG_DEBUG, "Initial Syscollector scan starting.");
    }
    else
    {
        // This device has already completed a first scan in a previous run: whatever restarted this
        // process (service restart, shared-config reload, upgrade) is not an enrollment, so there is no
        // "flood of created events" risk to guard against. Restoring m_notify here, instead of waiting
        // for this scan to finish, closes the window where a change detected before that point would be
        // silently absorbed into the baseline (marked as known in DBSync) without ever being notified.
        m_notify = true;
    }

    m_logFunction(LOG_INFO, "Starting evaluation.");
    TRY_CATCH_TASK(scanHardware);
    TRY_CATCH_TASK(scanOs);
    TRY_CATCH_TASK(scanNetwork);
    TRY_CATCH_TASK(scanPackages);
    TRY_CATCH_TASK(scanHotfixes);
    TRY_CATCH_TASK(scanPorts);
    TRY_CATCH_TASK(scanProcesses);
    TRY_CATCH_TASK(scanGroups);
    TRY_CATCH_TASK(scanUsers);
    TRY_CATCH_TASK(scanServices);
    TRY_CATCH_TASK(scanBrowserExtensions);

    // Container baseline (#37532) seeds a container's state the first time it
    // is seen (kept quiet — see scanContainerBaseline()'s per-container
    // notifyOverride) and computes real deltas against that seed afterwards,
    // via the same per-container scoped DBSync transactions host rows already
    // use.
    //
    // It rides scan()'s interval ONLY when it has no cadence of its own. With
    // <container_baseline_interval> set, syncLoop() dispatches it directly on
    // that deadline, and calling it here as well would double every pass.
    if (m_containerBaselineInterval == 0)
    {
        TRY_CATCH_TASK(scanContainerBaseline);
    }

    // Update sync=1 flag for all items that passed document limit check (unlimited items)
    // This must be done BEFORE processVDDataContext so that DataContext queries
    // can filter by sync=1 and only include items within document limits
    updateSyncFlagInDB(itemsToUpdateSync, 1);

    // Promote items to fill available slots after scan completes
    // This calculates available space (limit - current count) and promotes
    // unsynced items with deterministic ordering
    promoteItemsAfterScan();

    // Process VD DataContext after scan completes
    // This adds context data (e.g., all packages when OS changes) based on platform-specific rules
    if (m_vdSyncEnabled)
    {
        TRY_CATCH_TASK(processVDDataContext);
    }

    // Clean up after all scans
    m_failedItems = nullptr;
    m_itemsToUpdateSync = nullptr;

    // Delete all items that failed schema validation inside a DBSync transaction
    // This ensures deletions are committed to disk immediately
    deleteFailedItemsFromDB(failedItems);

    if (isFirstScan)
    {
        updateMetadataValue(SYSCOLLECTOR_FIRST_SCAN_COMPLETED_METADATA_KEY, Utils::getSecondsFromEpoch());
        m_logFunction(LOG_DEBUG, "First inventory scan completed — marker persisted.");
    }

    m_notify = true;
    m_logFunction(LOG_INFO, "Evaluation finished.");
}

void Syscollector::syncLoop(std::unique_lock<std::mutex>& scan_lock)
{
    // Coupled cadence (<container_baseline_interval> = 0, the default): the
    // container pass runs inside scan(), exactly as before, and this loop has
    // one deadline. That path is kept byte-for-byte rather than folded into
    // the two-deadline one below, because the loop below cannot reproduce
    // wait_for's relative-timeout semantics precisely and this is the path
    // every existing deployment is on.
    if (m_containerBaselineInterval == 0)
    {
        if (m_scanOnStart)
        {
            scan();
        }

        while (!m_cv.wait_for(scan_lock, std::chrono::seconds{m_intervalValue}, [&]()
    {
        return m_stopping.load();
        }))
        {
            if (m_paused)
            {
                m_logFunction(LOG_DEBUG, "Syscollector scanning paused, skipping scan iteration");
                continue;
            }

            scan();
        }
        m_cv.notify_all();
        return;
    }

    // Independent cadence: one loop, two deadlines, waking for whichever
    // elapses first — rather than a second thread, which would need its own
    // share of the DBSync handle and its own pause/stop handshake.
    if (m_scanOnStart)
    {
        scan();
        runContainerBaselinePass();
    }

    // Local, not members: their lifetime never outlives this loop.
    auto nextHostScan = std::chrono::steady_clock::now() + std::chrono::seconds{m_intervalValue};
    auto nextContainerScan = std::chrono::steady_clock::now() + std::chrono::seconds{m_containerBaselineInterval};

    while (!m_stopping.load())
    {
        const auto wakeAt = nextHostScan < nextContainerScan ? nextHostScan : nextContainerScan;

        if (m_cv.wait_until(scan_lock, wakeAt, [&]()
        {
            return m_stopping.load();
        }))
        {
            break;
        }

        const auto now = std::chrono::steady_clock::now();

        if (m_paused)
        {
            m_logFunction(LOG_DEBUG, "Syscollector scanning paused, skipping scan iteration");

            // Push any elapsed deadline forward. wait_for's relative timeout
            // gave this for free; an absolute deadline that has already passed
            // makes wait_until return immediately, so without this the loop
            // spins at full speed for as long as the pause lasts.
            if (now >= nextHostScan)
            {
                nextHostScan = now + std::chrono::seconds{m_intervalValue};
            }

            if (now >= nextContainerScan)
            {
                nextContainerScan = now + std::chrono::seconds{m_containerBaselineInterval};
            }

            continue;
        }

        if (now >= nextHostScan)
        {
            scan();
            nextHostScan = now + std::chrono::seconds{m_intervalValue};
        }

        if (now >= nextContainerScan)
        {
            runContainerBaselinePass();
            nextContainerScan = now + std::chrono::seconds{m_containerBaselineInterval};
        }
    }

    m_cv.notify_all();
}

std::string Syscollector::getPrimaryKeys([[maybe_unused]] const nlohmann::json& data, const std::string& table)
{
    std::string ret;

    if (table == OS_TABLE)
    {
        std::string osName = data.contains("os_name") ? data["os_name"].get<std::string>() : "";
        std::string osVersion = data.contains("os_version") ? data["os_version"].get<std::string>() : "";
        ret = osName + ":" + osVersion;
    }
    else if (table == HW_TABLE)
    {
        ret = data.contains("serial_number") ? data["serial_number"].get<std::string>() : "";
    }
    else if (table == HOTFIXES_TABLE)
    {
        ret = data.contains("hotfix_name") ? data["hotfix_name"].get<std::string>() : "";
    }
    else if (table == PACKAGES_TABLE)
    {
        std::string name = data.contains("name") ? data["name"].get<std::string>() : "";
        std::string version = data.contains("version_") ? data["version_"].get<std::string>() : "";
        std::string architecture = data.contains("architecture") ? data["architecture"].get<std::string>() : "";
        std::string type = data.contains("type") ? data["type"].get<std::string>() : "";
        std::string path = data.contains("path") ? data["path"].get<std::string>() : "";

        ret = name + ":" + version + ":" + architecture + ":" + type + ":" + path;
    }
    else if (table == PROCESSES_TABLE)
    {
        ret = data.contains("pid") ? data["pid"].get<std::string>() : "";
    }
    else if (table == PORTS_TABLE)
    {
        std::string file_inode = data.contains("file_inode") ? std::to_string(data["file_inode"].get<int>()) : "0";
        std::string transport = data.contains("network_transport") ? data["network_transport"].get<std::string>() : "";
        std::string source_ip = data.contains("source_ip") ? data["source_ip"].get<std::string>() : "";
        std::string source_port = data.contains("source_port") ? std::to_string(data["source_port"].get<int>()) : "0";

        ret = file_inode + ":" + transport + ":" + source_ip + ":" + source_port;
    }
    else if (table == NET_IFACE_TABLE)
    {
        std::string iface_name = data.contains("interface_name") ? data["interface_name"].get<std::string>() : "";
        std::string iface_alias = data.contains("interface_alias") ? data["interface_alias"].get<std::string>() : "";
        std::string iface_type = data.contains("interface_type") ? data["interface_type"].get<std::string>() : "";

        ret = iface_name + ":" + iface_alias + ":" + iface_type;
    }
    else if (table == NET_PROTOCOL_TABLE)
    {
        std::string iface_name = data.contains("interface_name") ? data["interface_name"].get<std::string>() : "";
        std::string net_type = data.contains("network_type") ? data["network_type"].get<std::string>() : "";

        ret = iface_name + ":" + net_type;
    }
    else if (table == NET_ADDRESS_TABLE)
    {
        std::string iface_name = data.contains("interface_name") ? data["interface_name"].get<std::string>() : "";
        std::string net_protocol = data.contains("network_type") ? std::to_string(data["network_type"].get<int>()) : "0";
        std::string net_ip = data.contains("network_ip") ? data["network_ip"].get<std::string>() : "";

        ret = iface_name + ":" + net_protocol + ":" + net_ip;
    }
    else if (table == USERS_TABLE)
    {
        ret = data.contains("user_name") ? data["user_name"].get<std::string>() : "";
    }
    else if (table == GROUPS_TABLE)
    {
        ret = data.contains("group_name") ? data["group_name"].get<std::string>() : "";
    }
    else if (table == SERVICES_TABLE)
    {
        std::string service_id = data.contains("service_id") ? data["service_id"].get<std::string>() : "";
        std::string file_path = data.contains("file_path") ? data["file_path"].get<std::string>() : "";

        ret = service_id + ":" + file_path;
    }
    else if (table == BROWSER_EXTENSIONS_TABLE)
    {
        std::string browser_name = data.contains("browser_name") ? data["browser_name"].get<std::string>() : "";
        std::string user_id = data.contains("user_id") ? data["user_id"].get<std::string>() : "";
        std::string browser_profile_path = data.contains("browser_profile_path") ? data["browser_profile_path"].get<std::string>() : "";
        std::string package_name = data.contains("package_name") ? data["package_name"].get<std::string>() : "";
        std::string package_version = data.contains("package_version_") ? data["package_version_"].get<std::string>() : "";

        ret = browser_name + ":" + user_id + ":" + browser_profile_path + ":" + package_name + ":" + package_version;
    }

    return ret;
}

std::string Syscollector::calculateHashId(const nlohmann::json& data, const std::string& table)
{
    std::string primaryKey = table + ":";

    if (data.contains(CONTAINER_ID_COLUMN) && data[CONTAINER_ID_COLUMN].is_string() &&
            !data[CONTAINER_ID_COLUMN].get_ref<const std::string&>().empty())
    {
        primaryKey += data[CONTAINER_ID_COLUMN].get<std::string>() + ":";
    }

    primaryKey += getPrimaryKeys(data, table);

    Utils::HashData hash(Utils::HashType::Sha1);
    hash.update(primaryKey.c_str(), primaryKey.size());

    return Utils::asciiToHex(hash.hash());
}

nlohmann::json Syscollector::addPreviousFields(nlohmann::json& current, const nlohmann::json& previous)
{
    using JsonPair = std::pair<nlohmann::json*, const nlohmann::json*>;
    using PathPair = std::pair<std::string, JsonPair>;

    std::stack<PathPair> stack;
    nlohmann::json modifiedKeys = nlohmann::json::array();

    stack.emplace("", JsonPair(&current, &previous));

    while (!stack.empty())
    {
        auto [path, pair] = stack.top();
        auto [curr, prev] = pair;
        stack.pop();

        for (auto& [key, value] : prev->items())
        {
            std::string currentPath = path;

            if (!path.empty())
            {
                currentPath.append(".").append(key);
            }
            else
            {
                currentPath = key;
            }

            if (curr->contains(key))
            {
                if ((*curr)[key].is_object() && value.is_object())
                {
                    stack.emplace(currentPath, JsonPair(&((*curr)[key]), &value));
                }
                else if ((*curr)[key] != value)
                {
                    modifiedKeys.push_back(currentPath);

                    size_t dotPos = currentPath.find('.');
                    std::string topLevelKey = (dotPos != std::string::npos) ? currentPath.substr(0, dotPos) : currentPath;

                    if (!current[topLevelKey].contains("previous"))
                    {
                        current[topLevelKey]["previous"] = nlohmann::json::object();
                    }

                    if (dotPos != std::string::npos)
                    {
                        std::string relativePath = currentPath.substr(dotPos + 1);
                        nlohmann::json::json_pointer pointer("/" + std::regex_replace(relativePath, std::regex("\\."), "/"));
                        current[std::move(topLevelKey)]["previous"][pointer] = value;
                    }
                    else
                    {
                        current[std::move(topLevelKey)]["previous"][key] = value;
                    }
                }
            }
        }
    }

    return modifiedKeys;
}

void Syscollector::setJsonField(nlohmann::json& target,
                                const nlohmann::json& source,
                                const std::string& keyPath,
                                const std::string& jsonKey,
                                bool createFields,
                                bool is_boolean)
{
    if (createFields || source.contains(jsonKey))
    {
        const nlohmann::json::json_pointer pointer(keyPath);

        if (source.contains(jsonKey) && source[jsonKey] != EMPTY_VALUE && source[jsonKey] != UNKNOWN_VALUE)
        {
            if (is_boolean)
            {
                const auto& value = source[jsonKey];

                if (value.is_number())
                {
                    target[pointer] = (value.get<int>() != 0);
                }
                else if (value.is_string())
                {
                    const std::string strValue = value.get<std::string>();
                    target[pointer] = (strValue != "0");
                }
                else
                {
                    target[pointer] = value;
                }
            }
            else
            {
                target[pointer] = source[jsonKey];
            }
        }
        else
        {
            target[pointer] = nullptr;
        }
    }
}

void Syscollector::setJsonFieldArray(nlohmann::json& target,
                                     const nlohmann::json& source,
                                     const std::string& destPath,
                                     const std::string& sourceKey,
                                     bool createFields)
{
    if (createFields || source.contains(sourceKey))
    {
        const nlohmann::json::json_pointer destPointer(destPath);
        target[destPointer] = nullptr;

        if (source.contains(sourceKey) && !source[sourceKey].is_null() && source[sourceKey] != EMPTY_VALUE && source[sourceKey] != UNKNOWN_VALUE)
        {
            const auto& value = source[sourceKey];
            target[destPointer] = nlohmann::json::array();

            // If the value is a string that contains commas, split it into multiple array elements
            if (value.is_string())
            {
                const auto valueStr = value.get<std::string>();
                const auto splitValues = Utils::split(valueStr, ',');

                for (const auto& splitValue : splitValues)
                {
                    const auto trimmedValue = Utils::trim(splitValue);

                    if (!trimmedValue.empty())
                    {
                        target[destPointer].push_back(trimmedValue);
                    }
                }
            }
            else
            {
                // For non-string values, add as single element
                target[destPointer].push_back(value);
            }
        }
    }
}

// Sync protocol methods implementation
void Syscollector::initSyncProtocol(const std::string& moduleName, const std::string& syncDbPath, const std::string& syncDbPathVD,
                                    uint32_t integrityInterval)
{
    // Publish the protocols under the exclusive lock so a concurrent reader taking the
    // shared lock sees either a fully constructed protocol or none, never a half-assigned one.
    std::unique_lock<std::shared_mutex> resourcesLock(m_resourcesMutex);

    m_dataCleanRetries = 3;  // Fixed default; the transport handles HTTP-level retries.
    m_integrityIntervalValue = integrityInterval;

    auto logger_func = [this](modules_log_level_t level, const std::string & msg)
    {
        this->m_logFunction(level, msg);
    };

    auto logger_func_vd = [moduleName, this](modules_log_level_t level, const std::string & msg)
    {
        this->m_logFunction(level, moduleName + "_vd: " + msg);
    };

    try
    {
        // Initialize regular sync protocol
        m_spSyncProtocol = std::make_unique<AgentSyncProtocol>(moduleName, syncDbPath, logger_func);
        m_logFunction(LOG_DEBUG, "Syscollector sync protocol initialized successfully with database: " + syncDbPath);

        // Initialize VD sync protocol with different module name to avoid routing conflicts
        std::string vdModuleName = moduleName + "_vd";
        m_spSyncProtocolVD = std::make_unique<AgentSyncProtocol>(vdModuleName, syncDbPathVD, logger_func_vd);
        m_logFunction(LOG_DEBUG, "Syscollector VD sync protocol initialized successfully with database: " + syncDbPathVD + " and module name: " + vdModuleName);

        // Initialize schema validator factory from embedded resources
        auto& validatorFactory = SchemaValidator::SchemaValidatorFactory::getInstance();

        if (!validatorFactory.isInitialized())
        {
            if (validatorFactory.initialize())
            {
                m_logFunction(LOG_DEBUG, "Schema validator initialized successfully from embedded resources");
            }
            else
            {
                m_logFunction(LOG_WARNING, "Failed to initialize schema validator. Schema validation will be disabled.");
            }
        }

        m_logFunction(LOG_DEBUG, "Integrity interval set to " + std::to_string(integrityInterval) + " seconds");
    }
    catch (const std::exception& ex)
    {
        m_logFunction(LOG_ERROR, "Failed to initialize Syscollector sync protocol: " + std::string(ex.what()));
        // Re-throw to allow caller to handle
        throw;
    }
}

// LCOV_EXCL_START
SyncModuleResult Syscollector::syncModule(Mode mode)
{
    if (m_paused || m_stopping.load())
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, "Syscollector module is paused or stopping, skipping synchronization");
        }

        return {false, {}};
    }

    m_logFunction(LOG_INFO, "Starting inventory synchronization.");

    // RAII guard ensures m_syncing is set to false even if function exits early
    ScanGuard syncGuard(m_syncing, m_pauseCv);

    bool overallSuccess = true;
    std::string failureReason;

    // Sync regular (non-VD) data
    if (m_spSyncProtocol)
    {
        SyncModuleResult result = m_spSyncProtocol->synchronizeModule(mode, Option::SYNC);

        if (result.success)
        {
            int64_t firstSyncCompleted = 0;

            if (!getMetadataValue(SYSCOLLECTOR_FIRST_SYNC_COMPLETED_METADATA_KEY, firstSyncCompleted) || firstSyncCompleted == 0)
            {
                updateMetadataValue(SYSCOLLECTOR_FIRST_SYNC_COMPLETED_METADATA_KEY, Utils::getSecondsFromEpoch());
            }
        }
        else
        {
            overallSuccess = false;
            failureReason = result.failureReason;

            if (result.stopped || m_stopping.load())
            {
                // Not a real failure: the sync was aborted because the module is stopping.
                // Report it as an expected event, not a WARNING.
                m_logFunction(LOG_INFO, "Syscollector synchronization aborted: the module is stopping.");
            }
            else if (result.awaitingPrerequisite)
            {
                // Not a real failure either: the manager hasn't synchronized this agent's groups
                // yet, most commonly right after enrollment/restart. Expected to clear on its own.
                m_logFunction(LOG_INFO, "Syscollector synchronization deferred: " + result.failureReason);
            }
            else if ((result.managerNotReady || result.localTransportUnavailable) &&
                     result.consecutiveFailures <= SYNC_MANAGER_NOT_READY_TOLERANCE)
            {
                // Either the manager is not ready for this agent yet, or the local sync intake
                // itself isn't reachable yet -- both mostly right after a restart -- and the sync
                // has not failed enough times in a row to suspect it will not clear.
                m_logFunction(LOG_INFO, "Syscollector synchronization deferred: " + result.failureReason +
                              " Will retry next cycle.");
            }
            else if (result.managerNotReady || result.localTransportUnavailable)
            {
                // Neither condition has cleared for several cycles in a row.
                m_logFunction(LOG_WARNING, "Syscollector synchronization failed " +
                              std::to_string(result.consecutiveFailures) + " times in a row: " + result.failureReason);
            }
            else
            {
                m_logFunction(LOG_WARNING, "Syscollector synchronization failed" +
                              (result.failureReason.empty() ? "." : ": " + result.failureReason));
            }
        }
    }

    // Check if stopping before proceeding with VD sync
    if (m_stopping.load())
    {
        m_logFunction(LOG_DEBUG, "Stop received during synchronization, skipping VD sync");
        return {false, {}};
    }

    // Sync VD data with appropriate option based on first scan status
    if (m_spSyncProtocolVD)
    {
        Option vdOption;
        bool firstSyncDone = isVDFirstSyncDone();

        if (!m_vdSyncEnabled)
        {
            // If both packages and OS are disabled, use regular SYNC option
            vdOption = Option::SYNC;
            m_logFunction(LOG_DEBUG, "Using SYNC option (VD scanning disabled)");
        }
        else
        {
            // Use VDFIRST for first scan, VDSYNC for subsequent syncs
            vdOption = firstSyncDone ? Option::VDSYNC : Option::VDFIRST;
        }

        SyncModuleResult vdResult = m_spSyncProtocolVD->synchronizeModule(mode, vdOption);

        persistVDFirstSyncIfNeeded(vdResult.success, firstSyncDone);

        if (!vdResult.success)
        {
            overallSuccess = false;

            if (failureReason.empty())
            {
                failureReason = vdResult.failureReason;
            }

            if (vdResult.stopped || m_stopping.load())
            {
                // Not a real failure: the VD sync was aborted because the module is stopping
                m_logFunction(LOG_INFO, "Syscollector VD synchronization aborted: the module is stopping.");
            }
            else if (vdResult.awaitingPrerequisite)
            {
                // Not a real failure either: no VD feed offset has been received from the manager
                // yet (via /control), most commonly during the first cycle(s) after an agent
                // restart, before the first notify round trip completes. Expected to clear on its
                // own within the next cycle or two.
                m_logFunction(LOG_INFO, "Syscollector VD synchronization deferred: " + vdResult.failureReason);
            }
            else if ((vdResult.managerNotReady || vdResult.localTransportUnavailable) &&
                     vdResult.consecutiveFailures <= SYNC_MANAGER_NOT_READY_TOLERANCE)
            {
                // Either the manager is not ready for this agent yet, or the local sync intake
                // itself isn't reachable yet -- both mostly right after a restart -- and the sync
                // has not failed enough times in a row to suspect it will not clear.
                m_logFunction(LOG_INFO, "Syscollector VD synchronization deferred: " + vdResult.failureReason +
                              " Will retry next cycle.");
            }
            else if (vdResult.managerNotReady || vdResult.localTransportUnavailable)
            {
                // Neither condition has cleared for several cycles in a row.
                m_logFunction(LOG_WARNING, "Syscollector VD synchronization failed " +
                              std::to_string(vdResult.consecutiveFailures) + " times in a row: " + vdResult.failureReason);
            }
            else
            {
                m_logFunction(LOG_WARNING, "Syscollector VD synchronization failed" +
                              (vdResult.failureReason.empty() ? "." : ": " + vdResult.failureReason));
            }
        }
    }

    if (overallSuccess)
    {
        m_logFunction(LOG_INFO, "Syscollector synchronization process finished successfully.");
    }

    return {overallSuccess, std::move(failureReason)};
}
// LCOV_EXCL_STOP

void Syscollector::persistDifference(const std::string& id, Operation operation, const std::string& index, const std::string& data, uint64_t version, bool isDataContext)
{
    // Serialize against releaseResources(): this entry point is driven by threads that
    // outlive the module teardown (wcom's detached dispatcher and agent-info's in-process
    // coordination polls), so the members it reaches must not be reset underneath it.
    std::shared_lock<std::shared_mutex> resourcesLock(m_resourcesMutex);

    // VD tables: system (os), packages, hotfixes
    bool isVDTable = (index == SYSCOLLECTOR_SYNC_INDEX_SYSTEM ||
                      index == SYSCOLLECTOR_SYNC_INDEX_PACKAGES ||
                      index == SYSCOLLECTOR_SYNC_INDEX_HOTFIXES);

    if (isVDTable && m_spSyncProtocolVD)
    {
        m_spSyncProtocolVD->persistDifference(id, operation, index, data, version, isDataContext);
    }
    else if (m_spSyncProtocol)
    {
        m_spSyncProtocol->persistDifference(id, operation, index, data, version, isDataContext);
    }
}

bool Syscollector::parseResponseBuffer(const uint8_t* data, size_t length)
{
    // Serialize against releaseResources(): this entry point is driven by threads that
    // outlive the module teardown (wcom's detached dispatcher and agent-info's in-process
    // coordination polls), so the members it reaches must not be reset underneath it.
    std::shared_lock<std::shared_mutex> resourcesLock(m_resourcesMutex);

    // Route to regular (non-VD) sync protocol only
    if (m_spSyncProtocol)
    {
        return m_spSyncProtocol->parseResponseBuffer(data, length);
    }

    return false;
}

bool Syscollector::parseResponseBufferVD(const uint8_t* data, size_t length)
{
    // Serialize against releaseResources(): this entry point is driven by threads that
    // outlive the module teardown (wcom's detached dispatcher and agent-info's in-process
    // coordination polls), so the members it reaches must not be reset underneath it.
    std::shared_lock<std::shared_mutex> resourcesLock(m_resourcesMutex);

    // Route to VD sync protocol only
    if (m_spSyncProtocolVD)
    {
        return m_spSyncProtocolVD->parseResponseBuffer(data, length);
    }

    return false;
}

// LCOV_EXCL_START
std::vector<nlohmann::json> Syscollector::fetchAllFromTable(const std::string& tableName, const std::set<std::string>& excludeIds, bool forceAll)
{
    std::vector<nlohmann::json> results;

    if (!m_spDBSync)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_WARNING, "Cannot fetch from table " + tableName + ": DBSync not initialized");
        }

        return results;
    }

    try
    {
        // Determine if we need to filter by sync=1
        // Find the index for this table to check document limits
        auto indexIt = INDEX_MAP.find(tableName);
        std::string rowFilterClause;

        if (forceAll)
        {
            // Force fetching all records regardless of limits (for VD hotfixes)
            rowFilterClause = "";

            if (m_logFunction)
            {
                m_logFunction(LOG_DEBUG, "Fetching ALL records from " + tableName + " (forceAll=true)");
            }
        }
        else if (indexIt != INDEX_MAP.end())
        {
            const std::string& index = indexIt->second;
            size_t documentLimit = getDocumentLimit(index);

            if (documentLimit > 0)
            {
                // With limits: only include items with sync=1 (within document limits)
                rowFilterClause = "WHERE sync=1";
            }
            else
            {
                // No limits: include all items regardless of sync value
                rowFilterClause = "";
            }
        }
        else
        {
            // No index mapping found, default to no filter
            rowFilterClause = "";
        }

        // Build SELECT query to fetch rows from the table
        auto selectQuery = SelectQuery::builder()
                           .table(tableName)
                           .columnList({"*"})
                           .rowFilter(rowFilterClause)
                           .build();

        // Callback to collect selected rows, filtering out excluded IDs in-memory
        // Note: We filter in the callback because excluded IDs are hash values (SHA1),
        // not primary keys, so we cannot use SQL WHERE clause directly
        const auto selectCallback = [&](ReturnTypeCallback returnType, const nlohmann::json & resultData)
        {
            if (returnType == SELECTED)
            {
                // Calculate the hash ID for this row
                std::string rowId = calculateHashId(resultData, tableName);

                // Only include if not in the exclude list
                if (excludeIds.find(rowId) == excludeIds.end())
                {
                    results.push_back(resultData);
                }
            }
        };

        m_spDBSync->selectRows(selectQuery.query(), selectCallback);

        if (m_logFunction)
        {
            std::string filterInfo = rowFilterClause.empty() ? " (no limit filter)" : " with sync=1";
            m_logFunction(LOG_DEBUG_VERBOSE, "Fetched " + std::to_string(results.size()) + " rows" + filterInfo +
                          " from table " + tableName + " (excluded " + std::to_string(excludeIds.size()) + " DataValue items)");
        }
    }
    catch (const std::exception& e)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Failed to fetch from table " + tableName + ": " + std::string(e.what()));
        }
    }

    return results;
}

std::vector<std::string> Syscollector::getDataContextTables(Operation operation, const std::string& index)
{
    std::vector<std::string> tables;

    // Apply platform-specific DataContext inclusion rules
    if (index == SYSCOLLECTOR_SYNC_INDEX_SYSTEM)
    {
        // OS changes → include packages as DataContext
        if (operation == Operation::CREATE || operation == Operation::MODIFY)
        {
            tables.push_back(PACKAGES_TABLE);

#ifdef _WIN32
            // Windows: also include hotfixes
            tables.push_back(HOTFIXES_TABLE);
#endif
        }
    }
    else if (index == SYSCOLLECTOR_SYNC_INDEX_PACKAGES)
    {
        // Package changes
        if (operation == Operation::DELETE_)
        {
            // Package DELETE → NO DataContext
            // (no tables added)
        }
        else  // CREATE or MODIFY
        {
            // Linux/macOS: include OS
            // Windows: include hotfixes (and OS implicitly needed but not in spec)
            tables.push_back(OS_TABLE);

#ifdef _WIN32
            // Windows: also include hotfixes (except on delete, handled above)
            tables.push_back(HOTFIXES_TABLE);
#endif
        }
    }

#ifdef _WIN32
    else if (index == SYSCOLLECTOR_SYNC_INDEX_HOTFIXES)
    {
        tables.push_back(OS_TABLE);
        tables.push_back(PACKAGES_TABLE);
        tables.push_back(HOTFIXES_TABLE);
    }

#endif

    if (m_logFunction && !tables.empty())
    {
        std::string tablesStr;

        for (const auto& table : tables)
        {
            if (!tablesStr.empty()) tablesStr += ", ";

            tablesStr += table;
        }

        m_logFunction(LOG_DEBUG, "DataContext tables for index=" + index +
                      " operation=" + std::to_string(static_cast<int>(operation)) +
                      ": [" + tablesStr + "]");
    }

    return tables;
}

bool Syscollector::isVDFirstSyncDone()
{
    int64_t vdFirstSyncCompleted = 0;
    return getMetadataValue(SYSCOLLECTOR_VD_FIRST_SYNC_COMPLETED_METADATA_KEY, vdFirstSyncCompleted)
           && vdFirstSyncCompleted > 0;
}

void Syscollector::persistVDFirstSyncIfNeeded(const bool vdResult, const bool firstSyncDone)
{
    if (vdResult && !firstSyncDone && !m_stopping.load())
    {
        if (updateMetadataValue(SYSCOLLECTOR_VD_FIRST_SYNC_COMPLETED_METADATA_KEY, Utils::getSecondsFromEpoch()))
        {
            if (m_logFunction)
            {
                m_logFunction(LOG_INFO, "VD first sync completed, metadata marker persisted.");
            }
        }
        else if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Failed to persist VD first sync metadata marker.");
        }
    }
    else if (m_stopping.load() && vdResult && !firstSyncDone)
    {
        m_logFunction(LOG_DEBUG, "VD first sync successful but module is stopping, metadata marker not persisted.");
    }
    else if (!vdResult)
    {
        m_logFunction(LOG_DEBUG, "VD sync was not successful, metadata marker not persisted.");
    }
}

void Syscollector::processVDDataContext()
{
    // Skip DataContext processing on first VD scan or if protocol not initialized
    if (!m_spSyncProtocolVD || !isVDFirstSyncDone())
    {
        return;
    }

    if (m_logFunction)
    {
        m_logFunction(LOG_DEBUG, "Processing VD DataContext after scan");
    }

    try
    {
        // Step 0: Clear any existing DataContext from previous scans
        // This prevents inconsistencies if a scan happens before the previous sync completes
        m_spSyncProtocolVD->clearAllDataContext();

        // Step 1: Fetch pending DataValue items from syscollector_vd_sync.db
        std::vector<PersistedData> pendingDataValues = m_spSyncProtocolVD->fetchPendingItems(true);

        if (pendingDataValues.empty())
        {
            return;
        }

        // Step 2: Build exclusion sets - IDs of items already submitted as DataValue
        // These IDs are calculated from local.db data, so they match what we'll calculate later
        std::map<std::string, std::set<std::string>> dataValueIdsByIndex;

        for (const auto& dataValue : pendingDataValues)
        {
            dataValueIdsByIndex[dataValue.index].insert(dataValue.id);
        }

        // Step 3: Determine what DataContext tables are needed based on platform rules
        std::set<std::string> dataContextTablesToFetch;

        for (const auto& dataValue : pendingDataValues)
        {
            std::vector<std::string> contextTables = getDataContextTables(dataValue.operation, dataValue.index);

            for (const auto& table : contextTables)
            {
                dataContextTablesToFetch.insert(table);
            }
        }

        if (dataContextTablesToFetch.empty())
        {
            return;
        }

        // Step 4: Fetch and submit DataContext for each required table
        size_t totalDataContextItems = 0;

        for (const auto& tableName : dataContextTablesToFetch)
        {
            std::string contextIndex;
            std::set<std::string> excludeIds;

            if (tableName == OS_TABLE)
            {
                contextIndex = SYSCOLLECTOR_SYNC_INDEX_SYSTEM;
                excludeIds = dataValueIdsByIndex[SYSCOLLECTOR_SYNC_INDEX_SYSTEM];
            }
            else if (tableName == PACKAGES_TABLE)
            {
                contextIndex = SYSCOLLECTOR_SYNC_INDEX_PACKAGES;
                excludeIds = dataValueIdsByIndex[SYSCOLLECTOR_SYNC_INDEX_PACKAGES];
            }
            else if (tableName == HOTFIXES_TABLE)
            {
                contextIndex = SYSCOLLECTOR_SYNC_INDEX_HOTFIXES;
                excludeIds = dataValueIdsByIndex[SYSCOLLECTOR_SYNC_INDEX_HOTFIXES];
            }

            if (contextIndex.empty())
            {
                continue;
            }

            // Fetch all items from local.db, excluding those already in DataValue
            // Since local.db is stable during scan, the calculated IDs will match
            // For HOTFIXES_TABLE: fetch ALL hotfixes regardless of document limits (VD needs complete data)
            bool forceAll = (tableName == HOTFIXES_TABLE);
            std::vector<nlohmann::json> contextItems = fetchAllFromTable(tableName, excludeIds, forceAll);

            for (const auto& item : contextItems)
            {
                try
                {
                    const auto ecsPair = ecsData(item, tableName);
                    const auto statefulToSend{ecsPair.first.dump()};

                    // Calculate ID the same way as done during scan for DataValue
                    std::string itemId = calculateHashId(item, tableName);

                    // Validate stateful event before persisting VD DataContext
                    bool shouldPersist = true;
                    std::string context = "VD DataContext, table: " + tableName;

                    // Use helper function to validate and log
                    bool validationPassed = validateSchemaAndLog(statefulToSend, contextIndex, context);

                    if (!validationPassed)
                    {
                        if (m_logFunction)
                        {
                            m_logFunction(LOG_DEBUG, "Skipping persistence of invalid VD DataContext event");
                        }

                        shouldPersist = false;
                    }

                    // Submit as DataContext (isDataContext=true)
                    // Note: operation and version parameters are not used for DataContext
                    if (shouldPersist)
                    {
                        m_spSyncProtocolVD->persistDifference(itemId, Operation::MODIFY, contextIndex, statefulToSend, 0, true);
                        totalDataContextItems++;
                    }
                }
                catch (const std::exception& e)
                {
                    if (m_logFunction)
                    {
                        m_logFunction(LOG_ERROR, "Failed to persist DataContext from " + tableName + ": " + std::string(e.what()));
                    }
                }
            }

            if (m_logFunction && !contextItems.empty())
            {
                m_logFunction(LOG_DEBUG, "Added " + std::to_string(contextItems.size()) + " DataContext items from " + tableName);
            }
        }

        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, "VD DataContext complete: " + std::to_string(totalDataContextItems) +
                          " items for " + std::to_string(pendingDataValues.size()) + " DataValues");
        }
    }
    catch (const std::exception& e)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Error processing VD DataContext: " + std::string(e.what()));
        }
    }
}

bool Syscollector::notifyDataClean(const std::vector<std::string>& indices)
{
    // Serialize against releaseResources(): this entry point is driven by threads that
    // outlive the module teardown (wcom's detached dispatcher and agent-info's in-process
    // coordination polls), so the members it reaches must not be reset underneath it.
    std::shared_lock<std::shared_mutex> resourcesLock(m_resourcesMutex);

    if (m_spSyncProtocol)
    {
        return m_spSyncProtocol->notifyDataClean(indices);
    }

    return false;
}

void Syscollector::deleteDatabase()
{
    // Serialize against releaseResources(): this entry point is driven by threads that
    // outlive the module teardown (wcom's detached dispatcher and agent-info's in-process
    // coordination polls), so the members it reaches must not be reset underneath it.
    std::shared_lock<std::shared_mutex> resourcesLock(m_resourcesMutex);
    deleteDatabaseUnlocked();
}

void Syscollector::deleteDatabaseUnlocked()
{
    // The caller must already hold m_resourcesMutex. This body is split out of
    // deleteDatabase() so deleteDisableCollectorsData(), which holds the mutex shared for
    // its whole body, does not acquire a second shared lock on the same thread: most
    // std::shared_mutex implementations block new readers once a writer is queued, so the
    // nested acquisition would wait behind a pending releaseResources() or
    // initSyncProtocol() while still holding the outer lock those writers are waiting for.
    if (m_spSyncProtocol)
    {
        m_spSyncProtocol->deleteDatabase();
    }

    if (m_spSyncProtocolVD)
    {
        m_spSyncProtocolVD->deleteDatabase();
    }

    if (m_spDBSync)
    {
        m_spDBSync->closeAndDeleteDatabase();
    }
}
// LCOV_EXCL_STOP

bool Syscollector::pause()
{
    if (m_logFunction)
    {
        m_logFunction(LOG_DEBUG, "Syscollector module pause requested");
    }

    // Set the pause flag first to prevent new operations from starting
    m_paused = true;

    // Wait for BOTH scan and sync operations to complete
    std::unique_lock<std::mutex> lock(m_pauseMutex);
    m_pauseCv.wait(lock, [this]
    {
        bool scanDone = !m_scanning.load();
        bool syncDone = !m_syncing.load();
        return (scanDone && syncDone) || m_stopping.load();
    });

    if (m_logFunction)
    {
        if (m_stopping.load())
        {
            m_logFunction(LOG_DEBUG, "Syscollector module pause interrupted by shutdown");
        }
        else
        {
            m_logFunction(LOG_DEBUG, "Syscollector module paused successfully");
        }
    }

    // Return false if interrupted by shutdown, true if successfully paused
    return !m_stopping.load();
}

void Syscollector::resume()
{
    if (m_logFunction)
    {
        m_logFunction(LOG_INFO, "Resuming Syscollector module");
    }

    m_paused = false;
    m_cv.notify_one();
}

int Syscollector::flush()
{
    if (!m_asyncFlushController)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Syscollector async flush controller not initialized");
        }

        return -1;
    }

    return m_asyncFlushController->startFlush() ? 0 : -1;
}

int Syscollector::executeFlushSync()
{
    if (m_logFunction)
    {
        m_logFunction(LOG_INFO, "Syscollector flush requested - syncing pending messages");
    }

    // Nothing to flush if neither sync protocol is initialized.
    if (!m_spSyncProtocol && !m_spSyncProtocolVD)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_INFO, "Syscollector sync protocol not initialized, flush skipped");
        }

        return 0; // Not an error - just nothing to flush
    }

    // Trigger immediate synchronization to flush pending messages.
    SyncModuleResult result = {true, {}};
    SyncModuleResult vdResult = {true, {}};

    if (m_spSyncProtocol)
    {
        result = m_spSyncProtocol->synchronizeModule(Mode::DELTA);
    }

    if (m_spSyncProtocolVD)
    {
        Option vdOption;
        const bool firstSyncDone = isVDFirstSyncDone();

        if (!m_vdSyncEnabled)
        {
            vdOption = Option::SYNC;
        }
        else
        {
            vdOption = firstSyncDone ? Option::VDSYNC : Option::VDFIRST;
        }

        vdResult = m_spSyncProtocolVD->synchronizeModule(Mode::DELTA, vdOption);

        persistVDFirstSyncIfNeeded(vdResult.success, firstSyncDone);
    }

    const bool overallSuccess = result.success && vdResult.success;

    if (overallSuccess)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_INFO, "Syscollector flush completed successfully");
        }

        return 0;
    }

    const bool stopping = (m_spSyncProtocol && m_spSyncProtocol->shouldStop()) ||
                          (m_spSyncProtocolVD && m_spSyncProtocolVD->shouldStop());

    if (m_logFunction)
    {
        if (stopping)
        {
            m_logFunction(LOG_INFO, "Syscollector flush skipped: module is stopping");
        }
        else
        {
            std::string failedQueues;

            if (!result.success && !vdResult.success)
                failedQueues = "both syscollector and VD queues";
            else if (!result.success)
                failedQueues = "syscollector queue";
            else
                failedQueues = "VD queue";

            std::string reason;

            if (!result.success && !result.failureReason.empty())
                reason = result.failureReason;

            if (!vdResult.success && !vdResult.failureReason.empty())
                reason += (reason.empty() ? "" : "; VD: ") + vdResult.failureReason;

            const std::string reasonSuffix = reason.empty() ? "" : ": " + reason;

            // A queue that failed counts as "manager not ready" only if that specific sync said so
            // (either the manager itself, or the local sync intake being unreachable -- both share
            // the same restart-hiccup shape); a queue that succeeded does not veto the deferral.
            const bool allFailuresManagerNotReady =
                (result.success   || result.managerNotReady || result.localTransportUnavailable) &&
                (vdResult.success || vdResult.managerNotReady || vdResult.localTransportUnavailable);

            // Longest manager-not-ready streak among the queues that actually failed.
            unsigned int streak = 0;

            if (!result.success && (result.managerNotReady || result.localTransportUnavailable) &&
                    result.consecutiveFailures > streak)
                streak = result.consecutiveFailures;

            if (!vdResult.success && (vdResult.managerNotReady || vdResult.localTransportUnavailable) &&
                    vdResult.consecutiveFailures > streak)
                streak = vdResult.consecutiveFailures;

            if (allFailuresManagerNotReady && streak <= SYNC_MANAGER_NOT_READY_TOLERANCE)
            {
                // The manager is not ready for this agent yet, mostly right after a restart, and the
                // sync has not failed enough times in a row to suspect it will not clear.
                m_logFunction(LOG_INFO, "Syscollector flush deferred: " + failedQueues + reasonSuffix +
                              " Will retry next cycle.");
            }
            else if (allFailuresManagerNotReady)
            {
                // Not a restart hiccup any more: the manager has not been ready for several cycles.
                m_logFunction(LOG_WARNING, "Syscollector flush failed " + std::to_string(streak) +
                              " times in a row: " + failedQueues + reasonSuffix);
            }
            else
            {
                m_logFunction(LOG_WARNING, "Syscollector flush failed: " + failedQueues + reasonSuffix);
            }
        }
    }

    return stopping ? 0 : -1;
}

int Syscollector::getMaxVersion()
{
    int maxVersion = 0;

    if (!m_spDBSync)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "DBSync is null, cannot get max version");
        }

        return -1;
    }

    try
    {
        // Iterate through all Syscollector tables to find the maximum version
        for (const auto& [tableName, indexName] : INDEX_MAP)
        {
            int tableMaxVersion = 0;

            auto selectQuery = SelectQuery::builder()
                               .table(tableName)
                               .columnList({"MAX(version) AS max_version"})
                               .build();

            const auto callback = [&tableMaxVersion](ReturnTypeCallback returnType, const nlohmann::json & resultData)
            {
                if (returnType == SELECTED && resultData.contains("max_version"))
                {
                    if (resultData["max_version"].is_number())
                    {
                        tableMaxVersion = resultData["max_version"].get<int>();
                    }
                    else if (resultData["max_version"].is_null())
                    {
                        tableMaxVersion = 0;
                    }
                }
            };

            m_spDBSync->selectRows(selectQuery.query(), callback);

            // Update global max if this table's max is higher
            if (tableMaxVersion > maxVersion)
            {
                maxVersion = tableMaxVersion;
            }
        }

        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, "Syscollector get_version returned: " + std::to_string(maxVersion));
        }
    }
    catch (const std::exception& ex)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Error getting max version: " + std::string(ex.what()));
        }

        return -1;
    }

    return maxVersion;
}

int Syscollector::setVersion(int version)
{
    if (!m_spDBSync)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "DBSync is null, cannot set version");
        }

        return -1;
    }

    try
    {
        int totalRowsUpdated = 0;

        // Iterate through all Syscollector tables to update version
        for (const auto& [tableName, indexName] : INDEX_MAP)
        {
            std::vector<nlohmann::json> rows;

            auto selectQuery = SelectQuery::builder()
                               .table(tableName)
                               .columnList({"*"})
                               .build();

            const auto selectCallback = [&rows](ReturnTypeCallback returnType, const nlohmann::json & resultData)
            {
                if (returnType == SELECTED)
                {
                    rows.push_back(resultData);
                }
            };

            m_spDBSync->selectRows(selectQuery.query(), selectCallback);

            if (!rows.empty())
            {
                const auto txnCallback = [](ReturnTypeCallback, const nlohmann::json&) {};

                DBSyncTxn txn
                {
                    m_spDBSync->handle(),
                    nlohmann::json{tableName},
                    0,
                    QUEUE_SIZE,
                    txnCallback
                };

                for (auto& row : rows)
                {
                    row["version"] = version;

                    nlohmann::json input;
                    input["table"] = tableName;
                    input["data"] = nlohmann::json::array({row});
                    input["options"]["ignore"] = nlohmann::json::array({"sync"});

                    txn.syncTxnRow(input);
                }

                txn.getDeletedRows(txnCallback);
                totalRowsUpdated += rows.size();
            }
        }

        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, "Syscollector set_version to " + std::to_string(version) +
                          " for " + std::to_string(totalRowsUpdated) + " total rows across all tables");
        }

        return 0;
    }
    catch (const std::exception& ex)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Error setting version: " + std::string(ex.what()));
        }

        return -1;
    }
}

void Syscollector::lockScanMutex()
{
    m_scan_mutex.lock();
}

void Syscollector::unlockScanMutex()
{
    m_scan_mutex.unlock();
}

std::string Syscollector::query(const std::string& jsonQuery)
{
    // Serialize against releaseResources(): this entry point is driven by threads that
    // outlive the module teardown (wcom's detached dispatcher and agent-info's in-process
    // coordination polls), so the members it reaches must not be reset underneath it.
    std::shared_lock<std::shared_mutex> resourcesLock(m_resourcesMutex);

    // Log the received query
    if (m_logFunction)
    {
        m_logFunction(LOG_DEBUG, "Received query: " + jsonQuery);
    }

    try
    {
        // Parse JSON command
        nlohmann::json query_json = nlohmann::json::parse(jsonQuery);

        if (!query_json.contains("command") || !query_json["command"].is_string())
        {
            nlohmann::json response;
            response["error"] = MQ_ERR_INVALID_PARAMS;
            response["message"] = MQ_MSG_INVALID_PARAMS;
            return response.dump();
        }

        std::string command = query_json["command"];
        nlohmann::json parameters = query_json.contains("parameters") ? query_json["parameters"] : nlohmann::json();

        // Log the command being executed
        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, "Executing command: " + command);
        }

        nlohmann::json response;

        // Handle coordination commands with JSON responses
        if (command == "pause")
        {
            bool pauseResult = pause();

            if (pauseResult)
            {
                response["error"] = MQ_SUCCESS;
                response["message"] = "Syscollector module paused successfully";
                response["data"]["module"] = "syscollector";
                response["data"]["action"] = "pause";
            }
            else
            {
                response["error"] = MQ_ERR_INTERNAL;
                response["message"] = "Syscollector module pause interrupted by shutdown";
                response["data"]["module"] = "syscollector";
                response["data"]["action"] = "pause";
            }
        }
        else if (command == "flush")
        {
            int flushResult = flush();

            if (flushResult == 0)
            {
                response["error"] = MQ_SUCCESS;
                response["message"] = "Syscollector module flush requested";
                response["data"]["module"] = "syscollector";
                response["data"]["action"] = "flush";
            }
            else
            {
                response["error"] = MQ_ERR_INTERNAL;
                response["message"] = "Syscollector module flush failed";
                response["data"]["module"] = "syscollector";
                response["data"]["action"] = "flush";
            }
        }
        else if (command == "is_flush_completed")
        {
            const auto flushStatus = m_asyncFlushController ? m_asyncFlushController->getFlushStatus()
                                     : Utils::AsyncFlushController::FlushStatus {false, true};

            response["error"] = MQ_SUCCESS;
            response["data"]["module"] = "syscollector";

            if (flushStatus.running)
            {
                response["message"] = "Syscollector flush in progress";
                response["data"]["status"] = "in_progress";
            }
            else
            {
                response["message"] = flushStatus.successful ? "Syscollector flush completed successfully"
                                      : "Syscollector flush completed with error";
                response["data"]["status"] = "completed";
                response["data"]["result"] = flushStatus.successful ? "success" : "error";
            }
        }
        else if (command == "get_version")
        {
            int maxVersion = getMaxVersion();

            if (maxVersion >= 0)
            {
                response["error"] = MQ_SUCCESS;
                response["message"] = "Syscollector version retrieved";
                response["data"]["version"] = maxVersion;
            }
            else
            {
                response["error"] = MQ_ERR_INTERNAL;
                response["message"] = "Failed to retrieve Syscollector version";
                response["data"]["version"] = -1;
            }
        }
        else if (command == "get_first_sync_completed")
        {
            int64_t firstSyncCompleted = 0;

            if (getMetadataValue(SYSCOLLECTOR_FIRST_SYNC_COMPLETED_METADATA_KEY, firstSyncCompleted))
            {
                response["error"] = MQ_SUCCESS;
                response["message"] = "Syscollector first sync completion retrieved";
                response["data"]["first_sync_completed"] = firstSyncCompleted > 0 ? 1 : 0;
            }
            else
            {
                response["error"] = MQ_ERR_INTERNAL;
                response["message"] = "Failed to retrieve Syscollector first sync completion";
            }
        }
        else if (command == "get_first_scan_completed")
        {
            int64_t firstScanCompleted = 0;

            if (getMetadataValue(SYSCOLLECTOR_FIRST_SCAN_COMPLETED_METADATA_KEY, firstScanCompleted))
            {
                response["error"] = MQ_SUCCESS;
                response["message"] = "Syscollector first scan completion retrieved";
                response["data"]["first_scan_completed"] = firstScanCompleted > 0 ? 1 : 0;
            }
            else
            {
                response["error"] = MQ_ERR_INTERNAL;
                response["message"] = "Failed to retrieve Syscollector first scan completion";
            }
        }
        else if (command == "get_vd_first_sync_completed")
        {
            int64_t vdFirstSyncCompleted = 0;

            if (getMetadataValue(SYSCOLLECTOR_VD_FIRST_SYNC_COMPLETED_METADATA_KEY, vdFirstSyncCompleted))
            {
                response["error"] = MQ_SUCCESS;
                response["message"] = "Syscollector VD first sync completion retrieved";
                response["data"]["vd_first_sync_completed"] = vdFirstSyncCompleted > 0 ? 1 : 0;
            }
            else
            {
                response["error"] = MQ_ERR_INTERNAL;
                response["message"] = "Failed to retrieve Syscollector VD first sync completion";
            }
        }
        else if (command == "set_version")
        {
            // Extract version from parameters
            int version = 0;

            if (parameters.is_object() && parameters.contains("version") && parameters["version"].is_number())
            {
                version = parameters["version"].get<int>();
            }
            else
            {
                response["error"] = MQ_ERR_INVALID_PARAMS;
                response["message"] = "Invalid or missing version parameter";
                return response.dump();
            }

            int result = setVersion(version);

            if (result == 0)
            {
                response["error"] = MQ_SUCCESS;
                response["message"] = "Syscollector version set successfully";
                response["data"]["version"] = version;
            }
            else
            {
                response["error"] = MQ_ERR_INTERNAL;
                response["message"] = "Failed to set Syscollector version";
                response["data"]["version"] = version;
            }
        }
        else if (command == "resume")
        {
            resume();
            response["error"] = MQ_SUCCESS;
            response["message"] = "Syscollector module resumed successfully";
            response["data"]["module"] = "syscollector";
            response["data"]["action"] = "resume";
        }
        else
        {
            response["error"] = MQ_ERR_UNKNOWN_COMMAND;
            response["message"] = "Unknown Syscollector command: " + command;
            response["data"]["command"] = command;
        }

        return response.dump();
    }
    catch (const std::exception& ex)
    {
        nlohmann::json response;
        response["error"] = MQ_ERR_INTERNAL;
        response["message"] = "Exception parsing JSON or executing command: " + std::string(ex.what());

        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Query error: " + std::string(ex.what()));
        }

        return response.dump();
    }
}

const char* Syscollector::scopeFilter(LimitScope scope)
{
    // CONTAINER_ID_COLUMN is part of every table's primary key and is stamped
    // '' for host rows (updateChanges() only fills it for container rows), so
    // equality against the empty string is what separates the two populations.
    return (scope == LimitScope::host) ? " AND container_id=''" : " AND container_id<>''";
}

std::map<std::string, size_t>& Syscollector::limitsFor(LimitScope scope)
{
    return (scope == LimitScope::host) ? m_documentLimits : m_containerDocumentLimits;
}

std::map<std::string, size_t>& Syscollector::countsFor(LimitScope scope)
{
    return (scope == LimitScope::host) ? m_documentCounts : m_containerDocumentCounts;
}

namespace
{
    /// The dbsync table backing a sync index, or "" when the index is unknown.
    std::string TableForIndex(const std::string& index)
    {
        for (const auto& [table, syncIndex] : INDEX_MAP)
        {
            if (syncIndex == index)
            {
                return table;
            }
        }

        return {};
    }
} // namespace

void Syscollector::applyDocumentLimit(const std::string& index,
                                      const std::string& tableName,
                                      size_t newLimit,
                                      LimitScope scope)
{
    const std::string scoped{scopeFilter(scope)};

    // A SUFFIX, not spliced into the message. These strings are asserted on
    // verbatim by syscollectorImp_test.cpp and are the kind of thing an
    // operator greps for, so the host scope's messages stay byte-identical to
    // what they were before container rows had a budget of their own.
    const std::string scopeSuffix = (scope == LimitScope::host) ? "" : " [container]";

    // Rows of THIS scope already counted against the manager. Every query below
    // carries the scope predicate, so adjusting one budget never moves a row
    // that belongs to the other.
    size_t currentCount = 0;

    if (m_spDBSync)
    {
        auto selectQuery = SelectQuery::builder()
                           .table(tableName)
                           .columnList({"COUNT(*)"})
                           .rowFilter("WHERE sync=1" + scoped)
                           .build();

        m_spDBSync->selectRows(selectQuery.query(),
                               [&currentCount](ReturnTypeCallback, const nlohmann::json & result)
        {
            if (result.contains("COUNT(*)") && result["COUNT(*)"].is_number())
            {
                currentCount = result["COUNT(*)"].get<size_t>();
            }
        });
    }

    limitsFor(scope)[index] = newLimit;

    if (newLimit == 0)
    {
        // No limit: promote ALL unsynced items of this scope.
        if (m_persistDiffFunction)
        {
            std::string reason = "Document limit changed to unlimited" + scopeSuffix;
            size_t promoted = promoteUnsyncedItems(index, tableName, INT_MAX, reason, scope);
            countsFor(scope)[index] = currentCount + promoted;

            if (m_logFunction)
            {
                m_logFunction(LOG_DEBUG, "Document limit set to unlimited for index '" + index +
                              "' (promoted " + std::to_string(promoted) + " unsynced items, total synced: " +
                              std::to_string(currentCount + promoted) + ")" + scopeSuffix);
            }
        }

        return;
    }

    if (newLimit < currentCount)
    {
        // Reduced below what is already reported: emit DELETE events for the
        // excess and put those rows back to sync=0 so a later increase can
        // promote them again.
        size_t excessCount = currentCount - newLimit;

        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, "Document limit reduced for index '" + index +
                          "' from " + std::to_string(currentCount) + " to " + std::to_string(newLimit) +
                          ". Resetting " + std::to_string(excessCount) + " excess records to sync=0." + scopeSuffix);
        }

        std::vector<nlohmann::json> excessRecords;
        std::string orderFields = getFirstPrimaryKeyField(tableName);

        if (orderFields.empty())
        {
            if (m_logFunction)
            {
                m_logFunction(LOG_ERROR, "Cannot determine ordering fields for table: " + tableName);
            }

            return;
        }

        // DESC: the rows a reduced cap drops are the ones at the far end of the
        // same deterministic ordering promotion fills from, so a shrink and a
        // regrow are inverses of each other.
        std::string orderByClause = buildOrderByClause(orderFields, false);

        auto selectQuery = SelectQuery::builder()
                           .table(tableName)
                           .columnList({"*"})
                           .rowFilter("WHERE sync=1" + scoped)
                           .orderByOpt(orderByClause)
                           .countOpt(static_cast<uint32_t>(excessCount))
                           .build();

        m_spDBSync->selectRows(selectQuery.query(),
                               [&excessRecords](ReturnTypeCallback, const nlohmann::json & result)
        {
            excessRecords.push_back(result);
        });

        if (!excessRecords.empty())
        {
            if (m_logFunction)
            {
                m_logFunction(LOG_DEBUG, "Generating DELETE events for " + std::to_string(excessRecords.size()) +
                              " excess records from " + tableName);
            }

            for (const auto& record : excessRecords)
            {
                try
                {
                    auto [ecsDataTransformed, version] = ecsData(record, tableName);
                    std::string statefulData = ecsDataTransformed.dump();
                    std::string hashId = calculateHashId(record, tableName);

                    m_persistDiffFunction(hashId, OPERATION_DELETE, index, statefulData, version);

                    if (m_logFunction)
                    {
                        m_logFunction(LOG_DEBUG, "Generated DELETE event for excess record in " + tableName +
                                      " (ID: " + hashId + ")");
                    }
                }
                catch (const std::exception& e)
                {
                    if (m_logFunction)
                    {
                        m_logFunction(LOG_ERROR, "Failed to generate DELETE event for excess record in " + tableName +
                                      ": " + std::string(e.what()));
                    }
                }
            }

            std::vector<std::pair<std::string, nlohmann::json>> itemsToReset;

            for (const auto& record : excessRecords)
            {
                itemsToReset.push_back({tableName, record});
            }

            updateSyncFlagInDB(itemsToReset, 0);
        }

        countsFor(scope)[index] = newLimit;
        return;
    }

    // newLimit >= currentCount: fill any new space from this scope's own
    // unsynced backlog.
    if (newLimit > currentCount && m_persistDiffFunction)
    {
        size_t availableSpace = newLimit - currentCount;
        std::string reason = "Document limit increased from " + std::to_string(currentCount) +
                             " to " + std::to_string(newLimit) + scopeSuffix;

        size_t promoted = promoteUnsyncedItems(index, tableName, availableSpace, reason, scope);
        countsFor(scope)[index] = currentCount + promoted;
    }
    else
    {
        countsFor(scope)[index] = currentCount;

        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, "Document limit set for index '" + index + "': " +
                          std::to_string(newLimit) +
                          " (current synced count: " + std::to_string(currentCount) + ")" + scopeSuffix);
        }
    }
}

bool Syscollector::applyLimitsForScope(const nlohmann::json& limits, LimitScope scope)
{
    try
    {
        if (!limits.is_object())
        {
            return false;
        }

        // Convert agentd short names to full index names
        nlohmann::json normalizedLimits = nlohmann::json::object();

        for (auto& [shortName, limit] : limits.items())
        {
            if (!limit.is_number_unsigned())
            {
                if (m_logFunction)
                {
                    m_logFunction(LOG_ERROR, "Invalid limit value for index: " + shortName);
                }

                return false;
            }

            auto it = AGENTD_TO_INDEX_MAP.find(shortName);

            if (it == AGENTD_TO_INDEX_MAP.end())
            {
                if (m_logFunction)
                {
                    m_logFunction(LOG_ERROR, "Unknown index from agentd: " + shortName);
                }

                return false;
            }

            normalizedLimits[it->second] = limit;
        }

        std::lock_guard<std::mutex> lock(m_limitsMutex);

        for (auto& [index, limit] : normalizedLimits.items())
        {
            const std::string tableName = TableForIndex(index);

            if (tableName.empty())
            {
                continue;
            }

            applyDocumentLimit(index, tableName, limit.get<size_t>(), scope);
        }

        return true;
    }
    catch (const std::exception& ex)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Exception setting document limits: " + std::string(ex.what()));
        }

        return false;
    }
}

bool Syscollector::setDocumentLimits(const nlohmann::json& limits)
{
    return applyLimitsForScope(limits, LimitScope::host);
}

bool Syscollector::setContainerDocumentLimits(const nlohmann::json& limits)
{
    return applyLimitsForScope(limits, LimitScope::container);
}
std::optional<nlohmann::json> Syscollector::fetchContainerDocumentLimitsFromAgentd()
{
    if (!m_agentdQuery)
    {
        return std::nullopt;
    }

    constexpr auto REQUEST_COMMAND = "getdoclimits syscollector_containers";

    // ONE attempt, unlike the host limits' retry-until-success loop. An older
    // manager answers "err Module limits not configured" forever, and blocking
    // startup on a module that may legitimately not exist would be a hang, not
    // a safeguard. Unlimited is the pre-container-inventory behaviour.
    std::string response_buffer;
    response_buffer.resize(OS_MAXSTR);

    if (!m_agentdQuery(REQUEST_COMMAND, response_buffer.data(), response_buffer.size()))
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG,
                          "No container document limits from agentd; container inventory stays unlimited.");
        }

        return std::nullopt;
    }

    try
    {
        auto limitsJson = nlohmann::json::parse(response_buffer);

        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, "Container document limits received: " + limitsJson.dump());
        }

        return limitsJson;
    }
    catch (const nlohmann::json::exception& ex)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Failed to parse container document limits JSON: " + std::string(ex.what()));
        }

        return std::nullopt;
    }
}

std::optional<nlohmann::json> Syscollector::fetchDocumentLimitsFromAgentd()
{
    if (!m_agentdQuery)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_WARNING, "Agentd query function not set, cannot fetch document limits");
        }

        return std::nullopt;
    }

    constexpr auto REQUEST_COMMAND = "getdoclimits syscollector";

    // Retry loop until success or stop signal
    while (!m_stopping.load())
    {
        // Use std::string for idiomatic C++ memory management
        std::string response_buffer;
        response_buffer.resize(OS_MAXSTR);

        // Call the agentd query function (fills our buffer)
        bool success = m_agentdQuery(REQUEST_COMMAND, response_buffer.data(), response_buffer.size());

        if (!success)
        {
            if (m_logFunction)
            {
                m_logFunction(LOG_DEBUG, "Failed to fetch document limits from agentd, retrying...");
            }

            std::this_thread::sleep_for(std::chrono::seconds(1));

            continue;
        }

        try
        {
            // Parse the JSON response directly from std::string
            auto limitsJson = nlohmann::json::parse(response_buffer);

            if (m_logFunction)
            {
                m_logFunction(LOG_DEBUG, "Successfully fetched document limits from agentd");
                m_logFunction(LOG_DEBUG, "Document limits received:   " + limitsJson.dump());
            }

            return limitsJson;
        }
        catch (const nlohmann::json::exception& ex)
        {
            if (m_logFunction)
            {
                m_logFunction(LOG_ERROR, "Failed to parse document limits JSON: " + std::string(ex.what()));
            }

            return std::nullopt;
        }
    }

    // Only reaches here if stopped before any attempt
    if (m_logFunction)
    {
        m_logFunction(LOG_DEBUG, "Document limits fetch aborted by stop signal");
    }

    return std::nullopt;
}

void Syscollector::initializeDocumentCounts()
{
    if (!m_spDBSync)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(m_limitsMutex);

    const std::vector<std::string> tables =
    {
        OS_TABLE, HW_TABLE, PACKAGES_TABLE, HOTFIXES_TABLE,
        PROCESSES_TABLE, PORTS_TABLE, NET_IFACE_TABLE,
        NET_PROTOCOL_TABLE, NET_ADDRESS_TABLE, USERS_TABLE,
        GROUPS_TABLE, SERVICES_TABLE, BROWSER_EXTENSIONS_TABLE
    };

    for (const auto& table : tables)
    {
        try
        {
            auto indexIt = INDEX_MAP.find(table);

            if (indexIt == INDEX_MAP.end())
            {
                continue;
            }

            const std::string& index = indexIt->second;

            // Once per scope: host and container rows live in the same table and
            // the same sync index, so one COUNT(*) would credit the host budget
            // with every container row already reported.
            for (const auto scope : {LimitScope::host, LimitScope::container})
            {
                auto selectQuery = SelectQuery::builder()
                                   .table(table)
                                   .columnList({"COUNT(*)"})
                                   .rowFilter(std::string{"WHERE sync=1"} + scopeFilter(scope))
                                   .build();

                size_t count = 0;
                m_spDBSync->selectRows(selectQuery.query(),
                                       [&count](ReturnTypeCallback, const nlohmann::json & result)
                {
                    // Result format: {"COUNT(*)": N}
                    if (result.contains("COUNT(*)") && result["COUNT(*)"].is_number())
                    {
                        count = result["COUNT(*)"].get<size_t>();
                    }
                });

                countsFor(scope)[index] = count;

                if (m_logFunction)
                {
                    m_logFunction(LOG_DEBUG, "Initialized document count for index '" + index +
                                  "': " + std::to_string(count) +
                                  ((scope == LimitScope::host) ? "" : " [container]"));
                }
            }
        }
        catch (const std::exception& ex)
        {
            if (m_logFunction)
            {
                m_logFunction(LOG_ERROR, "Failed to initialize count for table " + table +
                              ": " + std::string(ex.what()));
            }
        }
    }
}

bool Syscollector::checkDocumentLimit(const std::string& table,
                                      const nlohmann::json& data,
                                      ReturnTypeCallback result)
{
    auto indexIt = INDEX_MAP.find(table);

    if (indexIt == INDEX_MAP.end())
    {
        return true; // No index mapping, allow
    }

    const std::string& index = indexIt->second;

    // Which budget this row spends. A container row carries a non-empty
    // container_id (updateChanges() stamps it from the PK), and the two
    // populations share this index but not a cap — otherwise fifty containers'
    // processes can consume the whole host `processes` limit and starve the
    // agent's own rows, with the survivors decided by scan order.
    const bool isContainerRow = data.contains(CONTAINER_ID_COLUMN) &&
                                data[CONTAINER_ID_COLUMN].is_string() &&
                                !data[CONTAINER_ID_COLUMN].get<std::string>().empty();
    const LimitScope scope = isContainerRow ? LimitScope::container : LimitScope::host;

    std::lock_guard<std::mutex> lock(m_limitsMutex);

    // Get configured limit (0 = no limit)
    size_t limit = 0;
    auto& limits = limitsFor(scope);
    auto limitIt = limits.find(index);

    if (limitIt != limits.end())
    {
        limit = limitIt->second;
    }

    // Check if the record is already synced (sync=1)
    bool isAlreadySynced = false;

    if (data.contains("sync") && data["sync"].is_number())
    {
        isAlreadySynced = (data["sync"].get<int>() == 1);
    }

    if (result == INSERTED || result == MODIFIED)
    {
        if (isAlreadySynced)  // sync=1
        {
            // Already synced, generate event
            return true;
        }
        else  // sync=0, not synced yet
        {
            if (limit > 0)
            {
                // Has limit: don't generate event yet
                // Item stays with sync=0, will be promoted at end of scan
                return false;
            }
            else  // limit == 0 (unlimited)
            {
                // No limit: process immediately, mark sync=1
                if (m_itemsToUpdateSync)
                {
                    m_itemsToUpdateSync->push_back({table, data});
                }

                return true;
            }
        }
    }
    else if (result == DELETED)
    {
        if (isAlreadySynced)  // sync=1
        {
            // Decrement counter immediately to free up slot
            if (limit > 0 && countsFor(scope)[index] > 0)
            {
                countsFor(scope)[index]--;
            }

            return true;  // Generate DELETE event
        }
        else  // sync=0
        {
            // Not synced, don't generate DELETE event
            if (m_logFunction)
            {
                m_logFunction(LOG_DEBUG_VERBOSE,
                              "Skipping DELETE event for non-synced record in table '" + table +
                              "' (sync=0).");
            }

            return false;
        }
    }

    return true;
}

size_t Syscollector::promoteUnsyncedItems(const std::string& index,
                                          const std::string& tableName,
                                          size_t maxToPromote,
                                          const std::string& reason,
                                          LimitScope scope)
{
    if (maxToPromote == 0 || !m_spDBSync)
    {
        return 0;
    }

    // Scoped, and it matters: without the predicate a host budget with space
    // would promote CONTAINER rows into it, reporting them against the host's
    // cap and leaving the container's own backlog untouched.
    const std::string scoped{scopeFilter(scope)};

    // Count items with sync=0
    size_t unsyncedCount = 0;
    auto countQuery = SelectQuery::builder()
                      .table(tableName)
                      .columnList({"COUNT(*)"})
                      .rowFilter("WHERE sync=0" + scoped)
                      .build();

    m_spDBSync->selectRows(countQuery.query(),
                           [&unsyncedCount](ReturnTypeCallback, const nlohmann::json & result)
    {
        if (result.contains("COUNT(*)") && result["COUNT(*)"].is_number())
        {
            unsyncedCount = result["COUNT(*)"].get<size_t>();
        }
    });

    if (unsyncedCount == 0)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG_VERBOSE, reason + ": No unsynced items available to promote for index '" + index + "'");
        }

        return 0;
    }

    // Determine how many to promote
    size_t toPromote = std::min(maxToPromote, unsyncedCount);

    if (m_logFunction)
    {
        m_logFunction(LOG_DEBUG, reason + ": Promoting " + std::to_string(toPromote) +
                      " unsynced items for index '" + index + "'");
    }

    // Get ordering fields
    std::string orderFields = getFirstPrimaryKeyField(tableName);

    if (orderFields.empty())
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Cannot determine ordering fields for table: " + tableName);
        }

        return 0;
    }

    // Select items to promote with deterministic ordering
    std::string orderByClause = buildOrderByClause(orderFields, true); // ASC
    std::vector<nlohmann::json> recordsToPromote;

    auto selectQuery = SelectQuery::builder()
                       .table(tableName)
                       .columnList({"*"})
                       .rowFilter("WHERE sync=0" + scoped)
                       .orderByOpt(orderByClause)
                       .countOpt(static_cast<uint32_t>(toPromote))
                       .build();

    if (m_logFunction)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "promoteUnsyncedItems: orderByClause='" + orderByClause +
                      "', query=" + selectQuery.query().dump());
    }

    m_spDBSync->selectRows(selectQuery.query(),
                           [&recordsToPromote](ReturnTypeCallback, const nlohmann::json & result)
    {
        recordsToPromote.push_back(result);
    });

    // Generate INSERT events and mark as sync=1
    std::vector<std::pair<std::string, nlohmann::json>> itemsToMarkSynced;

    for (const auto& record : recordsToPromote)
    {
        try
        {
            uint64_t version = record.value("version", 1);
            auto [ecsDataTransformed, _] = ecsData(record, tableName, true);
            std::string hashId = calculateHashId(record, tableName);

            if (m_persistDiffFunction)
            {
                m_persistDiffFunction(hashId, OPERATION_CREATE, index, ecsDataTransformed.dump(), version);
            }

            itemsToMarkSynced.push_back({tableName, record});
        }
        catch (const std::exception& e)
        {
            if (m_logFunction)
            {
                m_logFunction(LOG_DEBUG, "Failed to promote record in table " + tableName +
                              ": " + std::string(e.what()));
            }
        }
    }

    // Mark promoted records as sync=1
    if (!itemsToMarkSynced.empty())
    {
        updateSyncFlagInDB(itemsToMarkSynced, 1);

        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, reason + ": Successfully promoted " +
                          std::to_string(itemsToMarkSynced.size()) + " records for index '" + index + "'");
        }
    }

    return itemsToMarkSynced.size();
}

void Syscollector::promoteItemsAfterScan()
{
    std::lock_guard<std::mutex> lock(m_limitsMutex);

    promoteItemsAfterScanLocked(LimitScope::host);
    promoteItemsAfterScanLocked(LimitScope::container);
}

void Syscollector::promoteItemsAfterScanLocked(LimitScope scope)
{
    // For each index with a limit, promote items to fill available slots
    for (const auto& [index, limit] : limitsFor(scope))
    {
        if (limit == 0)
        {
            continue;  // No limit, skip
        }

        const std::string tableName = TableForIndex(index);

        if (tableName.empty())
        {
            continue;
        }

        // Current count is already updated by DELETEs during scan
        size_t currentCount = countsFor(scope)[index];

        // Calculate available space
        size_t availableSpace = (currentCount < limit) ? (limit - currentCount) : 0;

        if (availableSpace == 0)
        {
            if (m_logFunction)
            {
                m_logFunction(LOG_DEBUG_VERBOSE, "Index '" + index + "' is at limit (" +
                              std::to_string(limit) + "), no items to promote");
            }

            continue;
        }

        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG_VERBOSE, "Index '" + index + "' has " +
                          std::to_string(availableSpace) + " available slots (current: " +
                          std::to_string(currentCount) + ", limit: " + std::to_string(limit) +
                          "). Promoting items with deterministic ordering.");
        }

        // Promote first availableSpace items with sync=0 using deterministic order
        std::string reason = std::string{"Post-scan promotion"} +
                             ((scope == LimitScope::host) ? "" : " [container]");
        size_t promoted = promoteUnsyncedItems(index, tableName, availableSpace, reason, scope);

        // Update counter with promoted items
        countsFor(scope)[index] = currentCount + promoted;

        if (m_logFunction && promoted > 0)
        {
            m_logFunction(LOG_DEBUG_VERBOSE, "Successfully promoted " + std::to_string(promoted) +
                          " items for index '" + index + "' (new count: " +
                          std::to_string(countsFor(scope)[index]) + ")");
        }
    }
}


bool Syscollector::hasDataInTable(const std::string& tableName)
{
    if (!m_spDBSync)
    {
        return false;
    }

    try
    {
        int count = 0;
        auto selectQuery = SelectQuery::builder()
                           .table(tableName)
                           .columnList({"COUNT(*) AS count"})
                           .build();

        const auto callback = [&count](ReturnTypeCallback returnType, const nlohmann::json & resultData)
        {
            if (returnType == SELECTED && resultData.contains("count"))
            {
                if (resultData["count"].is_number())
                {
                    count = resultData["count"].get<int>();
                }
            }
        };

        m_spDBSync->selectRows(selectQuery.query(), callback);
        return count > 0;
    }
    // LCOV_EXCL_START
    catch (const std::exception& ex)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Error checking data in table " + tableName + ": " + std::string(ex.what()));
        }

        return false;
    }

    // LCOV_EXCL_STOP
}

void Syscollector::checkDisabledCollectorsIndicesWithData()
{
    m_disabledCollectorsIndicesWithData.clear();
    bool already_included_vd = false;

    if (!m_hardware && hasDataInTable(HW_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_HARDWARE);
    }

    if (!m_os && hasDataInTable(OS_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_SYSTEM);

        if (!already_included_vd)
        {
            m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_VULNERABILITIES);
            already_included_vd = true;
        }
    }

    if (!m_packages && hasDataInTable(PACKAGES_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_PACKAGES);

        if (!already_included_vd)
        {
            m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_VULNERABILITIES);
            already_included_vd = true;
        }
    }

    if (!m_hotfixes && hasDataInTable(HOTFIXES_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_HOTFIXES);

        if (!already_included_vd)
        {
            m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_VULNERABILITIES);
        }
    }

    if (!m_processes && hasDataInTable(PROCESSES_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_PROCESSES);
    }

    if (!m_ports && hasDataInTable(PORTS_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_PORTS);
    }

    if (!m_users && hasDataInTable(USERS_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_USERS);
    }

    if (!m_groups && hasDataInTable(GROUPS_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_GROUPS);
    }

    if (!m_services && hasDataInTable(SERVICES_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_SERVICES);
    }

    if (!m_browserExtensions && hasDataInTable(BROWSER_EXTENSIONS_TABLE))
    {
        m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_BROWSER_EXTENSIONS);
    }

    if (!m_network)
    {
        if (hasDataInTable(NET_IFACE_TABLE))
        {
            m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_INTERFACES);
        }

        if (hasDataInTable(NET_PROTOCOL_TABLE))
        {
            m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_PROTOCOLS);
        }

        if (hasDataInTable(NET_ADDRESS_TABLE))
        {
            m_disabledCollectorsIndicesWithData.push_back(SYSCOLLECTOR_SYNC_INDEX_NETWORKS);
        }
    }

    if (!m_disabledCollectorsIndicesWithData.empty() && m_logFunction)
    {
        std::string indices;

        for (const auto& idx : m_disabledCollectorsIndicesWithData)
        {
            if (!indices.empty())
            {
                indices += ", ";
            }

            indices += idx;
        }

        m_logFunction(LOG_INFO, "Disabled collectors indices with data detected: " + indices);
    }
}

bool Syscollector::notifyDisableCollectorsDataClean()
{
    // Serialize against releaseResources(): this entry point is driven by threads that
    // outlive the module teardown (wcom's detached dispatcher and agent-info's in-process
    // coordination polls), so the members it reaches must not be reset underneath it.
    std::shared_lock<std::shared_mutex> resourcesLock(m_resourcesMutex);

    if (m_disabledCollectorsIndicesWithData.empty())
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, "No disabled collectors indices with data to notify for cleanup");
        }

        return true;
    }

    if (!m_spSyncProtocol)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_INFO, "Sync protocol not initialized, cannot notify data clean");
        }

        return false;
    }

    // LCOV_EXCL_START
    if (m_logFunction)
    {
        std::string indices;

        for (const auto& idx : m_disabledCollectorsIndicesWithData)
        {
            if (!indices.empty())
            {
                indices += ", ";
            }

            indices += idx;
        }

        m_logFunction(LOG_DEBUG, "Notifying DataClean for disabled collectors indices: " + indices);
    }

    return m_spSyncProtocol->notifyDataClean(m_disabledCollectorsIndicesWithData);
    // LCOV_EXCL_STOP
}

void Syscollector::deleteDisableCollectorsData()
{
    // Serialize against releaseResources(): this entry point is driven by threads that
    // outlive the module teardown (wcom's detached dispatcher and agent-info's in-process
    // coordination polls), so the members it reaches must not be reset underneath it.
    std::shared_lock<std::shared_mutex> resourcesLock(m_resourcesMutex);

    if (m_disabledCollectorsIndicesWithData.empty())
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, "No disabled collectors indices with data to delete");
        }

        return;
    }

    // If all collectors are disabled, delete the entire database instead of going table by table
    if (m_allCollectorsDisabled)
    {
        // LCOV_EXCL_START
        if (m_logFunction)
        {
            m_logFunction(LOG_INFO, "All collectors are disabled. Deleting entire database.");
        }

        // Already holding m_resourcesMutex shared; call the non-locking body so we do not
        // take a second shared lock on this thread (see deleteDatabaseUnlocked()).
        deleteDatabaseUnlocked();
        m_disabledCollectorsIndicesWithData.clear();
        return;
        // LCOV_EXCL_STOP
    }

    // Only some collectors are disabled, delete specific tables
    if (m_logFunction)
    {
        std::string indices;

        for (const auto& idx : m_disabledCollectorsIndicesWithData)
        {
            if (!indices.empty())
            {
                indices += ", ";
            }

            indices += idx;
        }

        m_logFunction(LOG_INFO, "Deleting data for disabled collectors indices: " + indices);
    }

    clearTablesForIndices(m_disabledCollectorsIndicesWithData);
    m_disabledCollectorsIndicesWithData.clear();
}

void Syscollector::clearTablesForIndices(const std::vector<std::string>& indices)
{
    if (!m_spDBSync)
    {
        return;
    }

    auto dbHandle = m_spDBSync->handle();

    if (dbHandle == nullptr)
    {
        return;
    }

    for (const auto& index : indices)
    {
        std::string tableName;

        for (const auto& [table, idx] : INDEX_MAP)
        {
            if (idx == index)
            {
                tableName = table;
                break;
            }
        }

        if (!tableName.empty())
        {
            try
            {
                // Callback for delete operations (no-op, we don't need to process deleted rows)
                const auto deleteCallback = [](ReturnTypeCallback, const nlohmann::json&) {};

                // Create transaction for this table - commits automatically on destruction
                DBSyncTxn txn
                {
                    dbHandle,
                    nlohmann::json {tableName},
                    0,
                    QUEUE_SIZE,
                    deleteCallback
                };

                // Sync with empty data to mark all existing rows as deleted
                nlohmann::json emptyInput;
                emptyInput["table"] = tableName;
                emptyInput["data"] = nlohmann::json::array();

                txn.syncTxnRow(emptyInput);
                txn.getDeletedRows(deleteCallback);

                // Transaction commits here when txn goes out of scope

                if (m_logFunction)
                {
                    m_logFunction(LOG_DEBUG, "Cleared table " + tableName);
                }
            }
            // LCOV_EXCL_START
            catch (const std::exception& ex)
            {
                if (m_logFunction)
                {
                    m_logFunction(LOG_ERROR, "Error clearing table " + tableName + ": " + std::string(ex.what()));
                }
            }

            // LCOV_EXCL_STOP
        }
    }
}

size_t Syscollector::getDocumentLimit(const std::string& index)
{
    std::lock_guard<std::mutex> limitsLock(m_limitsMutex);
    return m_documentLimits[index];
}

// LCOV_EXCL_START
bool Syscollector::checkIfFullSyncRequired(const std::string& tableName)
{
    m_logFunction(LOG_DEBUG, "Attempting to get checksum for " + tableName + " table");

    // Determine if we need to filter by sync=1 when calculating checksum
    // Only filter when document limits are configured (limit > 0)
    std::string rowFilter;
    auto indexIt = INDEX_MAP.find(tableName);

    if (indexIt != INDEX_MAP.end())
    {
        const std::string& index = indexIt->second;
        size_t documentLimit = getDocumentLimit(index);

        if (documentLimit > 0)
        {
            // With limits: only include items with sync=1 in checksum
            // This matches what the manager has (only synced items were sent)
            rowFilter = "WHERE sync=1";
            m_logFunction(LOG_DEBUG, "Calculating checksum with filter 'sync=1' (limit=" + std::to_string(documentLimit) + ")");
        }
        else
        {
            // No limits: include all items in checksum
            rowFilter = "";
            m_logFunction(LOG_DEBUG, "Calculating checksum without filter (no limit)");
        }
    }

    std::string final_checksum = m_spDBSync->calculateTableChecksum(tableName, rowFilter);

    m_logFunction(LOG_DEBUG, "Success! Final file table checksum is: " + std::string(final_checksum));

    bool needs_full_sync;
    needs_full_sync = m_spSyncProtocol->requiresFullSync(
                          INDEX_MAP.at(tableName),
                          final_checksum
                      );

    if (needs_full_sync)
    {
        m_logFunction(LOG_DEBUG, "Checksum mismatch detected for index " + tableName + " full sync required");
    }
    else
    {
        m_logFunction(LOG_DEBUG, "Checksum valid for index " + tableName + ", delta sync sufficient");
    }

    return needs_full_sync;
}
// LCOV_EXCL_STOP

bool Syscollector::getMetadataValue(const std::string& key, int64_t& value)
{
    value = 0;

    // Callers reach this from query(), which holds m_resourcesMutex shared, so the pointer
    // cannot be reset underneath us. Checked anyway, as every other DBSync user in this file
    // does: a null dereference here raises an SEH access violation on Windows, which the
    // catch below cannot handle, and it takes the whole agent process down.
    if (!m_spDBSync)
    {
        return false;
    }

    auto callback = [&value](ReturnTypeCallback result, const nlohmann::json & data)
    {
        if (result == ReturnTypeCallback::SELECTED && data.contains("last_sync_time"))
        {
            value = data.at("last_sync_time").get<int64_t>();
        }
    };

    try
    {
        auto selectQuery = SelectQuery::builder()
                           .table("table_metadata")
                           .columnList({"last_sync_time"})
                           .rowFilter("WHERE table_name = '" + key + "'")
                           .build();

        m_spDBSync->selectRows(selectQuery.query(), callback);
        return true;
    }
    catch (const std::exception& ex)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Failed to get metadata value '" + key + "': " + std::string(ex.what()));
        }
    }

    return false;
}

bool Syscollector::updateMetadataValue(const std::string& key, int64_t value)
{
    auto emptyCallback = [](ReturnTypeCallback, const nlohmann::json&) {};

    try
    {
        std::map<std::string, int64_t> metadataValues;
        auto selectQuery = SelectQuery::builder()
                           .table("table_metadata")
                           .columnList({"table_name", "last_sync_time"})
                           .build();

        auto selectCallback = [&metadataValues](ReturnTypeCallback result, const nlohmann::json & data)
        {
            if (result == ReturnTypeCallback::SELECTED &&
                    data.contains("table_name") &&
                    data.contains("last_sync_time") &&
                    data.at("table_name").is_string() &&
                    data.at("last_sync_time").is_number())
            {
                metadataValues[data.at("table_name").get<std::string>()] = data.at("last_sync_time").get<int64_t>();
            }
        };

        m_spDBSync->selectRows(selectQuery.query(), selectCallback);
        metadataValues[key] = value;

        DBSyncTxn txn
        {
            m_spDBSync->handle(),
            nlohmann::json{"table_metadata"},
            0,
            QUEUE_SIZE,
            emptyCallback
        };

        nlohmann::json allData = nlohmann::json::array();

        for (const auto& [tableName, timestamp] : metadataValues)
        {
            allData.push_back({{"table_name", tableName}, {"last_sync_time", timestamp}});
        }

        nlohmann::json input;
        input["table"] = "table_metadata";
        input["data"] = allData;

        txn.syncTxnRow(input);
        txn.getDeletedRows(emptyCallback);
        return true;
    }
    catch (const std::exception& ex)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Failed to update metadata value '" + key + "': " + std::string(ex.what()));
        }
    }

    return false;
}

int64_t Syscollector::getLastSyncTime(const std::string& tableName)
{
    int64_t lastSyncTime = 0;

    if (!getMetadataValue(tableName, lastSyncTime))
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Failed to retrieve last sync time for table: " + tableName);
        }

        // Reset to 0: the callback in getMetadataValue may have written a partial value
        // from a previous row before the exception was thrown mid-stream.
        // The caller relies on 0 as the "never synced" sentinel.
        lastSyncTime = 0;
    }

    return lastSyncTime;
}

void Syscollector::updateLastSyncTime(const std::string& tableName, int64_t timestamp)
{
    updateMetadataValue(tableName, timestamp);
}

bool Syscollector::recoveryIntervalHasEllapsed(const std::string& tableName, int64_t integrityInterval)
{
    int64_t currentTime = Utils::getSecondsFromEpoch();
    int64_t lastSyncTime = getLastSyncTime(tableName);

    // If never checked before (lastSyncTime == 0), initialize timestamp and don't run check yet
    // This enables integrity checks to run after the configured interval
    if (lastSyncTime == 0)
    {
        updateLastSyncTime(tableName, currentTime);
        return false;
    }

    int64_t elapsedTime = currentTime - lastSyncTime;
    return (elapsedTime >= integrityInterval);
}

void Syscollector::runRecoveryProcess()
{
    for (const auto& [tableName, index] : INDEX_MAP)
    {
        // Skip disabled modules
        if (tableName == OS_TABLE && !m_os) continue;

        if (tableName == HW_TABLE && !m_hardware) continue;

        if (tableName == HOTFIXES_TABLE && !m_hotfixes) continue;

        if (tableName == PACKAGES_TABLE && !m_packages) continue;

        if (tableName == PROCESSES_TABLE && !m_processes) continue;

        if (tableName == PORTS_TABLE && !m_ports) continue;

        if (((tableName == NET_ADDRESS_TABLE) || (tableName == NET_IFACE_TABLE) || (tableName == NET_PROTOCOL_TABLE)) && !m_network) continue;

        if (tableName == USERS_TABLE && !m_users) continue;

        if (tableName == GROUPS_TABLE && !m_groups) continue;

        if (tableName == SERVICES_TABLE && !m_services) continue;

        if (tableName == BROWSER_EXTENSIONS_TABLE && !m_browserExtensions) continue;

        // LCOV_EXCL_START
        // Recovery process requires manager integration for checksum validation.
        if (recoveryIntervalHasEllapsed(tableName, m_integrityIntervalValue))
        {
            m_logFunction(LOG_DEBUG, "Starting integrity validation process for " + tableName);
            bool full_sync_required = checkIfFullSyncRequired(tableName);

            if (full_sync_required)
            {
                try
                {
                    m_spDBSync->increaseEachEntryVersion(tableName);
                }
                catch (const std::exception& ex)
                {
                    m_logFunction(LOG_ERROR, "Couldn't update version for every entry in " + tableName);
                    return;
                }

                std::vector<nlohmann::json> items;

                // Determine if we need to filter by sync=1
                // Only filter when document limits are configured (limit > 0)
                // If limit == 0 (unlimited), recover all items without filtering
                size_t documentLimit = getDocumentLimit(index);
                std::string rowFilterClause;

                try
                {
                    if (documentLimit > 0)
                    {
                        // With limits: only recover items with sync=1
                        // Items with sync=0 exceeded the document limit and should not be recovered
                        rowFilterClause = "WHERE sync=1";
                    }
                    else
                    {
                        // No limits: recover all items regardless of sync value
                        rowFilterClause = "";
                    }

                    auto callback = [&items](ReturnTypeCallback result, const nlohmann::json & data)
                    {
                        if (result == ReturnTypeCallback::SELECTED)
                        {
                            items.push_back(data);
                        }
                    };

                    auto selectQuery = SelectQuery::builder()
                                       .table(tableName)
                                       .columnList({"*"})
                                       .rowFilter(rowFilterClause)
                                       .build();

                    m_spDBSync->selectRows(selectQuery.query(), callback);
                }
                catch (const std::exception& ex)
                {
                    m_logFunction(LOG_ERROR, "Failed to retrieve elements from " + tableName);
                    return;
                }

                // Clear the manager's index before resending: a full-replace sync is now a
                // DataClean followed by a DELTA sync of the fresh snapshot, never Mode::FULL
                // (which used to make the manager unconditionally deleteByQuery over a
                // byte-capped/truncated payload and could permanently drop whatever didn't
                // fit in that one session).
                if (!m_spSyncProtocol->notifyDataClean({index}))
                {
                    m_logFunction(LOG_WARNING, "Failed to clear index " + index + " before recovery resync for table " + tableName + "; will retry later");
                    return;
                }

                for (const auto& item : items)
                {
                    // Build stateful event
                    auto [newData, version] = ecsData(item, tableName);
                    const auto statefulToSend{newData.dump()};

                    // Validate stateful event before persisting for recovery
                    bool shouldPersist = true;
                    std::string context = "recovery event, table: " + tableName;

                    // Use helper function to validate and log
                    bool validationPassed = validateSchemaAndLog(statefulToSend, index, context);

                    if (!validationPassed)
                    {
                        m_logFunction(LOG_DEBUG, "Skipping persistence of invalid recovery event");
                        shouldPersist = false;
                    }

                    if (shouldPersist)
                    {
                        m_spSyncProtocol->persistDifference(
                            calculateHashId(item, tableName),
                            Operation::CREATE,
                            index,
                            statefulToSend,
                            item["version"].get<uint64_t>()
                        );
                    }
                }

                m_logFunction(LOG_DEBUG, "Persisted " + std::to_string(items.size()) + " recovery items");
                m_logFunction(LOG_DEBUG, "Starting recovery synchronization...");
                bool recoverySucceeded = syncModule(Mode::DELTA).success;

                if (recoverySucceeded)
                {
                    m_logFunction(LOG_DEBUG, "Recovery completed successfully");
                }
                else
                {
                    m_logFunction(LOG_DEBUG, "Recovery synchronization failed, will retry later");
                }

            }

            // Update the last sync time regardless of whether full sync was required
            // This ensures the integrity check doesn't run again until integrity_interval has elapsed
            updateLastSyncTime(tableName, Utils::getSecondsFromEpoch());
        }

        // LCOV_EXCL_STOP
    }
}

bool Syscollector::validateSchemaAndLog(const std::string& data, const std::string& index, const std::string& context) const
{
    auto& validatorFactory = SchemaValidator::SchemaValidatorFactory::getInstance();

    if (!validatorFactory.isInitialized())
    {
        return true;
    }

    auto validator = validatorFactory.getValidator(index);

    if (!validator)
    {
        // No validator for this index: be restrictive and discard the message
        // instead of queuing it unvalidated, since we cannot guarantee it matches
        // the schema the indexer expects.
        if (m_logFunction)
        {
            m_logFunction(LOG_WARNING, "No schema validator found for index: " + index + ". Discarding message.");
        }

        return false;
    }

    auto validationResult = validator->validate(data);

    if (validationResult.isValid)
    {
        return true;
    }

    // Validation failed - log errors
    std::string errorMsg = "Schema validation failed for Syscollector message (" + context + ", index: " + index + "). Errors: ";

    for (const auto& error : validationResult.errors)
    {
        errorMsg += "  - " + error;
    }

    if (m_logFunction)
    {
        m_logFunction(LOG_ERROR, errorMsg);
        m_logFunction(LOG_ERROR, "Raw event that failed validation: " + data);
    }

    return false;
}

void Syscollector::deleteFailedItemsFromDB(const std::vector<std::pair<std::string, nlohmann::json>>& failedItems) const
{
    if (failedItems.empty() || !m_spDBSync)
    {
        return;
    }

    try
    {
        // Create a transaction scope - BEGIN TRANSACTION will be executed
        DBSyncTxn deleteTxn(m_spDBSync->handle(),
                            nlohmann::json::array(),  // Empty table list
                            0,
                            1,
        [](ReturnTypeCallback, const nlohmann::json&) {});

        // Execute all deletions within the transaction scope
        for (const auto& [tableName, data] : failedItems)
        {
            if (m_logFunction)
            {
                m_logFunction(LOG_DEBUG, "Deleting entry from table " + tableName + " due to validation failure");
            }

            try
            {
                auto deleteQuery = DeleteQuery::builder()
                                   .table(tableName)
                                   .data(data)
                                   .rowFilter("")
                                   .build();

                m_spDBSync->deleteRows(deleteQuery.query());
            }
            catch (const std::exception& e)
            {
                if (m_logFunction)
                {
                    m_logFunction(LOG_ERROR, "Failed to delete from DBSync: " + std::string(e.what()));
                }
            }
        }

        // Call getDeletedRows to finalize the transaction properly
        // This triggers the internal commit mechanism in DBSync
        deleteTxn.getDeletedRows([](ReturnTypeCallback, const nlohmann::json&) {});

        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, "Deleted " + std::to_string(failedItems.size()) + " item(s) from DBSync due to validation failure");
        }
    }
    catch (const std::exception& e)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Failed to create DBSync transaction for deletion: " + std::string(e.what()));
        }
    }
}

void Syscollector::updateSyncFlagInDB(const std::vector<std::pair<std::string, nlohmann::json>>& itemsToUpdate, int syncValue) const
{
    if (itemsToUpdate.empty() || !m_spDBSync)
    {
        return;
    }

    try
    {
        // Strategy: Delete rows, then re-insert with new sync value
        // This is the only way to update fields not part of checksum using DBSync API

        // Step 1: Delete all rows in a transaction
        {
            const auto txnCallback = [](ReturnTypeCallback, const nlohmann::json&) {};
            DBSyncTxn deleteTxn{m_spDBSync->handle(), nlohmann::json::array(), 0, 1, txnCallback};

            for (const auto& [tableName, data] : itemsToUpdate)
            {
                try
                {
                    auto deleteQuery = DeleteQuery::builder()
                                       .table(tableName)
                                       .data(data)
                                       .rowFilter("")
                                       .build();

                    m_spDBSync->deleteRows(deleteQuery.query());
                }
                catch (const std::exception& e)
                {
                    if (m_logFunction)
                    {
                        m_logFunction(LOG_ERROR, "Failed to delete row: " + std::string(e.what()));
                    }
                }
            }

            deleteTxn.getDeletedRows(txnCallback);
        }

        // Step 2: Re-insert rows with new sync value in a transaction to force commit
        {
            const auto txnCallback = [](ReturnTypeCallback, const nlohmann::json&) {};
            DBSyncTxn insertTxn{m_spDBSync->handle(), nlohmann::json::array(), 0, 1, txnCallback};

            for (const auto& [tableName, data] : itemsToUpdate)
            {
                try
                {
                    nlohmann::json updatedData = data;
                    updatedData["sync"] = syncValue;

                    nlohmann::json insertInput;
                    insertInput["table"] = tableName;
                    insertInput["data"] = nlohmann::json::array({updatedData});

                    m_spDBSync->insertData(insertInput);
                }
                catch (const std::exception& e)
                {
                    if (m_logFunction)
                    {
                        m_logFunction(LOG_ERROR, "Failed to insert row for table " + tableName + ": " + std::string(e.what()));
                    }
                }
            }

            // Force commit of inserts
            insertTxn.getDeletedRows(txnCallback);
        }

        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG_VERBOSE, "Updated sync=" + std::to_string(syncValue) +
                          " for " + std::to_string(itemsToUpdate.size()) + " item(s) in DBSync");
        }
    }
    catch (const std::exception& e)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Failed to update sync flag: " + std::string(e.what()));
        }
    }
}

std::string Syscollector::getFirstPrimaryKeyField(const std::string& tableName) const
{
    // Map table names to their simplified ordering fields
    // Most use first PK field only, but some (like packages) use multiple for stability
    static const std::map<std::string, const char*> tableOrderByFields =
    {
        {OS_TABLE, OS_ORDER_BY},
        {HW_TABLE, HW_ORDER_BY},
        {HOTFIXES_TABLE, HOTFIXES_ORDER_BY},
        {PACKAGES_TABLE, PACKAGES_ORDER_BY},  // "name, type" for better ordering
        {PROCESSES_TABLE, PROCESSES_ORDER_BY},
        {PORTS_TABLE, PORTS_ORDER_BY},
        {NET_IFACE_TABLE, NET_IFACE_ORDER_BY},
        {NET_PROTOCOL_TABLE, NET_PROTOCOL_ORDER_BY},
        {NET_ADDRESS_TABLE, NET_ADDRESS_ORDER_BY},
        {USERS_TABLE, USERS_ORDER_BY},
        {GROUPS_TABLE, GROUPS_ORDER_BY},
        {SERVICES_TABLE, SERVICES_ORDER_BY},
        {BROWSER_EXTENSIONS_TABLE, BROWSER_EXTENSIONS_ORDER_BY}
    };

    auto it = tableOrderByFields.find(tableName);
    return (it != tableOrderByFields.end()) ? it->second : "";
}

std::string Syscollector::buildOrderByClause(const std::string& fields, bool ascending) const
{
    if (fields.empty())
    {
        return "";
    }

    // Parse fields (e.g., "name, type" -> ["name", "type"])
    std::vector<std::string> fieldList;
    size_t start = 0;
    size_t end = fields.find(',');

    while (end != std::string::npos)
    {
        std::string field = fields.substr(start, end - start);
        // Trim spaces
        field.erase(0, field.find_first_not_of(" "));
        field.erase(field.find_last_not_of(" ") + 1);

        if (!field.empty())
        {
            fieldList.push_back(std::move(field));
        }

        start = end + 1;
        end = fields.find(',', start);
    }

    // Add last field
    std::string lastField = fields.substr(start);
    lastField.erase(0, lastField.find_first_not_of(" "));
    lastField.erase(lastField.find_last_not_of(" ") + 1);

    if (!lastField.empty())
    {
        fieldList.push_back(std::move(lastField));
    }

    // Build ORDER BY with COLLATE NOCASE for case-insensitive ordering
    std::string orderBy;
    const std::string sortOrder = ascending ? " ASC" : " DESC";

    for (size_t i = 0; i < fieldList.size(); ++i)
    {
        if (i > 0)
        {
            orderBy += ", ";
        }

        orderBy += fieldList[i] + " COLLATE NOCASE" + sortOrder;
    }

    return orderBy;
}
