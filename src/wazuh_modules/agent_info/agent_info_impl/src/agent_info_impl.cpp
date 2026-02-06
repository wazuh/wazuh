#include "agent_info_impl.hpp"

#include "agent_sync_protocol.hpp"
#include "defs.h"
#include "hashHelper.h"
#include "stringHelper.h"
#include "timeHelper.h"
#include "metadata_provider.h"

#include <dbsync.hpp>
#include <file_io_utils.hpp>
#include <filesystem_wrapper.hpp>
#include <sysInfo.hpp>
#include "../../../module_query_errors.h"
#include "../../../wmodules.h"

#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>

// Forward declarations for handshake data getters (implemented in agent_info.cpp)
extern "C" {
    const char* agent_info_get_cluster_name(void);
    const char* agent_info_get_cluster_node(void);
    const char* agent_info_get_agent_groups(void);
    void agent_info_clear_agent_groups(void);
}

constexpr auto QUEUE_SIZE = 4096;
constexpr auto AGENT_METADATA_TABLE = "agent_metadata";
constexpr auto AGENT_GROUPS_TABLE = "agent_groups";

// Module coordination configuration
const std::vector<std::string> COORDINATION_MODULES = {SCA_WM_NAME, SYSCOLLECTOR_WM_NAME, FIM_NAME};
constexpr int MAX_COORDINATION_RETRIES = 3;
constexpr int COORDINATION_RETRY_DELAY_MS = 1000;

// Map DBSync callback results to operation strings for stateless events
static const std::map<ReturnTypeCallback, std::string> OPERATION_MAP
{
    {MODIFIED, "modified"},
    {DELETED, "deleted"},
    {INSERTED, "created"},
};

// Map tables to their delta synchronization modes
static const std::map<std::string, Mode> TABLE_DELTA_MODE_MAP
{
    {AGENT_METADATA_TABLE, Mode::METADATA_DELTA},
    {AGENT_GROUPS_TABLE, Mode::GROUP_DELTA},
};

// Map tables to their integrity check modes
static const std::map<std::string, Mode> TABLE_CHECK_MODE_MAP
{
    {AGENT_METADATA_TABLE, Mode::METADATA_CHECK},
    {AGENT_GROUPS_TABLE, Mode::GROUP_CHECK},
};

// Map modules to their corresponding indices that should be updated when agent metadata or groups change
static const std::map<std::string, std::vector<std::string>> MODULE_INDICES_MAP
{
    {
        FIM_NAME, {
            "wazuh-states-fim-files",
            "wazuh-states-fim-registry-keys",
            "wazuh-states-fim-registry-values"
        }
    },
    {
        SCA_WM_NAME, {
            "wazuh-states-sca"
        }
    },
    {
        SYSCOLLECTOR_WM_NAME, {
            "wazuh-states-inventory-system",
            "wazuh-states-inventory-hardware",
            "wazuh-states-inventory-hotfixes",
            "wazuh-states-inventory-packages",
            "wazuh-states-inventory-processes",
            "wazuh-states-inventory-ports",
            "wazuh-states-inventory-interfaces",
            "wazuh-states-inventory-protocols",
            "wazuh-states-inventory-networks",
            "wazuh-states-inventory-users",
            "wazuh-states-inventory-groups",
            "wazuh-states-inventory-services",
            "wazuh-states-inventory-browser-extensions",
            "wazuh-states-vulnerabilities"
        }
    }
};

const char* AGENT_METADATA_SQL_STATEMENT =
    "CREATE TABLE IF NOT EXISTS agent_metadata ("
    "agent_id          TEXT NOT NULL PRIMARY KEY,"
    "agent_name        TEXT,"
    "agent_version     TEXT,"
    "host_architecture TEXT,"
    "host_hostname     TEXT,"
    "host_os_name      TEXT,"
    "host_os_type      TEXT,"
    "host_os_platform  TEXT,"
    "host_os_version   TEXT,"
    "cluster_name      TEXT,"
    "cluster_node      TEXT);";

const char* AGENT_GROUPS_SQL_STATEMENT =
    "CREATE TABLE IF NOT EXISTS agent_groups ("
    "agent_id          TEXT NOT NULL,"
    "group_name        TEXT NOT NULL,"
    "PRIMARY KEY (agent_id, group_name),"
    "FOREIGN KEY (agent_id) REFERENCES agent_metadata(agent_id) ON DELETE CASCADE);";

const char* DB_METADATA_SQL_STATEMENT =
    "CREATE TABLE IF NOT EXISTS db_metadata ("
    "id                         INTEGER PRIMARY KEY CHECK (id = 1),"
    "should_sync_metadata       INTEGER NOT NULL DEFAULT 0,"
    "should_sync_groups         INTEGER NOT NULL DEFAULT 0,"
    "last_metadata_integrity    INTEGER NOT NULL DEFAULT 0,"
    "last_groups_integrity      INTEGER NOT NULL DEFAULT 0,"
    "is_first_run               INTEGER NOT NULL DEFAULT 1,"
    "is_first_groups_run        INTEGER NOT NULL DEFAULT 1);";

AgentInfoImpl::AgentInfoImpl(std::string dbPath,
                             std::function<void(const std::string&)> reportDiffFunction,
                             std::function<void(const modules_log_level_t, const std::string&)> logFunction,
                             module_query_callback_t queryModuleFunction,
                             std::shared_ptr<IDBSync> dbSync,
                             std::shared_ptr<ISysInfo> sysInfo,
                             std::shared_ptr<IFileIOUtils> fileIO,
                             std::shared_ptr<IFileSystemWrapper> fileSystem)
    : m_dBSync(
          dbSync ? std::move(dbSync)
          : std::make_shared<DBSync>(
              HostType::AGENT, DbEngineType::SQLITE3, dbPath, GetCreateStatement(), DbManagement::PERSISTENT))
    , m_sysInfo(sysInfo ? std::move(sysInfo) : std::make_shared<SysInfo>())
    , m_fileIO(fileIO ? std::move(fileIO) : std::make_shared<file_io::FileIOUtils>())
    , m_fileSystem(fileSystem ? std::move(fileSystem) : std::make_shared<file_system::FileSystemWrapper>())
    , m_reportDiffFunction(std::move(reportDiffFunction))
    , m_logFunction(std::move(logFunction))
    , m_queryModuleFunction(std::move(queryModuleFunction))
{
    if (!m_logFunction)
    {
        throw std::invalid_argument("Log function must be provided");
    }

    if (!m_queryModuleFunction)
    {
        throw std::invalid_argument("Query module function must be provided");
    }

    m_logFunction(LOG_INFO, "AgentInfo initialized.");
}

AgentInfoImpl::~AgentInfoImpl()
{
    stop();
    m_logFunction(LOG_INFO, "AgentInfo destroyed.");
}



void AgentInfoImpl::start(int interval, int integrityInterval, std::function<bool()> shouldContinue)
{
    m_logFunction(LOG_INFO, "AgentInfo module started with interval: " + std::to_string(interval) +
                " seconds, integrity interval: " + std::to_string(integrityInterval) + " seconds.");

    // Load sync flags from database at startup
    loadSyncFlags();

    std::unique_lock<std::mutex> lock(m_mutex);
    m_stopped = false;

    // Reset sync protocol stop flag to allow restarting operations
    if (m_spSyncProtocol)
    {
        m_spSyncProtocol->reset();
    }

    // Initial delay before first run to allow other modules to start
    std::this_thread::sleep_for(std::chrono::seconds(5));

    // Run at least once
    do
    {
        lock.unlock();

        try
        {
            populateAgentMetadata();
        }
        catch (const std::exception& e)
        {
            m_logFunction(LOG_ERROR, std::string("Failed to populate agent metadata: ") + e.what());
        }

        // After populateAgentMetadata(), check if synchronization is needed

        // Perform delta synchronization for metadata if needed
        if (m_shouldSyncMetadata)
        {
            // Check if this is the first run - applies to AGENT_METADATA_TABLE
            if (m_isFirstRun)
            {
                m_logFunction(LOG_DEBUG, "First run detected for agent-metadata, skipping synchronization.");
                resetSyncFlag(AGENT_METADATA_TABLE);
            }
            else
            {
                performDeltaSync(AGENT_METADATA_TABLE);
            }
        }

        // Perform delta synchronization for groups if needed
        if (m_shouldSyncGroups)
        {
            // Check if this is the first groups run - applies to AGENT_GROUPS_TABLE
            if (m_isFirstGroupsRun)
            {
                m_logFunction(LOG_DEBUG, "First groups run detected for agent-groups, skipping synchronization.");
                resetSyncFlag(AGENT_GROUPS_TABLE);
            }
            else
            {
                performDeltaSync(AGENT_GROUPS_TABLE);
            }
        }

        // Check if integrity check should be performed (only if no delta sync is in progress)
        if (!m_shouldSyncMetadata && shouldPerformIntegrityCheck(AGENT_METADATA_TABLE, integrityInterval))
        {
            performIntegritySync(AGENT_METADATA_TABLE);
        }

        if (!m_shouldSyncGroups && shouldPerformIntegrityCheck(AGENT_GROUPS_TABLE, integrityInterval))
        {
            performIntegritySync(AGENT_GROUPS_TABLE);
        }

        lock.lock();

        // If no shouldContinue function provided, use default behavior (continue until stopped)
        bool shouldLoop = shouldContinue ? shouldContinue() : !m_stopped;

        if (shouldLoop && !m_stopped)
        {
            // Wait for the interval or until stop is signaled
            m_cv.wait_for(lock, std::chrono::seconds(interval), [this] { return m_stopped; });
        }

    }
    while (!m_stopped && (shouldContinue ? shouldContinue() : true));

    m_logFunction(LOG_INFO, "AgentInfo module loop ended.");
    
}

void AgentInfoImpl::stop()
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_stopped)
        {
            return;
        }

        m_stopped = true;
    }

    m_cv.notify_one(); // Wake up the sleeping thread immediately

    {
        std::lock_guard<std::mutex> dbLock(m_dbSyncMutex);

        if (m_dBSync)
        {
            m_logFunction(LOG_DEBUG, "Closing DBSync connection...");
            m_dBSync.reset();
            m_logFunction(LOG_DEBUG, "DBSync connection closed");
        }
    }

    // Signal sync protocol to stop any ongoing operations AFTER DBSync is cleaned up
    // This ensures no new sync operations are started from DBSync callbacks
    if (m_spSyncProtocol)
    {
        m_spSyncProtocol->stop();
    }

    m_logFunction(LOG_INFO, "AgentInfo module stopped.");
}

void AgentInfoImpl::initSyncProtocol(const std::string& moduleName,
                                     const MQ_Functions& mqFuncs)
{
    auto logger_func = [this](modules_log_level_t level, const std::string & msg)
    {
        m_logFunction(level, msg);
    };

    try
    {
        m_spSyncProtocol = std::make_unique<AgentSyncProtocol>(moduleName, std::nullopt, mqFuncs, logger_func, std::chrono::seconds(m_syncEndDelay), std::chrono::seconds(m_syncResponseTimeout), m_syncRetries,
                                                               m_syncMaxEps, nullptr);
        m_logFunction(LOG_INFO, "Agent-info sync protocol initialized with only in-memory synchronization");
    }
    catch (const std::exception& ex)
    {
        m_logFunction(LOG_ERROR, "Failed to initialize sync protocol for agent_info: " + std::string(ex.what()));
        // Re-throw to allow caller to handle
        throw;
    }
}

void AgentInfoImpl::setSyncParameters(uint32_t syncEndDelay, uint32_t timeout, uint32_t retries, long maxEps)
{
    m_syncEndDelay = syncEndDelay;
    m_syncResponseTimeout = timeout;
    m_syncRetries = retries;
    m_syncMaxEps = maxEps;

    m_logFunction(LOG_DEBUG,
                  "Sync parameters set: syncEndDelay =" + std::to_string(syncEndDelay) + "s, timeout=" + std::to_string(timeout) + "s, retries=" +
                  std::to_string(retries) + ", maxEps=" + std::to_string(maxEps));
}

bool AgentInfoImpl::parseResponseBuffer(const uint8_t* data, size_t length)
{
    if (m_spSyncProtocol && data)
    {
        return m_spSyncProtocol->parseResponseBuffer(data, length);
    }

    m_logFunction(LOG_ERROR, "Sync protocol not initialized or invalid data");
    return false;
}

std::string AgentInfoImpl::GetCreateStatement() const
{
    std::string ret;
    ret += AGENT_METADATA_SQL_STATEMENT;
    ret += AGENT_GROUPS_SQL_STATEMENT;
    ret += DB_METADATA_SQL_STATEMENT;
    return ret;
}

void AgentInfoImpl::populateAgentMetadata()
{
    m_logFunction(LOG_DEBUG, "Populating agent metadata from sysinfo");

    // Get OS information from sysinfo
    nlohmann::json osInfo = m_sysInfo->os();

    // Read agent ID and name
    std::string agentId;
    std::string agentName;

    // For agents, read from client.keys
    if (!readClientKeys(agentId, agentName))
    {
        m_logFunction(LOG_WARNING, "Failed to read agent ID and name from client.keys");
    }

    // Build the agent metadata JSON
    nlohmann::json agentMetadata;

    agentMetadata["agent_id"] = agentId;
    agentMetadata["agent_name"] = agentName;
    agentMetadata["agent_version"] = __ossec_version;

    // Extract OS information
    if (osInfo.contains("architecture"))
    {
        agentMetadata["host_architecture"] = osInfo["architecture"];
    }

    if (osInfo.contains("hostname"))
    {
        agentMetadata["host_hostname"] = osInfo["hostname"];
    }

    if (osInfo.contains("os_name"))
    {
        agentMetadata["host_os_name"] = osInfo["os_name"];
    }

    if (osInfo.contains("os_type"))
    {
        agentMetadata["host_os_type"] = osInfo["os_type"];
    }

    if (osInfo.contains("os_platform"))
    {
        agentMetadata["host_os_platform"] = osInfo["os_platform"];
    }

    if (osInfo.contains("os_version"))
    {
        agentMetadata["host_os_version"] = osInfo["os_version"];
    }

    // Get cluster_name from handshake (set by agentd during connection via agent_info_set_cluster_name)
    const char* cluster_name = agent_info_get_cluster_name();

    agentMetadata["cluster_name"] = std::string(cluster_name);


    // Get cluster_node from handshake (set by agentd during connection via agent_info_set_cluster_node)
    const char* cluster_node = agent_info_get_cluster_node();


    agentMetadata["cluster_node"] = std::string(cluster_node);



    // Get agent groups (only for agents)
    // Priority: 1) Groups from handshake, 2) Groups from merged.mg
    std::vector<std::string> groups;

  
    // First, try to get groups from handshake (received from manager)
    const char* handshake_groups = agent_info_get_agent_groups();

    if (handshake_groups && handshake_groups[0] != '\0')
    {
        // Parse CSV groups from handshake
        std::string groups_str(handshake_groups);
        std::istringstream iss(groups_str);
        std::string group;

        while (std::getline(iss, group, ','))
        {
            if (!group.empty())
            {
                groups.push_back(group);
            }
        }

        m_logFunction(LOG_DEBUG, "Using " + std::to_string(groups.size()) + " groups from manager handshake");

        // Clear handshake groups after consuming them
        // Subsequent calls will read from merged.mg
        agent_info_clear_agent_groups();
    }
    else
    {
        // Fall back to reading from merged.mg
        groups = readAgentGroups();
    } 

    // Update the global metadata provider BEFORE updateChanges
    // This ensures the metadata is available when syncProtocol is triggered
    updateMetadataProvider(agentMetadata, groups);

    // Update agent metadata using dbsync to detect changes and emit events
    bool metadataChanged = updateChanges(AGENT_METADATA_TABLE, nlohmann::json::array({agentMetadata}));

    auto logMsg = std::string("Agent metadata populated successfully");
    m_logFunction(LOG_DEBUG, logMsg);

    // Always update agent groups in database (even if empty, to clear old groups)
    auto groupsData = nlohmann::json::array();

    for (const auto& group : groups)
    {
        nlohmann::json groupEntry;
        groupEntry["agent_id"] = agentId;
        groupEntry["group_name"] = group;
        groupsData.push_back(groupEntry);
    }

    // Update agent groups using dbsync to detect changes and emit events
    bool groupsChanged = updateChanges(AGENT_GROUPS_TABLE, groupsData);

    std::string groupLogMsg;

    if (groups.empty())
    {
        groupLogMsg = "Agent groups cleared (no groups found)";
    }
    else
    {
        groupLogMsg = "Agent groups populated successfully: " + std::to_string(groups.size()) + " groups";
    }

    m_logFunction(LOG_DEBUG, groupLogMsg);

    if (metadataChanged)
    {
        setSyncFlag(AGENT_METADATA_TABLE, true);
    }

    if (groupsChanged)
    {
        setSyncFlag(AGENT_GROUPS_TABLE, true);
    }
}

void AgentInfoImpl::updateMetadataProvider(const nlohmann::json& agentMetadata, const std::vector<std::string>& groups)
{
    agent_metadata_t metadata{};

    // Copy string fields safely
    auto copyField = [](char* dest, size_t dest_size, const nlohmann::json & json, const char* field)
    {
        if (json.contains(field) && json[field].is_string())
        {
            std::strncpy(dest, json[field].get<std::string>().c_str(), dest_size - 1);
            dest[dest_size - 1] = '\0';
        }
    };

    copyField(metadata.agent_id, sizeof(metadata.agent_id), agentMetadata, "agent_id");
    copyField(metadata.agent_name, sizeof(metadata.agent_name), agentMetadata, "agent_name");
    copyField(metadata.agent_version, sizeof(metadata.agent_version), agentMetadata, "agent_version");
    copyField(metadata.architecture, sizeof(metadata.architecture), agentMetadata, "host_architecture");
    copyField(metadata.hostname, sizeof(metadata.hostname), agentMetadata, "host_hostname");
    copyField(metadata.os_name, sizeof(metadata.os_name), agentMetadata, "host_os_name");
    copyField(metadata.os_type, sizeof(metadata.os_type), agentMetadata, "host_os_type");
    copyField(metadata.os_platform, sizeof(metadata.os_platform), agentMetadata, "host_os_platform");
    copyField(metadata.os_version, sizeof(metadata.os_version), agentMetadata, "host_os_version");
    copyField(metadata.cluster_name, sizeof(metadata.cluster_name), agentMetadata, "cluster_name");
    copyField(metadata.cluster_node, sizeof(metadata.cluster_node), agentMetadata, "cluster_node");

    // Copy groups
    if (!groups.empty())
    {
        metadata.groups = new char* [groups.size()];
        metadata.groups_count = groups.size();

        for (size_t i = 0; i < groups.size(); ++i)
        {
            const size_t len = groups[i].length();
            metadata.groups[i] = new char[len + 1];
            std::strcpy(metadata.groups[i], groups[i].c_str());
        }
    }

    // Update the provider
    if (metadata_provider_update(&metadata) == 0)
    {
        m_logFunction(LOG_DEBUG, "Successfully updated metadata provider");
    }
    else
    {
        m_logFunction(LOG_WARNING, "Failed to update metadata provider");
    }

    // Free allocated groups
    if (metadata.groups)
    {
        for (size_t i = 0; i < metadata.groups_count; ++i)
        {
            delete[] metadata.groups[i];
        }

        delete[] metadata.groups;
    }
}

bool AgentInfoImpl::readClientKeys(std::string& agentId, std::string& agentName) const
{
    // Check if client.keys file exists
    if (!m_fileSystem->exists(KEYS_FILE))
    {
        m_logFunction(LOG_DEBUG, std::string("File does not exist: ") + KEYS_FILE);
        return false;
    }

    bool found = false;

    // Read the first line of client.keys file
    m_fileIO->readLineByLine(KEYS_FILE,
                             [&](const std::string & line)
    {
        if (!line.empty())
        {
            // client.keys format: ID NAME IP KEY
            // Use stringHelper to split by space
            auto tokens = Utils::split(line, ' ');

            if (tokens.size() >= 2)
            {
                agentId = tokens[0];
                agentName = tokens[1];

                m_logFunction(LOG_DEBUG, "Read agent data from client.keys: ID=" + agentId + ", Name=" + agentName);
                found = true;
                return false; // Stop reading after first line
            }
        }

        return true; // Continue reading if first line was empty
    });

    return found;
}

std::vector<std::string> AgentInfoImpl::readAgentGroups() const
{
    std::vector<std::string> groups;

#ifndef WIN32
    const char* mergedFile = "etc/shared/merged.mg";
#else
    const char* mergedFile = "shared\\merged.mg";
#endif

    // Check if merged.mg file exists
    if (!m_fileSystem->exists(mergedFile))
    {
        m_logFunction(LOG_DEBUG, std::string("File does not exist: ") + mergedFile);
        return groups;
    }

    // merged.mg has two possible formats:
    // 1. Single group: First line is "#groupname" (where groupname is not a hash)
    // 2. Multiple groups: First line is "#hash_id" (8-char hex), groups appear as "<!-- Source file: groupname/agent.conf -->"
    bool isFirstLine = true;
    bool foundXMLComments = false;

    m_fileIO->readLineByLine(mergedFile,
                             [&](const std::string & line)
    {
        std::string trimmedLine = Utils::trim(line);

        // Check first line for group name or hash
        if (isFirstLine)
        {
            isFirstLine = false;

            // First line should start with '#'
            if (!trimmedLine.empty() && trimmedLine[0] == '#')
            {
                std::string firstLineValue = trimmedLine.substr(1); // Remove the '#'
                firstLineValue = Utils::trim(firstLineValue);

                if (!firstLineValue.empty())
                {
                    // Check if this looks like a hash (8 hex characters) or a group name
                    // Hashes are typically 8 characters and all hexadecimal
                    bool looksLikeHash = (firstLineValue.length() == 8);

                    if (looksLikeHash)
                    {
                        for (char c : firstLineValue)
                        {
                            if (!std::isxdigit(c))
                            {
                                looksLikeHash = false;
                                break;
                            }
                        }
                    }

                    if (!looksLikeHash)
                    {
                        // Single-group format: the first line is the actual group name
                        groups.push_back(firstLineValue);
                        return false; // Stop reading, we have the single group
                    }

                    // Otherwise, it's a hash - continue reading to find XML comments
                }

                return true; // Continue to next line
            }

            // If first line doesn't start with '#', continue processing as it might be an XML comment
        }

        // Look for multi-group format: XML comments with "Source file:"
        size_t sourceFilePos = trimmedLine.find("Source file:");

        if (sourceFilePos != std::string::npos && trimmedLine.find("<!--") == 0)
        {
            foundXMLComments = true;

            // Extract the path after "Source file:"
            size_t pathStart = sourceFilePos + 12; // Length of "Source file:"

            // Skip any leading whitespace after "Source file:"
            while (pathStart < trimmedLine.length() && std::isspace(trimmedLine[pathStart]))
            {
                pathStart++;
            }

            auto pathEnd = trimmedLine.find("/agent.conf", pathStart);

            if (pathEnd != std::string::npos && pathEnd > pathStart)
            {
                std::string groupName = trimmedLine.substr(pathStart, pathEnd - pathStart);
                groupName = Utils::trim(groupName);

                if (!groupName.empty())
                {
                    groups.push_back(groupName);
                }
            }
        }

        return true; // Continue reading to find all groups
    });

    if (!groups.empty())
    {
        m_logFunction(LOG_DEBUG, "Read " + std::to_string(groups.size()) + " groups from merged.mg");
    }

    return groups;
}

bool AgentInfoImpl::updateChanges(const std::string& table, const nlohmann::json& values)
{
    bool hasChanges = false;

    const auto callback = [this, table, &hasChanges](ReturnTypeCallback result, const nlohmann::json & data)
    {
        if (result == INSERTED || result == MODIFIED || result == DELETED)
        {
            hasChanges = true;
            processEvent(result, data, table);
        }
    };

    try
    {
        std::lock_guard<std::mutex> lock(m_dbSyncMutex);

        if (!m_dBSync)
        {
            m_logFunction(LOG_WARNING, "DBSync not available for table " + table);
            return false;
        }

        DBSyncTxn txn{m_dBSync->handle(), nlohmann::json{table}, 0, QUEUE_SIZE, callback};

        nlohmann::json input;
        input["table"] = table;
        input["data"] = values;
        input["options"]["return_old_data"] = true;

        txn.syncTxnRow(input);
        txn.getDeletedRows(callback);

        return hasChanges;
    }
    catch (const std::exception& e)
    {
        std::string errorMsg = "Error updating changes for table " + table + ": " + e.what();
        m_logFunction(LOG_ERROR, errorMsg);
        return false;
    }
}

void AgentInfoImpl::processEvent(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table)
{
    try
    {
        nlohmann::json eventData = result == MODIFIED && data.contains("new") ? data["new"] : data;
        nlohmann::json ecsFormattedData = ecsData(eventData, table);

        // Remove checksum from ECS data before sending stateless event
        if (ecsFormattedData.contains("checksum"))
        {
            ecsFormattedData.erase("checksum");
        }

        // Report stateless event
        if (m_reportDiffFunction)
        {
            // Check if stateless event should be generated based on changed fields
            bool shouldGenerateStateless = shouldGenerateStatelessEvent(result, data, table);

            if (shouldGenerateStateless)
            {
                nlohmann::json statelessEvent;
                statelessEvent["module"] = "agent_info";
                statelessEvent["type"] = table;
                statelessEvent["data"] = ecsFormattedData;
                statelessEvent["data"]["event"]["type"] = OPERATION_MAP.at(result);
                statelessEvent["data"]["event"]["created"] = Utils::getCurrentISO8601();

                // Add previous data for MODIFIED events
                if (result == MODIFIED && data.contains("old"))
                {
                    nlohmann::json oldEcsData = ecsData(data["old"], table);
                    // Add changed fields tracking
                    std::vector<std::string> changedFields;

                    for (auto& [key, value] : ecsFormattedData.items())
                    {
                        if (!oldEcsData.contains(key) || oldEcsData[key] != value)
                        {
                            changedFields.push_back(key);
                        }
                    }

                    statelessEvent["data"]["event"]["changed_fields"] = changedFields;
                }

                m_reportDiffFunction(statelessEvent.dump());

                std::string debugMsg = "Event reported for table " + table + ": " + OPERATION_MAP.at(result);
                m_logFunction(LOG_DEBUG_VERBOSE, debugMsg);
            }
        }
    }
    catch (const std::exception& e)
    {
        std::string errorMsg = "Error processing event for table " + table + ": " + e.what();
        m_logFunction(LOG_ERROR, errorMsg);
    }
}

bool AgentInfoImpl::shouldGenerateStatelessEvent(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table) const
{
    // For INSERTED and DELETED events, always generate stateless
    if (result != MODIFIED)
    {
        return true;
    }

    // For MODIFIED events, check if only OS-related fields changed in AGENT_METADATA_TABLE
    if (table == AGENT_METADATA_TABLE && data.contains("old") && data.contains("new"))
    {
        // OS-related fields (reported by Syscollector)
        static const std::set<std::string> OS_RELATED_FIELDS =
        {
            "host_architecture",
            "host_hostname",
            "host_os_name",
            "host_os_type",
            "host_os_platform",
            "host_os_version"
        };

        const nlohmann::json& newData = data["new"];
        const nlohmann::json& oldData = data["old"];

        // Determine which fields changed and if there are non-OS changes
        bool hasChanges = false;
        bool hasNonOsChanges = false;

        for (const auto& [key, value] : newData.items())
        {
            // A field only changed if it exists in oldData and has a different value
            // If a field is not in oldData, it means it didn't change
            if (oldData.contains(key) && oldData[key] != value)
            {
                hasChanges = true;

                // Check if this changed field is NOT an OS field
                if (OS_RELATED_FIELDS.find(key) == OS_RELATED_FIELDS.end())
                {
                    hasNonOsChanges = true;
                    break;
                }
            }
        }

        // If only OS fields changed, don't generate stateless event
        if (hasChanges && !hasNonOsChanges)
        {
            m_logFunction(LOG_INFO, "Skipping stateless event for " + table + ": only OS-related fields changed");
            return false;
        }
    }

    // For all other cases (non-metadata tables, or changes include non-OS fields), generate stateless
    return true;
}

nlohmann::json AgentInfoImpl::ecsData(const nlohmann::json& data, const std::string& table) const
{
    nlohmann::json ecsFormatted;

    if (table == AGENT_METADATA_TABLE)
    {
        // Map agent_metadata fields to ECS format
        if (data.contains("agent_id"))
            ecsFormatted["agent"]["id"] = data["agent_id"];

        if (data.contains("agent_name"))
            ecsFormatted["agent"]["name"] = data["agent_name"];

        if (data.contains("agent_version"))
            ecsFormatted["agent"]["version"] = data["agent_version"];

        if (data.contains("host_architecture"))
            ecsFormatted["host"]["architecture"] = data["host_architecture"];

        if (data.contains("host_hostname"))
            ecsFormatted["host"]["hostname"] = data["host_hostname"];

        if (data.contains("host_os_name"))
            ecsFormatted["host"]["os"]["name"] = data["host_os_name"];

        if (data.contains("host_os_type"))
            ecsFormatted["host"]["os"]["type"] = data["host_os_type"];

        if (data.contains("host_os_platform"))
            ecsFormatted["host"]["os"]["platform"] = data["host_os_platform"];

        if (data.contains("host_os_version"))
            ecsFormatted["host"]["os"]["version"] = data["host_os_version"];

        if (data.contains("checksum"))
            ecsFormatted["checksum"] = data["checksum"];
    }
    else if (table == AGENT_GROUPS_TABLE)
    {
        // Map agent_groups fields to ECS format
        if (data.contains("agent_id"))
            ecsFormatted["agent"]["id"] = data["agent_id"];

        if (data.contains("group_name"))
            ecsFormatted["agent"]["groups"] = nlohmann::json::array({data["group_name"]});
    }

    return ecsFormatted;
}

namespace
{
    /// @brief RAII wrapper for C-style strings allocated with malloc/strdup
    struct CStringDeleter
    {
        void operator()(char* ptr) const
        {
            if (ptr)
            {
                free(ptr);
            }
        }
    };
    using UniqueCString = std::unique_ptr<char, CStringDeleter>;

    /// @brief Parse JSON response and extract error information
    /// @param responseStr Raw JSON response string
    /// @return ModuleResponse with parsed information
    AgentInfoImpl::ModuleResponse parseModuleResponse(const std::string& responseStr)
    {
        AgentInfoImpl::ModuleResponse result;
        result.response = responseStr;
        result.success = false;
        result.errorCode = -1;
        result.isModuleUnavailable = false;

        try
        {
            nlohmann::json responseJson = nlohmann::json::parse(responseStr);

            if (responseJson.contains("error") && responseJson["error"].is_number())
            {
                result.errorCode = responseJson["error"].get<int>();
                result.success = (result.errorCode == 0);
                result.isModuleUnavailable = MQ_IS_MODULE_UNAVAILABLE(result.errorCode);
            }
        }
        catch (const std::exception&)
        {
            // If parsing fails, keep default values
        }

        return result;
    }
}

std::string AgentInfoImpl::createJsonCommand(const std::string& command,
                                             const std::map<std::string, nlohmann::json>& params) const
{
    nlohmann::json jsonCmd;
    jsonCmd["command"] = command;

    // Always include parameters field (even if empty)
    nlohmann::json paramObj = nlohmann::json::object();

    for (const auto& [key, value] : params)
    {
        paramObj[key] = value;
    }

    jsonCmd["parameters"] = paramObj;

    return jsonCmd.dump();
}

AgentInfoImpl::ModuleResponse AgentInfoImpl::queryModuleWithRetry(const std::string& moduleName,
                                                                  const std::string& jsonMessage)
{
    m_logFunction(LOG_DEBUG, "Sending JSON command to " + moduleName + ": " + jsonMessage);

    for (int attempt = 1; attempt <= MAX_COORDINATION_RETRIES; ++attempt)
    {
        char* rawResponse = nullptr;
        int result = m_queryModuleFunction(moduleName, jsonMessage, &rawResponse);

        // Use RAII to manage C string memory
        UniqueCString response(rawResponse);

        // If no response received, create structured error JSON
        std::string responseStr;

        if (response)
        {
            responseStr = std::string(response.get());
        }
        else
        {
            // Create structured error response for null pointer
            nlohmann::json errorJson;
            errorJson["error"] = MQ_ERR_INTERNAL;
            errorJson["message"] = "No response received from module query function";
            responseStr = errorJson.dump();
        }

        // Parse response using helper function
        ModuleResponse moduleResp = parseModuleResponse(responseStr);

        // If query succeeded (error code 0), return immediately
        if (result == 0 && moduleResp.success)
        {
            m_logFunction(LOG_DEBUG, moduleName + " query succeeded");
            return moduleResp;
        }

        // If module is unavailable (disabled/not found/not running), return immediately without retrying
        if (moduleResp.isModuleUnavailable)
        {
            m_logFunction(LOG_DEBUG, moduleName + " module is unavailable (error " +
                          std::to_string(moduleResp.errorCode) + "): " + responseStr);
            return moduleResp;
        }

        // For other errors, log and retry
        m_logFunction(LOG_DEBUG, "Attempt " + std::to_string(attempt) + "/" + std::to_string(MAX_COORDINATION_RETRIES) +
                      " failed for " + moduleName + " (error " + std::to_string(moduleResp.errorCode) + "): " + responseStr);

        if (attempt < MAX_COORDINATION_RETRIES)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(COORDINATION_RETRY_DELAY_MS));
        }
    }

    m_logFunction(LOG_WARNING, "Failed to query " + moduleName + " after " + std::to_string(MAX_COORDINATION_RETRIES) + " attempts");

    // Return failure response with structured error JSON
    nlohmann::json errorJson;
    errorJson["error"] = MQ_ERR_INTERNAL;
    errorJson["message"] = "Max retries exceeded (" + std::to_string(MAX_COORDINATION_RETRIES) + " attempts)";

    ModuleResponse failedResp;
    failedResp.success = false;
    failedResp.response = errorJson.dump();
    failedResp.errorCode = MQ_ERR_INTERNAL;
    failedResp.isModuleUnavailable = false;
    return failedResp;
}

void AgentInfoImpl::resumePausedModules(const std::set<std::string>& pausedModules)
{
    for (const auto& module : pausedModules)
    {
        m_logFunction(LOG_INFO, "Resuming paused module: " + module);
        std::string resumeMessage = createJsonCommand("resume");
        ModuleResponse response = queryModuleWithRetry(module, resumeMessage);
        m_logFunction(LOG_DEBUG, "Response from " + module + " resume: " + response.response);

        if (!response.success)
        {
            m_logFunction(LOG_ERROR, "Failed to resume module " + module + ": " + response.response);
        }
    }
}

bool AgentInfoImpl::pollFimPauseCompletion(const std::string& moduleName)
{
    constexpr int MAX_PAUSE_POLL_ATTEMPTS = 30;  // 30 seconds max wait
    constexpr int PAUSE_POLL_DELAY_MS = 1000;    // 1 second between polls

    m_logFunction(LOG_DEBUG_VERBOSE, "Polling " + moduleName + " for pause completion (async pause)");

    for (int attempt = 1; attempt <= MAX_PAUSE_POLL_ATTEMPTS; ++attempt)
    {
        std::string isPauseCompletedMessage = createJsonCommand("is_pause_completed");
        ModuleResponse pollResponse = queryModuleWithRetry(moduleName, isPauseCompletedMessage);

        if (!pollResponse.success)
        {
            m_logFunction(LOG_WARNING, "Failed to poll pause status for " + moduleName + " (attempt " +
                          std::to_string(attempt) + "/" + std::to_string(MAX_PAUSE_POLL_ATTEMPTS) + ")");
            std::this_thread::sleep_for(std::chrono::milliseconds(PAUSE_POLL_DELAY_MS));
            continue;
        }

        // Parse response to check pause status
        try
        {
            nlohmann::json pollJson = nlohmann::json::parse(pollResponse.response);

            if (pollJson.contains("data") && pollJson["data"].contains("status"))
            {
                std::string status = pollJson["data"]["status"].get<std::string>();

                if (status == "in_progress")
                {
                    m_logFunction(LOG_DEBUG, moduleName + " pause still in progress (attempt " +
                                  std::to_string(attempt) + "/" + std::to_string(MAX_PAUSE_POLL_ATTEMPTS) + ")");
                    std::this_thread::sleep_for(std::chrono::milliseconds(PAUSE_POLL_DELAY_MS));
                    continue;
                }
                else if (status == "completed")
                {
                    std::string result = pollJson["data"]["result"].get<std::string>();
                    bool pauseSucceeded = (result == "success");

                    if (!pauseSucceeded)
                    {
                        m_logFunction(LOG_ERROR, moduleName + " pause completed with error");
                        return false;
                    }

                    m_logFunction(LOG_INFO, moduleName + " pause completed successfully");
                    return true;
                }
            }
        }
        catch (const std::exception& e)
        {
            m_logFunction(LOG_WARNING, "Failed to parse pause poll response from " + moduleName + ": " +
                          std::string(e.what()) + " - Response: " + pollResponse.response);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(PAUSE_POLL_DELAY_MS));
    }

    m_logFunction(LOG_ERROR, moduleName + " pause did not complete within timeout (" +
                  std::to_string(MAX_PAUSE_POLL_ATTEMPTS) + " seconds)");
    return false;
}

bool AgentInfoImpl::pollFimFlushCompletion(const std::string& moduleName)
{
    constexpr int FLUSH_POLL_DELAY_MS = 10000;            // 10 seconds between polls
    constexpr int LOG_PROGRESS_EVERY_N_ATTEMPTS = 6;     // Log progress every 60 seconds (6 * 10s)
    int attempt = 0;

    m_logFunction(LOG_DEBUG_VERBOSE, "Polling " + moduleName + " for flush completion (async flush)");

    // Poll until flush completes or module is stopped
    while (!m_stopped)
    {
        attempt++;
        std::string isFlushCompletedMessage = createJsonCommand("is_flush_completed");
        ModuleResponse pollResponse = queryModuleWithRetry(moduleName, isFlushCompletedMessage);

        if (!pollResponse.success)
        {
            m_logFunction(LOG_WARNING, "Failed to poll flush status for " + moduleName + " (attempt " +
                          std::to_string(attempt) + "), will retry...");
            std::this_thread::sleep_for(std::chrono::milliseconds(FLUSH_POLL_DELAY_MS));
            continue;
        }

        // Parse response to check flush status
        try
        {
            nlohmann::json pollJson = nlohmann::json::parse(pollResponse.response);

            if (pollJson.contains("data") && pollJson["data"].contains("status"))
            {
                std::string status = pollJson["data"]["status"].get<std::string>();

                if (status == "in_progress")
                {
                    // Log progress periodically to show we're still waiting
                    if (attempt % LOG_PROGRESS_EVERY_N_ATTEMPTS == 0)
                    {
                        m_logFunction(LOG_INFO, "Waiting for " + moduleName + " module to complete synchronization (" +
                                      std::to_string(attempt * FLUSH_POLL_DELAY_MS / 1000) + " seconds elapsed)");
                    }
                    else
                    {
                        m_logFunction(LOG_DEBUG, moduleName + " flush still in progress (attempt " +
                                      std::to_string(attempt) + ")");
                    }
                }
                else if (status == "completed")
                {
                    std::string result = pollJson["data"]["result"].get<std::string>();
                    bool flushSucceeded = (result == "success");

                    m_logFunction(LOG_INFO, moduleName + " pending operations completed with result: " + result +
                                  " (took " + std::to_string(attempt * FLUSH_POLL_DELAY_MS / 1000) + " seconds)");

                    if (!flushSucceeded)
                    {
                        m_logFunction(LOG_ERROR, moduleName + " flush completed with error");
                        return false;
                    }

                    return true;
                }
            }
        }
        catch (const std::exception& e)
        {
            m_logFunction(LOG_WARNING, "Failed to parse flush poll response from " + moduleName + ": " +
                          std::string(e.what()) + " - Response: " + pollResponse.response);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(FLUSH_POLL_DELAY_MS));
    }

    // Check if we exited due to module stopping
    m_logFunction(LOG_INFO, "Module stopping, aborting pending operations polling for " + moduleName);
    return false;
}

bool AgentInfoImpl::pauseCoordinationModules(std::set<std::string>& pausedModules)
{
    for (const auto& module : COORDINATION_MODULES)
    {
        if (m_stopped)
        {
            m_logFunction(LOG_INFO, "Agent stopping, aborting module coordination during pause phase");
            return false;
        }

        m_logFunction(LOG_INFO, "Pausing " + module + " module for synchronization coordination");

        std::string pauseMessage = createJsonCommand("pause");
        ModuleResponse response = queryModuleWithRetry(module, pauseMessage);
        m_logFunction(LOG_DEBUG, "Response from " + module + " pause: " + response.response);

        if (response.success)
        {
            // FIM-specific: Poll for pause completion (pause is async for FIM)
            if (module == FIM_NAME)
            {
                if (!pollFimPauseCompletion(module))
                {
                    m_logFunction(LOG_ERROR, module + " pause failed or timed out, aborting coordination");
                    resumePausedModules(pausedModules);
                    return false;
                }
            }
            else
            {
                // Other modules: pause is synchronous, already completed
                m_logFunction(LOG_DEBUG, "Successfully paused " + module);
            }

            pausedModules.insert(module);
        }
        else
        {
            // Distinguish between "module unavailable" and "communication error"
            if (response.isModuleUnavailable)
            {
                // Module is disabled/not found/not running - skip it (not an error)
                m_logFunction(LOG_DEBUG, "Skipping " + module + " (unavailable, error " +
                              std::to_string(response.errorCode) + "): " + response.response);
            }
            else
            {
                // Communication error or other failure - abort coordination
                m_logFunction(LOG_WARNING, "Failed to pause " + module + " (communication error " +
                              std::to_string(response.errorCode) + "), aborting coordination: " + response.response);
                resumePausedModules(pausedModules);
                return false;
            }
        }
    }

    // Return true even if pausedModules is empty - this means all modules are unavailable,
    // which is a valid state (not an error)
    return true;
}

bool AgentInfoImpl::flushPausedModules(const std::set<std::string>& pausedModules)
{
    for (const auto& module : pausedModules)
    {
        if (m_stopped)
        {
            m_logFunction(LOG_INFO, "Agent stopping, aborting module coordination during pending operations phase");
            return false;
        }

        m_logFunction(LOG_INFO, "Waiting for " + module + " module to complete synchronization");

        std::string flushMessage = createJsonCommand("flush");
        ModuleResponse response = queryModuleWithRetry(module, flushMessage);
        m_logFunction(LOG_DEBUG, "Response from " + module + " flush: " + response.response);

        if (!response.success)
        {
            m_logFunction(LOG_ERROR, "Failed to flush " + module + " (error " +
                          std::to_string(response.errorCode) + "), aborting coordination");
            return false;
        }

        m_logFunction(LOG_DEBUG, "Successfully requested flush for " + module);

        // FIM-specific: Poll for flush completion (flush is async for FIM)
        if (module == FIM_NAME)
        {
            if (!pollFimFlushCompletion(module))
            {
                m_logFunction(LOG_ERROR, module + " flush failed, timed out, or module stopped");
                return false;
            }
        }
        else
        {
            // Other modules: flush is synchronous, already completed
            m_logFunction(LOG_DEBUG, "Successfully flushed " + module);
        }
    }

    return true;
}

int AgentInfoImpl::calculateNewVersion(const std::set<std::string>& pausedModules,
                                       bool incrementVersion,
                                       std::map<std::string, int>& moduleVersions)
{
    int globalMaxVersion = 0;

    // Step 1: Get version from each module
    for (const auto& module : pausedModules)
    {
        if (m_stopped)
        {
            m_logFunction(LOG_INFO, "Agent stopping, aborting module coordination during version calculation");
            return -1;
        }

        std::string getVersionMessage = createJsonCommand("get_version");
        ModuleResponse response = queryModuleWithRetry(module, getVersionMessage);
        m_logFunction(LOG_DEBUG, "Response from " + module + " get_version: " + response.response);

        if (!response.success)
        {
            m_logFunction(LOG_ERROR, "Failed to get version from " + module + " (error " +
                          std::to_string(response.errorCode) + "), aborting coordination");
            return -1;
        }

        // Parse version from JSON format
        int version = 0;

        try
        {
            nlohmann::json responseJson = nlohmann::json::parse(response.response);

            if (responseJson.contains("data") && responseJson["data"].contains("version") &&
                    responseJson["data"]["version"].is_number())
            {
                version = responseJson["data"]["version"].get<int>();
            }
            else
            {
                m_logFunction(LOG_WARNING, "Invalid JSON response format from " + module + ": missing or invalid version data");
                return -1;
            }
        }
        catch (const std::exception& e)
        {
            m_logFunction(LOG_ERROR, "Failed to parse JSON response from " + module + ": " +
                          std::string(e.what()) + " - Response: " + response.response);
            return -1;
        }

        moduleVersions[module] = version;
        globalMaxVersion = std::max(globalMaxVersion, version);
        m_logFunction(LOG_DEBUG, module + " current version: " + std::to_string(version));
    }

    // Step 2: Calculate new version
    // If incrementVersion is true (metadata update): newVersion = max + 1
    // If incrementVersion is false (groups update): newVersion = max
    int newVersion = incrementVersion ? (globalMaxVersion + 1) : globalMaxVersion;
    m_logFunction(LOG_DEBUG, "Calculated new global version: " + std::to_string(newVersion) +
                  (incrementVersion ? " (max + 1 for metadata update)" : " (max for groups update)"));

    // Step 3: Set new version on all modules
    for (const auto& module : pausedModules)
    {
        if (m_stopped)
        {
            m_logFunction(LOG_INFO, "Agent stopping, aborting module coordination during version update");
            return -1;
        }

        std::string setVersionMessage = createJsonCommand("set_version", {{"version", newVersion}});
        ModuleResponse response = queryModuleWithRetry(module, setVersionMessage);
        m_logFunction(LOG_DEBUG, "Response from " + module + " set_version: " + response.response);

        if (!response.success)
        {
            m_logFunction(LOG_WARNING, "Failed to set version on " + module + " (error " +
                          std::to_string(response.errorCode) + "), aborting coordination");
            return -1;
        }

        m_logFunction(LOG_DEBUG, "Successfully set version " + std::to_string(newVersion) + " on " + module);
    }

    return newVersion;
}

bool AgentInfoImpl::coordinateModules(const std::string& table)
{
    // Check if query function is available
    if (!m_queryModuleFunction)
    {
        m_logFunction(LOG_WARNING, "Module query function not available, skipping coordination");
        return false;
    }

    // Determine if we should increment version based on table
    // AGENT_METADATA_TABLE -> increment (max + 1)
    // AGENT_GROUPS_TABLE -> keep max (no increment)
    bool incrementVersion = (table == AGENT_METADATA_TABLE);

    // State tracking
    std::set<std::string> pausedModules;
    std::map<std::string, int> moduleVersions;

    m_logFunction(LOG_INFO, "Starting module coordination process");

    try
    {
        // Step 1: Pause all coordination modules
        if (!pauseCoordinationModules(pausedModules))
        {
            return false;
        }

        if (pausedModules.empty())
        {
            m_logFunction(LOG_DEBUG, "No modules available for coordination, skipping synchronization");
            return true;
        }

        // Step 2: Flush all paused modules
        if (!flushPausedModules(pausedModules))
        {
            resumePausedModules(pausedModules);
            return false;
        }

        // Step 3: Get versions, calculate new version, and set it on all modules
        int newVersion = calculateNewVersion(pausedModules, incrementVersion, moduleVersions);

        if (newVersion < 0)
        {
            resumePausedModules(pausedModules);
            return false;
        }

        // Step 4: Build indices list based on enabled modules and synchronize
        std::vector<std::string> indicesToSync;

        for (const auto& module : pausedModules)
        {
            auto it = MODULE_INDICES_MAP.find(module);

            if (it != MODULE_INDICES_MAP.end())
            {
                const auto& moduleIndices = it->second;
                indicesToSync.insert(indicesToSync.end(), moduleIndices.begin(), moduleIndices.end());
            }
        }

        if (m_spSyncProtocol)
        {
            bool syncSuccess = m_spSyncProtocol->synchronizeMetadataOrGroups(
                                   TABLE_DELTA_MODE_MAP.at(table),
                                   indicesToSync,
                                   newVersion);

            if (!syncSuccess)
            {
                m_logFunction(LOG_WARNING, "Failed to synchronize " + table);
                resumePausedModules(pausedModules);
                return false;
            }

            m_logFunction(LOG_DEBUG, "Successfully synchronized " + table);
        }
        else
        {
            m_logFunction(LOG_WARNING, "Sync protocol not available, skipping synchronization");
        }

        // Step 5: Resume all modules
        size_t coordinatedModulesCount = pausedModules.size();
        resumePausedModules(pausedModules);

        m_logFunction(LOG_INFO, "Synchronization coordination completed successfully");
        m_logFunction(LOG_DEBUG, "Coordinated modules: " + std::to_string(coordinatedModulesCount) +
                      ", New version: " + std::to_string(newVersion));

        return true;
    }
    catch (const std::exception& e)
    {
        m_logFunction(LOG_ERROR, "Exception during module coordination: " + std::string(e.what()));
        resumePausedModules(pausedModules);
        return false;
    }
    catch (...)
    {
        m_logFunction(LOG_ERROR, "Unknown exception during module coordination");
        resumePausedModules(pausedModules);
        return false;
    }
}

void AgentInfoImpl::updateDbMetadata()
{
    try
    {
        // Lock m_dbSyncMutex to prevent race condition with stop()
        std::lock_guard<std::mutex> lock(m_dbSyncMutex);

        if (!m_dBSync)
        {
            return;
        }

        auto handle = m_dBSync->handle();

        if (!handle)
        {
            return;
        }

        auto callback = [](ReturnTypeCallback, const nlohmann::json&) {};
        DBSyncTxn txn{handle, nlohmann::json{"db_metadata"}, 0, QUEUE_SIZE, callback};

        nlohmann::json rowData;
        rowData["id"] = 1;
        rowData["should_sync_metadata"] = m_shouldSyncMetadata ? 1 : 0;
        rowData["should_sync_groups"] = m_shouldSyncGroups ? 1 : 0;
        rowData["last_metadata_integrity"] = m_lastMetadataIntegrity;
        rowData["last_groups_integrity"] = m_lastGroupsIntegrity;
        rowData["is_first_run"] = m_isFirstRun ? 1 : 0;
        rowData["is_first_groups_run"] = m_isFirstGroupsRun ? 1 : 0;

        nlohmann::json input;
        input["table"] = "db_metadata";
        input["data"] = nlohmann::json::array({rowData});

        txn.syncTxnRow(input);
        txn.getDeletedRows(callback);
    }
    catch (const std::exception& e)
    {
        m_logFunction(LOG_ERROR, "Failed to update db_metadata: " + std::string(e.what()));
    }
}

void AgentInfoImpl::setSyncFlag(const std::string& table, bool value)
{
    try
    {
        std::lock_guard<std::mutex> lock(m_syncFlagsMutex);

        // Check m_dBSync availability within a separate scope
        {
            std::lock_guard<std::mutex> dbLock(m_dbSyncMutex);

            if (!m_dBSync)
            {
                m_logFunction(LOG_WARNING, "Cannot set sync flag: DBSync not available");
                return;
            }
        }

        // Update in-memory flag
        if (table == AGENT_METADATA_TABLE)
        {
            m_shouldSyncMetadata = value;
        }
        else if (table == AGENT_GROUPS_TABLE)
        {
            m_shouldSyncGroups = value;
        }

        updateDbMetadata();
        m_logFunction(LOG_DEBUG, "Set sync flag for " + table + " to " + std::to_string(value));
    }
    catch (const std::exception& e)
    {
        m_logFunction(LOG_ERROR, "Failed to set sync flag for " + table + ": " + std::string(e.what()));
    }
}

void AgentInfoImpl::loadSyncFlags()
{
    try
    {
        std::lock_guard<std::mutex> lock(m_syncFlagsMutex);

        // Capture shared_ptr with mutex protection
        std::shared_ptr<IDBSync> dbSync;
        {
            std::lock_guard<std::mutex> dbLock(m_dbSyncMutex);

            if (!m_dBSync)
            {
                m_logFunction(LOG_WARNING, "Cannot load sync flags: DBSync not available");
                return;
            }

            dbSync = m_dBSync;
        }

        bool rowFound = false;

        // Query the db_metadata table
        auto callback = [this, &rowFound](ReturnTypeCallback, const nlohmann::json & data)
        {
            rowFound = true;

            if (data.contains("should_sync_metadata") && data["should_sync_metadata"].is_number())
            {
                m_shouldSyncMetadata = (data["should_sync_metadata"].get<int>() != 0);
            }

            if (data.contains("should_sync_groups") && data["should_sync_groups"].is_number())
            {
                m_shouldSyncGroups = (data["should_sync_groups"].get<int>() != 0);
            }

            if (data.contains("last_metadata_integrity") && data["last_metadata_integrity"].is_number())
            {
                m_lastMetadataIntegrity = data["last_metadata_integrity"].get<int64_t>();
            }

            if (data.contains("last_groups_integrity") && data["last_groups_integrity"].is_number())
            {
                m_lastGroupsIntegrity = data["last_groups_integrity"].get<int64_t>();
            }

            if (data.contains("is_first_run") && data["is_first_run"].is_number())
            {
                m_isFirstRun = (data["is_first_run"].get<int>() != 0);
            }

            if (data.contains("is_first_groups_run") && data["is_first_groups_run"].is_number())
            {
                m_isFirstGroupsRun = (data["is_first_groups_run"].get<int>() != 0);
            }
        };

        // Build JSON for selectRows
        nlohmann::json input;
        input["table"] = "db_metadata";
        input["query"]["column_list"] = nlohmann::json::array({"*"});
        input["query"]["row_filter"] = "";
        input["query"]["distinct_opt"] = false;
        input["query"]["order_by_opt"] = "";
        input["query"]["count_opt"] = 100;

        // Try to select from db_metadata
        dbSync->selectRows(input, callback);

        // If no row was found, this is the first run
        if (!rowFound)
        {
            m_logFunction(LOG_DEBUG, "First run detected: db_metadata table is empty");
            m_isFirstRun = true;
            m_isFirstGroupsRun = true;
        }

    }
    catch (const std::exception& e)
    {
        m_logFunction(LOG_WARNING, "Failed to load sync flags (may be first run): " + std::string(e.what()));
        // Initialize with defaults if table doesn't exist yet
        m_shouldSyncMetadata = false;
        m_shouldSyncGroups = false;
        m_isFirstRun = true;
        m_isFirstGroupsRun = true;
    }
}

void AgentInfoImpl::resetSyncFlag(const std::string& table)
{
    try
    {
        std::lock_guard<std::mutex> lock(m_syncFlagsMutex);

        // Check m_dBSync availability within a separate scope
        {
            std::lock_guard<std::mutex> dbLock(m_dbSyncMutex);

            if (!m_dBSync)
            {
                m_logFunction(LOG_WARNING, "Cannot reset sync flag: DBSync not available");
                return;
            }
        }

        // Determine which flag to reset
        if (table == AGENT_METADATA_TABLE)
        {
            m_isFirstRun = false;
            m_shouldSyncMetadata = false;
        }
        else if (table == AGENT_GROUPS_TABLE)
        {
            m_isFirstGroupsRun = false;
            m_shouldSyncGroups = false;
        }
        else
        {
            m_logFunction(LOG_WARNING, "Unknown table for sync flag reset: " + table);
            return;
        }

        m_logFunction(LOG_DEBUG, "Resetting sync flag for " + table + " to false in database. m_shouldSyncMetadata=" +
                      std::to_string(m_shouldSyncMetadata) + ", m_shouldSyncGroups=" +
                      std::to_string(m_shouldSyncGroups));

        updateDbMetadata();
        m_logFunction(LOG_DEBUG, "Reset sync flag for " + table);
    }
    catch (const std::exception& e)
    {
        m_logFunction(LOG_ERROR, "Failed to reset sync flag for " + table + ": " + std::string(e.what()));
    }
}

bool AgentInfoImpl::shouldPerformIntegrityCheck(const std::string& table, int integrityInterval)
{
    std::unique_lock<std::mutex> lock(m_syncFlagsMutex);

    // Get current time in seconds since epoch
    auto now = std::chrono::system_clock::now();
    auto nowSeconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

    int64_t lastCheck = 0;

    if (table == AGENT_METADATA_TABLE)
    {
        lastCheck = m_lastMetadataIntegrity;
    }
    else if (table == AGENT_GROUPS_TABLE)
    {
        lastCheck = m_lastGroupsIntegrity;
    }
    else
    {
        m_logFunction(LOG_WARNING, "Unknown table for integrity check: " + table);
        return false;
    }

    // If never checked before (lastCheck == 0), initialize timestamp and don't run check yet
    // This enables integrity checks to run after the configured interval
    if (lastCheck == 0)
    {
        // Release lock before calling updateLastIntegrityTime to avoid deadlock
        lock.unlock();
        updateLastIntegrityTime(table);
        m_logFunction(LOG_INFO, "Initialized integrity check timestamp for " + table);
        return false;
    }

    // Check if enough time has elapsed since last integrity check
    return (nowSeconds - lastCheck) >= integrityInterval;
}

void AgentInfoImpl::updateLastIntegrityTime(const std::string& table)
{
    try
    {
        std::lock_guard<std::mutex> lock(m_syncFlagsMutex);

        // Check m_dBSync availability within a separate scope
        {
            std::lock_guard<std::mutex> dbLock(m_dbSyncMutex);

            if (!m_dBSync)
            {
                m_logFunction(LOG_WARNING, "Cannot update last integrity time: DBSync not available");
                return;
            }
        }

        // Get current time in seconds since epoch
        auto now = std::chrono::system_clock::now();
        auto nowSeconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

        // Update in-memory timestamp
        if (table == AGENT_METADATA_TABLE)
        {
            m_lastMetadataIntegrity = nowSeconds;
        }
        else if (table == AGENT_GROUPS_TABLE)
        {
            m_lastGroupsIntegrity = nowSeconds;
        }
        else
        {
            m_logFunction(LOG_WARNING, "Unknown table for integrity time update: " + table);
            return;
        }

        updateDbMetadata();
        m_logFunction(LOG_INFO, "Updated last integrity check time for " + table);
    }
    catch (const std::exception& e)
    {
        m_logFunction(LOG_ERROR, "Failed to update last integrity time for " + table + ": " + std::string(e.what()));
    }
}

bool AgentInfoImpl::performDeltaSync(const std::string& table)
{
    // Check if module is stopping or DB unavailable
    {
        std::lock_guard<std::mutex> lock(m_dbSyncMutex);

        if (!m_dBSync || m_stopped)
        {
            m_logFunction(LOG_DEBUG, "Skipping delta sync for " + table + " (module stopping or DB unavailable)");
            return false;
        }
    }

    try
    {
        m_logFunction(LOG_DEBUG, "Synchronization needed for " + table);
        bool success = coordinateModules(table);

        if (success)
        {
            m_logFunction(LOG_INFO, "Successfully coordinated " + table);
            resetSyncFlag(table);
        }
        else
        {
            m_logFunction(LOG_WARNING, "Failed to coordinate " + table + ", will retry in next cycle");
        }

        return success;
    }
    catch (const std::exception& e)
    {
        m_logFunction(LOG_ERROR, std::string("Exception during ") + table + " coordination: " + e.what());
        return false;
    }
}

bool AgentInfoImpl::performIntegritySync(const std::string& table)
{
    // Check if module is stopping or DB unavailable
    {
        std::lock_guard<std::mutex> lock(m_dbSyncMutex);

        if (!m_dBSync || m_stopped)
        {
            m_logFunction(LOG_DEBUG, "Skipping integrity sync for " + table + " (module stopping or DB unavailable)");
            return false;
        }
    }

    try
    {
        m_logFunction(LOG_INFO, "Starting integrity check for " + table);

        if (!m_spSyncProtocol)
        {
            m_logFunction(LOG_WARNING, "Sync protocol not available, skipping integrity check");
            return false;
        }

        // Build indices list for all modules
        // We check all indices regardless of module availability since integrity check is lightweight
        std::vector<std::string> indicesToCheck;

        for (const auto& [module, indices] : MODULE_INDICES_MAP)
        {
            indicesToCheck.insert(indicesToCheck.end(), indices.begin(), indices.end());
        }

        // Perform integrity check - no globalVersion needed for CHECK modes
        bool success = m_spSyncProtocol->synchronizeMetadataOrGroups(
                           TABLE_CHECK_MODE_MAP.at(table),
                           indicesToCheck);

        // Update the last sync time regardless of the synchronization result
        // This ensures we always wait for integrity_interval before trying again
        updateLastIntegrityTime(table);

        if (success)
        {
            m_logFunction(LOG_INFO, "Successfully completed integrity check for " + table);
        }
        else
        {
            m_logFunction(LOG_WARNING, "Failed integrity check for " + table);
        }

        return success;
    }
    catch (const std::exception& e)
    {
        m_logFunction(LOG_ERROR, std::string("Exception during integrity check for ") + table + ": " + e.what());
        return false;
    }
}
