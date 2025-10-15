#include "agent_info_impl.hpp"

#include "agent_sync_protocol.hpp"
#include "defs.h"
#include "hashHelper.h"
#include "stringHelper.h"
#include "timeHelper.h"

#include <dbsync.hpp>
#include <file_io_utils.hpp>
#include <filesystem_wrapper.hpp>
#include <sysInfo.hpp>

#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <thread>

constexpr auto QUEUE_SIZE = 4096;
constexpr auto AGENT_METADATA_TABLE = "agent_metadata";
constexpr auto AGENT_GROUPS_TABLE = "agent_groups";

// Map DBSync callback results to operation strings for stateless events
static const std::map<ReturnTypeCallback, std::string> OPERATION_MAP
{
    {MODIFIED, "modified"},
    {DELETED, "deleted"},
    {INSERTED, "created"},
};

// Map tables to their synchronization modes
static const std::map<std::string, Mode> TABLE_MODE_MAP
{
    {AGENT_METADATA_TABLE, Mode::METADATA_DELTA},
    {AGENT_GROUPS_TABLE, Mode::GROUP_DELTA},
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
    "checksum          TEXT NOT NULL);";

const char* AGENT_GROUPS_SQL_STATEMENT =
    "CREATE TABLE IF NOT EXISTS agent_groups ("
    "agent_id          TEXT NOT NULL,"
    "group_name        TEXT NOT NULL,"
    "PRIMARY KEY (agent_id, group_name),"
    "FOREIGN KEY (agent_id) REFERENCES agent_metadata(agent_id) ON DELETE CASCADE);";

AgentInfoImpl::AgentInfoImpl(std::string dbPath,
                             std::function<void(const std::string&)> reportDiffFunction,
                             std::function<void(const modules_log_level_t, const std::string&)> logFunction,
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
{
    if (!m_logFunction)
    {
        throw std::invalid_argument("Log function must be provided");
    }

    m_logFunction(LOG_INFO, "AgentInfo initialized.");
}

AgentInfoImpl::~AgentInfoImpl()
{
    stop();
    m_logFunction(LOG_INFO, "AgentInfo destroyed.");
}

void AgentInfoImpl::setIsAgent(bool isAgent)
{
    m_isAgent = isAgent;
}

void AgentInfoImpl::start(int interval, std::function<bool()> shouldContinue)
{
    m_logFunction(LOG_INFO, "AgentInfo module started with interval: " + std::to_string(interval) + " seconds.");

    std::unique_lock<std::mutex> lock(m_mutex);
    m_stopped = false;

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
    m_logFunction(LOG_INFO, "AgentInfo module stopped.");
}

void AgentInfoImpl::initSyncProtocol(const std::string& moduleName,
                                     const std::string& syncDbPath,
                                     const MQ_Functions& mqFuncs)
{
    auto logger_func = [this](modules_log_level_t level, const std::string & msg)
    {
        m_logFunction(level, msg);
    };

    m_spSyncProtocol = std::make_unique<AgentSyncProtocol>(moduleName, syncDbPath, mqFuncs, logger_func, nullptr);

    m_logFunction(LOG_INFO, "Agent-info sync protocol initialized with database: " + syncDbPath);
}

void AgentInfoImpl::setSyncParameters(uint32_t timeout, uint32_t retries, long maxEps)
{
    m_syncResponseTimeout = timeout;
    m_syncRetries = retries;
    m_syncMaxEps = maxEps;

    m_logFunction(LOG_DEBUG,
                  "Sync parameters set: timeout=" + std::to_string(timeout) + "s, retries=" +
                  std::to_string(retries) + ", maxEps=" + std::to_string(maxEps));
}

std::string AgentInfoImpl::GetCreateStatement() const
{
    std::string ret;
    ret += AGENT_METADATA_SQL_STATEMENT;
    ret += AGENT_GROUPS_SQL_STATEMENT;
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

    if (m_isAgent)
    {
        // For agents, read from client.keys
        if (!readClientKeys(agentId, agentName))
        {
            m_logFunction(LOG_WARNING, "Failed to read agent ID and name from client.keys");
        }
    }
    else
    {
        // For server/manager, use default values
        agentId = "000";

        if (osInfo.contains("hostname"))
        {
            agentName = osInfo["hostname"];
        }

        m_logFunction(LOG_DEBUG, "Using default server/manager agent data: ID=000, Name=" + agentName);
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

    // Calculate checksum
    agentMetadata["checksum"] = calculateMetadataChecksum(agentMetadata);

    // Update agent metadata using dbsync to detect changes and emit events
    updateChanges(AGENT_METADATA_TABLE, nlohmann::json::array({agentMetadata}));

    auto logMsg = std::string("Agent metadata populated successfully");
    m_logFunction(LOG_INFO, logMsg);

    // Read agent groups from merged.mg (only for agents)
    std::vector<std::string> groups;

    if (m_isAgent)
    {
        groups = readAgentGroups();
    }

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
    updateChanges(AGENT_GROUPS_TABLE, groupsData);

    std::string groupLogMsg;

    if (groups.empty())
    {
        groupLogMsg = "Agent groups cleared (no groups found)";
    }
    else
    {
        groupLogMsg = "Agent groups populated successfully: " + std::to_string(groups.size()) + " groups";
    }

    m_logFunction(LOG_INFO, groupLogMsg);
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

    // Look for group names in XML comments in merged.mg
    // Format: <!-- Source file: groupname/agent.conf --> or <!--Source file: groupname/agent.conf-->
    m_fileIO->readLineByLine(mergedFile,
                             [&](const std::string & line)
    {
        // Look for XML comment with "Source file:" (with or without space after <!--)
        std::string trimmedLine = Utils::trim(line);
        size_t sourceFilePos = trimmedLine.find("Source file:");

        if (sourceFilePos != std::string::npos && trimmedLine.find("<!--") == 0)
        {
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

void AgentInfoImpl::updateChanges(const std::string& table, const nlohmann::json& values)
{
    const auto callback = [this, table](ReturnTypeCallback result, const nlohmann::json & data)
    {
        if (result == INSERTED || result == MODIFIED || result == DELETED)
        {
            processEvent(result, data, table);
        }
    };

    try
    {
        DBSyncTxn txn{m_dBSync->handle(), nlohmann::json{table}, 0, QUEUE_SIZE, callback};

        nlohmann::json input;
        input["table"] = table;
        input["data"] = values;
        input["options"]["return_old_data"] = true;

        txn.syncTxnRow(input);
        txn.getDeletedRows(callback);
    }
    catch (const std::exception& e)
    {
        std::string errorMsg = "Error updating changes for table " + table + ": " + e.what();
        m_logFunction(LOG_ERROR, errorMsg);
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

            if (m_spSyncProtocol)
            {
                m_spSyncProtocol->synchronizeMetadataOrGroups(
                    TABLE_MODE_MAP.at(table),
                    std::chrono::seconds(m_syncResponseTimeout),
                    m_syncRetries,
                    m_syncMaxEps);
            }

            std::string debugMsg = "Event reported for table " + table + ": " + OPERATION_MAP.at(result);
            m_logFunction(LOG_DEBUG_VERBOSE, debugMsg);
        }
    }
    catch (const std::exception& e)
    {
        std::string errorMsg = "Error processing event for table " + table + ": " + e.what();
        m_logFunction(LOG_ERROR, errorMsg);
    }
}

std::string AgentInfoImpl::calculateMetadataChecksum(const nlohmann::json& metadata) const
{
    // Build a deterministic string from metadata fields (excluding checksum itself)
    std::string checksumInput;

    // Add fields in a specific order for deterministic checksum
    std::vector<std::string> fields =
    {
        "agent_id", "agent_name", "agent_version",
        "host_architecture", "host_hostname",
        "host_os_name", "host_os_type", "host_os_platform", "host_os_version"
    };

    for (const auto& field : fields)
    {
        if (metadata.contains(field))
        {
            checksumInput += metadata[field].is_string() ? metadata[field].get<std::string>() : metadata[field].dump();
            checksumInput += ":";
        }
    }

    // Use SHA-1 hash (consistent with other modules)
    Utils::HashData hash(Utils::HashType::Sha1);
    hash.update(checksumInput.c_str(), checksumInput.size());
    return Utils::asciiToHex(hash.hash());
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
