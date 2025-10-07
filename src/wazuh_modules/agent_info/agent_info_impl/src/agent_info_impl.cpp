#include "agent_info_impl.hpp"

#include "defs.h"
#include "logging_helper.hpp"
#include "stringHelper.h"
#include "hashHelper.h"
#include "timeHelper.h"

#include <dbsync.hpp>
#include <file_io_utils.hpp>
#include <filesystem_wrapper.hpp>
#include <sysInfo.hpp>

#include <map>

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

// Map DBSync callback results to Operation enums for stateful events
static const std::map<ReturnTypeCallback, Operation> OPERATION_STATES_MAP
{
    {MODIFIED, Operation::MODIFY},
    {DELETED, Operation::DELETE_},
    {INSERTED, Operation::CREATE},
};

// Map tables to their index names in the agent sync protocol
static const std::map<std::string, std::string> INDEX_MAP
{
    {AGENT_METADATA_TABLE, "wazuh-states-agent-metadata"},
    {AGENT_GROUPS_TABLE, "wazuh-states-agent-groups"},
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
                             std::function<void(const std::string&, Operation, const std::string&, const std::string&)> persistDiffFunction,
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
    , m_persistDiffFunction(std::move(persistDiffFunction))
    , m_logFunction(std::move(logFunction))
{
    if (m_logFunction)
    {
        m_logFunction(LOG_INFO, "AgentInfo initialized.");
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_INFO, "AgentInfo initialized.");
    }
}

AgentInfoImpl::~AgentInfoImpl()
{
    stop();
    LoggingHelper::getInstance().log(LOG_INFO, "AgentInfo destroyed.");
}

void AgentInfoImpl::start()
{
    LoggingHelper::getInstance().log(LOG_INFO, "AgentInfo module started.");

    try
    {
        populateAgentMetadata();
    }
    catch (const std::exception& e)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, std::string("Failed to populate agent metadata: ") + e.what());
    }
}

void AgentInfoImpl::stop()
{
    if (m_stopped)
    {
        return;
    }

    m_stopped = true;
    LoggingHelper::getInstance().log(LOG_INFO, "AgentInfo module stopped.");
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
    LoggingHelper::getInstance().log(LOG_DEBUG, "Populating agent metadata from sysinfo");

    // Read agent ID and name from client.keys
    std::string agentId;
    std::string agentName;

    if (!readClientKeys(agentId, agentName))
    {
        LoggingHelper::getInstance().log(LOG_WARNING, "Failed to read agent ID and name from client.keys");
    }

    // Get OS information from sysinfo
    nlohmann::json osInfo = m_sysInfo->os();

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

    if (m_logFunction)
    {
        m_logFunction(LOG_INFO, logMsg);
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_INFO, logMsg);
    }

    // Read agent groups from merged.mg
    std::vector<std::string> groups = readAgentGroups();

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

    if (m_logFunction)
    {
        m_logFunction(LOG_INFO, groupLogMsg);
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_INFO, groupLogMsg);
    }
}

bool AgentInfoImpl::readClientKeys(std::string& agentId, std::string& agentName) const
{
    // Check if client.keys file exists
    if (!m_fileSystem->exists(KEYS_FILE))
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, std::string("File does not exist: ") + KEYS_FILE);
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

                LoggingHelper::getInstance().log(
                    LOG_DEBUG,
                    "Read agent data from client.keys: ID=" + agentId + ", Name=" + agentName);
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
        LoggingHelper::getInstance().log(LOG_DEBUG, std::string("File does not exist: ") + mergedFile);
        return groups;
    }

    // Look for the group line in merged.mg
    // Format: #group: group1,group2,group3
    m_fileIO->readLineByLine(mergedFile,
                             [&](const std::string & line)
    {
        if (line.find("#group:") == 0)
        {
            // Extract the group names after "#group:"
            std::string groupsStr = line.substr(7); // Skip "#group:"

            // Trim whitespace and split by comma using stringHelper
            groupsStr = Utils::trim(groupsStr);
            auto groupTokens = Utils::split(groupsStr, ',');

            // Trim each group name
            for (auto& group : groupTokens)
            {
                group = Utils::trim(group);

                if (!group.empty())
                {
                    groups.push_back(group);
                }
            }

            return false; // Stop reading after finding the group line
        }

        return true; // Continue reading
    });

    if (!groups.empty())
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "Read " + std::to_string(groups.size()) + " groups from merged.mg");
    }

    return groups;
}

void AgentInfoImpl::updateChanges(const std::string& table, const nlohmann::json& values)
{
    const auto callback = [this, table](ReturnTypeCallback result, const nlohmann::json & data)
    {
        if (result == INSERTED || result == MODIFIED || result == DELETED)
        {
            notifyChange(result, data, table);
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

        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, errorMsg);
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_ERROR, errorMsg);
        }
    }
}

void AgentInfoImpl::processEvent(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table)
{
    try
    {
        nlohmann::json eventData = result == MODIFIED && data.contains("new") ? data["new"] : data;
        nlohmann::json ecsFormattedData = ecsData(eventData, table);

        // Persist stateful event
        auto indexIt = INDEX_MAP.find(table);

        if (indexIt != INDEX_MAP.end() && m_persistDiffFunction)
        {
            std::string hashId = calculateHashId(eventData, table);
            m_persistDiffFunction(hashId, OPERATION_STATES_MAP.at(result), indexIt->second, ecsFormattedData.dump());
        }

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

            std::string debugMsg = "Event reported for table " + table + ": " + OPERATION_MAP.at(result);

            if (m_logFunction)
            {
                m_logFunction(LOG_DEBUG_VERBOSE, debugMsg);
            }
            else
            {
                LoggingHelper::getInstance().log(LOG_DEBUG_VERBOSE, debugMsg);
            }
        }
    }
    catch (const std::exception& e)
    {
        std::string errorMsg = "Error processing event for table " + table + ": " + e.what();

        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, errorMsg);
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_ERROR, errorMsg);
        }
    }
}

void AgentInfoImpl::notifyChange(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table)
{
    processEvent(result, data, table);
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

std::string AgentInfoImpl::calculateHashId(const nlohmann::json& data, const std::string& table) const
{
    std::string hashInput;

    if (table == AGENT_METADATA_TABLE)
    {
        // Use agent_id as the primary key
        if (data.contains("agent_id"))
        {
            hashInput = table + ":" + data["agent_id"].get<std::string>();
        }
    }
    else if (table == AGENT_GROUPS_TABLE)
    {
        // Use combination of agent_id and group_name as composite key
        if (data.contains("agent_id") && data.contains("group_name"))
        {
            hashInput = table + ":" + data["agent_id"].get<std::string>() + ":" + data["group_name"].get<std::string>();
        }
    }

    // Return SHA-1 hash of the input (consistent with other modules)
    Utils::HashData hash(Utils::HashType::Sha1);
    hash.update(hashInput.c_str(), hashInput.size());
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
