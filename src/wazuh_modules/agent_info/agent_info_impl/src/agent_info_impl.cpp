#include "agent_info_impl.hpp"

#include "defs.h"
#include "logging_helper.hpp"
#include "stringHelper.h"

#include <dbsync.hpp>
#include <file_io_utils.hpp>
#include <filesystem_wrapper.hpp>
#include <sysInfo.hpp>

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
{
    LoggingHelper::getInstance().log(LOG_INFO, "AgentInfo initialized.");
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

    // Calculate checksum (simple approach for now)
    agentMetadata["checksum"] = std::to_string(std::hash<std::string> {}(agentMetadata.dump()));

    // Insert agent metadata into database
    nlohmann::json insertData;
    insertData["table"] = "agent_metadata";
    insertData["data"] = nlohmann::json::array({agentMetadata});

    m_dBSync->insertData(insertData);

    LoggingHelper::getInstance().log(LOG_INFO, "Agent metadata populated successfully");

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

    nlohmann::json insertGroups;
    insertGroups["table"] = "agent_groups";
    insertGroups["data"] = groupsData;

    m_dBSync->insertData(insertGroups);

    if (groups.empty())
    {
        LoggingHelper::getInstance().log(LOG_INFO, "Agent groups cleared (no groups found)");
    }
    else
    {
        LoggingHelper::getInstance().log(
            LOG_INFO, "Agent groups populated successfully: " + std::to_string(groups.size()) + " groups");
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
