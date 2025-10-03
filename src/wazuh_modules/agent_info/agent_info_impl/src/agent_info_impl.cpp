#include "agent_info_impl.hpp"

#include <dbsync.hpp>
#include <sysInfo.hpp>
#include "logging_helper.hpp"

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

AgentInfoImpl::AgentInfoImpl(std::string dbPath, std::shared_ptr<IDBSync> dbSync, std::shared_ptr<ISysInfo> sysInfo)
    : m_dBSync(
          dbSync ? std::move(dbSync)
          : std::make_shared<DBSync>(
              HostType::AGENT, DbEngineType::SQLITE3, dbPath, GetCreateStatement(), DbManagement::PERSISTENT))
    , m_sysInfo(sysInfo ? std::move(sysInfo) : std::make_shared<SysInfo>())
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
