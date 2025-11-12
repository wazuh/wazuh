#include <sca_impl.hpp>

#include <sca_event_handler.hpp>
#include <sca_policy.hpp>
#include <sca_policy_loader.hpp>

#include <dbsync.hpp>
#include <filesystem_wrapper.hpp>

#include <iostream>
#include <thread>

#include "agent_sync_protocol.hpp"
#include "logging_helper.hpp"

// Static member definitions
int (*SecurityConfigurationAssessment::s_wmExecFunc)(char*, char**, int*, int, const char*) = nullptr;

constexpr auto POLICY_SQL_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS sca_policy (
    id TEXT PRIMARY KEY,
    name TEXT,
    file TEXT,
    description TEXT,
    refs TEXT);)"
};

constexpr auto CHECK_SQL_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS sca_check (
    checksum TEXT NOT NULL,
    id TEXT PRIMARY KEY,
    policy_id TEXT REFERENCES sca_policy(id),
    name TEXT,
    description TEXT,
    rationale TEXT,
    remediation TEXT,
    refs TEXT,
    result TEXT DEFAULT 'Not run',
    reason TEXT,
    condition TEXT,
    compliance TEXT,
    rules TEXT,
    regex_type TEXT DEFAULT 'pcre2',
    version INTEGER NOT NULL DEFAULT 1);)"
};

SecurityConfigurationAssessment::SecurityConfigurationAssessment(
    std::string dbPath,
                                                                 std::shared_ptr<IDBSync> dbSync,
                                                                 std::shared_ptr<IFileSystemWrapper> fileSystemWrapper)
    : m_dBSync(dbSync ? std::move(dbSync)
          : std::make_shared<DBSync>(
                   HostType::AGENT,
                   DbEngineType::SQLITE3,
                   dbPath,
                   GetCreateStatement(),
                   DbManagement::PERSISTENT))
    , m_fileSystemWrapper(fileSystemWrapper ? std::move(fileSystemWrapper)
                          : std::make_shared<file_system::FileSystemWrapper>())
{
    LoggingHelper::getInstance().log(LOG_INFO, "SCA initialized.");
}

void SecurityConfigurationAssessment::Run()
{
    if (!m_enabled)
    {
        LoggingHelper::getInstance().log(LOG_INFO, "SCA module is disabled.");
        return;
    }

    m_keepRunning = true;

    // Reset sync protocol stop flag to allow restarting operations
    if (m_spSyncProtocol)
    {
        m_spSyncProtocol->reset();
    }

    LoggingHelper::getInstance().log(LOG_INFO, "SCA module running.");

    bool firstScan = true;

    while (m_keepRunning)
    {
        // If scan on start is enabled and this is the first iteration, scan immediately
        // Otherwise, wait for the scan interval before scanning
        if (!m_scanOnStart || !firstScan)
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait_for(lock, m_scanInterval, [this] { return !m_keepRunning; });
        }

        if (!m_keepRunning)
        {
            return;
        }

        if (firstScan && m_scanOnStart)
        {
            LoggingHelper::getInstance().log(LOG_INFO, "SCA module scan on start.");
        }

        // Load policies on each run iteration
        // *INDENT-OFF*
        const SCAPolicyLoader policyLoader(m_policiesData, m_fileSystemWrapper, m_dBSync);
        m_policies = policyLoader.LoadPolicies(
            m_commandsTimeout,
            m_remoteEnabled,
            [this](auto policyData, auto checksData)
            {
                const SCAEventHandler eventHandler(m_dBSync, m_pushStatelessMessage, m_pushStatefulMessage);
                eventHandler.ReportPoliciesDelta(policyData, checksData);
            },
            m_yamlToJsonFunc
        );
        // *INDENT-ON*

        // Check again after policy loading in case stop was called during load
        if (!m_keepRunning)
        {
            return;
        }

        auto reportCheckResult = [this](const CheckResult & checkResult)
        {
            const SCAEventHandler eventHandler(m_dBSync, m_pushStatelessMessage, m_pushStatefulMessage);
            eventHandler.ReportCheckResult(
                checkResult.policyId, checkResult.checkId, checkResult.result, checkResult.reason);
        };

        LoggingHelper::getInstance().log(LOG_INFO, "SCA scan started.");

        for (auto& policy : m_policies)
        {
            if (!m_keepRunning)
            {
                return;
            }

            policy->Run(reportCheckResult);
        }

        firstScan = false;

        LoggingHelper::getInstance().log(LOG_INFO, "SCA scan ended.");
    }
}

void SecurityConfigurationAssessment::Setup(bool enabled,
                                            bool scanOnStart,
                                            std::chrono::seconds scanInterval,
                                            const int commandsTimeout,
                                            const bool remoteEnabled,
                                            const std::vector<sca::PolicyData>& policies,
                                            const YamlToJsonFunc& yamlToJsonFunc)
{
    m_enabled = enabled;
    m_scanOnStart = scanOnStart;
    m_scanInterval = scanInterval;
    m_commandsTimeout = commandsTimeout;
    m_remoteEnabled = remoteEnabled;
    m_policiesData = policies;
    m_yamlToJsonFunc = yamlToJsonFunc;
}

void SecurityConfigurationAssessment::Stop()
{
    LoggingHelper::getInstance().log(LOG_INFO, "SecurityConfigurationAssessment::Stop() called");
    m_keepRunning = false;

    // Wake up the Run() loop if it's sleeping
    m_cv.notify_one();

    // Signal sync protocol to stop any ongoing operations
    if (m_spSyncProtocol)
    {
        m_spSyncProtocol->stop();
    }

    LoggingHelper::getInstance().log(LOG_INFO, "Stopping policies");

    for (auto& policy : m_policies)
    {
        policy->Stop();
    }

    // Explicitly release DBSync before static destruction to avoid use-after-free
    // during shutdown when DBSyncImplementation singleton may be destroyed first
    m_dBSync.reset();

    LoggingHelper::getInstance().log(LOG_INFO, "SCA module stopped.");
}

const std::string& SecurityConfigurationAssessment::Name() const
{
    return m_name;
}

void SecurityConfigurationAssessment::SetPushStatelessMessageFunction(const std::function<int(const std::string&)>& pushMessage)
{
    m_pushStatelessMessage = pushMessage;
}

void SecurityConfigurationAssessment::SetPushStatefulMessageFunction(const std::function<int(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)>& pushMessage)
{
    m_pushStatefulMessage = pushMessage;
}

void SecurityConfigurationAssessment::SetGlobalWmExecFunction(int (*wmExecFunc)(char*, char**, int*, int, const char*))
{
    s_wmExecFunc = wmExecFunc;
}

int (*SecurityConfigurationAssessment::GetGlobalWmExecFunction())(char*, char**, int*, int, const char*)
{
    return s_wmExecFunc;
}

std::string SecurityConfigurationAssessment::GetCreateStatement() const
{
    std::string ret;
    ret += POLICY_SQL_STATEMENT;
    ret += CHECK_SQL_STATEMENT;

    return ret;
}

// LCOV_EXCL_START

// Sync protocol methods implementation
void SecurityConfigurationAssessment::initSyncProtocol(const std::string& moduleName, const std::string& syncDbPath, MQ_Functions mqFuncs, std::chrono::seconds syncEndDelay,
                                                       std::chrono::seconds timeout, unsigned int retries, size_t maxEps)
{
    auto logger_func = [](modules_log_level_t level, const std::string & msg)
    {
        LoggingHelper::getInstance().log(level, msg);
    };

    try
    {
        m_spSyncProtocol = std::make_unique<AgentSyncProtocol>(moduleName, syncDbPath, mqFuncs, logger_func, syncEndDelay, timeout, retries, maxEps, nullptr);
        LoggingHelper::getInstance().log(LOG_INFO, "SCA sync protocol initialized successfully with database: " + syncDbPath);
    }
    catch (const std::exception& ex)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "Failed to initialize SCA sync protocol: " + std::string(ex.what()));
        // Re-throw to allow caller to handle
        throw;
    }
}

bool SecurityConfigurationAssessment::syncModule(Mode mode)
{
    if (m_spSyncProtocol)
    {
        return m_spSyncProtocol->synchronizeModule(mode);
    }

    return false;
}

void SecurityConfigurationAssessment::persistDifference(const std::string& id, Operation operation, const std::string& index, const std::string& data, uint64_t version)
{
    if (m_spSyncProtocol)
    {
        m_spSyncProtocol->persistDifference(id, operation, index, data, version);
    }
}

bool SecurityConfigurationAssessment::parseResponseBuffer(const uint8_t* data, size_t length)
{
    if (m_spSyncProtocol)
    {
        return m_spSyncProtocol->parseResponseBuffer(data, length);
    }

    return false;
}

bool SecurityConfigurationAssessment::notifyDataClean(const std::vector<std::string>& indices)
{
    if (m_spSyncProtocol)
    {
        return m_spSyncProtocol->notifyDataClean(indices);
    }

    return false;
}

void SecurityConfigurationAssessment::deleteDatabase()
{
    if (m_spSyncProtocol)
    {
        m_spSyncProtocol->deleteDatabase();
    }

    if (m_dBSync)
    {
        m_dBSync->closeAndDeleteDatabase();
    }
}

int SecurityConfigurationAssessment::getMaxVersion()
{
    int maxVersion = 0;

    if (!m_dBSync)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "DBSync is null, cannot get max version");
        return -1;
    }

    try
    {
        auto selectQuery =
            SelectQuery::builder().table("sca_check").columnList({"MAX(version) AS max_version"}).build();

        const auto callback = [&maxVersion](ReturnTypeCallback returnTypeCallback, const nlohmann::json & resultData)
        {
            if (returnTypeCallback == SELECTED && resultData.contains("max_version"))
            {
                if (resultData["max_version"].is_number())
                {
                    maxVersion = resultData["max_version"].get<int>();
                }
                else if (resultData["max_version"].is_null())
                {
                    // No rows in table, version is 0
                    maxVersion = 0;
                }
            }
        };

        m_dBSync->selectRows(selectQuery.query(), callback);
        LoggingHelper::getInstance().log(LOG_DEBUG, "SCA get_version returned: " + std::to_string(maxVersion));
    }
    catch (const std::exception& err)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "Error getting max version: " + std::string(err.what()));
        return -1;
    }

    return maxVersion;
}

int SecurityConfigurationAssessment::setVersion(int version)
{
    if (!m_dBSync)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "DBSync is null, cannot set version");
        return -1;
    }

    try
    {
        // First, get all check IDs from the table
        std::vector<std::string> checkIds;

        auto selectQuery = SelectQuery::builder().table("sca_check").columnList({"id"}).build();

        const auto selectCallback = [&checkIds](ReturnTypeCallback returnTypeCallback, const nlohmann::json & resultData)
        {
            if (returnTypeCallback == SELECTED && resultData.contains("id"))
            {
                checkIds.push_back(resultData["id"].get<std::string>());
            }
        };

        m_dBSync->selectRows(selectQuery.query(), selectCallback);

        // Now update each row with the new version
        for (const auto& checkId : checkIds)
        {
            nlohmann::json updateData;
            updateData["table"] = "sca_check";
            updateData["data"] = nlohmann::json::object();
            updateData["data"]["id"] = checkId;
            updateData["data"]["version"] = version;

            auto updateQuery = SyncRowQuery::builder().table("sca_check").data(updateData["data"]).build();

            const auto updateCallback = [](ReturnTypeCallback, const nlohmann::json&)
            {
                // No action needed for update callback
            };

            m_dBSync->syncRow(updateQuery.query(), updateCallback);
        }

        LoggingHelper::getInstance().log(LOG_DEBUG,
                                         "SCA set_version to " + std::to_string(version) + " for " +
                                         std::to_string(checkIds.size()) + " checks");
        return 0;
    }
    catch (const std::exception& err)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "Error setting version: " + std::string(err.what()));
        return -1;
    }
}

// LCOV_EXCL_STOP
