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

        // Check if paused for coordination - skip scanning but stay in loop
        if (m_paused)
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "SCA scanning paused, skipping scan iteration");
            firstScan = false;  // Clear first scan flag even when paused
            continue;
        }

        if (firstScan && m_scanOnStart)
        {
            LoggingHelper::getInstance().log(LOG_INFO, "SCA module scan on start.");
        }

        // Mark scan as in progress
        m_scanInProgress.store(true);

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
            // Mark scan as complete before returning
            m_scanInProgress.store(false);
            {
                std::lock_guard<std::mutex> lock(m_pauseMutex);
                m_pauseCv.notify_all();
            }
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
                // Mark scan as complete before returning
                m_scanInProgress.store(false);
                {
                    std::lock_guard<std::mutex> lock(m_pauseMutex);
                    m_pauseCv.notify_all();
                }
                return;
            }

            policy->Run(reportCheckResult);
        }

        firstScan = false;

        LoggingHelper::getInstance().log(LOG_INFO, "SCA scan ended.");

        // Mark scan as complete
        m_scanInProgress.store(false);

        // Notify anyone waiting for scan completion
        {
            std::lock_guard<std::mutex> lock(m_pauseMutex);
            m_pauseCv.notify_all();
        }
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
    // Check if paused - don't start new sync operations
    if (m_paused.load())
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "SCA sync skipped - module is paused");
        return true;  // Return success to avoid error handling in caller
    }

    if (m_spSyncProtocol)
    {
        // Log
        LoggingHelper::getInstance().log(LOG_DEBUG, "SCA synchronization started.");

        // Mark sync as in progress
        m_syncInProgress.store(true);

        bool result = m_spSyncProtocol->synchronizeModule(mode);

        // Mark sync as complete
        m_syncInProgress.store(false);

        // Notify anyone waiting for sync completion
        {
            std::lock_guard<std::mutex> lock(m_pauseMutex);
            m_pauseCv.notify_all();
        }

        if (result)
        {
            LoggingHelper::getInstance().log(LOG_INFO, "SCA synchronization finished successfully.");
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_INFO, "SCA synchronization failed.");
        }

        return result;
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
        // First, get ALL rows with ALL columns (like FIM does in db.cpp:130-137)
        std::vector<nlohmann::json> rows;

        auto selectQuery = SelectQuery::builder()
                           .table("sca_check")
                           .columnList({"*"}) // Get all columns to properly identify and update rows
                           .build();

        const auto selectCallback = [&rows](ReturnTypeCallback returnTypeCallback, const nlohmann::json & resultData)
        {
            if (returnTypeCallback == SELECTED)
            {
                rows.push_back(resultData);
            }
        };

        m_dBSync->selectRows(selectQuery.query(), selectCallback);

        // Use transaction-based approach to ensure changes are immediately reflected in DB
        // Create a transaction for syncing the version updates
        const auto txnCallback = [](ReturnTypeCallback, const nlohmann::json&)
        {
            // No action needed for transaction callback
        };

        DBSyncTxn txn {m_dBSync->handle(), nlohmann::json {"sca_check"}, 0, DBSYNC_QUEUE_SIZE, txnCallback};

        if (txn.handle() != nullptr)
        {
            // Update each row's version field (like FIM does in db.cpp:148-169)
            for (auto& row : rows)
            {
                row["version"] = version; // Modify just the version field in the complete row

                nlohmann::json input;
                input["table"] = "sca_check";
                input["data"] = nlohmann::json::array({row});

                txn.syncTxnRow(input);
            }

            // Call getDeletedRows to ensure changes are immediately reflected in the database
            txn.getDeletedRows(txnCallback);
        }

        LoggingHelper::getInstance().log(LOG_DEBUG,
                                         "SCA set_version to " + std::to_string(version) + " for " +
                                         std::to_string(rows.size()) + " checks");
        return 0;
    }
    catch (const std::exception& err)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "Error setting version: " + std::string(err.what()));
        return -1;
    }
}

void SecurityConfigurationAssessment::pause()
{
    LoggingHelper::getInstance().log(LOG_INFO, "SCA pause requested");

    // Set pause flag to prevent new operations from starting
    m_paused.store(true);

    // Wait for BOTH scan and sync operations to complete
    std::unique_lock<std::mutex> lock(m_pauseMutex);
    m_pauseCv.wait(lock, [this]
    {
        bool scanDone = !m_scanInProgress.load();
        bool syncDone = !m_syncInProgress.load();
        return (scanDone && syncDone) || !m_keepRunning;
    });

    LoggingHelper::getInstance().log(LOG_INFO, "SCA module paused - all operations completed");
}

int SecurityConfigurationAssessment::flush()
{
    LoggingHelper::getInstance().log(LOG_DEBUG, "SCA flush requested - syncing pending messages");

    if (!m_spSyncProtocol)
    {
        LoggingHelper::getInstance().log(LOG_WARNING, "SCA sync protocol not initialized, flush skipped");
        return 0;  // Not an error - just nothing to flush
    }

    // Trigger immediate synchronization to flush pending messages
    bool result = m_spSyncProtocol->synchronizeModule(Mode::DELTA);

    if (result)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "SCA flush completed successfully");
        return 0;
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "SCA flush failed");
        return -1;
    }
}

void SecurityConfigurationAssessment::resume()
{
    LoggingHelper::getInstance().log(LOG_INFO, "SCA scanning resumed after coordination");

    // Clear pause flag to allow operations to resume
    m_paused.store(false);

    // Wake up the Run() loop if it's waiting
    m_cv.notify_one();
}

std::string SecurityConfigurationAssessment::query(const std::string& jsonQuery)
{
    // Log the received query
    LoggingHelper::getInstance().log(LOG_DEBUG, "Received query: " + jsonQuery);

    try
    {
        // Parse JSON command
        nlohmann::json query_json = nlohmann::json::parse(jsonQuery);

        if (!query_json.contains("command") || !query_json["command"].is_string())
        {
            nlohmann::json response;
            response["error"] = 3; // MQ_ERR_INVALID_PARAMS
            response["message"] = "Missing or invalid parameters";
            return response.dump();
        }

        std::string command = query_json["command"];
        nlohmann::json parameters = query_json.contains("parameters") ? query_json["parameters"] : nlohmann::json();

        // Log the command being executed
        LoggingHelper::getInstance().log(LOG_DEBUG, "Executing command: " + command);

        nlohmann::json response;

        // Handle coordination commands with JSON responses
        if (command == "pause")
        {
            pause();
            response["error"] = 0; // MQ_SUCCESS
            response["message"] = "SCA module paused successfully";
            response["data"]["module"] = "sca";
            response["data"]["action"] = "pause";
        }
        else if (command == "flush")
        {
            // Flush triggers immediate sync protocol synchronization
            int result = flush();

            if (result == 0)
            {
                response["error"] = 0; // MQ_SUCCESS
                response["message"] = "SCA module flushed successfully";
                response["data"]["module"] = "sca";
                response["data"]["action"] = "flush";
            }
            else
            {
                response["error"] = 1;
                response["message"] = "SCA module flush failed";
                response["data"]["module"] = "sca";
                response["data"]["action"] = "flush";
            }
        }
        else if (command == "get_version")
        {
            const int maxVersion = getMaxVersion();

            if (maxVersion >= 0)
            {
                response["error"] = 0; // MQ_SUCCESS
                response["message"] = "SCA get_version successfully";
                response["data"]["action"] = "get_version";
                response["data"]["module"] = "sca";
                response["data"]["version"] = maxVersion;
            }
            else
            {
                response["error"] = 3;
                response["message"] = "SCA fails getting version";
                response["data"]["action"] = "get_version";
                response["data"]["module"] = "sca";
            }
        }
        else if (command == "set_version")
        {
            // Extract version from parameters
            int version = -1;

            if (parameters.is_object() && parameters.contains("version") && parameters["version"].is_number())
            {
                version = parameters["version"].get<int>();
            }

            if (version < 0)
            {
                response["error"] = 3; // MQ_ERR_INVALID_PARAMS
                response["message"] = "Invalid version parameter";
                response["data"]["action"] = "set_version";
                response["data"]["module"] = "sca";
            }
            else
            {
                int result = setVersion(version);

                if (result == 0)
                {
                    response["error"] = 0; // MQ_SUCCESS
                    response["message"] = "SCA version set successfully";
                    response["data"]["action"] = "set_version";
                    response["data"]["module"] = "sca";
                    response["data"]["version"] = version;
                }
                else
                {
                    response["error"] = 2;
                    response["message"] = "SCA fails setting version";
                    response["data"]["action"] = "set_version";
                    response["data"]["module"] = "sca";
                    response["data"]["version"] = version;
                }
            }
        }
        else if (command == "resume")
        {
            resume();
            response["error"] = 0; // MQ_SUCCESS
            response["message"] = "SCA module resumed successfully";
            response["data"]["module"] = "sca";
            response["data"]["action"] = "resume";
        }
        else
        {
            response["error"] = 1; // MQ_ERR_UNKNOWN_COMMAND
            response["message"] = "Unknown SCA command: " + command;
            response["data"]["command"] = command;
        }

        return response.dump();
    }
    catch (const std::exception& ex)
    {
        nlohmann::json response;
        response["error"] = 98; // MQ_ERR_INTERNAL
        response["message"] = "Exception parsing JSON or executing command: " + std::string(ex.what());

        LoggingHelper::getInstance().log(LOG_ERROR, "Query error: " + std::string(ex.what()));
        return response.dump();
    }
}

// LCOV_EXCL_STOP
