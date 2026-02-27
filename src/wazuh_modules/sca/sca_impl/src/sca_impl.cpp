#include <sca_impl.hpp>
#include <sca_recovery_utils.hpp>

#include <sca_event_handler.hpp>
#include <sca_policy.hpp>
#include <sca_policy_loader.hpp>
#include <sca_sync_manager.hpp>

#include <dbsync.hpp>
#include <filesystem_wrapper.hpp>

#include <algorithm>
#include <iostream>
#include <thread>

#include "agent_sync_protocol.hpp"
#include "logging_helper.hpp"
#include "hashHelper.h"
#include "sca.h"
#include "schemaValidator.hpp"

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
    version INTEGER NOT NULL DEFAULT 1,
    sync INTEGER NOT NULL DEFAULT 0);)"
};

constexpr auto METADATA_SQL_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS sca_metadata (
    key TEXT PRIMARY KEY,
    value INTEGER);)"
};

SecurityConfigurationAssessment::SecurityConfigurationAssessment(std::string dbPath,
                                                                 std::shared_ptr<IDBSync> dbSync,
                                                                 std::shared_ptr<IFileSystemWrapper> fileSystemWrapper)
    : m_dBSync(
          dbSync ? std::move(dbSync)
          : std::make_shared<DBSync>(
              HostType::AGENT, DbEngineType::SQLITE3, dbPath, GetCreateStatement(), DbManagement::PERSISTENT))
    , m_syncManager(std::make_shared<SCASyncManager>(m_dBSync))
    , m_fileSystemWrapper(fileSystemWrapper ? std::move(fileSystemWrapper)
                          : std::make_shared<file_system::FileSystemWrapper>())
{
    LoggingHelper::getInstance().log(LOG_INFO, "SCA initialized.");
}

SecurityConfigurationAssessment::~SecurityConfigurationAssessment()
{
    // Best-effort teardown guard: release possible waiters before condition_variable destruction.
    m_keepRunning = false;
    m_paused.store(false);
    m_scanInProgress.store(false);
    m_syncInProgress.store(false);
    m_cv.notify_all();
    m_pauseCv.notify_all();
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

    if (m_syncManager)
    {
        m_syncManager->initialize();
    }

    // Check for policies removed between agent restarts (before scan loop starts).
    // This early check uses m_policiesData (raw config) since policies haven't been loaded yet.
    bool hasEnabledPolicies =
        std::any_of(m_policiesData.begin(), m_policiesData.end(), [](const auto & policy)
    {
        return policy.isEnabled;
    });

    if (!hasEnabledPolicies)
    {
        if (!handleNoPoliciesAvailable())
        {
            return;
        }

        // If handleNoPoliciesAvailable returns true, it means no cleanup was needed - but we still exit
        // since there's nothing to scan
        LoggingHelper::getInstance().log(LOG_DEBUG, "No enabled policies configured. SCA module has nothing to scan.");
        return;
    }

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
            // LCOV_EXCL_START
            LoggingHelper::getInstance().log(LOG_DEBUG, "SCA scanning paused, skipping scan iteration");
            firstScan = false;  // Clear first scan flag even when paused
            continue;
            // LCOV_EXCL_STOP
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
                const SCAEventHandler eventHandler(m_dBSync, m_pushStatelessMessage, m_pushStatefulMessage, m_syncManager);
                eventHandler.ReportPoliciesDelta(policyData, checksData);
            },
            m_yamlToJsonFunc
        );
        // *INDENT-ON*

        if (m_syncManager)
        {
            m_syncManager->reconcile();
        }

        // Check for policies removed at runtime (e.g., config change during scan loop).
        // This uses m_policies (loaded objects) since LoadPolicies() may filter out invalid policies.
        if (m_policies.empty())
        {
            m_scanInProgress.store(false);
            {
                std::lock_guard<std::mutex> lock(m_pauseMutex);
                m_pauseCv.notify_all();
            }

            handleNoPoliciesAvailable();
            return;
        }

        // Check again after policy loading in case stop was called during load
        if (!m_keepRunning)
        {
            // LCOV_EXCL_START
            // Mark scan as complete before returning
            m_scanInProgress.store(false);
            {
                std::lock_guard<std::mutex> lock(m_pauseMutex);
                m_pauseCv.notify_all();
            }
            return;
            // LCOV_EXCL_STOP
        }

        auto reportCheckResult = [this](const CheckResult & checkResult)
        {
            const SCAEventHandler eventHandler(m_dBSync, m_pushStatelessMessage, m_pushStatefulMessage, m_syncManager);
            eventHandler.ReportCheckResult(
                checkResult.policyId, checkResult.checkId, checkResult.result, checkResult.reason);
        };

        LoggingHelper::getInstance().log(LOG_INFO, "SCA scan started.");

        for (auto& policy : m_policies)
        {
            if (!m_keepRunning)
            {
                // LCOV_EXCL_START
                // Mark scan as complete before returning
                m_scanInProgress.store(false);
                {
                    std::lock_guard<std::mutex> lock(m_pauseMutex);
                    m_pauseCv.notify_all();
                }
                return;
                // LCOV_EXCL_STOP
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
    m_paused.store(false);
    m_scanInProgress.store(false);
    m_syncInProgress.store(false);

    // Wake up the Run() loop if it's sleeping
    m_cv.notify_all();

    // Wake up pause() waiters so shutdown cannot block on condition variable destruction.
    m_pauseCv.notify_all();

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
    ret += METADATA_SQL_STATEMENT;

    return ret;
}

std::string SecurityConfigurationAssessment::calculateSyncedChecksChecksum()
{
    if (!m_dBSync)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "DBSync is null, cannot calculate checksum");
        return {};
    }

    std::string concatenatedChecksums = m_dBSync->getConcatenatedChecksums("sca_check", "WHERE sync = 1");

    Utils::HashData hash(Utils::HashType::Sha1);
    hash.update(concatenatedChecksums.c_str(), concatenatedChecksums.length());
    const std::vector<unsigned char> hashResult = hash.hash();
    return Utils::asciiToHex(hashResult);
}

// LCOV_EXCL_START

// Sync protocol methods implementation
void SecurityConfigurationAssessment::initSyncProtocol(const std::string& moduleName, const std::string& syncDbPath, MQ_Functions mqFuncs, std::chrono::seconds syncEndDelay,
                                                       std::chrono::seconds timeout, unsigned int retries, size_t maxEps, std::chrono::seconds integrityInterval)
{
    auto logger_func = [](modules_log_level_t level, const std::string & msg)
    {
        LoggingHelper::getInstance().log(level, msg);
    };

    try
    {
        m_spSyncProtocol = std::make_shared<AgentSyncProtocol>(moduleName, syncDbPath, mqFuncs, logger_func, syncEndDelay, timeout, retries, maxEps, nullptr);
        LoggingHelper::getInstance().log(LOG_INFO, "SCA sync protocol initialized successfully with database: " + syncDbPath);

        // Initialize schema validator factory from embedded resources
        auto& validatorFactory = SchemaValidator::SchemaValidatorFactory::getInstance();

        if (!validatorFactory.isInitialized())
        {
            if (validatorFactory.initialize())
            {
                LoggingHelper::getInstance().log(LOG_INFO, "Schema validator initialized successfully from embedded resources");
            }
            else
            {
                LoggingHelper::getInstance().log(LOG_WARNING, "Failed to initialize schema validator. Schema validation will be disabled.");
            }
        }

        // Set integrity interval
        m_integrityInterval = integrityInterval;
        LoggingHelper::getInstance().log(LOG_DEBUG, "SCA integrity interval set to " + std::to_string(integrityInterval.count()) + " seconds");
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
    if (!m_paused.load())
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "SCA sync skipped - module is not paused");
        return false;
    }

    if (m_syncInProgress.load())
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "SCA sync skipped - sync already in progress");
        return false;
    }

    if (m_spSyncProtocol)
    {
        // Log
        LoggingHelper::getInstance().log(LOG_INFO, "Starting SCA synchronization.");

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
            LoggingHelper::getInstance().log(LOG_WARNING, "SCA synchronization failed.");
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

void SecurityConfigurationAssessment::setSyncLimit(uint64_t syncLimit)
{
    if (m_syncManager)
    {
        const auto limitResult = m_syncManager->updateSyncLimit(syncLimit);

        if (!limitResult.demotedIds.empty())
        {
            const SCAEventHandler eventHandler(m_dBSync, m_pushStatelessMessage, m_pushStatefulMessage, m_syncManager);
            eventHandler.ReportDemotedChecks(limitResult.demotedIds);
        }
    }
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
    LoggingHelper::getInstance().log(LOG_DEBUG, "SCA module pause requested");

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

    if (!m_keepRunning)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "SCA module pause interrupted by shutdown");
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "SCA module paused successfully");
    }
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
    LoggingHelper::getInstance().log(LOG_DEBUG, "SCA scanning resumed after coordination");

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
        else if (command == "check_integrity")
        {
            int64_t currentTime = Utils::getSecondsFromEpoch();

            if (integrityIntervalElapsed(currentTime))
            {
                LoggingHelper::getInstance().log(LOG_DEBUG, "Integrity interval elapsed, performing integrity check");

                // Calculate local checksum
                std::string checksum;

                try
                {
                    checksum = calculateSyncedChecksChecksum();
                    LoggingHelper::getInstance().log(LOG_DEBUG, "SCA table checksum calculated: " + checksum);
                }
                catch (const std::exception& err)
                {
                    LoggingHelper::getInstance().log(LOG_ERROR, "Error calculating table checksum: " + std::string(err.what()));
                }

                if (checksum.empty())
                {
                    response["error"] = 1;
                    response["message"] = "Failed to calculate checksum";
                    response["data"]["module"] = "sca";
                    response["data"]["action"] = "check_integrity";
                    response["data"]["recovery_performed"] = false;
                }
                else
                {
                    // Check with manager if recovery needed
                    bool recoveryNeeded = checkIfRecoveryRequired(checksum);

                    if (recoveryNeeded)
                    {
                        // Perform full recovery
                        bool success = performRecovery();
                        response["error"] = success ? 0 : 1;
                        response["message"] = success ? "Recovery completed successfully" : "Recovery failed";
                        response["data"]["module"] = "sca";
                        response["data"]["action"] = "check_integrity";
                        response["data"]["recovery_performed"] = true;
                        response["data"]["recovery_success"] = success;
                    }
                    else
                    {
                        response["error"] = 0;
                        response["message"] = "Integrity check passed";
                        response["data"]["module"] = "sca";
                        response["data"]["action"] = "check_integrity";
                        response["data"]["recovery_performed"] = false;
                    }
                }

                // Update last check time regardless of outcome
                updateLastIntegrityCheckTime(currentTime);
            }
            else
            {
                response["error"] = 0;
                response["message"] = "Integrity interval not elapsed yet";
                response["data"]["module"] = "sca";
                response["data"]["action"] = "check_integrity";
                response["data"]["recovery_performed"] = false;
            }
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

// Recovery methods implementation
bool SecurityConfigurationAssessment::checkIfRecoveryRequired(const std::string& checksum)
{
    if (!m_spSyncProtocol)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "Sync protocol not initialized, cannot check recovery status");
        return false;
    }

    LoggingHelper::getInstance().log(LOG_DEBUG, "Checking with manager if recovery required");

    try
    {
        // Use AgentSyncProtocol::requiresFullSync
        // Note: returns true only if manager explicitly reports checksum mismatch
        // Returns false for: success (checksums match) OR communication errors
        // The sync protocol logs detailed messages for each case
        bool needsRecovery = m_spSyncProtocol->requiresFullSync(SCA_SYNC_INDEX, checksum);

        if (needsRecovery)
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Checksum mismatch detected, full recovery required");
        }

        return needsRecovery;
    }
    catch (const std::exception& err)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "Error checking recovery status: " + std::string(err.what()));
        return false;
    }
}

bool SecurityConfigurationAssessment::performRecovery()
{
    LoggingHelper::getInstance().log(LOG_INFO, "Starting SCA recovery process");

    try
    {
        // Increase version for all entries before recovery sync
        // This ensures our versions are higher than what's in the indexer
        if (!m_dBSync)
        {
            LoggingHelper::getInstance().log(LOG_ERROR, "DBSync is null, cannot perform recovery");
            return false;
        }

        m_dBSync->increaseEachEntryVersion("sca_check");

        // Get all synced checks from database (now with incremented versions)
        std::vector<nlohmann::json> checks;
        auto selectQuery = SelectQuery::builder()
                           .table("sca_check")
                           .columnList({"*"})
                           .rowFilter("WHERE sync = 1")
                           .build();

        const auto selectCallback = [&checks](ReturnTypeCallback returnTypeCallback, const nlohmann::json & resultData)
        {
            if (returnTypeCallback == SELECTED)
            {
                checks.push_back(resultData);
            }
        };

        m_dBSync->selectRows(selectQuery.query(), selectCallback);
        LoggingHelper::getInstance().log(LOG_DEBUG, "Retrieved " + std::to_string(checks.size()) + " checks from database");

        // Clear in-memory data before repopulating
        if (m_spSyncProtocol)
        {
            m_spSyncProtocol->clearInMemoryData();
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_ERROR, "Sync protocol not initialized, cannot perform recovery");
            return false;
        }

        // Persist all checks in memory for full sync
        for (const auto& check : checks)
        {
            if (!check.contains("id") || !check.contains("version") || !check.contains("policy_id"))
            {
                LoggingHelper::getInstance().log(LOG_ERROR, "Skipping check with missing id, version, or policy_id field");
                continue;
            }

            std::string checkId = check["id"].get<std::string>();
            std::string policyId = check["policy_id"].get<std::string>();

            // Get policy data for this check
            nlohmann::json policy = sca::recovery::getPolicyById(policyId, m_dBSync);

            if (policy.empty())
            {
                LoggingHelper::getInstance().log(LOG_WARNING, "Policy not found for check " + checkId + ", skipping");
                continue;
            }

            // Build stateful message in the format required by the indexer
            nlohmann::json statefulMessage = sca::recovery::buildStatefulMessage(check, policy);

            // Validate stateful message before persisting for recovery
            auto& validatorFactory = SchemaValidator::SchemaValidatorFactory::getInstance();
            bool shouldPersist = true;

            if (validatorFactory.isInitialized())
            {
                auto validator = validatorFactory.getValidator(SCA_SYNC_INDEX);

                if (validator)
                {
                    auto validationResult = validator->validate(statefulMessage.dump());

                    if (!validationResult.isValid)
                    {
                        // Log validation errors
                        std::string errorMsg = "Schema validation failed for SCA recovery message (policy: " +
                                               policyId + ", check: " + checkId + ", index: " +
                                               std::string(SCA_SYNC_INDEX) + "). Errors: ";

                        for (const auto& error : validationResult.errors)
                        {
                            errorMsg += "  - " + error;
                        }

                        LoggingHelper::getInstance().log(LOG_ERROR, errorMsg);
                        LoggingHelper::getInstance().log(LOG_ERROR, "Raw recovery event that failed validation: " + statefulMessage.dump());
                        LoggingHelper::getInstance().log(LOG_DEBUG, "Skipping persistence of invalid recovery event for check " + checkId);
                        shouldPersist = false;
                    }
                }
            }

            // Persist only if validation passed
            if (shouldPersist)
            {
                // Calculate SHA1 of policy_id:check_id for sync protocol (same as event handler)
                std::string baseId = policyId + ":" + checkId;
                Utils::HashData hash(Utils::HashType::Sha1);
                hash.update(baseId.c_str(), baseId.length());
                const std::vector<unsigned char> hashResult = hash.hash();
                std::string hashedId = Utils::asciiToHex(hashResult);

                m_spSyncProtocol->persistDifferenceInMemory(
                    hashedId,
                    Operation::CREATE,
                    SCA_SYNC_INDEX,
                    statefulMessage.dump(),
                    check["version"].get<uint64_t>()
                );
            }
        }

        // Trigger full synchronization
        LoggingHelper::getInstance().log(LOG_DEBUG, "Triggering full synchronization for recovery");
        bool success = m_spSyncProtocol->synchronizeModule(Mode::FULL);

        if (success)
        {
            LoggingHelper::getInstance().log(LOG_INFO, "SCA recovery completed successfully");
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_ERROR, "SCA recovery synchronization failed");
        }

        return success;
    }
    catch (const std::exception& err)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "Error during recovery: " + std::string(err.what()));
        return false;
    }
}

int64_t SecurityConfigurationAssessment::getLastIntegrityCheckTime()
{
    if (!m_dBSync)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "DBSync is null, cannot get last integrity check time");
        return 0;
    }

    try
    {
        int64_t timestamp = 0;

        auto selectQuery = SelectQuery::builder()
                           .table("sca_metadata")
                           .columnList({"value"})
                           .rowFilter("WHERE key = 'last_integrity_check'")
                           .build();

        const auto callback = [&timestamp](ReturnTypeCallback returnTypeCallback, const nlohmann::json & resultData)
        {
            if (returnTypeCallback == SELECTED && resultData.contains("value"))
            {
                if (resultData["value"].is_number())
                {
                    timestamp = resultData["value"].get<int64_t>();
                }
            }
        };

        m_dBSync->selectRows(selectQuery.query(), callback);
        return timestamp;
    }
    catch (const std::exception& err)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "Error getting last integrity check time: " + std::string(err.what()));
        return 0;
    }
}

void SecurityConfigurationAssessment::updateLastIntegrityCheckTime(int64_t timestamp)
{
    if (!m_dBSync)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "DBSync is null, cannot update last integrity check time");
        return;
    }

    try
    {
        // Prepare metadata record
        nlohmann::json metadata;
        metadata["key"] = "last_integrity_check";
        metadata["value"] = timestamp;

        // Use DBSync transaction to update/insert
        const auto txnCallback = [](ReturnTypeCallback, const nlohmann::json&)
        {
            // No action needed for transaction callback
        };

        DBSyncTxn txn {m_dBSync->handle(), nlohmann::json {"sca_metadata"}, 0, DBSYNC_QUEUE_SIZE, txnCallback};

        if (txn.handle() != nullptr)
        {
            nlohmann::json input;
            input["table"] = "sca_metadata";
            input["data"] = nlohmann::json::array({metadata});

            txn.syncTxnRow(input);
            txn.getDeletedRows(txnCallback);

            LoggingHelper::getInstance().log(LOG_DEBUG, "Updated last integrity check time to " + std::to_string(timestamp));
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_ERROR, "Failed to create DBSync transaction for updating last integrity check time");
        }
    }
    catch (const std::exception& err)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "Error updating last integrity check time: " + std::string(err.what()));
    }
}

bool SecurityConfigurationAssessment::integrityIntervalElapsed(int64_t currentTime)
{
    if (m_integrityInterval.count() == 0)
    {
        // Integrity checks disabled
        return false;
    }

    int64_t lastCheck = getLastIntegrityCheckTime();

    // First check - initialize timestamp and defer the actual check
    // This allows the system to stabilize before first integrity check
    if (lastCheck == 0)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "First integrity check - initializing timestamp, deferring check");
        updateLastIntegrityCheckTime(currentTime);
        return false;
    }

    int64_t elapsed = currentTime - lastCheck;
    bool intervalElapsed = elapsed >= m_integrityInterval.count();

    if (intervalElapsed)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG,
                                         "Integrity interval elapsed: " + std::to_string(elapsed) + " seconds >= " +
                                         std::to_string(m_integrityInterval.count()) + " seconds");
    }

    return intervalElapsed;
}

bool SecurityConfigurationAssessment::hasDataInDatabase()
{
    if (!m_dBSync)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "DBSync is null, cannot check database contents");
        return false;
    }

    try
    {
        int policyCount = 0;
        int checkCount = 0;

        // Count policies
        auto policyQuery = SelectQuery::builder()
                           .table("sca_policy")
                           .columnList({"COUNT(*) AS count"})
                           .build();

        const auto policyCallback = [&policyCount](ReturnTypeCallback returnTypeCallback, const nlohmann::json & resultData)
        {
            if (returnTypeCallback == SELECTED && resultData.contains("count"))
            {
                if (resultData["count"].is_number())
                {
                    policyCount = resultData["count"].get<int>();
                }
            }
        };

        m_dBSync->selectRows(policyQuery.query(), policyCallback);

        // Count checks
        auto checkQuery = SelectQuery::builder()
                          .table("sca_check")
                          .columnList({"COUNT(*) AS count"})
                          .build();

        const auto checkCallback = [&checkCount](ReturnTypeCallback returnTypeCallback, const nlohmann::json & resultData)
        {
            if (returnTypeCallback == SELECTED && resultData.contains("count"))
            {
                if (resultData["count"].is_number())
                {
                    checkCount = resultData["count"].get<int>();
                }
            }
        };

        m_dBSync->selectRows(checkQuery.query(), checkCallback);

        LoggingHelper::getInstance().log(LOG_DEBUG,
                                         "Database contains " + std::to_string(policyCount) + " policies and " +
                                         std::to_string(checkCount) + " checks");

        return (policyCount > 0 || checkCount > 0);
    }
    catch (const std::exception& err)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "Error checking database contents: " + std::string(err.what()));
        return false;
    }
}

bool SecurityConfigurationAssessment::handleNoPoliciesAvailable()
{
    if (hasDataInDatabase())
    {
        LoggingHelper::getInstance().log(LOG_DEBUG,
                                         "No policies available but database has data. Initiating DataClean process.");

        if (handleAllPoliciesRemoved())
        {
            LoggingHelper::getInstance().log(LOG_DEBUG,
                                             "All policies removed - DataClean completed. SCA module exiting.");
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Failed to complete DataClean process. SCA module exiting.");
        }

        // Cleanup was attempted (whether successful or not), caller should exit
        return false;
    }

    // No data in database, nothing to clean up
    LoggingHelper::getInstance().log(LOG_DEBUG, "No policies configured and no data in database.");
    return true;
}

bool SecurityConfigurationAssessment::handleAllPoliciesRemoved()
{
    LoggingHelper::getInstance().log(LOG_DEBUG,
                                     "All SCA policies removed from configuration. Initiating DataClean process.");

    if (!m_spSyncProtocol)
    {
        LoggingHelper::getInstance().log(LOG_ERROR,
                                         "Sync protocol not initialized, cannot send DataClean notification");
        return false;
    }

    // Wait for any in-progress sync to complete before sending DataClean.
    // We must lock m_pauseMutex BEFORE checking m_syncInProgress to avoid TOCTOU race:
    // Otherwise, sync could start between our check and the wait.
    {
        std::unique_lock<std::mutex> lock(m_pauseMutex);

        if (m_syncInProgress.load())
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Waiting for sync to complete before DataClean...");
        }

        m_pauseCv.wait(lock, [this] { return !m_syncInProgress.load() || !m_keepRunning; });

        if (!m_keepRunning)
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "DataClean aborted - module shutdown during sync wait");
            return false;
        }
    }

    LoggingHelper::getInstance().log(LOG_DEBUG, "Proceeding with DataClean (sync not in progress)");

    // Send DataClean notification to manager with retry logic (similar to FIM)
    std::vector<std::string> indices = {SCA_SYNC_INDEX};
    bool dataCleanSent = false;

    while (!dataCleanSent && m_keepRunning)
    {
        dataCleanSent = m_spSyncProtocol->notifyDataClean(indices);

        if (!dataCleanSent && m_keepRunning)
        {
            LoggingHelper::getInstance().log(LOG_DEBUG,
                                             "DataClean notification failed, retrying after scan interval...");

            // Wait for scan interval before retrying, using cv for immediate wake-up on Stop()
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait_for(lock, m_scanInterval, [this] { return !m_keepRunning; });
        }
    }

    if (dataCleanSent)
    {
        LoggingHelper::getInstance().log(LOG_INFO, "DataClean notification sent successfully for SCA index");

        // Delete both databases (sync protocol DB and SCA DB) like FIM does
        deleteDatabase();
        LoggingHelper::getInstance().log(LOG_DEBUG, "SCA databases deleted");

        // Set flag to exit after DataClean
        m_exitAfterDataClean.store(true);
        return true;
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_DEBUG,
                                         "DataClean notification aborted due to module shutdown");
        return false;
    }
}

// LCOV_EXCL_STOP
