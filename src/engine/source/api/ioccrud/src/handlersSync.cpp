
#include <api/ioccrud/handlers.hpp>

#include <atomic>
#include <fstream>
#include <memory>
#include <random>
#include <sstream>
#include <unordered_set>

#include <fmt/format.h>

#include <base/logging.hpp>
#include <base/utils/generator.hpp>
#include <eMessages/engine.pb.h>
#include <eMessages/ioc.pb.h>
#include <kvdbioc/helpers.hpp>

namespace api::ioccrud::handlers
{

namespace eIoc = com::wazuh::api::engine::ioc;
namespace eEngine = com::wazuh::api::engine;

namespace
{
// Global flag to track if a synchronization is in progress
std::atomic<bool> g_syncInProgress {false};

/**
 * @brief Perform IOC synchronization from a file
 *
 * @param weakKvdbManager Weak pointer to KVDB Manager
 * @param filePath Path to the ndjson file containing IOCs
 */
void performIOCSync(std::weak_ptr<::kvdbioc::IKVDBManager> weakKvdbManager, const std::string& filePath)
{
    auto lambdaName = logging::getLambdaName("syncIoc", "asyncTask");
    LOG_INFO_L(lambdaName.c_str(), "Starting IOC synchronization from file: {}", filePath);

    // Ensure the flag is released when task finishes (RAII pattern)
    struct SyncGuard
    {
        ~SyncGuard() { g_syncInProgress.store(false); }
    } guard;

    auto kvdbManager = weakKvdbManager.lock();
    if (!kvdbManager)
    {
        LOG_WARNING_L(lambdaName.c_str(), "KVDB Manager is not available, aborting IOC sync");
        return;
    }

    try
    {
        // Open the ndjson file
        std::ifstream file(filePath);
        if (!file.is_open())
        {
            LOG_WARNING_L(lambdaName.c_str(), "Failed to open file: {}", filePath);
            return;
        }

        // Generate random suffix for temporary databases
        const std::string tmpSuffix = "_tmp_" + base::utils::generators::randomHexString(4);
        std::unordered_set<std::string> tempDatabases;

        // Process file line by line
        std::string line;
        size_t lineNumber = 0;
        size_t processedLines = 0;
        while (std::getline(file, line))
        {
            ++lineNumber;

            // Skip empty lines
            if (line.empty())
            {
                continue;
            }

            try
            {
                // Parse JSON line
                json::Json iocDoc(line);

                // Extract DB name and key using helpers
                auto [dbName, key] = kvdbioc::details::getDbAndKeyFromIOC(iocDoc);

                // Create temporary DB name
                std::string tmpDbName = dbName + tmpSuffix;

                // Create temporary database if it doesn't exist
                if (tempDatabases.find(tmpDbName) == tempDatabases.end())
                {
                    if (!kvdbManager->exists(tmpDbName))
                    {
                        kvdbManager->add(tmpDbName);
                    }
                    tempDatabases.insert(tmpDbName);
                }

                // Update value in DB
                kvdbioc::details::updateValueInDB(kvdbManager, tmpDbName, key, iocDoc);
                ++processedLines;
            }
            catch (const std::exception& e)
            {
                LOG_WARNING_L(lambdaName.c_str(), "Error processing line {}: {}", lineNumber, e.what());
                file.close();
                return;
            }
        }

        file.close();
        LOG_DEBUG_L(lambdaName.c_str(), "Processed {} IOC entries from file", processedLines);

        // Perform hot-swap for each temporary database to production
        for (const auto& tmpDbName : tempDatabases)
        {
            // Extract original DB name by removing the temporary suffix
            std::string originalDbName = tmpDbName.substr(0, tmpDbName.length() - tmpSuffix.length());

            // If the target DB doesn't exist, create it first
            if (!kvdbManager->exists(originalDbName))
            {
                kvdbManager->add(originalDbName);
            }

            // Hot-swap: move tmp DB to production
            kvdbManager->hotSwap(tmpDbName, originalDbName);
            LOG_DEBUG_L(lambdaName.c_str(), "Hot-swap completed for DB: {}", originalDbName);
        }

        LOG_INFO_L(
            lambdaName.c_str(), "IOC synchronization completed successfully. {} DBs updated.", tempDatabases.size());
    }
    catch (const std::exception& e)
    {
        LOG_WARNING_L(lambdaName.c_str(), "IOC sync failed: {}", e.what());
    }
}

} // namespace

adapter::RouteHandler syncIoc(const std::shared_ptr<::kvdbioc::IKVDBManager>& kvdbManager,
                              const std::shared_ptr<scheduler::IScheduler>& scheduler)
{
    return [weakKvdbManager = std::weak_ptr<::kvdbioc::IKVDBManager>(kvdbManager),
            weakScheduler = std::weak_ptr<scheduler::IScheduler>(scheduler)](const httplib::Request& req,
                                                                             httplib::Response& res)
    {
        using RequestType = eIoc::UpdateIoc_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // Get handler and parse request
        auto result =
            adapter::getReqAndHandler<RequestType, ResponseType, ::kvdbioc::IKVDBManager>(req, weakKvdbManager);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [kvdbManager, protoReq] = adapter::getRes(result);

        // Validate path is not empty
        if (protoReq.path().empty())
        {
            res = adapter::userErrorResponse<ResponseType>("Field /path cannot be empty");
            return;
        }

        const std::string filePath = protoReq.path();
        // const std::string& fileHash = protoReq.hash(); // TODO: Use hash for optimization

        // Check if synchronization is already in progress
        bool expected = false;
        if (!g_syncInProgress.compare_exchange_strong(expected, true))
        {
            res = adapter::userErrorResponse<ResponseType>("IOC synchronization already in progress");
            return;
        }

        // Verify file exists before scheduling the task
        std::ifstream fileCheck(filePath);
        if (!fileCheck.is_open())
        {
            g_syncInProgress.store(false); // Release the semaphore
            res = adapter::userErrorResponse<ResponseType>(fmt::format("File not found: {}", filePath));
            return;
        }
        fileCheck.close();

        // Get scheduler reference
        auto schedulerRef = weakScheduler.lock();
        if (!schedulerRef)
        {
            g_syncInProgress.store(false); // Release the semaphore
            res = adapter::internalErrorResponse<ResponseType>("Scheduler is not available");
            return;
        }

        // Schedule asynchronous task for IOC synchronization
        try
        {
            scheduler::TaskConfig taskConfig {.interval = 0,    // One-time task (execute as soon as possible)
                                              .CPUPriority = 0, // Normal priority
                                              .timeout = 0,     // No timeout
                                              .taskFunction = [weakKvdbManager, filePath]()
                                              {
                                                  performIOCSync(weakKvdbManager, filePath);
                                              }};

            // Schedule the task with a unique name
            const std::string taskName = "ioc-sync-" + base::utils::generators::randomHexString(8);
            schedulerRef->scheduleTask(taskName, std::move(taskConfig));

            // Return success immediately (task will run asynchronously)
            ResponseType eResponse;
            eResponse.set_status(eEngine::ReturnStatus::OK);
            res = adapter::userResponse(eResponse);
        }
        catch (const std::exception& e)
        {
            g_syncInProgress.store(false); // Release the semaphore on error
            res =
                adapter::userErrorResponse<ResponseType>(fmt::format("Failed to schedule IOC sync task: {}", e.what()));
            return;
        }
    };
}

} // namespace api::ioccrud::handlers
