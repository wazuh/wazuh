
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
#include <iockvdb/helpers.hpp>

namespace api::ioccrud::handlers
{

namespace eIoc = com::wazuh::api::engine::ioc;
namespace eEngine = com::wazuh::api::engine;

namespace detail
{
std::atomic<bool> g_syncInProgress {false}; ///< Flag to indicate if an IOC synchronization is currently in progress

const base::Name IOC_STATUS_DOC {"ioc/remote-status/0"}; // Store document name for IOC sync status
constexpr std::string_view DOC_HASH_KEY = "/hash";       ///< Key to the hash field in the status document
constexpr std::string_view DOC_ERROR_KEY = "/lastError"; ///< Key to the last error field in the status document

/**
 * @brief Helper function to update IOC status in store
 *
 * @param storeRef Shared pointer to Store
 * @param newHash New hash value. If empty, preserves current hash from store.
 * @param lastError Error message (empty string to clear error)
 */
void updateIOCStatus(const std::shared_ptr<store::IStore>& storeRef,
                     const std::string& newHash,
                     const std::string& lastError)
{
    try
    {
        store::Doc statusDoc;

        if (!newHash.empty())
        {
            statusDoc.setString(newHash, DOC_HASH_KEY);
        }
        else
        {
            // Read current hash and preserve it (Empty on malformed documents or read errors)
            auto docResp = storeRef->readDoc(IOC_STATUS_DOC);
            if (!base::isError(docResp))
            {
                auto& doc = base::getResponse(docResp);
                auto currentHash = doc.getString(DOC_HASH_KEY).value_or("");
                statusDoc.setString(currentHash, DOC_HASH_KEY);
            }
            else
            {
                statusDoc.setString("", DOC_HASH_KEY);
            }
        }

        statusDoc.setString(lastError, DOC_ERROR_KEY);
        storeRef->upsertDoc(IOC_STATUS_DOC, statusDoc);
    }
    catch (const std::exception& e)
    {
        auto lambdaName = logging::getLambdaName("syncIoc", "updateStatus");
        LOG_WARNING_L(lambdaName.c_str(), "Failed to update IOC status: {}", e.what());
    }
}

/**
 * @brief Perform IOC synchronization from a file
 *
 * @param weakKvdbManager Weak pointer to KVDB Manager
 * @param weakStore Weak pointer to Store
 * @param filePath Path to the ndjson file containing IOCs
 * @param fileHash Hash of the file being synchronized
 */
void performIOCSync(const std::weak_ptr<::ioc::kvdb::IKVDBManager>& weakKvdbManager,
                    const std::weak_ptr<store::IStore>& weakStore,
                    const std::string& filePath,
                    const std::string& fileHash)
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
        if (auto store = weakStore.lock())
        {
            updateIOCStatus(store, "", "KVDB Manager is not available");
        }
        return;
    }

    auto storeRef = weakStore.lock();
    if (!storeRef)
    {
        LOG_WARNING_L(lambdaName.c_str(), "Store is not available, aborting IOC sync");
        return;
    }

    try
    {
        // Open the ndjson file
        std::ifstream file(filePath);
        if (!file.is_open())
        {
            LOG_WARNING_L(lambdaName.c_str(), "Failed to open file: {}", filePath);
            updateIOCStatus(storeRef, "", fmt::format("Failed to open file: {}", filePath));
            return;
        }

        // Generate random suffix for temporary databases
        const std::string tmpSuffix = "_" + base::utils::generators::randomHexString(4);

        // Initialize all temporary databases at once
        ioc::kvdb::details::initializeDBs(kvdbManager, tmpSuffix);

        // Process file line by line
        std::string line;
        size_t lineNumber = 0;
        size_t processedLines = 0;
        size_t skippedLines = 0;
        std::string lastSkipError;

        // Process the file line by line
        while (std::getline(file, line))
        {
            ++lineNumber;

            // Skip empty lines
            if (line.empty())
                continue;

            try
            {
                // Extract DB name and key from IOC document
                json::Json iocDoc(line);
                auto [dbName, key] = ioc::kvdb::details::getDbAndKeyFromIOC(iocDoc);

                // Create temporary DB name
                std::string tmpDbName = dbName + tmpSuffix;

                // Update value in DB
                ioc::kvdb::details::updateValueInDB(kvdbManager, tmpDbName, key, iocDoc);

                ++processedLines;
            }
            catch (const std::exception& e)
            {
                // Skip this line (unsupported DB type or missing key)
                LOG_DEBUG_L(lambdaName.c_str(), "Skipping line {}: {}", lineNumber, e.what());
                ++skippedLines;
                // Only store the last error to avoid excessive logging, but include line number for context
                lastSkipError = fmt::format("Line {}: {}", lineNumber, e.what());
                continue; // Continue processing next line
            }
        }

        file.close();

        // Log summary of processing
        if (skippedLines > 0)
        {
            LOG_WARNING_L(lambdaName.c_str(),
                          "Processed {} IOC entries, skipped {} invalid lines. Last error: {}",
                          processedLines,
                          skippedLines,
                          lastSkipError);
        }
        else
        {
            LOG_DEBUG_L(lambdaName.c_str(), "Processed {} IOC entries from file", processedLines);
        }

        // Perform hot-swap for ALL temporary databases to production
        size_t dbsUpdated = 0;
        for (const auto& entry : ioc::kvdb::details::IOC_TYPE_TABLE)
        {
            std::string tmpDbName = std::string(entry.dbName) + tmpSuffix;
            std::string originalDbName = std::string(entry.dbName);

            if (!kvdbManager->exists(originalDbName))
            {
                LOG_WARNING_L(
                    lambdaName.c_str(), "Original DB {} does not exist, skipping hot-swap for this DB", originalDbName);
                // Clean up the temporary database since production DB doesn't exist
                try
                {
                    kvdbManager->remove(tmpDbName);
                    LOG_DEBUG_L(lambdaName.c_str(), "Deleted unused temporary DB: {}", tmpDbName);
                }
                catch (const std::exception& e)
                {
                    LOG_WARNING_L(lambdaName.c_str(), "Failed to delete temporary DB {}: {}", tmpDbName, e.what());
                }
                continue;
            }

            // Hot-swap: move tmp DB to production (even if empty)
            kvdbManager->hotSwap(tmpDbName, originalDbName);
            LOG_DEBUG_L(lambdaName.c_str(), "Hot-swap completed for DB: {}", originalDbName);
            ++dbsUpdated;
        }

        LOG_INFO_L(lambdaName.c_str(), "IOC synchronization completed successfully. {} DBs updated.", dbsUpdated);

        // Update the hash in the store after successful synchronization
        std::string message =
            lastSkipError.empty()
                ? std::string("")
                : fmt::format("Completed with {} skipped lines. Last error: {}", skippedLines, lastSkipError);
        updateIOCStatus(storeRef, fileHash, message);
    }
    catch (const std::exception& e)
    {
        LOG_WARNING_L(lambdaName.c_str(), "IOC sync failed: {}", e.what());
        // Store error without updating hash
        updateIOCStatus(storeRef, "", fmt::format("IOC sync failed: {}", e.what()));
    }
}

} // namespace detail

adapter::RouteHandler syncIoc(const std::shared_ptr<::ioc::kvdb::IKVDBManager>& kvdbManager,
                              const std::shared_ptr<scheduler::IScheduler>& scheduler,
                              const std::shared_ptr<store::IStore>& store)
{
    return [weakKvdbManager = std::weak_ptr<::ioc::kvdb::IKVDBManager>(kvdbManager),
            weakScheduler = std::weak_ptr<scheduler::IScheduler>(scheduler),
            weakStore = std::weak_ptr<store::IStore>(store)](const httplib::Request& req, httplib::Response& res)
    {
        using RequestType = eIoc::UpdateIoc_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // Get handler and parse request
        auto result =
            adapter::getReqAndHandler<RequestType, ResponseType, ::ioc::kvdb::IKVDBManager>(req, weakKvdbManager);
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

        // Validate hash is not empty
        if (protoReq.hash().empty())
        {
            res = adapter::userErrorResponse<ResponseType>("Field /hash cannot be empty");
            return;
        }

        const std::string filePath = protoReq.path();
        const std::string fileHash = protoReq.hash();

        // Get store reference
        auto storeRef = weakStore.lock();
        if (!storeRef)
        {
            res = adapter::internalErrorResponse<ResponseType>("Store is not available");
            return;
        }

        // Read current hash from store
        std::string storedHash;
        auto docResp = storeRef->readDoc(detail::IOC_STATUS_DOC);
        if (base::isError(docResp))
        {
            // Document doesn't exist, create it with empty hash
            auto lambdaName = logging::getLambdaName("syncIoc", "handler");
            LOG_DEBUG_L(lambdaName.c_str(), "IOC status document does not exist, will be created on first sync");
            store::Doc statusDoc;
            statusDoc.setString("", detail::DOC_HASH_KEY);
            auto createResult = storeRef->upsertDoc(detail::IOC_STATUS_DOC, statusDoc);
            if (base::isError(createResult))
            {
                LOG_WARNING_L(lambdaName.c_str(),
                              "Failed to create IOC status document: {}",
                              base::getError(createResult).message);
            }
            storedHash = "";
        }
        else
        {
            auto doc = base::getResponse(docResp);
            auto hashOpt = doc.getString(detail::DOC_HASH_KEY);
            storedHash = hashOpt.value_or("");
        }

        // Compare hashes - if they match, no sync needed
        if (fileHash == storedHash)
        {
            auto lambdaName = logging::getLambdaName("syncIoc", "handler");
            LOG_DEBUG_L(
                lambdaName.c_str(), "IOC file hash matches stored hash ({}), skipping synchronization", fileHash);
            ResponseType eResponse;
            eResponse.set_status(eEngine::ReturnStatus::OK);
            eResponse.set_error("IOC data is already up to date");
            res = adapter::userResponse(eResponse);
            return;
        }

        // Check if synchronization is already in progress
        bool expected = false;
        if (!detail::g_syncInProgress.compare_exchange_strong(expected, true))
        {
            res = adapter::userErrorResponse<ResponseType>("IOC synchronization already in progress");
            return;
        }

        // Verify file exists before scheduling the task
        std::ifstream fileCheck(filePath);
        if (!fileCheck.is_open())
        {
            detail::g_syncInProgress.store(false); // Release the semaphore
            res = adapter::userErrorResponse<ResponseType>(fmt::format("File not found: {}", filePath));
            return;
        }
        fileCheck.close();

        // Get scheduler reference
        auto schedulerRef = weakScheduler.lock();
        if (!schedulerRef)
        {
            detail::g_syncInProgress.store(false); // Release the semaphore
            res = adapter::internalErrorResponse<ResponseType>("Scheduler is not available");
            return;
        }

        // Schedule asynchronous task for IOC synchronization
        try
        {
            scheduler::TaskConfig taskConfig {.interval = 0,    // One-time task (execute as soon as possible)
                                              .CPUPriority = 0, // Normal priority
                                              .timeout = 0,     // No timeout
                                              .taskFunction = [weakKvdbManager, weakStore, filePath, fileHash]()
                                              {
                                                  detail::performIOCSync(
                                                      weakKvdbManager, weakStore, filePath, fileHash);
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
            detail::g_syncInProgress.store(false); // Release the semaphore on error
            res =
                adapter::userErrorResponse<ResponseType>(fmt::format("Failed to schedule IOC sync task: {}", e.what()));
            return;
        }
    };
}

adapter::RouteHandler getIocState(const std::shared_ptr<store::IStore>& store)
{
    return [weakStore = std::weak_ptr<store::IStore>(store)](const httplib::Request& req, httplib::Response& res)
    {
        using ResponseType = eIoc::GetIocState_Response;

        // Get store reference
        auto storeRef = weakStore.lock();
        if (!storeRef)
        {
            ResponseType eResponse;
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_hash("");
            eResponse.set_updating(false);
            eResponse.set_lasterror("Store is not available");

            // Convert to JSON manually
            const auto result = eMessage::eMessageToJson<ResponseType>(eResponse);
            if (std::holds_alternative<base::Error>(result))
            {
                res.status = httplib::StatusCode::InternalServerError_500;
                res.set_content("Failed to serialize response", "plain/text");
            }
            else
            {
                res.status = httplib::StatusCode::OK_200;
                res.set_content(std::get<std::string>(result), "application/json");
            }
            return;
        }

        // Read current state from store
        std::string currentHash;
        std::string lastError;
        auto docResp = storeRef->readDoc(detail::IOC_STATUS_DOC);
        if (base::isError(docResp))
        {
            // Document doesn't exist yet
            currentHash = "";
            lastError = "";
        }
        else
        {
            auto doc = base::getResponse(docResp);
            currentHash = doc.getString(detail::DOC_HASH_KEY).value_or("");
            lastError = doc.getString(detail::DOC_ERROR_KEY).value_or("");
        }

        // Check if synchronization is in progress
        bool updating = detail::g_syncInProgress.load();

        // Build response
        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.set_hash(currentHash);
        eResponse.set_updating(updating);
        eResponse.set_lasterror(lastError);

        // Convert to JSON manually
        const auto result = eMessage::eMessageToJson<ResponseType>(eResponse);
        if (std::holds_alternative<base::Error>(result))
        {
            res.status = httplib::StatusCode::InternalServerError_500;
            res.set_content("Failed to serialize response", "plain/text");
        }
        else
        {
            res.status = httplib::StatusCode::OK_200;
            res.set_content(std::get<std::string>(result), "application/json");
        }
    };
}

} // namespace api::ioccrud::handlers
