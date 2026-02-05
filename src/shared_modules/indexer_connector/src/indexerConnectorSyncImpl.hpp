/*
 * Wazuh - Indexer connector implementation.
 * Copyright (C) 2015, Wazuh Inc.
 * July 2, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "IURLRequest.hpp"
#include "external/nlohmann/json.hpp"
#include "indexerConnector.hpp"
#include "keyStore.hpp"
#include "loggerHelper.h"
#include "reflectiveJson.hpp"
#include "secureCommunication.hpp"
#include "shared_modules/utils/certHelper.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <map>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

static std::mutex G_CREDENTIAL_MUTEX;

constexpr auto DEFAULT_PATH {"tmp/root-ca-merged.pem"};
constexpr auto INDEXER_COLUMN {"indexer"};
constexpr auto USER_KEY {"username"};
constexpr auto PASSWORD_KEY {"password"};

constexpr auto HTTP_OK {200};
constexpr auto HTTP_CREATED {201};
constexpr auto HTTP_NOT_FOUND {404};
constexpr auto HTTP_VERSION_CONFLICT {409};
constexpr auto HTTP_CONTENT_LENGTH {413};
constexpr auto HTTP_TOO_MANY_REQUESTS {429};

// JSON structure components for bulk operations
constexpr auto INDEX_OPERATION_PREFIX {20};  // {"index":{"_index":"
constexpr auto DELETE_OPERATION_PREFIX {21}; // {"delete":{"_index":"
constexpr auto ID_FIELD_PREFIX {8};          // ","_id":"
constexpr auto DELETE_ID_FIELD_PREFIX {9};   // ","_id":"
constexpr auto CLOSING_BRACES {2};           // "}}
constexpr auto NEWLINE_CHAR {1};             // \n

// Overhead is the fixed JSON scaffolding for one bulk item:
// {"index":{"_index":"<index>","_id":"<id>"}}
constexpr auto FORMATTED_LENGTH {INDEX_OPERATION_PREFIX + ID_FIELD_PREFIX + CLOSING_BRACES + CLOSING_BRACES +
                                 NEWLINE_CHAR};
// Overhead for delete operations:
// {"delete":{"_index":"<index>","_id":"<id>"}}
constexpr auto DELETE_FORMATTED_LENGTH {DELETE_OPERATION_PREFIX + DELETE_ID_FIELD_PREFIX + CLOSING_BRACES +
                                        NEWLINE_CHAR};

/**
 * @brief Appends an ID to bulkData, escaping special characters if necessary
 * @param bulkData The string to append the ID to
 * @param id The ID to append (will be escaped if needed)
 */
inline void appendEscapedId(std::string& bulkData, std::string_view id)
{
    if (needEscape(id))
    {
        std::string escapedId;
        escapeJSONString(id, escapedId);
        bulkData.append(escapedId);
    }
    else
    {
        bulkData.append(id);
    }
}

/**
 * @brief Validates bulk API response at document level
 * @param response The bulk API response JSON string
 * @return true if all operations succeeded (or had acceptable version conflicts), false otherwise
 * @throws std::exception if response parsing fails
 *
 * This function validates each document in the bulk response individually.
 * It treats version conflicts where the same document version already exists as success.
 * Memory-safe: uses nlohmann::json which handles large documents efficiently.
 */
inline bool validateBulkResponse(const std::string& response)
{
    try
    {
        // Parse response - nlohmann::json handles large documents efficiently
        auto responseJson = nlohmann::json::parse(response);

        // Check if response has errors flag
        if (!responseJson.contains("errors"))
        {
            logDebug2(IC_NAME, "Bulk response missing 'errors' field, treating as success");
            return true;
        }

        // If no errors reported, success
        if (!responseJson["errors"].get<bool>())
        {
            logDebug2(IC_NAME, "Bulk operation completed with no errors");
            return true;
        }

        // Errors were reported, validate each item
        if (!responseJson.contains("items") || !responseJson["items"].is_array())
        {
            logError(IC_NAME, "Bulk response has errors but missing 'items' array");
            return false;
        }

        size_t totalItems = responseJson["items"].size();
        size_t successCount = 0;
        size_t versionConflictAcceptedCount = 0;
        size_t realFailureCount = 0;

        // Validate each item individually
        for (const auto& item : responseJson["items"])
        {
            // Each item is an object with one key (operation type: index, delete, update, create)
            if (item.empty())
            {
                realFailureCount++;
                continue;
            }

            // Get the first (and only) key-value pair
            auto it = item.begin();
            const auto& operation = it.key(); // "index", "delete", etc.
            const auto& result = it.value();

            // Check status code
            if (!result.contains("status"))
            {
                logError(IC_NAME, "Item missing status field");
                realFailureCount++;
                continue;
            }

            int status = result["status"].get<int>();

            // Success statuses
            if (status == HTTP_OK || status == HTTP_CREATED)
            {
                successCount++;
                continue;
            }

            // Version conflict - check if it's the acceptable type
            if (status == HTTP_VERSION_CONFLICT)
            {
                bool isAcceptableConflict = false;

                // Check if this is a version_conflict_engine_exception
                if (result.contains("error"))
                {
                    const auto& error = result["error"];
                    if (error.contains("type") && error["type"].is_string())
                    {
                        std::string errorType = error["type"].get<std::string>();
                        // version_conflict_engine_exception means document version already exists
                        // This is acceptable for inventory sync - treat as success
                        if (errorType == "version_conflict_engine_exception")
                        {
                            isAcceptableConflict = true;
                            versionConflictAcceptedCount++;
                            logDebug2(IC_NAME,
                                      "Document version conflict (same version already indexed) for %s operation - "
                                      "treating as success",
                                      operation.c_str());
                        }
                    }
                }

                if (!isAcceptableConflict)
                {
                    // Version conflict without the expected error type - treat as failure
                    logWarn(IC_NAME,
                            "Version conflict without version_conflict_engine_exception for %s operation",
                            operation.c_str());
                    realFailureCount++;
                }
                continue;
            }

            // Any other error status is a real failure
            std::string errorMsg = "Unknown error";
            if (result.contains("error"))
            {
                const auto& error = result["error"];
                if (error.is_string())
                {
                    errorMsg = error.get<std::string>();
                }
                else if (error.is_object() && error.contains("reason"))
                {
                    errorMsg = error["reason"].get<std::string>();
                }
            }

            logError(IC_NAME,
                     "Indexing failure for %s operation (status %d): %s",
                     operation.c_str(),
                     status,
                     errorMsg.c_str());
            realFailureCount++;
        }

        // Log summary
        logInfo(IC_NAME,
                "Bulk operation summary: %zu total, %zu success, %zu acceptable version conflicts, %zu failures",
                totalItems,
                successCount,
                versionConflictAcceptedCount,
                realFailureCount);

        // Return success only if no real failures occurred
        return realFailureCount == 0;
    }
    catch (const nlohmann::json::exception& e)
    {
        logError(IC_NAME, "Failed to parse bulk response: %s", e.what());
        return false;
    }
    catch (const std::exception& e)
    {
        logError(IC_NAME, "Error validating bulk response: %s", e.what());
        return false;
    }
}

template<typename TSelector,
         typename THttpRequest,
         size_t MaxBulkSize = 10 * 1024 * 1024,
         size_t RetryDelay = 1,
         size_t FlushInterval = 20>
class IndexerConnectorSyncImpl final
{
    SecureCommunication m_secureCommunication;
    std::unique_ptr<TSelector> m_selector;
    THttpRequest* m_httpRequest;
    std::string m_bulkData;
    std::map<std::string, nlohmann::json, std::less<>> m_deleteByQuery;
    std::vector<std::function<void()>> m_notify;
    std::chrono::steady_clock::time_point m_lastBulkTime;
    std::condition_variable m_cv;
    std::mutex m_mutex;
    std::thread m_bulkThread;
    std::atomic<bool> m_stopping {false};
    std::vector<size_t> m_boundaries;

    void processBulk()
    {
        bool needToRetry = false;
        if (m_bulkData.empty() && m_deleteByQuery.empty())
        {
            throw IndexerConnectorException("No data to process");
        }

        auto serverUrl = m_selector->getNext();
        const auto onSuccessDeleteByQuery = [](const std::string& response)
        {
            logDebug2(IC_NAME, "Response: %s", response.c_str());
        };

        const auto onErrorDeleteByQuery =
            [this](const std::string& error, const long statusCode, const std::string& responseBody)
        {
            if (statusCode == HTTP_NOT_FOUND)
            {
                // Index doesn't exist - this is OK, nothing to delete
                logDebug2(IC_NAME, "Index not found (404) for deleteByQuery - nothing to delete, continuing.");
                return;
            }
            else if (statusCode == HTTP_VERSION_CONFLICT)
            {
                logDebug2(IC_NAME, "Document version conflict for deleteByQuery - continuing.");
                // For deleteByQuery, we don't retry - just log and continue
                return;
            }
            else if (statusCode == HTTP_TOO_MANY_REQUESTS)
            {
                logDebug2(IC_NAME, "Too many requests for deleteByQuery - continuing.");
                // For deleteByQuery, we don't retry - just log and continue
                return;
            }
            else
            {
                logError(IC_NAME, "deleteByQuery error: %s, status code: %ld.", error.c_str(), statusCode);
                m_bulkData.clear();
                m_lastBulkTime = std::chrono::steady_clock::now();
                throw IndexerConnectorException(error);
            }
        };

        // Track if we have pending deleteByQuery operations that need notification
        const bool hasDeleteByQuery = !m_deleteByQuery.empty();

        for (const auto& [index, query] : m_deleteByQuery)
        {
            std::string url;
            url += serverUrl;
            url += "/";
            url += index;
            url += "/_delete_by_query";
            logDebug2(IC_NAME, "Deleting by query: %s", url.c_str());
            m_httpRequest->post(
                RequestParameters {
                    .url = HttpURL(url), .data = query.dump(), .secureCommunication = m_secureCommunication},
                PostRequestParameters {.onSuccess = onSuccessDeleteByQuery, .onError = onErrorDeleteByQuery},
                {});
        }

        const auto onSuccess = [this, &needToRetry](const std::string& response)
        {
            logDebug2(IC_NAME, "Response: %s", response.c_str());

            // Validate bulk response at document level
            if (!validateBulkResponse(response))
            {
                logError(IC_NAME, "Bulk operation had indexing failures");
                m_bulkData.clear();
                m_boundaries.clear();
                m_lastBulkTime = std::chrono::steady_clock::now();
                throw IndexerConnectorException("Bulk operation had indexing failures");
            }

            // All documents processed successfully (including acceptable version conflicts)
            for (const auto& notify : m_notify)
            {
                notify();
            }
            m_notify.clear();
            needToRetry = false;
        };

        const auto onError = [this, &needToRetry](const std::string& error,
                                                  const long statusCode,
                                                  const std::string& responseBody) -> void
        {
            logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
            if (statusCode == HTTP_CONTENT_LENGTH)
            {
                logDebug2(IC_NAME, "Received 413 error (Payload Too Large). Splitting bulk data.");
                if (const size_t currentOperations = m_boundaries.size(); currentOperations <= 1)
                {
                    logError(IC_NAME,
                             "Unable to send data even with single operation. "
                             "Consider increasing http.max_content_length in OpenSearch settings. "
                             "Current data size: %zu bytes.",
                             m_bulkData.size());
                    m_bulkData.clear();
                    m_boundaries.clear();
                    throw IndexerConnectorException("Single operation exceeds server payload limits");
                }
                splitAndProcessBulk();
            }
            else if (statusCode == HTTP_VERSION_CONFLICT)
            {
                logDebug2(IC_NAME, "Document version conflict, retrying in 1 second.");
                needToRetry = true;
            }
            else if (statusCode == HTTP_TOO_MANY_REQUESTS)
            {
                needToRetry = true;
                logDebug2(IC_NAME, "Too many requests, retrying in 1 second.");
            }
            else
            {
                logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
                m_bulkData.clear();
                m_boundaries.clear();
                m_lastBulkTime = std::chrono::steady_clock::now();
                throw IndexerConnectorException(error);
            }
        };

        // Only process bulk data if there is data to process
        if (!m_bulkData.empty())
        {
            do
            {
                if (m_stopping.load())
                {
                    logDebug2(IC_NAME, "Stopping requested, aborting bulk processing");
                    return;
                }

                std::string url;
                url += m_selector->getNext();
                url += "/_bulk";
                logDebug2(IC_NAME, "Sending bulk data to: %s", url.c_str());
                logDebug2(IC_NAME, "Bulk data: %s", m_bulkData.c_str());

                m_httpRequest->post(RequestParameters {.url = HttpURL(url),
                                                       .data = m_bulkData,
                                                       .secureCommunication = m_secureCommunication},
                                    PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                                    {});
                if (needToRetry && RetryDelay > 0)
                {
                    std::this_thread::sleep_for(std::chrono::seconds(RetryDelay));
                }
            } while (needToRetry);
        }

        // If we only had deleteByQuery operations (no bulk data), trigger notify callbacks
        // since they weren't triggered by the bulk POST onSuccess callback
        if (hasDeleteByQuery && m_bulkData.empty())
        {
            for (const auto& notify : m_notify)
            {
                notify();
            }
            m_notify.clear();
        }

        m_bulkData.clear();
        m_boundaries.clear();
        m_deleteByQuery.clear();
        m_lastBulkTime = std::chrono::steady_clock::now();
    }

    void splitAndProcessBulk()
    {
        const size_t totalOperations = m_boundaries.size();
        if (totalOperations <= 1)
        {
            throw IndexerConnectorException(
                "Cannot split bulk data with less than two operations. Consider increasing http.max_content_length in "
                "Wazuh-Indexer settings.");
        }
        logDebug2(IC_NAME, "Splitting %zu operations into two halves", totalOperations);

        const size_t midPoint = totalOperations / 2;
        std::span<size_t> firstBoundaries(m_boundaries.begin(), m_boundaries.begin() + midPoint);
        const size_t firstEndPos = m_boundaries[midPoint - 1];
        std::string_view firstHalf(m_bulkData.data(), firstEndPos);
        std::span<size_t> secondBoundaries(m_boundaries.begin() + midPoint, m_boundaries.end());
        const size_t secondStartPos = m_boundaries[midPoint - 1];
        std::string_view secondHalf(m_bulkData.data() + secondStartPos, m_bulkData.size() - secondStartPos);
        bool allProcessed = true;

        if (!firstHalf.empty() && !firstBoundaries.empty())
        {
            try
            {
                processBulkChunk(firstHalf, firstBoundaries);
            }
            catch (const IndexerConnectorException& e)
            {
                logError(IC_NAME, "Failed to process first half: %s", e.what());
                allProcessed = false;
                throw;
            }
        }
        if (!secondHalf.empty() && !secondBoundaries.empty())
        {
            try
            {
                processBulkChunk(secondHalf, secondBoundaries);
            }
            catch (const IndexerConnectorException& e)
            {
                logError(IC_NAME, "Failed to process second half: %s", e.what());
                allProcessed = false;
                throw;
            }
        }
        if (allProcessed)
        {
            for (const auto& notify : m_notify)
            {
                notify();
            }
            m_notify.clear();
        }
        m_bulkData.clear();
        m_boundaries.clear();
        m_lastBulkTime = std::chrono::steady_clock::now();
    }

    void processBulkChunk(std::string_view data, const std::span<size_t>& boundaries)
    {
        std::string url;
        url += m_selector->getNext();
        url += "/_bulk";
        bool needToRetry = false;

        const auto onSuccess = [](const std::string& response)
        {
            logDebug2(IC_NAME, "Chunk processed successfully: %s", response.c_str());

            // Validate bulk response at document level
            if (!validateBulkResponse(response))
            {
                logError(IC_NAME, "Bulk chunk operation had indexing failures");
                throw IndexerConnectorException("Bulk chunk operation had indexing failures");
            }
        };
        const auto onError = [this, &needToRetry, boundaries](
                                 const std::string& error, const long statusCode, const std::string& responseBody)
        {
            logError(IC_NAME, "Chunk processing failed: %s, status code: %ld", error.c_str(), statusCode);
            if (statusCode == HTTP_CONTENT_LENGTH)
            {
                if (boundaries.size() > 1)
                {
                    logDebug2(IC_NAME, "Chunk still too large, splitting recursively");
                    const size_t midPoint = boundaries.size() / 2;
                    std::span<size_t> firstBoundaries(boundaries.begin(),
                                                      boundaries.begin() + static_cast<long>(midPoint));
                    const size_t firstEndPos = boundaries[midPoint - 1];
                    std::string_view firstHalf(m_bulkData.data(), firstEndPos);
                    std::span<size_t> secondBoundaries(boundaries.begin() + static_cast<long>(midPoint),
                                                       boundaries.end());
                    const size_t secondStartPos = boundaries[midPoint - 1];
                    std::string_view secondHalf(m_bulkData.data() + secondStartPos, m_bulkData.size() - secondStartPos);
                    processBulkChunk(firstHalf, firstBoundaries);
                    processBulkChunk(secondHalf, secondBoundaries);
                    return;
                }
                logError(IC_NAME, "Single operation too large for server limits");
                throw IndexerConnectorException("Single operation exceeds server limits");
            }
            else if (statusCode == HTTP_VERSION_CONFLICT)
            {
                logDebug2(IC_NAME, "Document version conflict, retrying in 1 second.");
                needToRetry = true;
            }
            else if (statusCode == HTTP_TOO_MANY_REQUESTS)
            {
                logDebug2(IC_NAME, "Too many requests, retrying in 1 second.");
                needToRetry = true;
            }
            else
            {
                throw IndexerConnectorException(error);
            }
        };
        do
        {
            if (m_stopping.load())
            {
                logDebug2(IC_NAME, "Stopping requested, aborting bulk chunk processing");
                return;
            }
            needToRetry = false;
            logDebug2(IC_NAME, "Sending bulk chunk to: %s", url.c_str());
            m_httpRequest->post(RequestParametersStringView {.url = HttpURL(url),
                                                             .data = data,
                                                             .secureCommunication = m_secureCommunication},
                                PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                                {});
            if (needToRetry && RetryDelay > 0)
            {
                std::this_thread::sleep_for(std::chrono::seconds(RetryDelay));
            }
        } while (needToRetry);
    }

public:
    ~IndexerConnectorSyncImpl()
    {
        {
            std::lock_guard timeoutLock(m_mutex);
            m_stopping.store(true);
            m_cv.notify_one();
        }
        if (m_bulkThread.joinable())
        {
            m_bulkThread.join();
        }
    }

    explicit IndexerConnectorSyncImpl(
        const nlohmann::json& config,
        const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
            logFunction,
        THttpRequest* httpRequest = nullptr,
        std::unique_ptr<TSelector> selector = nullptr)
        : m_httpRequest(httpRequest ? httpRequest : &THttpRequest::instance())
    {
        if (logFunction)
        {
            Log::assignLogFunction(logFunction);
        }

        std::string caRootCertificate;
        std::string sslCertificate;
        std::string sslKey;
        if (config.contains("ssl"))
        {
            if (config.at("ssl").contains("certificate_authorities") &&
                !config.at("ssl").at("certificate_authorities").empty())
            {
                std::vector<std::string> filePaths =
                    config.at("ssl").at("certificate_authorities").get<std::vector<std::string>>();
                if (filePaths.size() > 1)
                {
                    Utils::CertHelper::mergeCaRootCertificates(filePaths, caRootCertificate, DEFAULT_PATH);
                }
                else
                {
                    if (std::filesystem::exists(filePaths.front()))
                    {
                        caRootCertificate = filePaths.front();
                    }
                    else
                    {
                        throw IndexerConnectorException("The CA root certificate file: '" + filePaths.front() +
                                                        "' does not exist.");
                    }
                }
            }
            if (config.at("ssl").contains("certificate"))
            {
                sslCertificate = config.at("ssl").at("certificate").get_ref<const std::string&>();
            }
            if (config.at("ssl").contains("key"))
            {
                sslKey = config.at("ssl").at("key").get_ref<const std::string&>();
            }
        }

        if (!config.contains("hosts") || config.at("hosts").empty())
        {
            throw IndexerConnectorException("No hosts found in the configuration");
        }

        std::lock_guard lock(G_CREDENTIAL_MUTEX);
        static auto username = Keystore::get(INDEXER_COLUMN, USER_KEY);
        static auto password = Keystore::get(INDEXER_COLUMN, PASSWORD_KEY);
        if (username.empty() && password.empty())
        {
            username = "admin";
            password = "admin";
            logWarn(IC_NAME, "No username and password found in the keystore, using default values.");
        }
        if (username.empty())
        {
            username = "admin";
            logWarn(IC_NAME, "No username found in the keystore, using default value.");
        }
        m_secureCommunication = SecureCommunication::builder();
        m_secureCommunication.basicAuth(username + ":" + password)
            .sslCertificate(sslCertificate)
            .sslKey(sslKey)
            .caRootCertificate(caRootCertificate);

        m_selector =
            selector ? std::move(selector) : std::make_unique<TSelector>(config.at("hosts"), 10, m_secureCommunication);

        m_lastBulkTime = std::chrono::steady_clock::now();
        m_bulkThread = std::thread(
            [this]()
            {
                std::unique_lock timeoutLock(m_mutex);
                while (!m_stopping.load())
                {
                    auto timeoutResult = m_cv.wait_for(
                        timeoutLock, std::chrono::seconds(FlushInterval), [this] { return m_stopping.load(); });

                    // Process bulk data or deleteByQuery if there's data to process
                    if (!m_bulkData.empty() || !m_deleteByQuery.empty())
                    {
                        try
                        {
                            processBulk();
                        }
                        catch (const IndexerConnectorException& e)
                        {
                            logError(IC_NAME, "Error processing bulk: %s", e.what());
                        }
                        catch (const std::exception& e)
                        {
                            logDebug2(IC_NAME, "Cannot process bulk: %s", e.what());
                        }
                    }

                    // Exit if stopping was requested
                    if (timeoutResult || m_stopping.load())
                    {
                        break;
                    }
                }
            });
    }

    void deleteByQuery(const std::string& index, const std::string& agentId)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto [it, success] = m_deleteByQuery.try_emplace(index, nlohmann::json::object());
        it->second["query"]["bool"]["filter"]["terms"]["wazuh.agent.id"].push_back(agentId);
    }

    void executeUpdateByQuery(const std::vector<std::string>& indices, const nlohmann::json& updateQuery)
    {
        // Join indices with comma
        std::string indexList;
        for (size_t i = 0; i < indices.size(); ++i)
        {
            if (i > 0)
            {
                indexList.append(",");
            }
            indexList.append(indices[i]);
        }

        bool needToRetry = false;

        const auto onSuccess = [this](const std::string& response)
        {
            logDebug2(IC_NAME, "Update by query response: %s", response.c_str());

            // Parse response to extract update statistics and check for failures
            try
            {
                auto responseJson = nlohmann::json::parse(response);

                // Check for failures first
                if (responseJson.contains("failures") && !responseJson["failures"].empty())
                {
                    auto failures = responseJson["failures"];
                    logError(IC_NAME, "Update by query completed with %zu failures", failures.size());

                    // Log first few failures for debugging
                    size_t logCount = std::min<size_t>(failures.size(), 3);
                    for (size_t i = 0; i < logCount; ++i)
                    {
                        logError(IC_NAME, "Failure %zu: %s", i + 1, failures[i].dump().c_str());
                    }
                }

                if (responseJson.contains("updated") && responseJson.contains("total"))
                {
                    auto updated = responseJson["updated"].get<int>();
                    auto total = responseJson["total"].get<int>();
                    auto noops = responseJson.contains("noops") ? responseJson["noops"].get<int>() : 0;
                    auto failures = responseJson.contains("failures") ? responseJson["failures"].size() : 0;

                    if (updated > 0)
                    {
                        logInfo(IC_NAME,
                                "Update by query completed: %d documents updated out of %d total (%d unchanged, %zu "
                                "failures)",
                                updated,
                                total,
                                noops,
                                failures);
                    }
                    else
                    {
                        logDebug2(IC_NAME,
                                  "Update by query completed: no documents needed updating (all %d documents already "
                                  "up-to-date, %zu failures)",
                                  total,
                                  failures);
                    }
                }
            }
            catch (const std::exception& e)
            {
                logDebug2(IC_NAME, "Could not parse update by query response: %s", e.what());
            }

            // Notify registered callbacks on success
            for (const auto& notify : m_notify)
            {
                notify();
            }
            m_notify.clear();
        };

        const auto onError =
            [this, &needToRetry](const std::string& url, const long statusCode, const std::string& error)
        {
            if (statusCode == HTTP_VERSION_CONFLICT)
            {
                logDebug2(IC_NAME, "Document version conflict, retrying in 1 second.");
                needToRetry = true;
            }
            else if (statusCode == HTTP_TOO_MANY_REQUESTS)
            {
                needToRetry = true;
                logDebug2(IC_NAME, "Too many requests, retrying in 1 second.");
            }
            else
            {
                logError(IC_NAME, "Update by query failed: %s, status code: %ld.", error.c_str(), statusCode);
                m_notify.clear();
                throw IndexerConnectorException(error);
            }
        };

        do
        {
            if (m_stopping.load())
            {
                logDebug2(IC_NAME, "Stopping requested, aborting update by query");
                m_notify.clear();
                return;
            }

            needToRetry = false;
            auto serverUrl = m_selector->getNext();
            std::string url;
            url += serverUrl;
            url += "/";
            url += indexList;
            url += "/_update_by_query";

            m_httpRequest->post(RequestParameters {.url = HttpURL(url),
                                                   .data = updateQuery.dump(),
                                                   .secureCommunication = m_secureCommunication},
                                PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                                {});

            if (needToRetry && RetryDelay > 0)
            {
                std::this_thread::sleep_for(std::chrono::seconds(RetryDelay));
            }
        } while (needToRetry);
    }

    nlohmann::json executeSearchQuery(const std::string& index, const nlohmann::json& searchQuery)
    {
        nlohmann::json resultJson;

        const auto onSuccess = [&resultJson](const std::string& response)
        {
            logDebug2(IC_NAME, "Search query response: %s", response.c_str());
            resultJson = nlohmann::json::parse(response);
        };

        const auto onError = [](const std::string& error, const long statusCode, const std::string&)
        {
            logError(IC_NAME, "Search query failed: %s, status code: %ld", error.c_str(), statusCode);
            throw IndexerConnectorException("Search query failed: " + error);
        };

        auto serverUrl = m_selector->getNext();
        std::string url;
        url += serverUrl;
        url += "/";
        url += index;
        url += "/_search";

        logDebug2(IC_NAME, "Executing search query on: %s", url.c_str());

        m_httpRequest->post(RequestParameters {.url = HttpURL(url),
                                               .data = searchQuery.dump(),
                                               .secureCommunication = m_secureCommunication},
                            PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                            {});

        return resultJson;
    }

    void executeSearchQueryWithPagination(const std::string& index,
                                          const nlohmann::json& query,
                                          std::function<void(const nlohmann::json&)> onResponse)
    {
        nlohmann::json currentQuery = query;
        std::string searchAfter;
        while (true)
        {
            nlohmann::json searchResult = executeSearchQuery(index, currentQuery);

            // Always call the callback, even for empty pages, to notify the caller of each page's result (including
            // empty pages).
            onResponse(searchResult);

            const auto itHits = searchResult.find("hits");
            if (itHits == searchResult.end())
            {
                logDebug2(IC_NAME, "No 'hits' object in response, breaking pagination loop");
                break;
            }

            const auto itInner = itHits->find("hits");
            if (itInner == itHits->end() || !itInner->is_array() || itInner->empty())
            {
                logDebug2(IC_NAME, "No 'hits' array in response or it is empty, breaking pagination loop");
                break;
            }

            const auto& hits = *itInner;
            const auto& lastHit = hits.back();
            const auto itSort = lastHit.find("sort");

            if (itSort != lastHit.end() && itSort->is_array() && !itSort->empty())
            {
                const auto& first_sort_item = itSort->front();
                if (first_sort_item.is_string())
                {
                    searchAfter = first_sort_item.get<std::string>();
                }
                else
                {
                    logDebug2(IC_NAME, "Pagination loop finished: 'sort' field's first element is not a string.");
                    break;
                }
            }
            else
            {
                logDebug2(IC_NAME,
                          "Pagination loop finished: Last hit has no 'sort' field, it is not an array, or it is "
                          "empty.");
                break;
            }

            // If we got less results than requested, this is the last page
            if (currentQuery.contains("size") && hits.size() < currentQuery["size"].template get<size_t>())
            {
                logDebug2(IC_NAME, "Fewer results than page size, breaking pagination loop");
                break;
            }

            // Update query for next page
            auto& sa = currentQuery["search_after"];
            sa = nlohmann::json::array();
            sa.push_back(searchAfter);
        }
    }

    void bulkDelete(std::string_view id, std::string_view index)
    {
        if (constexpr auto FORMATTED_SIZE {DELETE_FORMATTED_LENGTH};
            m_bulkData.length() + FORMATTED_SIZE + index.size() + id.size() > MaxBulkSize)
        {
            processBulk();
        }
        m_bulkData.append(R"({"delete":{"_index":")");
        m_bulkData.append(index);
        m_bulkData.append(R"(","_id":")");
        appendEscapedId(m_bulkData, id);
        m_bulkData.append(R"("}})");
        m_bulkData.append("\n");
        m_boundaries.push_back(m_bulkData.size());
    }
    void bulkIndex(std::string_view id, std::string_view index, std::string_view data)
    {
        bulkIndex(id, index, data, std::string_view());
    }

    void bulkIndex(std::string_view id, std::string_view index, std::string_view data, std::string_view version)
    {
        constexpr auto FORMATTED_SIZE {FORMATTED_LENGTH};
        constexpr auto VERSION_SIZE {32};

        // Validate input parameters
        if (index.empty())
        {
            logError(IC_NAME, "Index name cannot be empty for document: %.*s", static_cast<int>(id.size()), id.data());
            throw IndexerConnectorException("Index name cannot be empty");
        }

        if (data.empty())
        {
            logWarn(IC_NAME,
                    "Empty data provided for document %.*s in index %.*s",
                    static_cast<int>(id.size()),
                    id.data(),
                    static_cast<int>(index.size()),
                    index.data());
        }

        const auto totalSize =
            m_bulkData.length() + FORMATTED_SIZE + VERSION_SIZE + index.size() + id.size() + data.size();

        if (totalSize > MaxBulkSize)
        {
            processBulk();
        }
        m_bulkData.append(R"({"index":{"_index":")");
        m_bulkData.append(index);
        if (!version.empty())
        {
            // In case the version is provided, the id must be provided too
            if (!id.empty())
            {
                m_bulkData.append(R"(","_id":")");
                appendEscapedId(m_bulkData, id);
            }
            else
            {
                logError(IC_NAME, "Id must be provided if version value is provided");
                throw IndexerConnectorException("Id must be provided if version value is provided");
            }

            m_bulkData.append(R"(","version":")");
            m_bulkData.append(version);
            m_bulkData.append(R"(","version_type":"external_gte)");
            logDebug2(IC_NAME,
                      "Using external version %.*s for document %.*s",
                      static_cast<int>(version.size()),
                      version.data(),
                      static_cast<int>(id.size()),
                      id.data());
        }
        else
        {
            if (!id.empty())
            {
                m_bulkData.append(R"(","_id":")");
                appendEscapedId(m_bulkData, id);
            }
            logDebug2(IC_NAME,
                      "No version specified for document %.*s, using default versioning",
                      static_cast<int>(id.size()),
                      id.data());
        }
        m_bulkData.append(R"("}})");
        m_bulkData.append("\n");
        m_bulkData.append(data);
        m_bulkData.append("\n");
        m_boundaries.push_back(m_bulkData.size());
    }

    void flush()
    {
        std::lock_guard lock(m_mutex);
        if (!m_bulkData.empty() || !m_deleteByQuery.empty())
        {
            processBulk();
        }
    }

    [[nodiscard]] std::unique_lock<std::mutex> scopeLock()
    {
        return std::unique_lock<std::mutex> {m_mutex};
    }

    void registerNotify(std::function<void()> callback)
    {
        m_notify.push_back(std::move(callback));
    }

    bool isAvailable() const
    {
        return m_selector->isAvailable();
    }
};
