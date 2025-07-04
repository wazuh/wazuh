/*
 * Wazuh - Indexer connector.
 * Copyright (C) 2015, Wazuh Inc.
 * June 2, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "HTTPRequest.hpp"
#include "indexerConnector.hpp"
#include "keyStore.hpp"
#include "loggerHelper.h"
#include "serverSelector.hpp"
#include <filesystem>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <stringHelper.h>
#include <unistd.h>

constexpr auto USER_GROUP {"wazuh"};
constexpr auto DEFAULT_PATH {"tmp/root-ca-merged.pem"};
constexpr auto INDEXER_COLUMN {"indexer"};
constexpr auto USER_KEY {"username"};
constexpr auto PASSWORD_KEY {"password"};

constexpr auto HTTP_CONTENT_LENGTH {413};
constexpr auto HTTP_VERSION_CONFLICT {409};
constexpr auto HTTP_TOO_MANY_REQUESTS {429};
constexpr auto PROCESS_TIMEOUT {std::chrono::seconds(20)};

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
};

static std::mutex G_CREDENTIAL_MUTEX;
constexpr auto MAX_BULK_SIZE {10 * 1024 * 1024};

void IndexerConnectorSync::bulkDelete(std::string_view id, std::string_view index)
{
    constexpr auto FORMATTED_SIZE {21 + 9 + 2 + 1};
    std::lock_guard<std::mutex> lock(m_mutex);
    // Project size and calculate if it's too large.
    if (m_bulkData.size() + FORMATTED_SIZE + index.size() + id.size() > MAX_BULK_SIZE)
    {
        processBulk();
    }
    m_bulkData.append(R"({"delete":{"_index":")");
    m_bulkData.append(index);
    m_bulkData.append(R"(","_id":")");
    m_bulkData.append(id);
    m_bulkData.append(R"("}})");
    m_bulkData.append("\n");
    m_boundaries.push_back(m_bulkData.size());
}

void IndexerConnectorSync::deleteByQuery(const std::string& index, const std::string& agentId)
{
    auto [it, success] = m_deleteByQuery.try_emplace(index, nlohmann::json::object());
    it->second["query"]["bool"]["filter"]["terms"]["agent.id"].push_back(agentId);
}

void IndexerConnectorSync::bulkIndex(std::string_view id, std::string_view index, std::string_view data)
{
    constexpr auto FORMATTED_SIZE {20 + 8 + 2 + 2 + 1};
    std::lock_guard lock(m_mutex);
    // Project size and calculate if it's too large.
    if (m_bulkData.size() + FORMATTED_SIZE + index.size() + id.size() + data.size() > MAX_BULK_SIZE)
    {
        processBulk();
    }
    m_bulkData.append(R"({"index":{"_index":")");
    m_bulkData.append(index);
    m_bulkData.append(R"(","_id":")");
    m_bulkData.append(id);
    m_bulkData.append(R"("}})");
    m_bulkData.append("\n");
    m_bulkData.append(data);
    m_bulkData.append("\n");
    m_boundaries.push_back(m_bulkData.size());
}

void IndexerConnectorSync::processBulk()
{
    bool needToRetry = false;
    if (m_bulkData.empty())
    {
        return;
    }

    // Send data to the indexer to be processed.
    const auto serverUrl = m_selector->getNext();

    const auto onSuccessDeleteByQuery = [](const std::string& response)
    {
        logDebug2(IC_NAME, "Response: %s", response.c_str());
    };

    const auto onErrorDeleteByQuery = [this](const std::string& error, const long statusCode)
    {
        logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
        if (statusCode == HTTP_VERSION_CONFLICT)
        {
            logDebug2(IC_NAME, "Document version conflict, retrying in 1 second.");
        }
        else if (statusCode == HTTP_TOO_MANY_REQUESTS)
        {
            logDebug2(IC_NAME, "Too many requests, retrying in 1 second.");
        }
        else
        {
            logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
            m_bulkData.clear();
            m_lastBulkTime = std::chrono::steady_clock::now();
            throw IndexerConnectorException(error);
        }
    };

    // Process delete by query.
    for (const auto& [index, query] : m_deleteByQuery)
    {
        std::string url = serverUrl;
        url += "/";
        url += index;
        url += "/_delete_by_query";

        HTTPRequest::instance().post(
            RequestParameters {.url = HttpURL(url), .data = query, .secureCommunication = m_secureCommunication},
            PostRequestParameters {.onSuccess = onSuccessDeleteByQuery, .onError = onErrorDeleteByQuery},
            {});
    }

    const auto onSuccess = [this, &needToRetry](const std::string& response) -> void
    {
        logDebug2(IC_NAME, "Response: %s", response.c_str());
        for (const auto& notify : m_notify)
        {
            notify();
        }
        m_notify.clear();
        needToRetry = false;
    };

    const auto onError = [this, &needToRetry](const std::string& error, const long statusCode) -> void
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

    do
    {
        auto url = m_selector->getNext() + "/_bulk?refresh=wait_for";
        HTTPRequest::instance().post(
            RequestParameters {.url = HttpURL(url), .data = m_bulkData, .secureCommunication = m_secureCommunication},
            PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
            {});
        if (needToRetry)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    } while (needToRetry);

    m_bulkData.clear();
    m_boundaries.clear();
    m_lastBulkTime = std::chrono::steady_clock::now();
}

void IndexerConnectorSync::splitAndProcessBulk()
{
    const size_t totalOperations = m_boundaries.size();
    if (totalOperations <= 1)
    {
        throw IndexerConnectorException(
            "Cannot split bulk data with less than two operations. Consider increasing http.max_content_length in "
            "Wazuh-Indexer settings.");
    }

    logDebug2(IC_NAME, "Splitting %zu operations into two halves", totalOperations);

    // Split the bulk data into two halves based on the boundaries
    const size_t midPoint = totalOperations / 2;

    std::span<const size_t> firstBoundaries(m_boundaries.data(), midPoint);
    const size_t firstEndPos = m_boundaries[midPoint - 1];
    std::string_view firstHalf(m_bulkData.data(), firstEndPos);

    std::span<const size_t> secondBoundaries(m_boundaries.data() + midPoint, totalOperations - midPoint);
    const size_t secondStartPos = m_boundaries[midPoint - 1];
    std::string_view secondHalf(m_bulkData.data() + secondStartPos, m_bulkData.size() - secondStartPos);

    // Procesar recursivamente cada mitad
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
            // Ajustar boundaries para la segunda mitad (restar offset)
            std::vector<size_t> adjustedBoundaries;
            adjustedBoundaries.reserve(secondBoundaries.size());
            for (const auto& boundary : secondBoundaries)
            {
                adjustedBoundaries.push_back(boundary - secondStartPos);
            }
            processBulkChunk(secondHalf, std::span<const size_t>(adjustedBoundaries));
        }
        catch (const IndexerConnectorException& e)
        {
            logError(IC_NAME, "Failed to process second half: %s", e.what());
            allProcessed = false;
            throw;
        }
    }

    // Solo notificar cuando ambas mitades se hayan procesado exitosamente
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

void IndexerConnectorSync::processBulkChunk(std::string_view data, std::span<const size_t> boundaries)
{
    const auto serverUrl = m_selector->getNext();
    auto url = serverUrl + "/_bulk?refresh=wait_for";

    bool needToRetry = false;
    // TODO - Add support for string views in HTTPRequest submodule.
    std::string dataStr(data); // Convert to string for HTTP request

    const auto onSuccess = [](const std::string& response)
    {
        logDebug2(IC_NAME, "Chunk processed successfully: %s", response.c_str());
    };

    const auto onError = [this, &needToRetry, data, boundaries](const std::string& error, const long statusCode)
    {
        logError(IC_NAME, "Chunk processing failed: %s, status code: %ld", error.c_str(), statusCode);

        if (statusCode == HTTP_CONTENT_LENGTH)
        {
            if (boundaries.size() > 1)
            {
                logDebug2(IC_NAME, "Chunk still too large, splitting recursively");

                const size_t midPoint = boundaries.size() / 2;
                std::span<const size_t> firstBoundaries(boundaries.data(), midPoint);
                const size_t firstEndPos = boundaries[midPoint - 1];
                std::string_view firstHalf(data.data(), firstEndPos);

                std::span<const size_t> secondBoundaries(boundaries.data() + midPoint, boundaries.size() - midPoint);
                const size_t secondStartPos = boundaries[midPoint - 1];
                std::string_view secondHalf(data.data() + secondStartPos, data.size() - secondStartPos);

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
        HTTPRequest::instance().post(
            RequestParameters {.url = HttpURL(url), .data = dataStr, .secureCommunication = m_secureCommunication},
            PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
            {});

        if (needToRetry)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    } while (needToRetry);
}

static void mergeCaRootCertificates(const std::vector<std::string>& filePaths, std::string& caRootCertificate)
{
    std::string caRootCertificateContentMerged;

    for (const auto& filePath : filePaths)
    {
        if (!std::filesystem::exists(filePath))
        {
            throw IndexerConnectorException("The CA root certificate file: '" + filePath + "' does not exist.");
        }

        std::ifstream file(filePath);
        if (!file.is_open())
        {
            throw IndexerConnectorException("Could not open CA root certificate file: '" + filePath + "'.");
        }

        caRootCertificateContentMerged.append((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    }

    caRootCertificate = DEFAULT_PATH;

    if (std::filesystem::path dirPath = std::filesystem::path(caRootCertificate).parent_path();
        !std::filesystem::exists(dirPath) && !std::filesystem::create_directories(dirPath))
    {
        throw IndexerConnectorException("Could not create the directory for the CA root merged file");
    }

    std::ofstream outputFile(caRootCertificate);
    if (!outputFile.is_open())
    {
        throw IndexerConnectorException("Could not write the CA root merged file");
    }

    outputFile << caRootCertificateContentMerged;
    outputFile.close();

    struct passwd const* pwd = getpwnam(USER_GROUP);
    struct group const* grp = getgrnam(USER_GROUP);

    if (pwd == nullptr || grp == nullptr)
    {
        throw IndexerConnectorException("Could not get the user and group information.");
    }

    if (chown(caRootCertificate.c_str(), pwd->pw_uid, grp->gr_gid) != 0)
    {
        throw IndexerConnectorException("Could not change the ownership of the CA root merged file");
    }

    logDebug2(IC_NAME, "All CA files merged into '%s' successfully.", caRootCertificate.c_str());
}
IndexerConnectorSync::~IndexerConnectorSync()
{
    m_stopping.store(true);
    m_cv.notify_one();
    if (m_bulkThread.joinable())
    {
        m_bulkThread.join();
    }
}

IndexerConnectorSync::IndexerConnectorSync(
    const nlohmann::json& config,
    const std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>&
        logFunction)
    : m_secureCommunication {SecureCommunication::builder()}
    , m_stopping {false}
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
                mergeCaRootCertificates(filePaths, caRootCertificate);
            }
            else
            {
                caRootCertificate = filePaths.front();
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

    // Basically we need to lock a global mutex, because the keystore::get method open the same database connection, and
    // that action is not thread safe.
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

    m_secureCommunication.basicAuth(username + ":" + password)
        .sslCertificate(sslCertificate)
        .sslKey(sslKey)
        .caRootCertificate(caRootCertificate);

    m_selector = std::make_unique<ServerSelector>(config.at("hosts"), 10, m_secureCommunication);

    m_lastBulkTime = std::chrono::steady_clock::now();

    // Thread to process bulk data every 20 seconds if the buffer is not empty.
    m_bulkThread = std::thread(
        [this]()
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            if (!m_bulkData.empty())
            {
                processBulk();
            }
            m_cv.wait_for(lock, PROCESS_TIMEOUT, [this] { return m_stopping.load(); });
        });
}

// void IndexerConnectorSync::bulk(const std::string& message)
// {
//     // Send data to the indexer to be processed.
//     const auto processData = [this](const std::string& data, const std::string& url)
//     {
//         const auto onSuccess = [](const std::string& response)
//         {
//             logDebug2(IC_NAME, "Response: %s", response.c_str());

//             // If the request was successful and the current bulk size is less than ELEMENTS_PER_BULK, increase
//             // the bulk size if the success count is SUCCESS_COUNT_TO_INCREASE_BULK_SIZE

//             // if (m_successCount < SUCCESS_COUNT_TO_INCREASE_BULK_SIZE)
//             // {
//             //     m_successCount++;
//             // }

//             // m_error413FirstTime = false;

//             // if (bulkSize < ELEMENTS_PER_BULK)
//             // {
//             //     if (m_successCount < SUCCESS_COUNT_TO_INCREASE_BULK_SIZE)
//             //     {
//             //         logDebug2(IC_NAME,
//             //                   "Waiting for %d successful requests to increase the bulk size.",
//             //                   SUCCESS_COUNT_TO_INCREASE_BULK_SIZE - m_successCount);
//             //         return;
//             //     }

//             //     if (bulkSize * 2 > ELEMENTS_PER_BULK)
//             //     {
//             //         this->m_dispatcher->bulkSize(ELEMENTS_PER_BULK);
//             //         logDebug2(IC_NAME, "Increasing the elements to be sent to the indexer: %d.",
//             ELEMENTS_PER_BULK);
//             //     }
//             //     else
//             //     {
//             //         this->m_dispatcher->bulkSize(bulkSize * 2);
//             //         logDebug2(IC_NAME, "Increasing the elements to be sent to the indexer: %d.", bulkSize * 2);
//             //     }
//             // }
//         };

//         const auto onError = [](const std::string& error, const long statusCode)
//         {
//             if (statusCode == HTTP_CONTENT_LENGTH)
//             {
//                 // m_successCount = 0;
//                 // if (bulkSize / 2 < MINIMAL_ELEMENTS_PER_BULK)
//                 // {
//                 //     // If the bulk size is too small, log an error and throw an exception.
//                 //     // This error will be fixed by the user by increasing the http.max_content_length value in
//                 //     // the wazuh-indexer settings.
//                 //     if (m_error413FirstTime == false)
//                 //     {
//                 //         m_error413FirstTime = true;
//                 //         logError(IC_NAME,
//                 //                  "The amount of elements to process is too small, review the "
//                 //                  "'http.max_content_length' value in "
//                 //                  "the wazuh-indexer settings. Current data size: %llu.",
//                 //                  data.size());
//                 //     }

//                 //     throw IndexerConnectorException("The amount of elements to process is too small, review the "
//                 //                              "'http.max_content_length' value in "
//                 //                              "the wazuh-indexer settings.");
//             }
//             else
//             {
//                 // logDebug2(IC_NAME, "Reducing the elements to be sent to the indexer: %llu.", bulkSize / 2);
//                 // this->m_dispatcher->bulkSize(bulkSize / 2);
//                 // throw IndexerConnectorException("Bulk size is too large, reducing the elements to be sent to the "
//                 //                          "indexer.");
//                 if (statusCode == HTTP_VERSION_CONFLICT)
//                 {
//                     logDebug2(IC_NAME, "Document version conflict, retrying in 1 second.");
//                     throw IndexerConnectorException("Document version conflict, retrying in 1 second.");
//                 }
//                 else if (statusCode == HTTP_TOO_MANY_REQUESTS)
//                 {
//                     logDebug2(IC_NAME, "Too many requests, retrying in 1 second.");
//                     throw IndexerConnectorException("Too many requests, retrying in 1 second.");
//                 }
//                 else
//                 {
//                     logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
//                     throw IndexerConnectorException(error);
//                 }
//             }
//         };
//         HTTPRequest::instance().post(
//             RequestParameters {.url = HttpURL(url), .data = data, .secureCommunication = m_secureCommunication},
//             PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
//             {});
//     };

//     const auto serverUrl = m_selector->getNext();
//     processData(message, serverUrl + "/_bulk?refresh=wait_for");
// }

// void IndexerConnectorSync::bulk(const std::string& message, size_t initialOperationCount)
// {
//     constexpr size_t MIN_OPERATIONS = 1; // Minimum operations per chunk

//     // Helper function to find operation boundaries (line positions)
//     auto findOperationBoundaries = [](const std::string& bulkData) -> std::vector<size_t>
//     {
//         std::vector<size_t> boundaries;
//         boundaries.push_back(0); // Start of first operation

//         size_t pos = 0;
//         while (pos < bulkData.size())
//         {
//             // Find next newline
//             size_t newlinePos = bulkData.find('\n', pos);
//             if (newlinePos == std::string::npos)
//                 break;

//             // Check if this line starts with an operation
//             if (pos < bulkData.size() &&
//                 (bulkData.compare(pos, 9, R"({"index":)") == 0 || bulkData.compare(pos, 10, R"({"delete":)") == 0))
//             {
//                 boundaries.push_back(pos);
//             }

//             pos = newlinePos + 1;
//         }

//         boundaries.push_back(bulkData.size()); // End of last operation
//         return boundaries;
//     };

//     // Send data to the indexer to be processed with 413 error handling
//     std::function<void(const std::string&, const std::string&, size_t)> processDataWithRetry;

//     processDataWithRetry = [this, &findOperationBoundaries, MIN_OPERATIONS, &processDataWithRetry](
//                                const std::string& data, const std::string& url, size_t operationCount) -> void
//     {
//         const auto onSuccess = [](const std::string& response)
//         {
//             logDebug2(IC_NAME, "Response: %s", response.c_str());
//         };

//         const auto onError =
//             [this, &data, &url, &findOperationBoundaries, operationCount, MIN_OPERATIONS, &processDataWithRetry](
//                 const std::string& error, const long statusCode) -> void
//         {
//             if (statusCode == HTTP_CONTENT_LENGTH)
//             {
//                 // Find all operation boundaries
//                 auto boundaries = findOperationBoundaries(data);

//                 // Calculate current operation count
//                 size_t currentOperations = boundaries.size() - 1;

//                 // Reduce operation count for next attempt
//                 size_t newOperationCount = std::max(operationCount / 2, MIN_OPERATIONS);

//                 logDebug2(IC_NAME,
//                           "Received 413 error. Current operations: %zu, reducing to: %zu",
//                           currentOperations,
//                           newOperationCount);

//                 if (newOperationCount == MIN_OPERATIONS && currentOperations == 1)
//                 {
//                     logError(IC_NAME,
//                              "Unable to send data even with minimum operation count. "
//                              "Consider increasing http.max_content_length in OpenSearch settings. "
//                              "Current data size: %zu bytes.",
//                              data.size());
//                     throw IndexerConnectorException("Unable to send data even with minimum operation count");
//                 }

//                 // Process chunks using offsets instead of copying strings
//                 size_t chunkStart = 0;
//                 size_t operationsInChunk = 0;

//                 for (size_t i = 1; i < boundaries.size(); ++i) // Skip first boundary (start of data)
//                 {
//                     operationsInChunk++;

//                     // If we've reached the max operations for this chunk, send it
//                     if (operationsInChunk >= newOperationCount || i == boundaries.size() - 1)
//                     {
//                         size_t chunkEnd = boundaries[i];

//                         // Create chunk using string_view to avoid copying
//                         std::string_view chunkView(data.data() + chunkStart, chunkEnd - chunkStart);
//                         std::string chunk(chunkView); // Only copy when sending

//                         if (!chunk.empty())
//                         {
//                             // Recursive call with smaller operation count
//                             try
//                             {
//                                 processDataWithRetry(chunk, url, newOperationCount);
//                             }
//                             catch (const IndexerConnectorException& e)
//                             {
//                                 // Re-throw 413 errors to continue the retry logic
//                                 if (std::string(e.what()).find("413") != std::string::npos ||
//                                     std::string(e.what()).find("Payload Too Large") != std::string::npos ||
//                                     std::string(e.what()).find("Content Length") != std::string::npos)
//                                 {
//                                     throw;
//                                 }
//                                 // For other errors, just re-throw
//                                 throw;
//                             }
//                         }

//                         // Reset for next chunk
//                         chunkStart = chunkEnd;
//                         operationsInChunk = 0;
//                     }
//                 }
//             }
//             else if (statusCode == HTTP_VERSION_CONFLICT)
//             {
//                 logDebug2(IC_NAME, "Document version conflict, retrying in 1 second.");
//                 throw IndexerConnectorException("Document version conflict, retrying in 1 second.");
//             }
//             else if (statusCode == HTTP_TOO_MANY_REQUESTS)
//             {
//                 logDebug2(IC_NAME, "Too many requests, retrying in 1 second.");
//                 throw IndexerConnectorException("Too many requests, retrying in 1 second.");
//             }
//             else
//             {
//                 logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
//                 throw IndexerConnectorException(error);
//             }
//         };

//         HTTPRequest::instance().post(
//             RequestParameters {.url = HttpURL(url), .data = data, .secureCommunication = m_secureCommunication},
//             PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
//             {});
//     };

//     const auto serverUrl = m_selector->getNext();
//     const std::string url = serverUrl + "/_bulk?refresh=wait_for";

//     logDebug2(
//         IC_NAME, "Sending bulk data with %zu operations (size: %zu bytes)", initialOperationCount, message.size());

//     processDataWithRetry(message, url, initialOperationCount);
// }

// void IndexerConnectorSync::deleteByQuery(const std::string& message, const std::string& index)
// {
//     if (!index.empty() && Utils::haveUpperCaseCharacters(index))
//     {
//         throw IndexerConnectorException("Index name must be lowercase: " + index);
//     }

//     const auto serverUrl = m_selector->getNext();
//     const auto url = serverUrl + "/" + index + "/_delete_by_query";

//     const auto processData = [this](const std::string& data, const std::string& url)
//     {
//         const auto onSuccess = [](const std::string& response)
//         {
//             logDebug2(IC_NAME, "Response: %s", response.c_str());
//         };

//         const auto onError = [](const std::string& error, const long statusCode)
//         {
//             if (statusCode == HTTP_CONTENT_LENGTH)
//             {
//                 logDebug2(IC_NAME, "Document content length.");
//                 throw IndexerConnectorException("Document content length, retrying in 1 second.");
//             }
//             else if (statusCode == HTTP_VERSION_CONFLICT)
//             {
//                 logDebug2(IC_NAME, "Document version conflict, retrying in 1 second.");
//                 throw IndexerConnectorException("Document version conflict, retrying in 1 second.");
//             }
//             else if (statusCode == HTTP_TOO_MANY_REQUESTS)
//             {
//                 logDebug2(IC_NAME, "Too many requests, retrying in 1 second.");
//                 throw IndexerConnectorException("Too many requests, retrying in 1 second.");
//             }
//             else
//             {
//                 logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
//                 throw IndexerConnectorException(error);
//             }
//         };

//         HTTPRequest::instance().post(
//             RequestParameters {.url = HttpURL(url), .data = data, .secureCommunication = m_secureCommunication},
//             PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
//             {});
//     };

//     processData(message, url);
// }
