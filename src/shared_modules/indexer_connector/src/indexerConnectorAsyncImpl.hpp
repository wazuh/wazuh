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
#include "asyncValueDispatcher.hpp"
#include "external/nlohmann/json.hpp"
#include "indexerConnector.hpp"
#include "keyStore.hpp"
#include "loggerHelper.h"
#include "reflectiveJson.hpp"
#include "secureCommunication.hpp"
#include "shared_modules/utils/certHelper.hpp"
#include "simdjson.h"
#include "threadEventDispatcher.hpp"
#include <filesystem>
#include <mutex>
#include <queue>
#include <string>
#include <string_view>
#include <vector>

static std::mutex G_CREDENTIAL_MUTEX;
constexpr auto DATABASE_BASE_PATH = "queue/indexer/";

constexpr auto DEFAULT_PATH {"tmp/root-ca-merged.pem"};
constexpr auto INDEXER_COLUMN {"indexer"};
constexpr auto USER_KEY {"username"};
constexpr auto PASSWORD_KEY {"password"};

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

constexpr auto HTTP_CONTENT_LENGTH {413};
constexpr auto HTTP_VERSION_CONFLICT {409};
constexpr auto HTTP_TOO_MANY_REQUESTS {429};
constexpr auto MINIMAL_ELEMENTS_PER_BULK {1};

// Overhead is the fixed JSON scaffolding for one bulk item:
// {"index":{"_index":"<index>","id":"<id>"}}
constexpr auto FORMATTED_LENGTH {20 + 8 + 2 + 2 + 1};

class IndexerResponse final
{
public:
    std::string m_payload;
    std::vector<uint64_t> m_boundaries;
    std::string m_response;

    IndexerResponse() = default;

    explicit IndexerResponse(std::string&& payload, std::vector<uint64_t>&& boundaries, std::string&& response)
        : m_payload(std::move(payload))
        , m_boundaries(std::move(boundaries))
        , m_response(std::move(response))
    {
    }

    // Delete copy constructor and assignment operator.
    IndexerResponse(const IndexerResponse&) = delete;
    IndexerResponse& operator=(const IndexerResponse&) = delete;

    IndexerResponse(IndexerResponse&& data) noexcept
    {
        m_payload = std::move(data.m_payload);
        m_boundaries = std::move(data.m_boundaries);
        m_response = std::move(data.m_response);
    }
    IndexerResponse& operator=(IndexerResponse&& data) noexcept
    {
        m_payload = std::move(data.m_payload);
        m_boundaries = std::move(data.m_boundaries);
        m_response = std::move(data.m_response);
        return *this;
    }
};

using ThreadDispatchQueue = ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>>;
using ThreadLoggerQueue = Utils::AsyncValueDispatcher<IndexerResponse, std::function<void(IndexerResponse&&)>>;

template<typename TSelector,
         typename THttpRequest,
         size_t ElementsPerBulk = 25000,
         size_t FlushInterval = 20,
         size_t RetryDelay = 1,
         size_t MaxSuccessCount = 5>
class IndexerConnectorAsyncImpl final
{
    SecureCommunication m_secureCommunication;
    std::unique_ptr<TSelector> m_selector;
    THttpRequest* m_httpRequest;
    std::atomic<bool> m_stopping {false};
    std::unique_ptr<ThreadLoggerQueue> m_loggerProcessor;
    const std::string m_queueId;
    bool m_error413Logged {false};
    size_t m_successCount {0};
    std::unique_ptr<ThreadDispatchQueue> m_dispatcher;

public:
    ~IndexerConnectorAsyncImpl() = default;

    explicit IndexerConnectorAsyncImpl(
        const nlohmann::json& config,
        const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
            logFunction,
        THttpRequest* httpRequest = nullptr,
        std::unique_ptr<TSelector> selector = nullptr,
        std::string queueId = "")
        : m_httpRequest(httpRequest ? httpRequest : &THttpRequest::instance())
        , m_queueId(std::move(queueId))
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

        m_loggerProcessor = std::make_unique<ThreadLoggerQueue>(
            [this](const IndexerResponse& data)
            {
                // Use thread_local parser for better performance and memory reuse
                thread_local simdjson::dom::parser parser;
                simdjson::dom::element parsedResponse;

                if (auto parseResult = parser.parse(data.m_response).get(parsedResponse);
                    parseResult != simdjson::SUCCESS)
                {
                    logDebug2(IC_NAME, "Failed to parse the indexer response %s", data.m_response.c_str());
                    return;
                }

                // Fast path: check errors field first
                if (simdjson::dom::element errorsElement;
                    parsedResponse["errors"].get(errorsElement) != simdjson::SUCCESS ||
                    !errorsElement.get_bool().value_unsafe())
                {
                    return;
                }

                // Get items array
                simdjson::dom::array itemsArray;
                if (parsedResponse["items"].get_array().get(itemsArray) != simdjson::SUCCESS)
                {
                    return;
                }

                const size_t itemsSize = itemsArray.size();
                if (data.m_boundaries.size() != itemsSize)
                {
                    logWarn(IC_NAME,
                            "Mismatch between the number of events (%zu) and response items (%zu)",
                            data.m_boundaries.size(),
                            itemsSize);
                    return;
                }

                // Pre-compute payload view once
                const std::string_view payloadView = data.m_payload;
                const size_t payloadSize = payloadView.size();

                // Process items with optimized iteration
                size_t itemIndex = 0;
                for (const auto& item : itemsArray)
                {
                    // Try to find the operation element (could be "index", "create")
                    simdjson::dom::element operationElement;
                    bool foundOperation = false;

                    if (item["index"].get(operationElement) == simdjson::SUCCESS)
                    {
                        foundOperation = true;
                    }
                    else if (item["create"].get(operationElement) == simdjson::SUCCESS)
                    {
                        foundOperation = true;
                    }

                    if (!foundOperation)
                    {
                        ++itemIndex;
                        continue;
                    }

                    simdjson::dom::element errorElement;
                    if (operationElement["error"].get(errorElement) != simdjson::SUCCESS)
                    {
                        ++itemIndex;
                        continue;
                    }

                    // Extract error details with zero-copy string views
                    std::string_view errorReason = "Unknown reason";
                    std::string_view errorType = "Unknown type";
                    std::string_view causedByReason {""};
                    std::string_view causedByType {""};

                    if (simdjson::dom::element reasonElement;
                        errorElement["reason"].get(reasonElement) == simdjson::SUCCESS)
                    {
                        errorReason = reasonElement.get_string().value_unsafe();
                    }

                    if (simdjson::dom::element typeElement; errorElement["type"].get(typeElement) == simdjson::SUCCESS)
                    {
                        errorType = typeElement.get_string().value_unsafe();
                    }

                    // Extract caused_by information if available
                    simdjson::dom::element causedByElement;
                    if (errorElement["caused_by"].get(causedByElement) == simdjson::SUCCESS)
                    {
                        if (simdjson::dom::element causedByReasonElement;
                            causedByElement["reason"].get(causedByReasonElement) == simdjson::SUCCESS)
                        {
                            causedByReason = causedByReasonElement.get_string().value_unsafe();
                        }

                        if (simdjson::dom::element causedByTypeElement;
                            causedByElement["type"].get(causedByTypeElement) == simdjson::SUCCESS)
                        {
                            causedByType = causedByTypeElement.get_string().value_unsafe();
                        }
                    }

                    // Optimized payload extraction with boundary checks
                    const size_t startPos = data.m_boundaries[itemIndex];
                    const size_t endPos =
                        (itemIndex == (itemsSize - 1)) ? payloadSize : data.m_boundaries[itemIndex + 1];

                    const std::string_view payload = payloadView.substr(startPos, endPos - startPos);

                    // Build error message with caused_by info if available
                    if (!causedByReason.empty() && !causedByType.empty())
                    {
                        logWarn(IC_NAME,
                                "Error indexing document (type %.*s - reason: '%.*s' - caused by: %.*s - '%.*s') - "
                                "Associated event: %.*s",
                                static_cast<int>(errorType.size()),
                                errorType.data(),
                                static_cast<int>(errorReason.size()),
                                errorReason.data(),
                                static_cast<int>(causedByType.size()),
                                causedByType.data(),
                                static_cast<int>(causedByReason.size()),
                                causedByReason.data(),
                                static_cast<int>(payload.size()),
                                payload.data());
                    }
                    else
                    {
                        logWarn(IC_NAME,
                                "Error indexing document (type %.*s - reason: '%.*s') - Associated event: %.*s",
                                static_cast<int>(errorType.size()),
                                errorType.data(),
                                static_cast<int>(errorReason.size()),
                                errorReason.data(),
                                static_cast<int>(payload.size()),
                                payload.data());
                    }

                    ++itemIndex;
                }
            });

        m_dispatcher = std::make_unique<ThreadDispatchQueue>(
            [this](std::queue<std::string>& dataQueue)
            {
                if (m_stopping.load())
                {
                    logDebug2(IC_NAME, "IndexerConnector is stopping, event processing will be skipped.");
                    throw IndexerConnectorException("IndexerConnector is stopping, event processing will be skipped.");
                }

                // Accumulator for data to be sent to the indexer via bulk requests.
                std::string bulkData;
                std::vector<uint64_t> boundaries;

                const auto bulkSize = dataQueue.size();
                boundaries.reserve(bulkSize);

                while (!dataQueue.empty())
                {
                    boundaries.push_back(bulkData.size());
                    bulkData.append(dataQueue.front());

                    dataQueue.pop();
                }

                const auto onSuccess = [this, &bulkData, &boundaries](std::string&& response)
                {
                    if (m_dispatcher->bulkSize() != ElementsPerBulk && m_successCount == MaxSuccessCount)
                    {
                        logDebug2(IC_NAME, "Resetting bulk size to %zu.", ElementsPerBulk);
                        m_dispatcher->bulkSize(ElementsPerBulk);
                        m_error413Logged = false;
                    }

                    if (m_successCount < MaxSuccessCount)
                    {
                        m_successCount++;
                    }
                    IndexerResponse responseData(std::move(bulkData), std::move(boundaries), std::move(response));
                    m_loggerProcessor->push(std::move(responseData));
                    // Dispatch to error logger.
                };

                const auto onError = [this, &bulkData, bulkSize](const std::string& error,
                                                                 const long statusCode,
                                                                 const std::string& responseBody)
                {
                    logError(IC_NAME, "Chunk processing failed: %s, status code: %ld", error.c_str(), statusCode);
                    if (statusCode == HTTP_CONTENT_LENGTH)
                    {
                        logDebug2(IC_NAME, "Received 413 error (Payload Too Large). Splitting bulk data.");
                        if (const size_t currentOperations = bulkData.size(); currentOperations <= 1)
                        {
                            logError(IC_NAME,
                                     "Unable to send data even with single operation. "
                                     "Consider increasing http.max_content_length in OpenSearch settings. "
                                     "Current data size: %zu bytes.",
                                     bulkData.size());
                        }
                        else
                        {
                            if (bulkSize / 2 < MINIMAL_ELEMENTS_PER_BULK)
                            {
                                // If the bulk size is too small, log an error and throw an exception.
                                // This error will be fixed by the user by increasing the http.max_content_length
                                // value in the wazuh-indexer settings.
                                if (m_error413Logged == false)
                                {
                                    m_error413Logged = true;
                                    logError(IC_NAME,
                                             "The amount of elements to process is too small, review the "
                                             "'http.max_content_length' value in "
                                             "the wazuh-indexer settings. Current data size: %llu.",
                                             bulkData.size());
                                }

                                throw IndexerConnectorException(
                                    "The amount of elements to process is too small, review the "
                                    "'http.max_content_length' value in "
                                    "the wazuh-indexer settings.");
                            }
                            else
                            {
                                logDebug2(
                                    IC_NAME, "Reducing the elements to be sent to the indexer: %llu.", bulkSize / 2);
                                this->m_dispatcher->bulkSize(bulkSize / 2);
                                m_successCount = 0;
                                throw IndexerConnectorException(
                                    "Bulk size is too large, reducing the elements to be sent to the "
                                    "indexer.");
                            }
                        }
                    }
                    else if (statusCode == HTTP_VERSION_CONFLICT)
                    {
                        logDebug2(IC_NAME, "Document version conflict, retrying in 1 second.");
                        throw IndexerConnectorException(error);
                    }
                    else if (statusCode == HTTP_TOO_MANY_REQUESTS)
                    {
                        logDebug2(IC_NAME, "Too many requests, retrying in 1 second.");
                        throw IndexerConnectorException(error);
                    }
                    else
                    {
                        logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
                    }
                };

                std::string url;
                url = m_selector->getNext();
                url += "/_bulk";
                logDebug2(IC_NAME, "Bulk data: %s", bulkData.c_str());

                m_httpRequest->post(RequestParameters {.url = HttpURL(url),
                                                       .data = bulkData,
                                                       .secureCommunication = m_secureCommunication},
                                    PostRequestParametersRValue {.onSuccess = onSuccess, .onError = onError},
                                    {});
            },
            DATABASE_BASE_PATH + m_queueId,
            ElementsPerBulk,
            UNLIMITED_QUEUE_SIZE,
            RetryDelay,
            FlushInterval);
    }

    void bulkIndex(std::string_view id, std::string_view index, std::string_view data)
    {
        bulkIndex(id, index, data, std::string_view());
    }

    void bulkIndex(std::string_view id, std::string_view index, std::string_view data, std::string_view version)
    {
        constexpr auto FORMATTED_SIZE {FORMATTED_LENGTH};
        constexpr auto ID_SIZE {64};
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

        std::string bulkData;
        bulkData.reserve(data.size() + index.size() + ID_SIZE + FORMATTED_SIZE + VERSION_SIZE);

        bulkData.append(R"({"index":{"_index":")");
        bulkData.append(index);
        if (!version.empty())
        {
            // In case the version is provided, the id must be provided too
            if (!id.empty())
            {
                bulkData.append(R"(","_id":")");
                appendEscapedId(bulkData, id);
            }
            else
            {
                logError(IC_NAME, "Id must be provided if version value is provided");
                throw IndexerConnectorException("Id must be provided if version value is provided");
            }

            bulkData.append(R"(","version":")");
            bulkData.append(version);
            bulkData.append(R"(","version_type":"external_gte)");
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
                bulkData.append(R"(","_id":")");
                appendEscapedId(bulkData, id);
            }
            logDebug2(IC_NAME,
                      "No version specified for document %.*s, using default versioning",
                      static_cast<int>(id.size()),
                      id.data());
        }
        bulkData.append(R"("}})");
        bulkData.append("\n");
        bulkData.append(data);
        bulkData.append("\n");
        m_dispatcher->push(bulkData);
    }

    void bulkIndexDataStream(std::string_view index, std::string_view data)
    {
        constexpr auto FORMATTED_SIZE {24}; // {"create":{"_index":""}} + newlines"

        // Validate input parameters
        if (index.empty())
        {
            throw IndexerConnectorException("Data stream name cannot be empty");
        }

        if (data.empty())
        {
            throw IndexerConnectorException("Data cannot be empty for data stream: " + std::string(index));
        }

        std::string bulkData;
        bulkData.reserve(data.size() + index.size() + FORMATTED_SIZE);

        bulkData.append(R"({"create":{"_index":")");
        bulkData.append(index);
        bulkData.append(R"("}})");
        bulkData.append("\n");
        bulkData.append(data);
        bulkData.append("\n");
        m_dispatcher->push(bulkData);
    }

    bool isAvailable() const
    {
        return m_selector->isAvailable();
    }

    uint64_t getQueueSize() const
    {
        return m_dispatcher->size();
    }

    PointInTime
    createPointInTime(const std::vector<std::string>& indices, std::string_view keepAlive, bool expandWildcards)
    {
        if (indices.empty())
        {
            throw IndexerConnectorException("Indices list cannot be empty for PIT creation");
        }

        if (keepAlive.empty())
        {
            throw IndexerConnectorException("keepAlive parameter cannot be empty for PIT creation");
        }

        // Build the indices string (comma-separated)
        std::string indicesStr;
        auto reservedSize = [&]() -> std::size_t
        {
            std::size_t size = 0;
            for (const auto& index : indices)
            {
                size += index.size();
            }
            size += indices.size() - 1; // for commas
            return size;
        }();
        indicesStr.reserve(reservedSize);
        for (size_t i = 0; i < indices.size(); ++i)
        {
            if (i > 0)
            {
                indicesStr += ",";
            }
            indicesStr += indices[i];
        }

        // Build the URL with query parameters
        const std::string baseUrl {m_selector->getNext()};
        std::string url;
        // Pre-reserve: base_url + '/' + indices + '/_search/point_in_time?keep_alive=' + keepAlive + potential
        // '&expand_wildcards=all'
        url.reserve(baseUrl.size() + 1 + indicesStr.size() + 35 + keepAlive.size() + 25);
        url = baseUrl;
        url += "/";
        url += indicesStr;
        url += "/_search/point_in_time?keep_alive=";
        url += keepAlive;

        if (expandWildcards)
        {
            url += "&expand_wildcards=all";
        }

        // Variables to capture the response
        std::string pitId;
        uint64_t creationTime = 0;
        bool success = false;
        std::string errorMessage;

        const auto onSuccess = [&pitId, &creationTime, &success, &errorMessage](std::string&& response)
        {
            try
            {
                auto jsonResponse = nlohmann::json::parse(response);

                if (!jsonResponse.contains("pit_id"))
                {
                    errorMessage = "Response does not contain 'pit_id' field";
                    return;
                }

                if (!jsonResponse.contains("creation_time"))
                {
                    errorMessage = "Response does not contain 'creation_time' field";
                    return;
                }

                pitId = jsonResponse["pit_id"].get<std::string>();
                creationTime = jsonResponse["creation_time"].get<uint64_t>();
                success = true;

                logDebug2(
                    IC_NAME, "PIT created successfully. PIT ID: %s, Creation time: %lu", pitId.c_str(), creationTime);
            }
            catch (const std::exception& e)
            {
                errorMessage = std::string("Failed to parse PIT response: ") + e.what();
                logDebug1(IC_NAME, "%s", errorMessage.c_str());
            }
        };

        const auto onError =
            [&errorMessage](const std::string& error, const long statusCode, const std::string& responseBody)
        {
            errorMessage = "Failed to create PIT. Error: " + error + ", Status code: " + std::to_string(statusCode) +
                           ", Response: " + responseBody;
            logDebug1(IC_NAME, "%s", errorMessage.c_str());
        };

        // Execute the POST request synchronously
        m_httpRequest->post(RequestParameters {.url = HttpURL(url), .secureCommunication = m_secureCommunication},
                            PostRequestParametersRValue {.onSuccess = onSuccess, .onError = onError},
                            {});

        if (!success)
        {
            throw IndexerConnectorException(errorMessage.empty() ? "Failed to create PIT" : errorMessage);
        }

        // Return the PointInTime object
        return PointInTime(std::move(pitId), creationTime, keepAlive);
    }

    void deletePointInTime(const PointInTime& pit)
    {
        try
        {
            const std::string& pitId = pit.getPitId();
            if (pitId.empty())
            {
                throw IndexerConnectorException("PIT ID is empty, cannot delete PIT");
            }

            const std::string baseUrl {m_selector->getNext()};
            std::string url;
            url.reserve(baseUrl.size() + 25); // base_url + '/_search/point_in_time'
            url = baseUrl;
            url += "/_search/point_in_time";

            nlohmann::json deleteBody;
            deleteBody["pit_id"] = pitId;

            const auto onSuccess = [](const std::string& response)
            {
                logDebug2(IC_NAME, "PIT successfully deleted. Response: %s", response.c_str());
            };

            const auto onError =
                [&pitId](const std::string& error, const long statusCode, const std::string& responseBody)
            {
                throw IndexerConnectorException("Failed to delete PIT " + pitId + ". Error: " + error + ", Status: " +
                                                std::to_string(statusCode) + ", Response: " + responseBody);
            };

            m_httpRequest->delete_(RequestParameters {.url = HttpURL(url),
                                                      .data = deleteBody.dump(),
                                                      .secureCommunication = m_secureCommunication},
                                   PostRequestParametersRValue {.onSuccess = onSuccess, .onError = onError},
                                   {});
        }
        catch (const std::exception& e)
        {
            throw IndexerConnectorException(std::string("Error deleting PIT: ") + e.what());
        }
        catch (...)
        {
            throw IndexerConnectorException("Unknown error deleting PIT");
        }
    }
    nlohmann::json search(const PointInTime& pit,
                          std::size_t size,
                          const nlohmann::json& query,
                          const nlohmann::json& sort,
                          const std::optional<nlohmann::json>& searchAfter)
    {
        // Build the search request body
        nlohmann::json requestBody;
        requestBody["size"] = size;
        requestBody["pit"]["id"] = pit.getPitId();
        requestBody["pit"]["keep_alive"] = pit.getKeepAlive();
        requestBody["query"] = query;
        requestBody["sort"] = sort;

        // Add track_total_hits only if searchAfter is not provided
        if (!searchAfter.has_value())
        {
            requestBody["track_total_hits"] = true;
        }
        else
        {
            requestBody["search_after"] = searchAfter.value();
        }

        // Build the URL
        const std::string baseUrl {m_selector->getNext()};
        std::string url;
        url.reserve(baseUrl.size() + 10); // base_url + '/_search'
        url = baseUrl;
        url += "/_search";

        // Variables to capture the response
        nlohmann::json hitsResult;
        bool success = false;
        std::string errorMessage;

        const auto onSuccess = [&hitsResult, &success](std::string&& response)
        {
            try
            {
                auto jsonResponse = nlohmann::json::parse(response);

                // Check if the response contains hits
                if (!jsonResponse.contains("hits"))
                {
                    throw IndexerConnectorException("Response does not contain 'hits' field");
                }

                hitsResult = std::move(jsonResponse["hits"]);
                success = true;
            }
            catch (const nlohmann::json::exception& e)
            {
                throw IndexerConnectorException(std::string("Failed to parse search response: ") + e.what());
            }
        };

        const auto onError = [](const std::string& error, const long statusCode, const std::string& responseBody)
        {
            throw IndexerConnectorException("Search request failed with status " + std::to_string(statusCode) + ": " +
                                            error + ". Response: " + responseBody);
        };

        // Execute the POST request synchronously
        m_httpRequest->post(RequestParameters {.url = HttpURL(url),
                                               .data = requestBody.dump(),
                                               .secureCommunication = m_secureCommunication},
                            PostRequestParametersRValue {.onSuccess = onSuccess, .onError = onError},
                            {});

        if (!success)
        {
            throw IndexerConnectorException("Search request failed");
        }

        return hitsResult;
    }

    /**
     * @brief Execute a search query on an index or alias without PIT.
     *
     * @param index Index or alias name.
     * @param size Maximum number of documents to return.
     * @param query Query object.
     * @param source Optional source filtering configuration.
     * @return The hits object from the search response.
     * @throws IndexerConnectorException if the search fails.
     */
    nlohmann::json search(std::string_view index,
                          std::size_t size,
                          const nlohmann::json& query,
                          const std::optional<nlohmann::json>& source)
    {
        // Build the search request body
        nlohmann::json requestBody;
        requestBody["size"] = size;
        requestBody["track_total_hits"] = true;
        requestBody["stored_fields"] = nlohmann::json::array();
        requestBody["query"] = query;

        // Add source filtering if provided
        if (source.has_value())
        {
            requestBody["_source"] = source.value();
        }

        // Build the URL
        std::string url {};
        url.reserve(128);
        url = m_selector->getNext();
        url += "/";
        url += index;
        url += "/_search";

        // Variables to capture the response
        bool success = false;
        nlohmann::json hitsResult;

        // Define success callback
        auto onSuccess = [&success, &hitsResult](const std::string& responseBody)
        {
            try
            {
                auto jsonResponse = nlohmann::json::parse(responseBody);

                // Check if the response contains hits
                if (!jsonResponse.contains("hits"))
                {
                    throw IndexerConnectorException("Search response does not contain 'hits' field");
                }

                hitsResult = jsonResponse["hits"];
                success = true;
            }
            catch (const nlohmann::json::exception& e)
            {
                throw IndexerConnectorException("Failed to parse search response: " + std::string(e.what()));
            }
        };

        // Define error callback
        auto onError = [](const std::string& error, const long statusCode, const std::string& responseBody)
        {
            throw IndexerConnectorException("Search request failed with status " + std::to_string(statusCode) + ": " +
                                            error + ". Response: " + responseBody);
        };

        // Execute the POST request synchronously
        m_httpRequest->post(RequestParameters {.url = HttpURL(url),
                                               .data = requestBody.dump(),
                                               .secureCommunication = m_secureCommunication},
                            PostRequestParametersRValue {.onSuccess = onSuccess, .onError = onError},
                            {});

        if (!success)
        {
            throw IndexerConnectorException("Search request failed");
        }

        return hitsResult;
    }
};
