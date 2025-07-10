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
#include "keyStore.hpp"
#include "loggerHelper.h"
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

constexpr auto IC_NAME {"IndexerConnector"};

constexpr auto DEFAULT_PATH {"tmp/root-ca-merged.pem"};
constexpr auto INDEXER_COLUMN {"indexer"};
constexpr auto USER_KEY {"username"};
constexpr auto PASSWORD_KEY {"password"};

constexpr auto HTTP_CONTENT_LENGTH {413};
constexpr auto HTTP_VERSION_CONFLICT {409};
constexpr auto HTTP_TOO_MANY_REQUESTS {429};

class IndexerConnectorException : public std::exception
{
private:
    std::string m_message;

public:
    explicit IndexerConnectorException(std::string message)
        : m_message(std::move(message))
    {
    }

    const char* what() const noexcept override
    {
        return m_message.c_str();
    }
};

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

        const auto onErrorDeleteByQuery = [this](const std::string& error, const long statusCode)
        {
            logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
            if (statusCode == HTTP_VERSION_CONFLICT)
            {
                logDebug2(IC_NAME, "Document version conflict, retrying in 1 second.");
                // For deleteByQuery, we don't retry - just log and continue
                return;
            }
            else if (statusCode == HTTP_TOO_MANY_REQUESTS)
            {
                logDebug2(IC_NAME, "Too many requests, retrying in 1 second.");
                // For deleteByQuery, we don't retry - just log and continue
                return;
            }
            else
            {
                logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
                m_bulkData.clear();
                m_lastBulkTime = std::chrono::steady_clock::now();
                throw IndexerConnectorException(error);
            }
        };

        for (const auto& [index, query] : m_deleteByQuery)
        {
            std::string url;
            url += serverUrl;
            url += "/";
            url += index;
            url += "/_delete_by_query";
            m_httpRequest->post(
                RequestParameters {
                    .url = HttpURL(url), .data = query.dump(), .secureCommunication = m_secureCommunication},
                PostRequestParameters {.onSuccess = onSuccessDeleteByQuery, .onError = onErrorDeleteByQuery},
                {});
        }

        const auto onSuccess = [this, &needToRetry](const std::string& response)
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
                url += "/_bulk?refresh=wait_for";

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
        url += "/_bulk?refresh=wait_for";
        bool needToRetry = false;

        std::string dataStr(data);

        const auto onSuccess = [](const std::string& response)
        {
            logDebug2(IC_NAME, "Chunk processed successfully: %s", response.c_str());
        };
        const auto onError = [this, &needToRetry, boundaries](const std::string& error, const long statusCode)
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
            m_httpRequest->post(
                RequestParameters {.url = HttpURL(url), .data = dataStr, .secureCommunication = m_secureCommunication},
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

    explicit IndexerConnectorSyncImpl(const nlohmann::json& config,
                                      const std::function<void(const int,
                                                               const std::string&,
                                                               const std::string&,
                                                               const int,
                                                               const std::string&,
                                                               const std::string&,
                                                               va_list)>& logFunction,
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

                    // Process bulk data if there's data to process
                    if (!m_bulkData.empty())
                    {
                        try
                        {
                            processBulk();
                        }
                        catch (const IndexerConnectorException& e)
                        {
                            logError(IC_NAME, "Error processing bulk: %s", e.what());
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
        auto [it, success] = m_deleteByQuery.try_emplace(index, nlohmann::json::object());
        it->second["query"]["bool"]["filter"]["terms"]["agent.id"].push_back(agentId);
    }
    void bulkDelete(std::string_view id, std::string_view index)
    {
        constexpr auto FORMATTED_SIZE {21 + 9 + 2 + 1};
        std::lock_guard lock(m_mutex);
        if (m_bulkData.length() + FORMATTED_SIZE + index.size() + id.size() > MaxBulkSize)
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
    void bulkIndex(std::string_view id, std::string_view index, std::string_view data)
    {
        constexpr auto FORMATTED_SIZE {20 + 8 + 2 + 2 + 1};
        std::lock_guard lock(m_mutex);

        if (m_bulkData.length() + FORMATTED_SIZE + index.size() + id.size() + data.size() > MaxBulkSize)
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

    void flush()
    {
        std::lock_guard lock(m_mutex);
        if (!m_bulkData.empty() || !m_deleteByQuery.empty())
        {
            processBulk();
        }
    }
};
