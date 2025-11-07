/*
 * Wazuh - Quickwit connector implementation.
 * Copyright (C) 2015, Wazuh Inc.
 * November 7, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "IURLRequest.hpp"
#include "asyncValueDispatcher.hpp"
#include "external/nlohmann/json.hpp"
#include "quickwitConnector.hpp"
#include "keyStore.hpp"
#include "loggerHelper.h"
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

static std::mutex G_QW_CREDENTIAL_MUTEX;
constexpr auto QW_DATABASE_BASE_PATH = "queue/quickwit/";

constexpr auto DEFAULT_PATH {"tmp/root-ca-merged.pem"};
constexpr auto QUICKWIT_COLUMN {"quickwit"};
constexpr auto USER_KEY {"username"};
constexpr auto PASSWORD_KEY {"password"};

constexpr auto HTTP_TOO_MANY_REQUESTS {429};
constexpr auto HTTP_BAD_REQUEST {400};
constexpr auto MINIMAL_ELEMENTS_PER_BULK {1};

// Quickwit NDJSON format overhead
constexpr auto FORMATTED_LENGTH {2}; // Just newline separators

class QuickwitResponse final
{
public:
    std::string m_payload;
    std::vector<uint64_t> m_boundaries;
    std::string m_response;
    std::string m_index;

    QuickwitResponse() = default;

    explicit QuickwitResponse(std::string&& payload,
                             std::vector<uint64_t>&& boundaries,
                             std::string&& response,
                             std::string&& index)
        : m_payload(std::move(payload))
        , m_boundaries(std::move(boundaries))
        , m_response(std::move(response))
        , m_index(std::move(index))
    {
    }

    QuickwitResponse(const QuickwitResponse&) = delete;
    QuickwitResponse& operator=(const QuickwitResponse&) = delete;

    QuickwitResponse(QuickwitResponse&& data) noexcept
    {
        m_payload = std::move(data.m_payload);
        m_boundaries = std::move(data.m_boundaries);
        m_response = std::move(data.m_response);
        m_index = std::move(data.m_index);
    }

    QuickwitResponse& operator=(QuickwitResponse&& data) noexcept
    {
        m_payload = std::move(data.m_payload);
        m_boundaries = std::move(data.m_boundaries);
        m_response = std::move(data.m_response);
        m_index = std::move(data.m_index);
        return *this;
    }
};

using ThreadDispatchQueue = ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>>;
using ThreadLoggerQueue = Utils::AsyncValueDispatcher<QuickwitResponse, std::function<void(QuickwitResponse&&)>>;

template<typename TSelector,
         typename THttpRequest,
         size_t ElementsPerBulk = 10000,  // Quickwit recommends smaller batches
         size_t FlushInterval = 20,
         size_t RetryDelay = 1,
         size_t MaxSuccessCount = 5>
class QuickwitConnectorAsyncImpl final
{
    SecureCommunication m_secureCommunication;
    std::unique_ptr<TSelector> m_selector;
    THttpRequest* m_httpRequest;
    std::atomic<bool> m_stopping {false};
    std::unique_ptr<ThreadLoggerQueue> m_loggerProcessor;
    const std::string m_queueId;
    bool m_error400Logged {false};
    size_t m_successCount {0};
    std::unique_ptr<ThreadDispatchQueue> m_dispatcher;
    std::string m_databasePath;
    std::mutex m_indexMutex;
    std::map<std::string, std::shared_ptr<Utils::AsyncValueDispatcher<std::string, std::function<void(std::queue<std::string>&)>>>> m_indexDispatchers;

public:
    ~QuickwitConnectorAsyncImpl()
    {
        m_stopping = true;
        if (m_dispatcher)
        {
            m_dispatcher->cancel();
        }
        if (m_loggerProcessor)
        {
            m_loggerProcessor->cancel();
        }
        for (auto& [index, dispatcher] : m_indexDispatchers)
        {
            if (dispatcher)
            {
                dispatcher->cancel();
            }
        }
    }

    explicit QuickwitConnectorAsyncImpl(
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

        // Parse SSL configuration
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
                        throw QuickwitConnectorException("The CA root certificate file: '" + filePaths.front() +
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
            throw QuickwitConnectorException("No hosts found in the configuration");
        }

        // Authentication for Quickwit (if needed)
        std::lock_guard lock(G_QW_CREDENTIAL_MUTEX);
        static auto username = Keystore::get(QUICKWIT_COLUMN, USER_KEY);
        static auto password = Keystore::get(QUICKWIT_COLUMN, PASSWORD_KEY);

        m_secureCommunication = SecureCommunication::builder();
        if (!username.empty() && !password.empty())
        {
            m_secureCommunication.basicAuth(username + ":" + password);
        }
        m_secureCommunication.sslCertificate(sslCertificate)
            .sslKey(sslKey)
            .caRootCertificate(caRootCertificate);

        m_selector =
            selector ? std::move(selector) : std::make_unique<TSelector>(config.at("hosts"), 10, m_secureCommunication);

        // Initialize logger processor for handling responses
        m_loggerProcessor = std::make_unique<ThreadLoggerQueue>(
            [this](const QuickwitResponse& data)
            {
                thread_local simdjson::dom::parser parser;
                simdjson::dom::element parsedResponse;

                if (auto parseResult = parser.parse(data.m_response).get(parsedResponse);
                    parseResult != simdjson::SUCCESS)
                {
                    logDebug2(QW_NAME, "Quickwit response (non-JSON): %s", data.m_response.c_str());
                    // Quickwit may return non-JSON success responses
                    return;
                }

                // Check for errors in the response
                if (simdjson::dom::element numDocsForProcessing;
                    parsedResponse["num_docs_for_processing"].get(numDocsForProcessing) == simdjson::SUCCESS)
                {
                    int64_t docsProcessed = 0;
                    numDocsForProcessing.get(docsProcessed);
                    logDebug1(QW_NAME, "Successfully indexed %lld documents to index: %s",
                             docsProcessed, data.m_index.c_str());
                }

                // Check for errors
                if (simdjson::dom::element errorElement;
                    parsedResponse["error"].get(errorElement) == simdjson::SUCCESS)
                {
                    std::string_view errorMsg;
                    if (errorElement.get(errorMsg) == simdjson::SUCCESS)
                    {
                        logError(QW_NAME, "Quickwit indexing error: %s", std::string(errorMsg).c_str());
                    }
                }
            });

        // Set database path for persistent queue
        if (config.contains("database_path"))
        {
            m_databasePath = config.at("database_path").get<std::string>();
        }
        else
        {
            m_databasePath = QW_DATABASE_BASE_PATH;
        }

        logInfo(QW_NAME, "Quickwit connector initialized successfully");
    }

    void index(std::string_view index, std::string_view data)
    {
        if (m_stopping || !m_selector || !m_selector->isAvailable())
        {
            return;
        }

        // Get or create dispatcher for this index
        auto dispatcher = getOrCreateDispatcher(std::string(index));

        // Queue the data for async processing
        dispatcher->push(std::string(data));
    }

    bool isAvailable() const
    {
        return m_selector && m_selector->isAvailable();
    }

    void createIndex(std::string_view index, const nlohmann::json& indexConfig)
    {
        if (!m_selector || !m_selector->isAvailable())
        {
            throw QuickwitConnectorException("No Quickwit servers available");
        }

        try
        {
            const auto server = m_selector->getNext();
            std::string url = server + "/api/v1/indexes";

            auto response = m_httpRequest->post(url, indexConfig.dump(), m_secureCommunication);

            if (response.m_error)
            {
                throw QuickwitConnectorException("Failed to create index: " + response.m_error.message());
            }

            logInfo(QW_NAME, "Created Quickwit index: %s", std::string(index).c_str());
        }
        catch (const std::exception& e)
        {
            throw QuickwitConnectorException(std::string("Index creation failed: ") + e.what());
        }
    }

private:
    std::shared_ptr<Utils::AsyncValueDispatcher<std::string, std::function<void(std::queue<std::string>&)>>>
    getOrCreateDispatcher(const std::string& index)
    {
        std::lock_guard lock(m_indexMutex);

        auto it = m_indexDispatchers.find(index);
        if (it != m_indexDispatchers.end())
        {
            return it->second;
        }

        // Create new dispatcher for this index
        auto dispatcher = std::make_shared<Utils::AsyncValueDispatcher<std::string, std::function<void(std::queue<std::string>&)>>>(
            [this, index](std::queue<std::string>& dataQueue)
            {
                processIndexQueue(index, dataQueue);
            },
            FlushInterval);

        m_indexDispatchers[index] = dispatcher;
        return dispatcher;
    }

    void processIndexQueue(const std::string& index, std::queue<std::string>& dataQueue)
    {
        if (m_stopping || dataQueue.empty())
        {
            return;
        }

        // Build NDJSON payload for Quickwit
        std::string payload;
        std::vector<uint64_t> boundaries;
        size_t count = 0;

        while (!dataQueue.empty() && count < ElementsPerBulk)
        {
            const auto& data = dataQueue.front();
            boundaries.push_back(payload.size());
            payload += data;
            payload += "\n"; // NDJSON format
            dataQueue.pop();
            count++;
        }

        if (payload.empty())
        {
            return;
        }

        // Send to Quickwit
        sendToQuickwit(index, std::move(payload), std::move(boundaries));
    }

    void sendToQuickwit(const std::string& index, std::string&& payload, std::vector<uint64_t>&& boundaries)
    {
        if (!m_selector || !m_selector->isAvailable())
        {
            logWarn(QW_NAME, "No Quickwit servers available");
            return;
        }

        try
        {
            const auto server = m_selector->getNext();
            // Quickwit ingest endpoint: POST /api/v1/<index>/ingest
            std::string url = server + "/api/v1/" + index + "/ingest?commit=auto";

            auto response = m_httpRequest->post(url, payload, m_secureCommunication);

            if (response.m_error)
            {
                logError(QW_NAME, "Failed to send data to Quickwit: %s", response.m_error.message().c_str());
                m_selector->setNextAvailable();
                return;
            }

            // Process response asynchronously
            m_loggerProcessor->push(QuickwitResponse(std::move(payload),
                                                     std::move(boundaries),
                                                     std::move(response.m_response),
                                                     std::string(index)));

            m_successCount++;
            if (m_successCount >= MaxSuccessCount)
            {
                m_selector->reportServerHealthy();
                m_successCount = 0;
            }
        }
        catch (const std::exception& e)
        {
            logError(QW_NAME, "Exception while sending to Quickwit: %s", e.what());
            m_selector->setNextAvailable();
        }
    }
};

