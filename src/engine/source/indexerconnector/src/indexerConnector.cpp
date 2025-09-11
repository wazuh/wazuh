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

#include <filesystem>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>

#include <HTTPRequest.hpp>
#include <base/logging.hpp>
#include <base/utils/stringUtils.hpp>
#include <base/utils/timeUtils.hpp>
#include <indexerConnector/indexerConnector.hpp>

#include "secureCommunication.hpp"
#include "serverSelector.hpp"

constexpr auto INDEXER_COLUMN {"indexer"};
constexpr auto USER_KEY {"username"};
constexpr auto PASSWORD_KEY {"password"};
constexpr auto ELEMENTS_PER_BULK {1000};
constexpr auto WAZUH_OWNER {"wazuh"};
constexpr auto WAZUH_GROUP {"wazuh"};
constexpr auto MERGED_CA_PATH {"/var/lib/wazuh-server/tmp/root-ca-merged.pem"};

// Single thread in case the events needs to be processed in order.
constexpr auto SINGLE_ORDERED_DISPATCHING = 1;

static void initConfiguration(SecureCommunication& secureCommunication, const IndexerConnectorOptions& config)
{
    std::string caRootCertificate;
    std::string sslCertificate;
    std::string sslKey;
    std::string username;
    std::string password;

    if (!config.sslOptions.cacert.empty())
    {
        caRootCertificate = config.sslOptions.cacert;
    }
    else
    {
        LOG_DEBUG("No CA root certificate found in the configuration.");
    }

    sslCertificate = config.sslOptions.cert;
    sslKey = config.sslOptions.key;
    username = config.username;
    password = config.password;

    if (config.username.empty())
    {
        username = "admin";
        LOG_WARNING("No username found in the configuration, using default value.");
    }

    if (config.password.empty())
    {
        password = "admin";
        LOG_WARNING("No password found in the configuration, using default value.");
    }

    secureCommunication.basicAuth(username + ":" + password)
        .sslCertificate(sslCertificate)
        .sslKey(sslKey)
        .caRootCertificate(caRootCertificate)
        .skipPeerVerification(config.sslOptions.skipVerifyPeer);
}

static void builderBulkDelete(std::string& bulkData, std::string_view id, std::string_view index)
{
    bulkData.append(R"({"delete":{"_index":")");
    bulkData.append(index);
    bulkData.append(R"(","_id":")");
    bulkData.append(id);
    bulkData.append(R"("}})");
    bulkData.append("\n");
}

static void builderBulkIndex(std::string& bulkData, std::string_view id, std::string_view index, std::string_view data)
{
    bulkData.append(R"({"index":{"_index":")");
    bulkData.append(index);

    if (!id.empty())
    {
        bulkData.append(R"(","_id":")");
        bulkData.append(id);
    }

    bulkData.append(R"("}})");
    bulkData.append("\n");
    bulkData.append(data);
    bulkData.append("\n");
}

IndexerConnector::IndexerConnector(const IndexerConnectorOptions& indexerConnectorOptions)
{
    // Get index name.
    m_indexName = indexerConnectorOptions.name;

    if (base::utils::string::haveUpperCaseCharacters(m_indexName))
    {
        throw std::invalid_argument("Index name must be lowercase.");
    }

    auto secureCommunication = SecureCommunication::builder();
    initConfiguration(secureCommunication, indexerConnectorOptions);

    // Initialize publisher.
    auto selector {std::make_shared<TServerSelector<Monitoring>>(
        indexerConnectorOptions.hosts, indexerConnectorOptions.timeout, secureCommunication)};

    // Validate threads number
    if (indexerConnectorOptions.workingThreads <= 0)
    {
        LOG_DEBUG("Invalid number of working threads, using default value.");
    }

    m_dispatcher = std::make_unique<ThreadDispatchQueue>(
        [this, selector, secureCommunication, functionName = logging::getLambdaName(__FUNCTION__, "processEventQueue")](
            std::queue<std::string>& dataQueue)
        {
            std::scoped_lock lock(m_syncMutex);

            if (m_stopping.load())
            {
                LOG_DEBUG_L(functionName.c_str(), "IndexerConnector is stopping, event processing will be skipped.");
                throw std::runtime_error("IndexerConnector is stopping, event processing will be skipped.");
            }

            auto url = selector->getNext();
            std::string bulkData;
            url.append("/_bulk");

            std::string indexNameCurrentDate = m_indexName;
            base::utils::string::replaceAll(indexNameCurrentDate, "$(date)", base::utils::time::getCurrentDate("."));

            while (!dataQueue.empty())
            {
                auto data = dataQueue.front();
                dataQueue.pop();
                auto parsedData = nlohmann::json::parse(data, nullptr, false);

                // If the data is not a valid JSON, log a warning and continue.
                if (parsedData.is_discarded())
                {
                    LOG_WARNING("Failed to parse event data: {}", data);
                    continue;
                }

                // Validate required fields.
                if (!parsedData.contains("operation"))
                {
                    LOG_WARNING("Event required field (operation) is missing: {}", data);
                    continue;
                }

                // Operation is the action to be performed on the element.
                const auto& operation = parsedData.at("operation").get_ref<const std::string&>();

                // Id is the unique identifier of the element.
                const auto& id = parsedData.contains("id") ? parsedData.at("id").get_ref<const std::string&>() : "";

                if (operation.compare("DELETED") == 0)
                {
                    // Validate required fields.
                    if (id.empty())
                    {
                        LOG_WARNING("Event required field (id) is missing: {}", data);
                        continue;
                    }

                    builderBulkDelete(bulkData, id, indexNameCurrentDate);
                }
                else
                {
                    // Validate required fields.
                    if (!parsedData.contains("data"))
                    {
                        LOG_WARNING("Event required field (data) is missing: {}", data);
                        continue;
                    }

                    if (parsedData.contains("index"))
                    {
                        indexNameCurrentDate = parsedData.at("index").get<std::string>();
                        base::utils::string::replaceAll(
                            indexNameCurrentDate, "$(date)", base::utils::time::getCurrentDate("."));
                    }

                    const auto dataString = parsedData.at("data").dump();
                    builderBulkIndex(bulkData, id, indexNameCurrentDate, dataString);
                }
            }

            if (!bulkData.empty())
            {
                // Process data.
                HTTPRequest::instance().post(
                    {.url = HttpURL(url), .data = bulkData, .secureCommunication = secureCommunication},
                    {.onSuccess = [functionName = logging::getLambdaName(__FUNCTION__, "handleSuccessfulPostResponse")](
                                      const std::string& response)
                     { LOG_DEBUG_L(functionName.c_str(), "Response: {}", response.c_str()); },
                     .onError =
                         [functionName = logging::getLambdaName(__FUNCTION__, "handlePostResponseError")](
                             const std::string& error, const long statusCode)
                     {
                         LOG_ERROR_L(functionName.c_str(), "{}, status code: {}.", error.c_str(), statusCode);
                         throw std::runtime_error(error);
                     }});
            }
        },
        ThreadEventDispatcherParams {.dbPath = indexerConnectorOptions.databasePath + m_indexName,
                                     .bulkSize = ELEMENTS_PER_BULK,
                                     .dispatcherType =
                                         (indexerConnectorOptions.workingThreads <= SINGLE_ORDERED_DISPATCHING
                                              ? ThreadEventDispatcherType::SINGLE_THREADED_ORDERED
                                              : ThreadEventDispatcherType::MULTI_THREADED_UNORDERED)});
}

IndexerConnector::~IndexerConnector()
{
    m_stopping.store(true);
    m_cv.notify_all();

    m_dispatcher->cancel();
}

void IndexerConnector::publish(const std::string& message)
{
    m_dispatcher->push(message);
}
