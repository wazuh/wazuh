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
#include <keyStore.hpp>

#include "secureCommunication.hpp"
#include "serverSelector.hpp"

constexpr auto INDEXER_COLUMN {"indexer"};
constexpr auto USER_KEY {"username"};
constexpr auto PASSWORD_KEY {"password"};
constexpr auto ELEMENTS_PER_BULK {1000};
constexpr auto WAZUH_OWNER {"wazuh"};
constexpr auto WAZUH_GROUP {"wazuh"};
constexpr auto MERGED_CA_PATH {"/tmp/wazuh-server/root-ca-merged.pem"};

// Single thread in case the events needs to be processed in order.
constexpr auto SINGLE_ORDERED_DISPATCHING = 1;

/**
 * @brief Merges the CA root certificates into a single file.
 * @param filePaths The list of CA root certificates file paths.
 * @param caRootCertificate The path to the merged CA root certificate.
 * @throws std::runtime_error If the CA root certificate file does not exist, could not be opened, written or the
 * ownership could not be changed.
 */
static void mergeCaRootCertificates(const std::vector<std::string>& filePaths, std::string& caRootCertificate)
{
    std::string caRootCertificateContentMerged;

    for (const auto& filePath : filePaths)
    {
        if (!std::filesystem::exists(filePath))
        {
            throw std::runtime_error("The CA root certificate file: '" + filePath + "' does not exist.");
        }

        std::ifstream file(filePath);
        if (!file.is_open())
        {
            throw std::runtime_error("Could not open CA root certificate file: '" + filePath + "'.");
        }

        caRootCertificateContentMerged.append((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    }

    caRootCertificate = MERGED_CA_PATH;

    if (std::filesystem::path dirPath = std::filesystem::path(caRootCertificate).parent_path();
        !std::filesystem::exists(dirPath) && !std::filesystem::create_directories(dirPath))
    {
        throw std::runtime_error("Could not create the directory for the CA root merged file");
    }

    std::ofstream outputFile(caRootCertificate);
    if (!outputFile.is_open())
    {
        throw std::runtime_error("Could not write the CA root merged file");
    }

    outputFile << caRootCertificateContentMerged;
    outputFile.close();

    struct passwd* pwd = getpwnam(WAZUH_OWNER);
    struct group* grp = getgrnam(WAZUH_GROUP);

    if (pwd == nullptr && grp == nullptr)
    {
        throw std::runtime_error("Could not get the user and group information.");
    }

    if (chown(caRootCertificate.c_str(), pwd->pw_uid, grp->gr_gid) != 0)
    {
        throw std::runtime_error("Could not change the ownership of the CA root merged file");
    }

    LOG_DEBUG("All CA files merged into '{}' successfully.", caRootCertificate.c_str());
}

static void initConfiguration(SecureCommunication& secureCommunication, const IndexerConnectorOptions& config)
{
    std::string caRootCertificate;
    std::string sslCertificate;
    std::string sslKey;
    std::string username;
    std::string password;

    if (config.sslOptions.cacert.size() > 1)
    {
        mergeCaRootCertificates(config.sslOptions.cacert, caRootCertificate);
    }
    else if (!config.sslOptions.cacert.empty())
    {
        caRootCertificate = config.sslOptions.cacert.front();
    }
    else
    {
        LOG_DEBUG("No CA root certificate found in the configuration.");
    }

    sslCertificate = config.sslOptions.cert;
    sslKey = config.sslOptions.key;

    Keystore::get(INDEXER_COLUMN, USER_KEY, username);
    Keystore::get(INDEXER_COLUMN, PASSWORD_KEY, password);

    if (username.empty())
    {
        username = "admin";
        LOG_WARNING("No username found in the configuration, using default value.");
    }

    if (password.empty())
    {
        password = "admin";
        LOG_WARNING("No password found in the configuration, using default value.");
    }

    secureCommunication.basicAuth(username + ":" + password)
        .sslCertificate(sslCertificate)
        .sslKey(sslKey)
        .caRootCertificate(caRootCertificate);
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
            url.append("/_bulk?refresh=wait_for");

            std::string indexNameCurrentDate = m_indexName;
            base::utils::string::replaceAll(indexNameCurrentDate, "$(date)", base::utils::time::getCurrentDate("."));

            while (!dataQueue.empty())
            {
                auto data = dataQueue.front();
                dataQueue.pop();
                auto parsedData = nlohmann::json::parse(data, nullptr, false);

                if (parsedData.is_discarded())
                {
                    continue;
                }

                if (parsedData.at("operation").get_ref<const std::string&>().compare("DELETED") == 0)
                {
                    const auto& id = parsedData.at("id").get_ref<const std::string&>();
                    builderBulkDelete(bulkData, id, indexNameCurrentDate);
                }
                else
                {
                    const auto& id = parsedData.contains("id") ? parsedData.at("id").get_ref<const std::string&>() : "";
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
