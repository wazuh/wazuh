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

#include "indexerConnector.hpp"
#include "HTTPRequest.hpp"
#include "keyStore.hpp"
#include "loggerHelper.h"
#include "secureCommunication.hpp"
#include "serverSelector.hpp"
#include <filesystem>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>

constexpr auto USER_GROUP {"wazuh"};
constexpr auto DEFAULT_PATH {"tmp/root-ca-merged.pem"};
constexpr auto NOT_USED {-1};
constexpr auto INDEXER_COLUMN {"indexer"};
constexpr auto USER_KEY {"username"};
constexpr auto PASSWORD_KEY {"password"};
constexpr auto ELEMENTS_PER_BULK {25000};
constexpr auto MINIMAL_ELEMENTS_PER_BULK {5};

constexpr auto HTTP_BAD_REQUEST {400};
constexpr auto HTTP_CONTENT_LENGTH {413};
constexpr auto HTTP_VERSION_CONFLICT {409};
constexpr auto HTTP_TOO_MANY_REQUESTS {429};

constexpr auto RECURSIVE_MAX_DEPTH {20};

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
};
constexpr auto MAX_WAIT_TIME {60};
constexpr auto START_TIME {1};
constexpr auto DOUBLE_FACTOR {2};

// Single thread because the events needs to be processed in order.
constexpr auto DATABASE_WORKERS = 1;
constexpr auto DATABASE_BASE_PATH = "queue/indexer/";

// Sync configuration
constexpr auto SYNC_WORKERS = 1;
constexpr auto SYNC_QUEUE_LIMIT = 4096;

// Abuse control
constexpr auto MINIMAL_SYNC_TIME {30}; // In minutes

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

    caRootCertificate = DEFAULT_PATH;

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

    struct passwd* pwd = getpwnam(USER_GROUP);
    struct group* grp = getgrnam(USER_GROUP);

    if (pwd == nullptr || grp == nullptr)
    {
        throw std::runtime_error("Could not get the user and group information.");
    }

    if (chown(caRootCertificate.c_str(), pwd->pw_uid, grp->gr_gid) != 0)
    {
        throw std::runtime_error("Could not change the ownership of the CA root merged file");
    }

    logDebug2(IC_NAME, "All CA files merged into '%s' successfully.", caRootCertificate.c_str());
}

static void initConfiguration(SecureCommunication& secureCommunication, const nlohmann::json& config)
{
    std::string caRootCertificate;
    std::string sslCertificate;
    std::string sslKey;
    std::string username;
    std::string password;

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

    Keystore::get(INDEXER_COLUMN, USER_KEY, username);
    Keystore::get(INDEXER_COLUMN, PASSWORD_KEY, password);

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

static void builderDeleteByQuery(nlohmann::json& bulkData, const std::string& agentId)
{
    bulkData["query"]["bool"]["filter"]["terms"]["agent.id"].push_back(agentId);
}

static void builderBulkIndex(std::string& bulkData, std::string_view id, std::string_view index, std::string_view data)
{
    bulkData.append(R"({"index":{"_index":")");
    bulkData.append(index);
    bulkData.append(R"(","_id":")");
    bulkData.append(id);
    bulkData.append(R"("}})");
    bulkData.append("\n");
    bulkData.append(data);
    bulkData.append("\n");
}

bool IndexerConnector::abuseControl(const std::string& agentId)
{
    const auto currentTime = std::chrono::system_clock::now();
    // If the agent is in the map, check if the last sync was less than MINIMAL_SYNC_TIME minutes ago.
    if (const auto lastSync = m_lastSync.find(agentId); lastSync != m_lastSync.end())
    {
        const auto diff = std::chrono::duration_cast<std::chrono::minutes>(currentTime - lastSync->second);
        // If the last sync was less than MINIMAL_SYNC_TIME minutes ago, return true.
        if (diff.count() < MINIMAL_SYNC_TIME)
        {
            logDebug2(IC_NAME, "Agent '%s' sync omitted due to abuse control.", agentId.c_str());
            return true;
        }
    }
    // If the agent is not in the map, add it to the map with the current time.
    m_lastSync[agentId] = currentTime;
    return false;
}

nlohmann::json IndexerConnector::getAgentDocumentsIds(const std::string& url,
                                                      const std::string& agentId,
                                                      const SecureCommunication& secureCommunication) const
{
    nlohmann::json postData;
    nlohmann::json responseJson;
    constexpr auto ELEMENTS_PER_QUERY {10000}; // The max value for queries is 10000 in the wazuh-indexer.

    postData["query"]["match"]["agent.id"] = agentId;
    postData["size"] = ELEMENTS_PER_QUERY;
    postData["_source"] = nlohmann::json::array({"_id"});

    {
        const auto onSuccess = [&responseJson](const std::string& response)
        {
            responseJson = nlohmann::json::parse(response);
        };

        const auto onError = [](const std::string& error, const long statusCode)
        {
            logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
            throw std::runtime_error(error);
        };

        HTTPRequest::instance().post(
            RequestParametersJson {.url = HttpURL(url + "/" + m_indexName + "/_search?scroll=1m"),
                                   .data = postData,
                                   .secureCommunication = secureCommunication},
            PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
            ConfigurationParameters {});
    }

    // If the response have more than ELEMENTS_PER_QUERY elements, we need to scroll.
    if (responseJson.at("hits").at("total").at("value").get<int>() > ELEMENTS_PER_QUERY)
    {
        const auto& scrollId = responseJson.at("_scroll_id").get_ref<const std::string&>();
        const auto scrollUrl = url + "/_search/scroll";
        const auto scrollData = R"({"scroll":"1m","scroll_id":")" + scrollId + "\"}";

        const auto onError = [](const std::string& error, const long)
        {
            throw std::runtime_error(error);
        };

        const auto onSuccess = [&responseJson](const std::string& response)
        {
            auto newResponse = nlohmann::json::parse(response);
            for (const auto& hit : newResponse.at("hits").at("hits"))
            {
                responseJson.at("hits").at("hits").push_back(hit);
            }
        };

        while (responseJson.at("hits").at("hits").size() < responseJson.at("hits").at("total").at("value").get<int>())
        {
            HTTPRequest::instance().post(RequestParameters {.url = HttpURL(scrollUrl),
                                                            .data = scrollData,
                                                            .secureCommunication = secureCommunication},
                                         PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                                         ConfigurationParameters {});
        }
    }

    return responseJson;
}

void IndexerConnector::sendBulkReactive(const std::vector<std::pair<std::string, bool>>& actions,
                                        const std::string& url,
                                        const SecureCommunication& secureCommunication,
                                        const int depth)
{
    if (depth > RECURSIVE_MAX_DEPTH)
    {
        throw std::runtime_error("Error 413 recursion limit reached, cannot split further.");
    }

    std::string bulkData;
    // Iterate over the actions vector and build the bulk data.
    // If the element is marked as deleted, the element will be deleted from the indexer.
    // If the element is not marked as deleted, the element will be added to the indexer.
    for (const auto& [id, deleted] : actions)
    {
        if (deleted)
        {
            builderBulkDelete(bulkData, id, m_indexName);
        }
        else
        {
            std::string data;
            if (!m_db->get(id, data))
            {
                throw std::runtime_error("Failed to get data from the database.");
            }
            builderBulkIndex(bulkData, id, m_indexName, data);
        }
    }

    if (!bulkData.empty())
    {
        const auto onSuccess = [](const std::string& response)
        {
            logDebug2(IC_NAME, "Response: %s", response.c_str());
        };

        const auto onError =
            [this, &actions, &url, &secureCommunication, depth](const std::string& error, const long statusCode)
        {
            if (statusCode == HTTP_CONTENT_LENGTH)
            {
                logWarn(IC_NAME, "The request is too large. Splitting the bulk data.");
                if (actions.size() == 1)
                {
                    logError(IC_NAME, "One document is too large, cannot split further.");
                    throw std::runtime_error("Single-document 413, cannot split further.");
                }

                auto mid = actions.begin() + std::ptrdiff_t(actions.size() / 2);
                std::vector<std::pair<std::string, bool>> left(actions.begin(), mid);
                std::vector<std::pair<std::string, bool>> right(mid, actions.end());

                sendBulkReactive(left, url, secureCommunication, depth + 1);
                sendBulkReactive(right, url, secureCommunication, depth + 1);
            }
            else if (statusCode == HTTP_VERSION_CONFLICT)
            {
                logDebug2(IC_NAME, "Document version conflict, sync omitted.");
                throw std::runtime_error("Document version conflict, sync omitted.");
            }
            else if (statusCode == HTTP_TOO_MANY_REQUESTS)
            {
                logDebug2(IC_NAME, "Too many requests, sync ommited.");
                throw std::runtime_error("Too many requests, sync ommited.");
            }
            else
            {
                logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
                throw std::runtime_error(error);
            }
        };

        HTTPRequest::instance().post(
            RequestParameters {.url = HttpURL(url), .data = bulkData, .secureCommunication = secureCommunication},
            PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
            ConfigurationParameters {});
    }
}

void IndexerConnector::diff(const nlohmann::json& responseJson,
                            const std::string& agentId,
                            const SecureCommunication& secureCommunication,
                            const std::shared_ptr<ServerSelector>& selector)
{
    std::vector<std::pair<std::string, bool>> status;
    std::vector<std::pair<std::string, bool>> actions;

    // Move elements to vector.
    for (const auto& hit : responseJson.at("hits").at("hits"))
    {
        if (hit.contains("_id"))
        {
            status.emplace_back(hit.at("_id").get_ref<const std::string&>(), false);
        }
    }

    // Iterate over the database and check if the element is in the status vector.
    for (const auto& [key, value] : m_db->seek(agentId))
    {
        bool found {false};
        for (auto& [id, data] : status)
        {
            // If the element is found, mark it as found.
            if (key.compare(id) == 0)
            {
                data = true;
                found = true;
                break;
            }
        }

        // If the element is not found, add it to the actions vector. This element will be added to the indexer.
        if (!found)
        {
            actions.emplace_back(key, false);
        }
    }

    // Iterate over the status vector and check if the element is marked as not found.
    // This means that the element is in the indexer but not in the database. To solve this, the element will be deleted
    for (const auto& [id, data] : status)
    {
        if (!data)
        {
            actions.emplace_back(id, true);
        }
    }

    auto url = selector->getNext();
    url.append("/_bulk?refresh=wait_for");

    sendBulkReactive(actions, url, secureCommunication);
}

void IndexerConnector::initialize(const nlohmann::json& templateData,
                                  const nlohmann::json& updateMappingsData,
                                  const std::shared_ptr<ServerSelector>& selector,
                                  const SecureCommunication& secureCommunication)
{
    // Define the error callback
    auto onError = [](const std::string& error, const long statusCode)
    {
        if (statusCode != HTTP_BAD_REQUEST) // Assuming 400 is for bad requests which we expect to handle differently
        {
            std::string errorMessage = error;
            if (statusCode != NOT_USED)
            {
                errorMessage += " (Status code: " + std::to_string(statusCode) + ")";
            }

            throw std::runtime_error(errorMessage);
        }
    };

    // Define the success callback
    auto onSuccess = [](const std::string&)
    {
        // Not used
    };

    // Initialize template.
    HTTPRequest::instance().put(
        RequestParametersJson {.url = HttpURL(selector->getNext() + "/_index_template/" + m_indexName + "_template"),
                               .data = templateData,
                               .secureCommunication = secureCommunication},
        PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
        ConfigurationParameters {});

    // Initialize Index.
    HTTPRequest::instance().put(RequestParametersJson {.url = HttpURL(selector->getNext() + "/" + m_indexName),
                                                       .data = templateData.at("template"),
                                                       .secureCommunication = secureCommunication},
                                PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                                ConfigurationParameters {});

    // Create new mappings after update.
    if (!updateMappingsData.empty())
    {
        HTTPRequest::instance().put(
            RequestParametersJson {.url = HttpURL(selector->getNext() + "/" + m_indexName + "/_mapping"),
                                   .data = updateMappingsData,
                                   .secureCommunication = secureCommunication},
            PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
            ConfigurationParameters {});
    }

    m_initialized = true;
    logInfo(IC_NAME, "IndexerConnector initialized successfully for index: %s.", m_indexName.c_str());
}

void IndexerConnector::preInitialization(
    const std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>&
        logFunction,
    const nlohmann::json& config)
{
    if (logFunction)
    {
        Log::assignLogFunction(logFunction);
    }

    // Get index name.
    m_indexName = config.at("name").get_ref<const std::string&>();

    if (Utils::haveUpperCaseCharacters(m_indexName))
    {
        throw std::runtime_error("Index name must be lowercase.");
    }

    m_db = std::make_unique<Utils::RocksDBWrapper>(std::string(DATABASE_BASE_PATH) + "db/" + m_indexName);
}

IndexerConnector::IndexerConnector(
    const nlohmann::json& config,
    const std::string& templatePath,
    const std::string& updateMappingsPath,
    const std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>&
        logFunction,
    const uint32_t& timeout)
{
    preInitialization(logFunction, config);

    auto secureCommunication = SecureCommunication::builder();
    initConfiguration(secureCommunication, config);

    // Read template file.
    std::ifstream templateFile(templatePath);
    if (!templateFile.is_open())
    {
        throw std::runtime_error("Could not open template file: " + templatePath);
    }
    nlohmann::json templateData = nlohmann::json::parse(templateFile);

    // Read add mappings file.
    nlohmann::json updateMappingsData = nlohmann::json::object();
    if (!updateMappingsPath.empty())
    {

        std::ifstream updateMappingsFile(updateMappingsPath);
        if (!updateMappingsFile.is_open())
        {
            throw std::runtime_error("Could not open the update mappings file: " + updateMappingsPath);
        }
        updateMappingsData = nlohmann::json::parse(updateMappingsFile);
    }

    // Initialize publisher.
    auto selector {std::make_shared<ServerSelector>(config.at("hosts"), timeout, secureCommunication)};

    m_dispatcher = std::make_unique<ThreadDispatchQueue>(
        [this, selector, secureCommunication](std::queue<std::string>& dataQueue)
        {
            std::scoped_lock lock(m_syncMutex);

            if (!m_initialized && m_initializeThread.joinable())
            {
                logDebug2(IC_NAME, "Waiting for initialization thread to process events.");
                m_initializeThread.join();
            }

            if (m_stopping.load())
            {
                logDebug2(IC_NAME, "IndexerConnector is stopping, event processing will be skipped.");
                throw std::runtime_error("IndexerConnector is stopping, event processing will be skipped.");
            }

            // Accumulator for data to be sent to the indexer via bulk requests.
            std::string bulkData;

            // Accumulator for data to be sent to the indexer via query requests.
            nlohmann::json queryData;

            while (!dataQueue.empty())
            {
                auto data = dataQueue.front();
                dataQueue.pop();
                const auto parsedData = nlohmann::json::parse(data, nullptr, false);
                // If the data is not a valid JSON, log a warning and continue.
                if (parsedData.is_discarded())
                {
                    logWarn(IC_NAME, "Failed to parse event data: %s", data.c_str());
                    continue;
                }

                // If the data does not contain the required fields, log a warning and continue.
                if (!parsedData.contains("id") || !parsedData.contains("operation"))
                {
                    logWarn(IC_NAME, "Event required fields (id or operation) are missing: %s", data.c_str());
                    continue;
                }

                // Id is the unique identifier of the element.
                const auto& id = parsedData.at("id").get_ref<const std::string&>();

                // Operation is the action to be performed on the element.
                const auto& operation = parsedData.at("operation").get_ref<const std::string&>();

                // If the element should not be indexed, only delete it from the sync database.
                const auto noIndex = parsedData.contains("no-index") ? parsedData.at("no-index").get<bool>() : false;

                if (operation.compare("DELETED") == 0)
                {
                    logDebug2(IC_NAME, "Added document for deletion with id: %s.", id.c_str());
                    if (!noIndex)
                    {
                        builderBulkDelete(bulkData, id, m_indexName);
                    }
                    m_db->delete_(id);
                }
                else if (operation.compare("DELETED_BY_QUERY") == 0)
                {
                    logDebug2(IC_NAME, "Added document for deletion by query with id: %s.", id.c_str());
                    if (!noIndex)
                    {
                        builderDeleteByQuery(queryData, id);
                    }

                    for (const auto& [key, _] : m_db->seek(id))
                    {
                        m_db->delete_(key);
                    }
                }
                else
                {
                    logDebug2(IC_NAME, "Added document for insertion with id: %s.", id.c_str());
                    // If the data does not contain the required fields, log a warning and continue.
                    if (!parsedData.contains("data"))
                    {
                        logWarn(IC_NAME, "Event required field (data) is missing required fields: %s", data.c_str());
                        continue;
                    }

                    const auto dataString = parsedData.at("data").dump();
                    if (!noIndex)
                    {
                        builderBulkIndex(bulkData, id, m_indexName, dataString);
                    }
                    m_db->put(id, dataString);
                }
            }

            // Send data to the indexer to be processed.
            const auto processData = [this, &secureCommunication](const std::string& data, const std::string& url)
            {
                const auto bulkSize = this->m_dispatcher->bulkSize();
                constexpr auto SUCCESS_COUNT_TO_INCREASE_BULK_SIZE {5};

                const auto onSuccess = [this, bulkSize](const std::string& response)
                {
                    logDebug2(IC_NAME, "Response: %s", response.c_str());

                    // If the request was successful and the current bulk size is less than ELEMENTS_PER_BULK, increase
                    // the bulk size if the success count is SUCCESS_COUNT_TO_INCREASE_BULK_SIZE

                    if (m_successCount < SUCCESS_COUNT_TO_INCREASE_BULK_SIZE)
                    {
                        m_successCount++;
                    }

                    m_error413FirstTime = false;

                    if (bulkSize < ELEMENTS_PER_BULK)
                    {
                        if (m_successCount < SUCCESS_COUNT_TO_INCREASE_BULK_SIZE)
                        {
                            logDebug2(IC_NAME,
                                      "Waiting for %d successful requests to increase the bulk size.",
                                      SUCCESS_COUNT_TO_INCREASE_BULK_SIZE - m_successCount);
                            return;
                        }

                        if (bulkSize * 2 > ELEMENTS_PER_BULK)
                        {
                            this->m_dispatcher->bulkSize(ELEMENTS_PER_BULK);
                            logDebug2(
                                IC_NAME, "Increasing the elements to be sent to the indexer: %d.", ELEMENTS_PER_BULK);
                        }
                        else
                        {
                            this->m_dispatcher->bulkSize(bulkSize * 2);
                            logDebug2(IC_NAME, "Increasing the elements to be sent to the indexer: %d.", bulkSize * 2);
                        }
                    }
                };

                const auto onError = [this, &data, bulkSize](const std::string& error, const long statusCode)
                {
                    if (statusCode == HTTP_CONTENT_LENGTH)
                    {
                        m_successCount = 0;
                        if (bulkSize / 2 < MINIMAL_ELEMENTS_PER_BULK)
                        {
                            // If the bulk size is too small, log an error and throw an exception.
                            // This error will be fixed by the user by increasing the http.max_content_length value in
                            // the wazuh-indexer settings.
                            if (m_error413FirstTime == false)
                            {
                                m_error413FirstTime = true;
                                logError(IC_NAME,
                                         "The amount of elements to process is too small, review the "
                                         "'http.max_content_length' value in "
                                         "the wazuh-indexer settings. Current data size: %llu.",
                                         data.size());
                            }

                            throw std::runtime_error("The amount of elements to process is too small, review the "
                                                     "'http.max_content_length' value in "
                                                     "the wazuh-indexer settings.");
                        }
                        else
                        {
                            logDebug2(IC_NAME, "Reducing the elements to be sent to the indexer: %llu.", bulkSize / 2);
                            this->m_dispatcher->bulkSize(bulkSize / 2);
                            throw std::runtime_error("Bulk size is too large, reducing the elements to be sent to the "
                                                     "indexer.");
                        }
                    }
                    else if (statusCode == HTTP_VERSION_CONFLICT)
                    {
                        logDebug2(IC_NAME, "Document version conflict, retrying in 1 second.");
                        throw std::runtime_error("Document version conflict, retrying in 1 second.");
                    }
                    else if (statusCode == HTTP_TOO_MANY_REQUESTS)
                    {
                        logDebug2(IC_NAME, "Too many requests, retrying in 1 second.");
                        throw std::runtime_error("Too many requests, retrying in 1 second.");
                    }
                    else
                    {
                        logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
                        throw std::runtime_error(error);
                    }
                };

                HTTPRequest::instance().post(
                    RequestParameters {.url = HttpURL(url), .data = data, .secureCommunication = secureCommunication},
                    PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                    {});
            };

            const auto serverUrl = selector->getNext();

            if (!bulkData.empty())
            {
                const auto url = serverUrl + "/_bulk?refresh=wait_for";
                processData(bulkData, url);
            }

            if (!queryData.empty())
            {
                const auto url = serverUrl + "/" + m_indexName + "/_delete_by_query";
                processData(queryData.dump(), url);
            }
        },
        DATABASE_BASE_PATH + m_indexName,
        ELEMENTS_PER_BULK);

    m_syncQueue = std::make_unique<ThreadSyncQueue>(
        // coverity[missing_lock]
        [this, selector, secureCommunication](const std::string& agentId)
        {
            try
            {
                std::scoped_lock lock(m_syncMutex);
                if (!abuseControl(agentId))
                {
                    logDebug2(IC_NAME, "Syncing agent '%s' with the indexer.", agentId.c_str());
                    diff(getAgentDocumentsIds(selector->getNext(), agentId, secureCommunication),
                         agentId,
                         secureCommunication,
                         selector);
                }
            }
            catch (const std::exception& e)
            {
                logWarn(IC_NAME, "Failed to sync agent '%s' with the indexer.", agentId.c_str());
                logDebug1(IC_NAME, "Error: %s", e.what());
            }
        },
        SYNC_WORKERS,
        SYNC_QUEUE_LIMIT);

    m_initializeThread = std::thread(
        // coverity[copy_constructor_call]
        [this, templateData, updateMappingsData, selector, secureCommunication]()
        {
            auto sleepTime = std::chrono::seconds(START_TIME);
            std::unique_lock lock(m_mutex);
            auto warningPrinted {false};
            do
            {
                try
                {
                    sleepTime *= DOUBLE_FACTOR;
                    if (sleepTime.count() > MAX_WAIT_TIME)
                    {
                        sleepTime = std::chrono::seconds(MAX_WAIT_TIME);
                    }

                    initialize(templateData, updateMappingsData, selector, secureCommunication);
                }
                catch (const std::exception& e)
                {
                    logDebug1(IC_NAME,
                              "Unable to initialize IndexerConnector for index '%s': %s. Retrying in %ld "
                              "seconds.",
                              m_indexName.c_str(),
                              e.what(),
                              sleepTime.count());
                    if (!warningPrinted)
                    {
                        logWarn(IC_NAME,
                                "IndexerConnector initialization failed for index '%s', retrying until the connection "
                                "is successful.",
                                m_indexName.c_str());
                        warningPrinted = true;
                    }
                }
            } while (!m_initialized && !m_cv.wait_for(lock, sleepTime, [this]() { return m_stopping.load(); }));
        });
}

IndexerConnector::IndexerConnector(
    const nlohmann::json& config,
    const std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>&
        logFunction)
{
    preInitialization(logFunction, config);

    m_dispatcher = std::make_unique<ThreadDispatchQueue>(
        [this](std::queue<std::string>& dataQueue)
        {
            while (!dataQueue.empty())
            {
                auto data = dataQueue.front();
                dataQueue.pop();
                auto parsedData = nlohmann::json::parse(data);
                const auto& id = parsedData.at("id").get_ref<const std::string&>();

                // We only sync the local DB when the indexer is disabled
                if (parsedData.at("operation").get_ref<const std::string&>().compare("DELETED") == 0)
                {
                    m_db->delete_(id);
                }
                // We made the same operation for DELETED_BY_QUERY as for DELETED
                else if (parsedData.at("operation").get_ref<const std::string&>().compare("DELETED_BY_QUERY") == 0)
                {
                    for (const auto& [key, _] : m_db->seek(id))
                    {
                        m_db->delete_(key);
                    }
                }
                else
                {
                    // If the data does not contain the required fields, log a warning and continue.
                    if (!parsedData.contains("data"))
                    {
                        logWarn(IC_NAME, "Event required field (data) is missing required fields: %s", data.c_str());
                        continue;
                    }
                    const auto dataString = parsedData.at("data").dump();
                    m_db->put(id, dataString);
                }
            }
        },
        DATABASE_BASE_PATH + m_indexName,
        ELEMENTS_PER_BULK);

    m_syncQueue = std::make_unique<ThreadSyncQueue>(
        [](const std::string& agentId)
        {
            // We don't sync the DB when the indexer is disabled
        },
        SYNC_WORKERS,
        SYNC_QUEUE_LIMIT);

    m_initializeThread = std::thread(
        []()
        {
            // We don't initialize when the indexer is disabled
        });
}

IndexerConnector::~IndexerConnector()
{
    m_stopping.store(true);
    m_cv.notify_all();

    m_dispatcher->cancel();

    if (m_initializeThread.joinable())
    {
        m_initializeThread.join();
    }
}

void IndexerConnector::publish(const std::string& message)
{
    m_dispatcher->push(message);
}

void IndexerConnector::sync(const std::string& agentId)
{
    m_syncQueue->push(agentId);
}
