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
#include <chrono>
#include <filesystem>
#include <fstream>
#include <grp.h>
#include <mutex>
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
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
}; // namespace Log
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

static std::mutex G_CREDENTIAL_MUTEX;

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

/**
 * @brief Fast check if error is resource_already_exists_exception
 */
static inline bool isResourceAlreadyExists(std::string_view errorBody) noexcept
{
    return errorBody.find("resource_already_exists_exception") != std::string_view::npos;
}

/**
 * @brief Fast check if error is template priority conflict
 */
static inline bool isTemplatePriorityConflict(std::string_view errorBody) noexcept
{
    return errorBody.find("illegal_argument_exception") != std::string_view::npos &&
           errorBody.find("multiple index templates") != std::string_view::npos &&
           errorBody.find("same priority") != std::string_view::npos;
}

/**
 * @brief Fast check if error is validation_exception with shard limit
 */
static inline bool isShardLimitError(std::string_view errorBody) noexcept
{
    return errorBody.find("validation_exception") != std::string_view::npos &&
           errorBody.find("maximum shards open") != std::string_view::npos;
}

static inline void extractErrorInfo(const std::string& errorBody, std::string& type, std::string& reason) noexcept
{
    try
    {
        const auto errorJson = nlohmann::json::parse(errorBody);
        if (errorJson.contains("error"))
        {
            const auto& error = errorJson.at("error");
            if (error.contains("type"))
            {
                type = error.at("type").get_ref<const std::string&>();
            }
            if (error.contains("reason"))
            {
                reason = error.at("reason").get_ref<const std::string&>();
            }
        }
    }
    catch (const nlohmann::json::exception&)
    {
        logError(IC_NAME, "Failed to parse error body JSON.");
    }
}

// ------- IndexerConnector methods implementation -------

nlohmann::json IndexerConnector::getAgentDocumentsIds(const std::string& url,
                                                      const std::string& agentId,
                                                      const SecureCommunication& secureCommunication) const
{
    nlohmann::json postData;
    nlohmann::json responseJson;
    constexpr auto ELEMENTS_PER_QUERY {10000}; // The max value for queries is 10000 in the wazuh-indexer.
    std::string scrollId;

    postData["query"]["match"]["agent.id"] = agentId;
    postData["size"] = ELEMENTS_PER_QUERY;
    postData["_source"] = nlohmann::json::array({"_id"});

    {
        const auto onSuccess = [&responseJson, &scrollId](const std::string& response)
        {
            responseJson = nlohmann::json::parse(response);
            scrollId = responseJson.at("_scroll_id").get_ref<const std::string&>();
        };

        const auto onError = [](const std::string& error, const long statusCode, const std::string& errorBody)
        {
            if (statusCode >= 400 && statusCode < 500)
            {
                std::string type, reason;
                extractErrorInfo(errorBody, type, reason);

                if (!type.empty() && !reason.empty())
                {
                    logWarn(IC_NAME,
                            "Failed to retrieve agent documents - type: '%s', reason: '%s'",
                            type.c_str(),
                            reason.c_str());
                }
            }
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
        const auto scrollUrl = url + "/_search/scroll";
        const auto scrollData = R"({"scroll":"1m","scroll_id":")" + scrollId + "\"}";

        const auto onError = [](const std::string& error, const long, const std::string& /*errorBody*/)
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

    // Delete the scroll id.
    const auto deleteScrollUrl = url + "/_search/scroll/" + scrollId;

    const auto onError = [&](const std::string& error, const long statusCode, const std::string& errorBody)
    {
        logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
        // print payload
        logError(IC_NAME, "Url: %s", deleteScrollUrl.c_str());
    };
    const auto onSuccess = [](const std::string& response)
    {
        logDebug2(IC_NAME, "Response: %s", response.c_str());
    };

    HTTPRequest::instance().delete_(
        RequestParameters {.url = HttpURL(deleteScrollUrl), .secureCommunication = secureCommunication},
        PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
        ConfigurationParameters {});

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

        const auto onError = [this, &actions, &url, &secureCommunication, depth](
                                 const std::string& error, const long statusCode, const std::string& errorBody)
        {
            // Handle 4xx errors with detailed logging
            if (statusCode >= 400 && statusCode < 500)
            {
                std::string type, reason;
                extractErrorInfo(errorBody, type, reason);

                if (!type.empty() && !reason.empty())
                {
                    logWarn(IC_NAME,
                            "Sync operation failed for index '%s' - type: '%s', reason: '%s'",
                            m_indexName.c_str(),
                            type.c_str(),
                            reason.c_str());
                }
            }

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

std::string IndexerConnector::hashMappings(const std::string& mappings)
{
    // Using SHA1
    Utils::HashData hash;
    hash.update(mappings.c_str(), mappings.size());
    return Utils::asciiToHex(hash.hash());
}

void IndexerConnector::validateMappings(const nlohmann::json& templateData,
                                        const std::shared_ptr<ServerSelector>& selector,
                                        const SecureCommunication& secureCommunication)
{
    if (templateData.contains("template") && templateData["template"].contains("mappings"))
    {
        // Get template mappings.
        auto& templateMappings = templateData["template"]["mappings"];

        const auto onError = [](const std::string& error, const long statusCode, const std::string& responseBody)
        {
            logError(
                IC_NAME, "%s, status code: %ld, response body: %s.", error.c_str(), statusCode, responseBody.c_str());
            throw std::runtime_error(error);
        };

        const auto onSuccess = [](const std::string&)
        {
            // Not used
        };

        // Get current mappings.
        nlohmann::json currentMappings;
        HTTPRequest::instance().get(
            RequestParameters {.url = HttpURL(selector->getNext() + "/" + m_indexName + "/_mapping"),
                               .secureCommunication = secureCommunication},
            PostRequestParameters {.onSuccess = [&currentMappings](const std::string& response)
                                   { currentMappings = nlohmann::json::parse(response, nullptr, false); },
                                   .onError = onError},
            ConfigurationParameters {});

        if (currentMappings.is_discarded())
        {
            throw std::runtime_error("Couldn't retrieve current mappings.");
        }

        // Calculating hashes.
        auto hashTemplateMappings = hashMappings(templateMappings.dump());
        auto hashCurrentMappings = hashMappings(currentMappings[m_indexName]["mappings"].dump());
        if (hashTemplateMappings != hashCurrentMappings)
        {
            logDebug2(IC_NAME,
                      "Current mappings '%s' do not match the expected mappings '%s'.",
                      hashCurrentMappings.c_str(),
                      hashTemplateMappings.c_str());

            // Block write operations to the index.
            logDebug2(IC_NAME, "Blocking write operations to index '%s'.", m_indexName.c_str());
            HTTPRequest::instance().put(
                RequestParametersJson {.url = HttpURL(selector->getNext() + "/" + m_indexName + "/_block/write"),
                                       .secureCommunication = secureCommunication},
                PostRequestParameters {.onSuccess = [this](const std::string& response) { m_blockedIndex = true; },
                                       .onError = onError},
                ConfigurationParameters {});

            // Get settings of the index.
            nlohmann::json currentSettings;
            HTTPRequest::instance().get(
                RequestParameters {.url = HttpURL(selector->getNext() + "/" + m_indexName + "/_settings"),
                                   .secureCommunication = secureCommunication},
                PostRequestParameters {.onSuccess = [&currentSettings](const std::string& response)
                                       { currentSettings = nlohmann::json::parse(response, nullptr, false); },
                                       .onError = onError},
                ConfigurationParameters {});

            if (currentSettings.is_discarded())
            {
                throw std::runtime_error("Invalid current settings retrieved.");
            }

            // Prepare clone settings.
            std::string cloneSettings =
                R"({"settings":{"index":{"number_of_shards":)" +
                currentSettings[m_indexName]["settings"]["index"]["number_of_shards"].get_ref<const std::string&>() +
                R"(,"number_of_replicas":)" +
                currentSettings[m_indexName]["settings"]["index"]["number_of_replicas"].get_ref<const std::string&>() +
                R"(}}})";

            // Remove any previous backup if exists.
            std::string currentIndices;
            HTTPRequest::instance().get(
                RequestParameters {.url = HttpURL(selector->getNext() + "/_cat/indices/"),
                                   .secureCommunication = secureCommunication},
                PostRequestParameters {.onSuccess = [&currentIndices](const std::string& response)
                                       { currentIndices = response; },
                                       .onError = onError},
                ConfigurationParameters {});

            if (currentIndices.find(m_indexName + "-backup") != std::string::npos)
            {
                logDebug2(IC_NAME, "Deleting previous backup index '%s-backup'.", m_indexName.c_str());
                HTTPRequest::instance().delete_(
                    RequestParameters {.url = HttpURL(selector->getNext() + "/" + m_indexName + "-backup"),
                                       .secureCommunication = secureCommunication},
                    PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                    ConfigurationParameters {});
            }

            logDebug2(IC_NAME, "Cloning index '%s' to '%s-backup'.", m_indexName.c_str(), m_indexName.c_str());
            HTTPRequest::instance().put(RequestParameters {.url = HttpURL(selector->getNext() + "/" + m_indexName +
                                                                          "/_clone/" + m_indexName + "-backup"),
                                                           .data = cloneSettings,
                                                           .secureCommunication = secureCommunication},
                                        PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                                        ConfigurationParameters {});

            // Delete index
            logDebug2(IC_NAME, "Deleting index '%s'.", m_indexName.c_str());
            HTTPRequest::instance().delete_(RequestParameters {.url = HttpURL(selector->getNext() + "/" + m_indexName),
                                                               .secureCommunication = secureCommunication},
                                            PostRequestParameters {.onSuccess =
                                                                       [this](const std::string& response)
                                                                   {
                                                                       m_blockedIndex = false;
                                                                       m_deletedIndex = true;
                                                                   },
                                                                   .onError = onError},
                                            ConfigurationParameters {});

            // Reindex data.
            std::string reindexData = R"({"source":{"index":")" + m_indexName + "-backup" + R"("},"dest":{"index":")" +
                                      m_indexName + R"("}})";
            logDebug2(IC_NAME,
                      "Reindexing data from '%s-backup' to '%s'. With data: %s",
                      m_indexName.c_str(),
                      m_indexName.c_str(),
                      reindexData.c_str());

            auto start = std::chrono::high_resolution_clock::now();
            HTTPRequest::instance().post(RequestParameters {.url = HttpURL(selector->getNext() + "/_reindex"),
                                                            .data = reindexData,
                                                            .secureCommunication = secureCommunication},
                                         PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                                         ConfigurationParameters {});
            auto end = std::chrono::high_resolution_clock::now();

            logInfo(IC_NAME,
                    "It tooks '%ld' seconds to reindex the index '%s'.",
                    std::chrono::duration_cast<std::chrono::seconds>(end - start).count(),
                    m_indexName.c_str());

            // Delete backup index.
            logDebug2(IC_NAME, "Deleting backup index '%s-backup'.", m_indexName.c_str());
            HTTPRequest::instance().delete_(
                RequestParameters {.url = HttpURL(selector->getNext() + "/" + m_indexName + "-backup"),
                                   .secureCommunication = secureCommunication},
                PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                ConfigurationParameters {});
        }
    }
    else
    {
        throw std::runtime_error("Invalid template.");
    }
}

void IndexerConnector::rollbackIndexChanges(const std::shared_ptr<ServerSelector>& selector,
                                            const SecureCommunication& secureCommunication)
{
    if (m_blockedIndex)
    {
        const auto onError = [](const std::string& error, const long statusCode, const std::string& errorBody)
        {
            logError(IC_NAME, "%s, status code: %ld, response body: %s.", error.c_str(), statusCode, errorBody.c_str());
            throw std::runtime_error(error);
        };

        const auto onSuccess = [](const std::string&)
        {
            // Not used
        };

        // Unblock write operations to the index.
        logDebug2(IC_NAME, "Unblocking write operations to index '%s'.", m_indexName.c_str());
        HTTPRequest::instance().put(
            RequestParameters {.url = HttpURL(selector->getNext() + "/" + m_indexName + "/_settings"),
                               .data = R"({"index":{"blocks":{"write":false}}})",
                               .secureCommunication = secureCommunication},
            PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
            ConfigurationParameters {});

        m_blockedIndex = false;
    }
}

void IndexerConnector::initialize(const nlohmann::json& templateData,
                                  const nlohmann::json& updateMappingsData,
                                  const std::shared_ptr<ServerSelector>& selector,
                                  const SecureCommunication& secureCommunication)
{
    // Define the error callback
    auto onError = [this](const std::string& error, const long statusCode, const std::string& errorBody)
    {
        // Special case: Resource already exists during initialization - SILENCE
        if (statusCode == HTTP_BAD_REQUEST && isResourceAlreadyExists(errorBody))
        {
            return; // Silently continue, don't throw
        }

        // Special case: Template priority conflict - SILENCE (cleanup issue)
        if (statusCode == HTTP_BAD_REQUEST && isTemplatePriorityConflict(errorBody))
        {
            return; // Silently continue, cleanup will handle it
        }

        // Extract error info once for all 4xx cases
        std::string type, reason;
        if (statusCode >= 400 && statusCode < 500)
        {
            extractErrorInfo(errorBody, type, reason);
        }

        // Special case: Shard limit exceeded - LOG WITH RECOMMENDATION
        if (statusCode == HTTP_BAD_REQUEST && isShardLimitError(errorBody))
        {
            logWarn(IC_NAME,
                    "Indexer request failed - type: '%s', reason: '%s' - Consider increasing "
                    "cluster.max_shards_per_node setting",
                    type.c_str(),
                    reason.c_str());

            std::string errorMessage = error;
            if (statusCode != NOT_USED)
            {
                errorMessage += " (Status code: " + std::to_string(statusCode) + ")";
            }
            throw std::runtime_error(errorMessage);
        }

        // Generic 4xx errors - LOG WITH DETAILS
        if (statusCode >= 400 && statusCode < 500)
        {
            if (!type.empty() && !reason.empty())
            {
                logWarn(IC_NAME, "Indexer request failed - type: '%s', reason: '%s'", type.c_str(), reason.c_str());
            }
            else
            {
                // Log with raw body for debugging when JSON parsing fails
                logWarn(IC_NAME,
                        "Indexer request failed - status: %ld, response: %s",
                        statusCode,
                        errorBody.empty() ? error.c_str() : errorBody.c_str());
            }
        }
        else if (statusCode >= 500)
        {
            // 5xx errors - server issues
            logError(IC_NAME, "Indexer server error - status: %ld, error: %s", statusCode, error.c_str());
        }
        else
        {
            // Connection errors, timeouts, etc.
            logError(IC_NAME, "Indexer connection error: %s", error.c_str());
        }

        // Throw for all non-silenced errors
        std::string errorMessage = error;
        if (statusCode != NOT_USED)
        {
            errorMessage += " (Status code: " + std::to_string(statusCode) + ")";
        }
        throw std::runtime_error(errorMessage);
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

    // At this point the template is already created or updated and the index initialized.
    try
    {
        validateMappings(templateData, selector, secureCommunication);
        // Re-initialize Index in case no documents where reindexed.
        HTTPRequest::instance().put(RequestParametersJson {.url = HttpURL(selector->getNext() + "/" + m_indexName),
                                                           .data = templateData.at("template"),
                                                           .secureCommunication = secureCommunication},
                                    PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                                    ConfigurationParameters {});
    }
    catch (const std::exception& e)
    {
        logWarn(IC_NAME,
                "Failed to reindex for: %s. %s. Updating mappings fallback mechanism.",
                m_indexName.c_str(),
                e.what());
        rollbackIndexChanges(selector, secureCommunication);
        // Re-initialize Index if it was not recreated during reindexing.
        if (m_deletedIndex)
        {
            HTTPRequest::instance().put(RequestParametersJson {.url = HttpURL(selector->getNext() + "/" + m_indexName),
                                                               .data = templateData.at("template"),
                                                               .secureCommunication = secureCommunication},
                                        PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                                        ConfigurationParameters {});
        }
        // Fallback legacy mechanism. Create new mappings after update.
        if (!updateMappingsData.empty())
        {
            HTTPRequest::instance().put(
                RequestParametersJson {.url = HttpURL(selector->getNext() + "/" + m_indexName + "/_mapping"),
                                       .data = updateMappingsData,
                                       .secureCommunication = secureCommunication},
                PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                ConfigurationParameters {});
        }
    }

    m_initialized = true;
    logInfo(IC_NAME, "IndexerConnector initialized successfully for index: %s.", m_indexName.c_str());
}

void IndexerConnector::preInitialization(
    const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
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
        throw std::runtime_error("Index name must be lowercase: " + m_indexName);
    }

    m_db = std::make_unique<Utils::RocksDBWrapper>(
        std::string(DATABASE_BASE_PATH) + "db/" + m_indexName, true, true, true);
}

IndexerConnector::IndexerConnector(
    const nlohmann::json& config,
    const std::string& templatePath,
    const std::string& updateMappingsPath,
    const bool useSeekDelete,
    const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
        logFunction,
    const uint32_t& timeout)
    : m_useSeekDelete(useSeekDelete)
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

                if (operation == "DELETED")
                {
                    if (m_useSeekDelete)
                    {
                        for (const auto& [key, _] : m_db->seek(id))
                        {
                            logDebug2(IC_NAME, "Added document for deletion with id: %s.", key.c_str());
                            if (!noIndex)
                            {
                                builderBulkDelete(bulkData, key, m_indexName);
                            }

                            m_db->delete_(key);
                        }
                    }
                    else
                    {
                        if (!noIndex)
                        {
                            builderBulkDelete(bulkData, id, m_indexName);
                        }

                        m_db->delete_(id);
                    }
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

                const auto onError = [this, &data, bulkSize](
                                         const std::string& error, const long statusCode, const std::string& errorBody)
                {
                    // Handle 4xx errors with detailed logging
                    if (statusCode >= 400 && statusCode < 500)
                    {
                        std::string type, reason;
                        extractErrorInfo(errorBody, type, reason);

                        // Special case: Shard limit exceeded
                        if (statusCode == HTTP_BAD_REQUEST && isShardLimitError(errorBody))
                        {
                            logWarn(IC_NAME,
                                    "Document operation failed for index '%s' - type: '%s', reason: '%s' - Consider "
                                    "increasing cluster.max_shards_per_node setting",
                                    m_indexName.c_str(),
                                    type.c_str(),
                                    reason.c_str());
                        }
                        // Generic 4xx logging
                        else if (!type.empty() && !reason.empty())
                        {
                            logWarn(IC_NAME,
                                    "Document operation failed for index '%s' - type: '%s', reason: '%s'",
                                    m_indexName.c_str(),
                                    type.c_str(),
                                    reason.c_str());
                        }
                    }

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
        ELEMENTS_PER_BULK,
        UNLIMITED_QUEUE_SIZE,
        true);

    m_syncQueue = std::make_unique<ThreadSyncQueue>(
        // coverity[missing_lock]
        [this, selector, secureCommunication](const std::string& agentId)
        {
            std::unique_lock lock(m_syncMutex);

            // Check if we should skip due to rate limit
            const auto now = std::chrono::system_clock::now();

            // Check if sync is already in progress for this agent
            if (m_syncInProgress.find(agentId) != m_syncInProgress.end())
            {
                logDebug2(IC_NAME, "Agent '%s' sync already in progress, skipping.", agentId.c_str());
                return;
            }

            // Check last successful sync time
            if (auto syncIt = m_lastSync.find(agentId); syncIt != m_lastSync.end())
            {
                const auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - syncIt->second);
                if (elapsed.count() < MINIMAL_SYNC_TIME)
                {
                    logDebug2(IC_NAME,
                              "Agent '%s' sync blocked by rate limit (elapsed: %ld min, remaining: %ld min).",
                              agentId.c_str(),
                              elapsed.count(),
                              MINIMAL_SYNC_TIME - elapsed.count());
                    return;
                }
            }

            // Mark sync as in progress BEFORE releasing lock
            m_syncInProgress.insert(agentId);

            lock.unlock(); // release mutex for long-running sync

            try
            {
                logDebug2(IC_NAME, "Syncing agent '%s' with indexer.", agentId.c_str());
                diff(getAgentDocumentsIds(selector->getNext(), agentId, secureCommunication),
                     agentId,
                     secureCommunication,
                     selector);

                lock.lock();
                m_lastSync[agentId] = std::chrono::system_clock::now();
                m_syncInProgress.erase(agentId); // Clear in-progress flag
                logDebug2(IC_NAME, "Agent '%s' sync succeeded.", agentId.c_str());
            }
            catch (const std::exception& e)
            {
                lock.lock();
                m_syncInProgress.erase(agentId); // Clear in-progress flag even on failure
                logWarn(IC_NAME, "Failed to sync agent '%s': %s", agentId.c_str(), e.what());
            }
        },
        SYNC_WORKERS,
        SYNC_QUEUE_LIMIT);

    m_initializeThread = std::thread(
        // coverity[copy_constructor_call]
        [this,
         templateData,
         updateMappingsData,
         selector = std::move(selector),
         secureCommunication = std::move(secureCommunication)]()
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
                    logDebug2(IC_NAME,
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
    const bool useSeekDelete,
    const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
        logFunction)
    : m_useSeekDelete(useSeekDelete)
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
                    if (m_useSeekDelete)
                    {
                        for (const auto& [key, _] : m_db->seek(id))
                        {
                            m_db->delete_(key);
                        }
                    }
                    else
                    {
                        m_db->delete_(id);
                    }
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
        ELEMENTS_PER_BULK,
        UNLIMITED_QUEUE_SIZE,
        true);

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
