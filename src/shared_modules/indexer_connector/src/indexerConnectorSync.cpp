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

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
};

static std::mutex G_CREDENTIAL_MUTEX;

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
IndexerConnectorSync::~IndexerConnectorSync() = default;

IndexerConnectorSync::IndexerConnectorSync(
    const nlohmann::json& config,
    const std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>&
        logFunction)
    : m_secureCommunication {SecureCommunication::builder()}
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
}

void IndexerConnectorSync::bulk(const std::string& message)
{
    // Send data to the indexer to be processed.
    const auto processData = [this](const std::string& data, const std::string& url)
    {
        const auto onSuccess = [](const std::string& response)
        {
            logDebug2(IC_NAME, "Response: %s", response.c_str());

            // If the request was successful and the current bulk size is less than ELEMENTS_PER_BULK, increase
            // the bulk size if the success count is SUCCESS_COUNT_TO_INCREASE_BULK_SIZE

            // if (m_successCount < SUCCESS_COUNT_TO_INCREASE_BULK_SIZE)
            // {
            //     m_successCount++;
            // }

            // m_error413FirstTime = false;

            // if (bulkSize < ELEMENTS_PER_BULK)
            // {
            //     if (m_successCount < SUCCESS_COUNT_TO_INCREASE_BULK_SIZE)
            //     {
            //         logDebug2(IC_NAME,
            //                   "Waiting for %d successful requests to increase the bulk size.",
            //                   SUCCESS_COUNT_TO_INCREASE_BULK_SIZE - m_successCount);
            //         return;
            //     }

            //     if (bulkSize * 2 > ELEMENTS_PER_BULK)
            //     {
            //         this->m_dispatcher->bulkSize(ELEMENTS_PER_BULK);
            //         logDebug2(IC_NAME, "Increasing the elements to be sent to the indexer: %d.", ELEMENTS_PER_BULK);
            //     }
            //     else
            //     {
            //         this->m_dispatcher->bulkSize(bulkSize * 2);
            //         logDebug2(IC_NAME, "Increasing the elements to be sent to the indexer: %d.", bulkSize * 2);
            //     }
            // }
        };

        const auto onError = [](const std::string& error, const long statusCode)
        {
            if (statusCode == HTTP_CONTENT_LENGTH)
            {
                // m_successCount = 0;
                // if (bulkSize / 2 < MINIMAL_ELEMENTS_PER_BULK)
                // {
                //     // If the bulk size is too small, log an error and throw an exception.
                //     // This error will be fixed by the user by increasing the http.max_content_length value in
                //     // the wazuh-indexer settings.
                //     if (m_error413FirstTime == false)
                //     {
                //         m_error413FirstTime = true;
                //         logError(IC_NAME,
                //                  "The amount of elements to process is too small, review the "
                //                  "'http.max_content_length' value in "
                //                  "the wazuh-indexer settings. Current data size: %llu.",
                //                  data.size());
                //     }

                //     throw IndexerConnectorException("The amount of elements to process is too small, review the "
                //                              "'http.max_content_length' value in "
                //                              "the wazuh-indexer settings.");
            }
            else
            {
                // logDebug2(IC_NAME, "Reducing the elements to be sent to the indexer: %llu.", bulkSize / 2);
                // this->m_dispatcher->bulkSize(bulkSize / 2);
                // throw IndexerConnectorException("Bulk size is too large, reducing the elements to be sent to the "
                //                          "indexer.");
                if (statusCode == HTTP_VERSION_CONFLICT)
                {
                    logDebug2(IC_NAME, "Document version conflict, retrying in 1 second.");
                    throw IndexerConnectorException("Document version conflict, retrying in 1 second.");
                }
                else if (statusCode == HTTP_TOO_MANY_REQUESTS)
                {
                    logDebug2(IC_NAME, "Too many requests, retrying in 1 second.");
                    throw IndexerConnectorException("Too many requests, retrying in 1 second.");
                }
                else
                {
                    logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
                    throw IndexerConnectorException(error);
                }
            }
        };
        HTTPRequest::instance().post(
            RequestParameters {.url = HttpURL(url), .data = data, .secureCommunication = m_secureCommunication},
            PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
            {});
    };

    const auto serverUrl = m_selector->getNext();
    processData(message, serverUrl + "/_bulk?refresh=wait_for");
}

void IndexerConnectorSync::deleteByQuery(const std::string& message, const std::string& index)
{
    if (!index.empty() && Utils::haveUpperCaseCharacters(index))
    {
        throw IndexerConnectorException("Index name must be lowercase: " + index);
    }

    const auto serverUrl = m_selector->getNext();
    const auto url = serverUrl + "/" + index + "/_delete_by_query";

    const auto processData = [this](const std::string& data, const std::string& url)
    {
        const auto onSuccess = [](const std::string& response)
        {
            logDebug2(IC_NAME, "Response: %s", response.c_str());
        };

        const auto onError = [](const std::string& error, const long statusCode)
        {
            if (statusCode == HTTP_CONTENT_LENGTH)
            {
                logDebug2(IC_NAME, "Document content length.");
                throw IndexerConnectorException("Document content length, retrying in 1 second.");
            }
            else if (statusCode == HTTP_VERSION_CONFLICT)
            {
                logDebug2(IC_NAME, "Document version conflict, retrying in 1 second.");
                throw IndexerConnectorException("Document version conflict, retrying in 1 second.");
            }
            else if (statusCode == HTTP_TOO_MANY_REQUESTS)
            {
                logDebug2(IC_NAME, "Too many requests, retrying in 1 second.");
                throw IndexerConnectorException("Too many requests, retrying in 1 second.");
            }
            else
            {
                logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
                throw IndexerConnectorException(error);
            }
        };

        HTTPRequest::instance().post(
            RequestParameters {.url = HttpURL(url), .data = data, .secureCommunication = m_secureCommunication},
            PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
            {});
    };

    processData(message, url);
}
