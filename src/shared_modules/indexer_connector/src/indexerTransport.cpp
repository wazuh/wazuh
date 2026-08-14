/*
 * Wazuh - Indexer connector transport settings.
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "indexerTransport.hpp"
#include "indexerConnector.hpp"
#include "keyStore.hpp"
#include "shared_modules/utils/certHelper.hpp"
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace
{
    std::mutex G_CREDENTIAL_MUTEX;

    constexpr auto DEFAULT_PATH {"tmp/root-ca-merged.pem"};
    constexpr auto INDEXER_COLUMN {"indexer"};
    constexpr auto USER_KEY {"username"};
    constexpr auto PASSWORD_KEY {"password"};
    constexpr auto DEFAULT_CREDENTIAL {"wazuh-manager"};
} // namespace

SecureCommunication buildSecureCommunication(const nlohmann::json& config, const LogFn& logFn)
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

    // Function-local statics: the keystore is read once and cached for the process lifetime, so
    // rotating the credentials requires a restart. That was already true per connector class; the
    // only change is that there is now one cache instead of two.
    std::lock_guard lock(G_CREDENTIAL_MUTEX);
    static auto username = Keystore::get(INDEXER_COLUMN, USER_KEY);
    static auto password = Keystore::get(INDEXER_COLUMN, PASSWORD_KEY);
    if (username.empty() && password.empty())
    {
        username = DEFAULT_CREDENTIAL;
        password = DEFAULT_CREDENTIAL;
        LOGFN_WARN(logFn, "No username and password found in the keystore, using default values.");
    }
    if (username.empty())
    {
        username = DEFAULT_CREDENTIAL;
        LOGFN_WARN(logFn, "No username found in the keystore, using default value.");
    }

    auto secureCommunication = SecureCommunication::builder();
    secureCommunication.basicAuth(username + ":" + password)
        .sslCertificate(sslCertificate)
        .sslKey(sslKey)
        .caRootCertificate(caRootCertificate);

    return secureCommunication;
}
