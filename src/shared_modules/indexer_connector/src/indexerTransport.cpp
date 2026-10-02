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

    // No fallback to a built-in "wazuh-manager"/"wazuh-manager" pair. Substituting a credential
    // every installation shares is what https://github.com/wazuh/wazuh/issues/39554 removes: it
    // turned a missing key into an authentication attempt with a known password, and the warning
    // it logged scrolled past unread. The credential resolver refuses to start the manager when
    // this key is unresolved, so reaching here empty means the keystore was emptied behind a
    // running manager -- an error, not a default.
    if (username.empty() || password.empty())
    {
        throw IndexerConnectorException(
            "No indexer credentials found in the keystore. Set them with 'wazuh-manager-keystore -f indexer -k "
            "username' and '-k password', or supply WAZUH_INDEXER_MANAGER_PASSWORD in /etc/wazuh/credentials.env "
            "and restart the manager.");
    }

    // The account name, never the password: which identity the manager presents is the thing an
    // operator needs when the indexer answers 401.
    LOGFN_DEBUG1(logFn, "Authenticating to the indexer as '%s'.", username.c_str());

    auto secureCommunication = SecureCommunication::builder();
    secureCommunication.basicAuth(username + ":" + password)
        .sslCertificate(sslCertificate)
        .sslKey(sslKey)
        .caRootCertificate(caRootCertificate);

    return secureCommunication;
}
