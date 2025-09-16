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

#ifndef _WINDEXER_CONNECTOR_HPP
#define _WINDEXER_CONNECTOR_HPP

#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <wiconnector/iwindexerconnector.hpp>

// Forward declaration
class IndexerConnectorAsync;

namespace wiconnector
{

using LogFunctionType =
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>;

struct Config
{
    std::vector<std::string> hosts; ///< The list of hosts to connect to. i.e. ["https://localhost:9200"]
    std::string username;           ///< The username to authenticate with OpenSearch, admin by default.
    std::string password;           ///< The password to authenticate with OpenSearch, admin by default.

    struct
    {
        std::vector<std::string> cacert; ///< Path to the CA bundle file. '/certificate_authorities'
        std::string cert;                ///< The certificate to connect to OpenSearch. '/certificate'
        std::string key;                 ///< The key to connect to OpenSearch.'/key'
    } ssl;                               ///< SSL options. '/ssl'

    std::string toJson() const;
};

class WIndexerConnector : public IWIndexerConnector
{

private:
    std::unique_ptr<IndexerConnectorAsync> m_indexerConnectorAsync;
    std::shared_mutex m_mutex;

public:
    WIndexerConnector() = delete;
    WIndexerConnector(const Config&, const LogFunctionType& logFunction);
    WIndexerConnector(std::string_view jsonOssecConfig);
    ~WIndexerConnector();

    void index(std::string_view index, std::string_view data) override;
    void shutdown();
};
}; // namespace wiconnector

#endif // _WINDEXER_CONNECTOR_HPP
