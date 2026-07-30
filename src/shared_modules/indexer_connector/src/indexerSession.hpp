/*
 * Wazuh - Shared indexer session.
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_SESSION_HPP
#define _INDEXER_SESSION_HPP

#include "HTTPRequest.hpp"
#include "external/nlohmann/json.hpp"
#include "indexerConnector.hpp"
#include "monitoring.hpp"
#include "secureCommunication.hpp"
#include "serverSelector.hpp"
#include <memory>
#include <string>
#include <vector>

/**
 * @brief What an IndexerSession actually carries.
 *
 * Deliberately NOT in the installed header: `TMonitoring` is templated on HTTPRequest, so exposing
 * it publicly would pull libcurl into every consumer translation unit. IndexerSession is the opaque
 * pimpl handle over this.
 */
struct IndexerSessionData
{
    std::vector<std::string> m_hosts;                       ///< Hosts the monitor was built for.
    SecureCommunication m_secureCommunication;              ///< Credentials + SSL, resolved once.
    std::shared_ptr<TMonitoring<HTTPRequest>> m_monitoring; ///< The one shared health monitor.
};

/**
 * @brief Reaches inside a session. Declared here rather than as a member so it can be a friend of
 *        IndexerSession without exposing its nested Impl in the public header -- friendship does not
 *        extend to a nested class, so friending IndexerConnectorSync would not reach
 *        IndexerConnectorSync::Impl, which is what actually needs the access.
 */
const IndexerSessionData& sessionData(const IndexerSession& session);

/**
 * @brief Builds a selector over the session's shared monitor, refusing a mismatched host list.
 *
 * The monitor only knows the hosts it was constructed with; TMonitoring::isAvailable() throws
 * std::out_of_range for anything else. Checking here turns a configuration mistake into a clear
 * exception at construction instead of an out_of_range on the first request.
 *
 * Shared by both facades so the check cannot drift between them.
 *
 * @throws IndexerConnectorException if `hosts` is missing, empty, or differs from the session's.
 */
inline std::unique_ptr<TServerSelector<HTTPRequest>> makeSharedSelector(const nlohmann::json& config,
                                                                        const IndexerSession& session)
{
    if (!config.contains("hosts") || config.at("hosts").empty())
    {
        throw IndexerConnectorException("No hosts found in the configuration");
    }

    const auto& data = sessionData(session);
    const auto hosts = config.at("hosts").get<std::vector<std::string>>();
    if (hosts != data.m_hosts)
    {
        throw IndexerConnectorException(
            "The connector's `hosts` list does not match the hosts monitored by the shared indexer session");
    }

    return std::make_unique<TServerSelector<HTTPRequest>>(data.m_monitoring, hosts);
}

#endif // _INDEXER_SESSION_HPP
