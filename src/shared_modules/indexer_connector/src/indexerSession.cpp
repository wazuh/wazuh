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

#include "indexerSession.hpp"
#include "indexerTransport.hpp"
#include "loggerHelper.h"
#include <utility>

/// Health-check period, seconds. Matches the literal both connectors pass when they build their own
/// selector, so sharing a session does not change how often hosts are polled.
constexpr auto SESSION_MONITORING_INTERVAL {10};

// LCOV_EXCL_START
class IndexerSession::Impl
{
public:
    Impl(const nlohmann::json& config, LoggingContext logging)
    {
        auto logFn = LogFn {logging.first}.compose("indexer-connector");
        // Install caller context so sub-objects pick up the right base tag via makeLibLogFn().
        // Restores the previous thread-local value when the constructor exits.
        const Log::ScopedModuleLogFn guard {logging.first.empty() ? LogFn {"indexer-connector"}
                                                                  : LogFn {logging.first}};

        if (logging.second)
        {
            Log::assignLogFunction(logging.second);
        }

        // `hosts` first: cheapest check, and the most common one to fail. Doing it before
        // buildSecureCommunication() keeps a hosts-less configuration from opening `queue/keystore`.
        if (!config.contains("hosts") || config.at("hosts").empty())
        {
            throw IndexerConnectorException("No hosts found in the configuration");
        }

        m_data.m_hosts = config.at("hosts").get<std::vector<std::string>>();
        m_data.m_secureCommunication = buildSecureCommunication(config, logFn);

        // The one synchronous round of `GET /_cat/health` (5 s timeout per host) plus the one polling
        // thread. Every connector sharing this session reuses both.
        m_data.m_monitoring = std::make_shared<TMonitoring<HTTPRequest>>(
            m_data.m_hosts, SESSION_MONITORING_INTERVAL, m_data.m_secureCommunication);
    }

    IndexerSessionData m_data;
};

const IndexerSessionData& sessionData(const IndexerSession& session)
{
    return session.m_impl->m_data;
}

IndexerSession::IndexerSession(const nlohmann::json& config, LoggingContext logging)
    : m_impl(std::make_unique<Impl>(config, std::move(logging)))
{
}

IndexerSession::~IndexerSession() = default;
// LCOV_EXCL_STOP
