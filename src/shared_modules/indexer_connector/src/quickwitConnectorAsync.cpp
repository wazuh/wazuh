/*
 * Wazuh - Quickwit connector.
 * Copyright (C) 2015, Wazuh Inc.
 * November 7, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "HTTPRequest.hpp"
#include "quickwitConnector.hpp"
#include "quickwitConnectorAsyncImpl.hpp"
#include "loggerHelper.h"
#include "serverSelector.hpp"

// Implementation of QuickwitConnectorAsync
class QuickwitConnectorAsync::Impl
{
private:
    QuickwitConnectorAsyncImpl<TServerSelector<HTTPRequest>, HTTPRequest> m_impl;

public:
    Impl(const nlohmann::json& config,
         const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
             logFunction)
        : m_impl(config, logFunction)
    {
    }

    void index(std::string_view id, std::string_view index, std::string_view data)
    {
        // Quickwit doesn't require explicit IDs in NDJSON format
        // The ID parameter is ignored
        m_impl.index(index, data);
    }

    void index(std::string_view id, std::string_view index, std::string_view data, std::string_view version)
    {
        // Quickwit doesn't support versioning like Elasticsearch
        // Both ID and version are ignored
        m_impl.index(index, data);
    }

    void index(std::string_view index, std::string_view data)
    {
        m_impl.index(index, data);
    }

    bool isAvailable() const
    {
        return m_impl.isAvailable();
    }

    void createIndex(std::string_view index, const nlohmann::json& config)
    {
        m_impl.createIndex(index, config);
    }
};

QuickwitConnectorAsync::QuickwitConnectorAsync(
    const nlohmann::json& config,
    const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
        logFunction)
    : m_impl(std::make_unique<Impl>(config, logFunction))
{
}

QuickwitConnectorAsync::~QuickwitConnectorAsync() = default;

void QuickwitConnectorAsync::index(std::string_view id, std::string_view index, std::string_view data)
{
    m_impl->index(id, index, data);
}

void QuickwitConnectorAsync::index(std::string_view id, std::string_view index, std::string_view data, std::string_view version)
{
    m_impl->index(id, index, data, version);
}

void QuickwitConnectorAsync::index(std::string_view index, std::string_view data)
{
    m_impl->index(index, data);
}

bool QuickwitConnectorAsync::isAvailable() const
{
    return m_impl->isAvailable();
}

void QuickwitConnectorAsync::createIndex(std::string_view index, const nlohmann::json& config)
{
    m_impl->createIndex(index, config);
}
