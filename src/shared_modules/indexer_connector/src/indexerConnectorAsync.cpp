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
#include "indexerConnectorAsyncImpl.hpp"
#include "loggerHelper.h"
#include "serverSelector.hpp"
#include <sstream>

// LCOV_EXCL_START
// Implementation of PointInTime class
class PointInTime::Impl
{
private:
    std::string m_pitId;
    uint64_t m_creationTime;
    TServerSelector<HTTPRequest>* m_selector;
    SecureCommunication* m_secureCommunication;
    HTTPRequest* m_httpRequest;

public:
    Impl(std::string pitId,
         uint64_t creationTime,
         void* selector,
         void* secureCommunication,
         void* httpRequest)
        : m_pitId(std::move(pitId))
        , m_creationTime(creationTime)
        , m_selector(static_cast<TServerSelector<HTTPRequest>*>(selector))
        , m_secureCommunication(static_cast<SecureCommunication*>(secureCommunication))
        , m_httpRequest(static_cast<HTTPRequest*>(httpRequest))
    {
    }

    ~Impl()
    {
        // Delete the PIT - this operation should not throw exceptions
        try
        {
            if (!m_pitId.empty() && m_selector && m_httpRequest)
            {
                std::string url {m_selector->getNext()};
                url += "/_pit";

                nlohmann::json deleteBody;
                deleteBody["id"] = m_pitId;

                const auto onSuccess = [](std::string&& response)
                {
                    logDebug2(IC_NAME, "PIT successfully deleted. Response: %s", response.c_str());
                };

                const auto onError = [this](const std::string& error, const long statusCode, const std::string& responseBody)
                {
                    // Log but don't throw - destructors should not throw
                    logWarn(IC_NAME,
                            "Failed to delete PIT %s. Error: %s, Status: %ld, Response: %s",
                            m_pitId.c_str(),
                            error.c_str(),
                            statusCode,
                            responseBody.c_str());
                };

                m_httpRequest->delete_(
                    RequestParameters {.url = HttpURL(url),
                                      .data = deleteBody.dump(),
                                      .secureCommunication = *m_secureCommunication},
                    PostRequestParametersRValue {.onSuccess = onSuccess, .onError = onError},
                    {});
            }
        }
        catch (const std::exception& e)
        {
            // Log but don't rethrow - destructors should not throw
            logError(IC_NAME, "Exception while deleting PIT: %s", e.what());
        }
        catch (...)
        {
            // Log but don't rethrow - destructors should not throw
            logError(IC_NAME, "Unknown exception while deleting PIT");
        }
    }

    const std::string& getPitId() const
    {
        return m_pitId;
    }

    uint64_t getCreationTime() const
    {
        return m_creationTime;
    }
};

PointInTime::PointInTime(std::string pitId,
                         uint64_t creationTime,
                         void* selector,
                         void* secureCommunication,
                         void* httpRequest)
    : m_impl(std::make_unique<Impl>(std::move(pitId), creationTime, selector, secureCommunication, httpRequest))
{
}

PointInTime::~PointInTime() = default;

PointInTime::PointInTime(PointInTime&&) noexcept = default;
PointInTime& PointInTime::operator=(PointInTime&&) noexcept = default;

const std::string& PointInTime::getPitId() const
{
    return m_impl->getPitId();
}

uint64_t PointInTime::getCreationTime() const
{
    return m_impl->getCreationTime();
}

// Implementation of the facade IndexerConnectorAsync
class IndexerConnectorAsync::Impl
{
private:
    IndexerConnectorAsyncImpl<TServerSelector<HTTPRequest>, HTTPRequest> m_impl;

public:
    Impl(const nlohmann::json& config,
         const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
             logFunction)
        : m_impl(config, logFunction)
    {
    }

    void index(std::string_view id, std::string_view index, std::string_view data)
    {
        m_impl.bulkIndex(id, index, data);
    }

    void index(std::string_view id, std::string_view index, std::string_view data, std::string_view version)
    {
        m_impl.bulkIndex(id, index, data, version);
    }

    void index(std::string_view index, std::string_view data)
    {
        m_impl.bulkIndex(std::string_view(), index, data);
    }

    void indexDataStream(std::string_view index, std::string_view data)
    {
        m_impl.bulkIndexDataStream(index, data);
    }

    bool isAvailable() const
    {
        return m_impl.isAvailable();
    }

    uint64_t getQueueSize() const
    {
        return m_impl.getQueueSize();
    }

    std::unique_ptr<PointInTime> createPointInTime(const std::vector<std::string>& indices,
                                                    const std::string& keepAlive,
                                                    bool expandWildcards)
    {
        return m_impl.createPointInTime(indices, keepAlive, expandWildcards);
    }
};

IndexerConnectorAsync::IndexerConnectorAsync(
    const nlohmann::json& config,
    const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
        logFunction)
    : m_impl(std::make_unique<Impl>(config, logFunction))
{
}

IndexerConnectorAsync::~IndexerConnectorAsync() = default;

void IndexerConnectorAsync::index(std::string_view id, std::string_view index, std::string_view data)
{
    m_impl->index(id, index, data);
}

void IndexerConnectorAsync::index(std::string_view id, std::string_view index, std::string_view data, std::string_view version)
{
    m_impl->index(id, index, data, version);
}

void IndexerConnectorAsync::index(std::string_view index, std::string_view data)
{
    m_impl->index(std::string_view(), index, data);
}

void IndexerConnectorAsync::indexDataStream(std::string_view index, std::string_view data)
{
    m_impl->indexDataStream(index, data);
}

bool IndexerConnectorAsync::isAvailable() const
{
    return m_impl->isAvailable();
}

uint64_t IndexerConnectorAsync::getQueueSize() const
{
    return m_impl->getQueueSize();
}

std::unique_ptr<PointInTime> IndexerConnectorAsync::createPointInTime(const std::vector<std::string>& indices,
                                                                       const std::string& keepAlive,
                                                                       bool expandWildcards)
{
    return m_impl->createPointInTime(indices, keepAlive, expandWildcards);
}

// LCOV_EXCL_STOP
