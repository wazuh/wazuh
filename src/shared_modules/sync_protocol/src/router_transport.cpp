/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "router_transport.hpp"
#include "agentInfo_generated.h"
#include <thread>

RouterTransport::RouterTransport(const std::string& agentId,
                                 const std::string& agentName,
                                 const std::string& agentIp,
                                 const std::string& moduleName,
                                 LoggerFunc logger,
                                 std::function<void(const std::vector<char>&)> callback)
    : m_agentId(agentId)
    , m_agentName(agentName)
    , m_agentIp(agentIp)
    , m_moduleName(moduleName)
    , m_logger(std::move(logger))
    , m_responseCallback(callback)
{
}

RouterTransport::~RouterTransport()
{
    shutdown();
}

bool RouterTransport::initialize()
{
    try
    {
        m_provider = std::make_unique<RouterProvider>(m_inventoryStatesTopic, true);
        m_provider->start();
        m_logger(LOG_INFO, "RouterProvider started for topic: " + std::string(m_inventoryStatesTopic));
        subscribeToResponses();
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR_EXIT, "Failed to initialize RouterTransport: " + std::string(ex.what()));
        return false;
    }
    return true;
}

void RouterTransport::shutdown()
{
    try
    {
        if (m_provider)
        {
            m_provider->stop();
        }
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, "Exception in RouterTransport destructor: " + std::string(ex.what()));
    }
}

// TODO: Implement checkStatus for RouterTransport
bool RouterTransport::checkStatus()
{
    return true;
}

bool RouterTransport::sendMessage(const std::vector<uint8_t>& message, size_t maxEps)
{
    try
    {
        auto wrappedMessage = wrapWithAgentInfo(message);
        std::vector<char> routerMessage(wrappedMessage.begin(), wrappedMessage.end());
        m_provider->send(routerMessage);

        if (maxEps > 0)
        {
            if (++m_msgSent >= maxEps)
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                m_msgSent.store(0);
            }
        }
        return true;
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Failed to publish sync message: ") + e.what());
        return false;
    }
}

std::vector<uint8_t> RouterTransport::wrapWithAgentInfo(const std::vector<uint8_t>& syncMessage)
{
    flatbuffers::FlatBufferBuilder builder;

    auto id = builder.CreateString(m_agentId);
    auto name = builder.CreateString(m_agentName);
    auto ip = builder.CreateString(m_agentIp);
    auto version = builder.CreateString("");
    auto module = builder.CreateString(m_moduleName);
    auto data = builder.CreateVector(syncMessage.data(), syncMessage.size());

    auto agentInfo = Wazuh::Sync::CreateAgentInfo(builder, id, name, ip, version, module, data);
    builder.Finish(agentInfo);

    const uint8_t* buffer_ptr = builder.GetBufferPointer();
    const size_t buffer_size = builder.GetSize();

    return std::vector<uint8_t>(buffer_ptr, buffer_ptr + buffer_size);
}

void RouterTransport::subscribeToResponses()
{
    const std::string responseTopic = getResponseTopic();
    const std::string subscriberId = "agent-sync-protocol-" + m_agentId;

    try
    {
        m_subscriber = std::make_unique<RouterSubscriber>(responseTopic, subscriberId, true);
        m_subscriber->subscribe(m_responseCallback);
        m_logger(LOG_INFO, "RouterSubscriber created for topic: " + responseTopic);
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR_EXIT, "Failed to initialize RouterSubscriber: " + std::string(ex.what()));
    }
}

std::string RouterTransport::getResponseTopic() const
{
    return "inventory-sync-agent-" + m_agentId + "-responses";
}
