/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "router_transport.hpp"
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
    , m_subscriberReady(false)
{
}

RouterTransport::~RouterTransport()
{
    shutdown();
}

bool RouterTransport::initialize()
{
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

bool RouterTransport::checkStatus()
{
    // Like MQueueTransport::checkStatus() - simply try to ensure router is available
    if (!configRouter())
    {
        m_logger(LOG_ERROR, "Failed to initialize Router");
        return false;  // Graceful failure, will retry on next sync attempt
    }
    return true;
}

bool RouterTransport::sendMessage(const std::vector<uint8_t>& message, size_t maxEps)
{
    try
    {
        // Null check like MQueue checks m_queue < 0
        if (!m_provider)
        {
            m_logger(LOG_ERROR, "Cannot send: RouterProvider not initialized");
            return false;
        }

        std::vector<char> routerMessage(message.begin(), message.end());
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

void RouterTransport::subscribeToResponses()
{
    const std::string responseTopic = getResponseTopic();
    const std::string subscriberId = "agent-sync-protocol-" + m_agentId;

    // Let exceptions propagate to configRouter() - no LOG_ERROR_EXIT here
    m_subscriber = std::make_unique<RouterSubscriber>(responseTopic, subscriberId, true);

    // Use onConnect callback to ensure subscription is established before marking as ready
    auto onConnect = [this]()
    {
        m_subscriberReady.store(true);
        m_logger(LOG_INFO, "RouterSubscriber connected and ready");
    };

    m_subscriber->subscribe(m_responseCallback, onConnect);
    m_logger(LOG_INFO, "RouterSubscriber created for topic: " + responseTopic);
}

std::string RouterTransport::getResponseTopic() const
{
    return "inventory-sync-agent-" + m_agentId + "-responses";
}

bool RouterTransport::configRouter()
{
    try
    {
        // Check if already initialized (null check pattern like MQueue's m_queue < 0)
        if (!m_provider)
        {
            m_provider = std::make_unique<RouterProvider>(m_inventoryStatesTopic, false);
            m_provider->start();
            m_logger(LOG_INFO, "RouterProvider started for topic: " + std::string(m_inventoryStatesTopic));
        }

        // Check if subscriber already initialized
        if (!m_subscriber)
        {
            subscribeToResponses();
        }

        // Return true only if both are valid and subscriber is ready
        return (m_provider != nullptr) && (m_subscriber != nullptr) && m_subscriberReady;
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, "Failed to initialize RouterTransport: " + std::string(ex.what()));
        // Clean up partial state like MQueue does
        m_provider.reset();
        m_subscriber.reset();
        m_subscriberReady = false;
        return false;  // Graceful failure, allows retry
    }
}
