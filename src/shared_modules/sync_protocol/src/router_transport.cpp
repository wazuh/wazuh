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

RouterTransport::RouterTransport(const std::string& moduleName, LoggerFunc logger,
                                 std::function<void(const std::vector<char>&)> callback)
    : m_moduleName(moduleName)
    , m_logger(std::move(logger))
    , m_responseCallback(callback)
    , m_subscriberReady(false)
{
}

RouterTransport::~RouterTransport()
{
    shutdown();
}

void RouterTransport::shutdown()
{
    try
    {
        // Stop subscriber first to prevent new callbacks from being queued
        if (m_subscriber)
        {
            // Reset the unique_ptr, which triggers ~RouterSubscriber() -> unsubscribe()
            // This ensures no more callbacks will be invoked
            m_subscriber.reset();
        }

        // Stop and reset provider to ensure clean state for re-initialization
        if (m_provider)
        {
            m_provider->stop();
            m_provider.reset();  // Must reset so configRouter() creates a new one
        }

        // Reset ready flag to ensure proper re-initialization
        m_subscriberReady = false;
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, "Exception in RouterTransport shutdown: " + std::string(ex.what()));
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
    const std::string subscriberId = "agent-000";

    // Let exceptions propagate to configRouter() - no LOG_ERROR_EXIT here
    if (m_moduleName == "fim")
    {
        m_subscriber = std::make_unique<RouterSubscriber>(responseTopic, subscriberId, false);  // fim runs in another process
    }
    else
    {
        m_subscriber = std::make_unique<RouterSubscriber>(responseTopic, subscriberId, true);
    }

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
    return m_moduleName + "-agent-responses";
}

std::string RouterTransport::getPublishTopic() const
{
    return "inventory-states";
}

bool RouterTransport::configRouter()
{
    try
    {
        // Check if already initialized (null check pattern like MQueue's m_queue < 0)
        if (!m_provider)
        {
            const std::string publishTopic = getPublishTopic();

            if (m_moduleName == "fim")
            {
                m_provider = std::make_unique<RouterProvider>(publishTopic, false);   // fim runs in another process
            }
            else
            {
                m_provider = std::make_unique<RouterProvider>(publishTopic, true);
            }

            m_provider->start();
            m_logger(LOG_INFO, "RouterProvider started for topic: " + publishTopic);
        }

        // Check if subscriber already initialized
        if (!m_subscriber)
        {
            // Reset ready flag when creating new subscriber (in case of re-initialization after shutdown)
            m_subscriberReady = false;
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
