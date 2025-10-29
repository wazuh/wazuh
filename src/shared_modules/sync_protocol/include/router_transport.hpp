/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "agent_sync_protocol_types.hpp"
#include "isync_message_transport.hpp"
#include "routerProvider.hpp"
#include "routerSubscriber.hpp"
#include <atomic>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Router-based transport for Agent 0.
 */
class RouterTransport : public ISyncMessageTransport
{
public:
    RouterTransport(const std::string& agentId,
                    const std::string& agentName,
                    const std::string& agentIp,
                    const std::string& moduleName,
                    LoggerFunc logger,
                    std::function<void(const std::vector<char>&)> callback);
    ~RouterTransport() override;
    bool sendMessage(const std::vector<uint8_t>& message, size_t maxEps) override;
    bool initialize() override;
    void shutdown() override;
    bool checkStatus() override;

private:
    std::string m_agentId;
    std::string m_agentName;
    std::string m_agentIp;
    std::string m_moduleName;
    LoggerFunc m_logger;
    std::unique_ptr<RouterProvider> m_provider;
    std::unique_ptr<RouterSubscriber> m_subscriber;
    std::atomic<size_t> m_msgSent {0};
    std::function<void(const std::vector<char>&)> m_responseCallback;

    void subscribeToResponses();
    std::string getResponseTopic() const;
    bool configRouter();  // Returns bool like ensureQueueAvailable()

    static constexpr const char* m_inventoryStatesTopic = "inventory-states";
    std::atomic<bool> m_subscriberReady;
};
