/*
 * Wazuh router
 * Copyright (C) 2015, Wazuh Inc.
 * December 19, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTE_STATE_HELPER_HPP
#define _REMOTE_STATE_HELPER_HPP

#include "socketClient.hpp"
#include <external/nlohmann/json.hpp>
#include <future>
#include <iostream>
#include <string>

constexpr auto REMOTE_SUBSCRIPTION_ENDPOINT {"queue/router/subscription.sock"};

/**
 * @brief RemoteSubscriptionsManager class.
 *
 */
class RemoteSubscriptionManager final
{
private:
    std::unique_ptr<SocketClient<Socket<OSPrimitives>, EpollWrapper>> m_socketClient {};

    /**
     * @brief Registration message process.
     *
     * @param jsonMsg Message to be sent.
     * @param onSuccess Callback to be called when the message is sent.
     */
    void sendRouterServerMessage(const nlohmann::json& jsonMsg, const std::function<void()>& onSuccess)
    {
        try
        {
            m_socketClient =
                std::make_unique<SocketClient<Socket<OSPrimitives>, EpollWrapper>>(REMOTE_SUBSCRIPTION_ENDPOINT);
            m_socketClient->connect(
                [onSuccess](const char* body, uint32_t bodySize, const char*, uint32_t)
                {
                    try
                    {
                        auto result = nlohmann::json::parse(body, body + bodySize);
                        if (result.at("Result") != "OK")
                        {
                            throw std::runtime_error(result.at("Result")); // LCOV_EXCL_LINE
                        }
                        onSuccess();
                    }
                    // LCOV_EXCL_START
                    catch (const std::exception& e)
                    {
                        std::cerr << "Invalid result: " << e.what() << std::endl;
                    }
                    // LCOV_EXCL_STOP
                },
                [jsonMsg, socketClient = m_socketClient.get()]()
                {
                    try
                    {
                        const auto msg = jsonMsg.dump();
                        socketClient->send(msg.data(), msg.size());
                    }
                    // LCOV_EXCL_START
                    catch (const std::exception& e)
                    {
                        std::cerr << "Failed to send message: " << e.what() << std::endl;
                    }
                    // LCOV_EXCL_STOP
                });
        }
        // LCOV_EXCL_START
        catch (const std::exception& e)
        {
            std::cerr << "Failed to connect to router: " << e.what() << std::endl;
        }
        // LCOV_EXCL_STOP
    }

public:
    RemoteSubscriptionManager() = default;
    ~RemoteSubscriptionManager() = default;

    /**
     * @brief Creates and sends the init provider message.
     *
     * @param endpointName Name of the endpoint.
     * @param onSuccess Callback to be called when provider is added.
     */
    void sendInitProviderMessage(const std::string& endpointName, const std::function<void()>& onSuccess)
    {
        nlohmann::json jsonMsg {{"EndpointName", endpointName}, {"MessageType", "InitProvider"}};
        sendRouterServerMessage(jsonMsg, onSuccess);
    }
};

#endif // _REMOTE_STATE_HELPER_HPP
