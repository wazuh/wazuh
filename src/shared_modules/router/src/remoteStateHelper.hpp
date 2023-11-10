/*
 * Wazuh router
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
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
 * @brief RemoteStateHelper class.
 *
 */
class RemoteStateHelper final
{
private:
    RemoteStateHelper() = default;
    ~RemoteStateHelper() = default;

    /**
     * @brief Registration message process.
     *
     * @param jsonMsg Message to be sent.
     */
    static void sendRouterServerMessage(const nlohmann::json& jsonMsg, bool stopIfSocketRemoved)
    {
        try
        {
            std::promise<void> promiseObj;
            auto futureObj = promiseObj.get_future();
            auto socketClient = std::make_shared<SocketClient<Socket<OSPrimitives>, EpollWrapper>>(
                REMOTE_SUBSCRIPTION_ENDPOINT, stopIfSocketRemoved);
            socketClient->connect(
                [&](const char* body, uint32_t bodySize, const char*, uint32_t)
                {
                    try
                    {
                        auto result = nlohmann::json::parse(body, body + bodySize);
                        if (result.at("Result") != "OK")
                        {
                            throw std::runtime_error(result.at("Result"));
                        }
                    }
                    catch (const std::exception& e)
                    {
                        std::cerr << "RemoteProvider: Invalid result: " << e.what() << std::endl;
                    }
                    promiseObj.set_value();
                });

            const auto msg = jsonMsg.dump();
            socketClient->send(msg.data(), msg.size());
            futureObj.wait();
        }
        catch (const std::exception& e)
        {
            std::cerr << "RemoteStateHelper failed to send message: " << e.what() << std::endl;
        }
    }

public:
    static void sendInitProviderMessage(const std::string& endpointName)
    {
        nlohmann::json jsonMsg {{"EndpointName", endpointName}, {"MessageType", "InitProvider"}};
        sendRouterServerMessage(jsonMsg, false);
    }

    static void sendRemoveProviderMessage(const std::string& endpointName)
    {
        nlohmann::json jsonMsg {{"EndpointName", endpointName}, {"MessageType", "RemoveProvider"}};
        sendRouterServerMessage(jsonMsg, true);
    }

    static void sendRemoveSubscriberMessage(const std::string& endpointName, const std::string& subscriberId)
    {
        nlohmann::json jsonMsg {
            {"EndpointName", endpointName}, {"MessageType", "RemoveSubscriber"}, {"SubscriberId", subscriberId}};
        sendRouterServerMessage(jsonMsg, true);
    }
};

#endif // _REMOTE_STATE_HELPER_HPP
