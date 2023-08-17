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
 * @brief RemoteStateHelper
 *
 */
class RemoteStateHelper final
{
private:
    RemoteStateHelper() = default;
    ~RemoteStateHelper() = default;

public:
    /**
     * @brief
     *
     * @param jsonMsg
     */
    static void sendRegistrationMessage(const nlohmann::json& jsonMsg)
    {
        std::promise<void> promiseObj;
        auto futureObj = promiseObj.get_future();
        auto socketClient =
            std::make_shared<SocketClient<Socket<OSPrimitives>, EpollWrapper>>(REMOTE_SUBSCRIPTION_ENDPOINT);
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
};

#endif // _REMOTE_STATE_HELPER_HPP
