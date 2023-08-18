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

#ifndef _REMOTE_PROVIDER_HPP
#define _REMOTE_PROVIDER_HPP

#include "epollWrapper.hpp"
#include "observer.hpp"
#include "remoteStateHelper.hpp"
#include "routerProvider.hpp"
#include "socketClient.hpp"
#include <external/nlohmann/json.hpp>
#include <functional>

/**
 * @brief RemoteProvider class.
 *
 */
class RemoteProvider final
{
private:
    std::shared_ptr<SocketClient<Socket<OSPrimitives>, EpollWrapper>> m_socketClient {};
    std::string m_endpointName {};

public:
    /**
     * @brief Class constructor.
     *
     * @param endpoint Endpoint name.
     * @param socketPath Client socket path.
     */
    explicit RemoteProvider(std::string endpoint, const std::string& socketPath)
        : m_endpointName {std::move(endpoint)}
    {
        nlohmann::json jsonMsg {{"EndpointName", m_endpointName}, {"MessageType", "InitProvider"}};
        RemoteStateHelper::sendRegistrationMessage(jsonMsg);

        m_socketClient =
            std::make_shared<SocketClient<Socket<OSPrimitives>, EpollWrapper>>(socketPath + m_endpointName);
        m_socketClient->connect([&](const char*, uint32_t, const char*, uint32_t) {});
    }

    /**
     * @brief Sends a message into the client socket.
     *
     * @param message Message to be sent.
     */
    void push(const std::vector<char>& message)
    {
        m_socketClient->send(message.data(), message.size(), "P", 1);
    }

    ~RemoteProvider()
    {
        nlohmann::json jsonMsg {{"EndpointName", m_endpointName}, {"MessageType", "RemoveProvider"}};
        RemoteStateHelper::sendRegistrationMessage(jsonMsg);
    }
};

#endif // _REMOTE_PROVIDER_HPP
