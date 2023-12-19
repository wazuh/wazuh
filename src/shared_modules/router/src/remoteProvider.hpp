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
#include "remoteSubscriptionManager.hpp"
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
    std::unique_ptr<SocketClient<Socket<OSPrimitives>, EpollWrapper>> m_socketClient {};
    std::unique_ptr<RemoteSubscriptionManager> m_remoteSubscriptionManager {};
    std::string m_endpointName {};

public:
    /**
     * @brief Class constructor.
     *
     * @param endpoint Endpoint name.
     * @param socketPath Client socket path.
     * @param onConnect Callback to be called when the provider is connected.
     */
    // LCOV_EXCL_START
    explicit RemoteProvider(std::string endpoint,
                            const std::string& socketPath,
                            const std::function<void()>& onConnect = {})
        : m_endpointName {std::move(endpoint)}
        , m_remoteSubscriptionManager {std::make_unique<RemoteSubscriptionManager>()}
    {

        m_socketClient =
            std::make_unique<SocketClient<Socket<OSPrimitives>, EpollWrapper>>(socketPath + m_endpointName);
        m_remoteSubscriptionManager->sendInitProviderMessage(
            m_endpointName,
            [&, onConnect, socketClient = m_socketClient.get()]()
            { socketClient->connect([&](const char*, uint32_t, const char*, uint32_t) {}, onConnect); });
    }
    // LCOV_EXCL_STOP

    /**
     * @brief Sends a message into the client socket.
     *
     * @param message Message to be sent.
     */
    void push(const std::vector<char>& message)
    {
        m_socketClient->send(message.data(), message.size(), "P", 1);
    }

    ~RemoteProvider() = default;
};

#endif // _REMOTE_PROVIDER_HPP
