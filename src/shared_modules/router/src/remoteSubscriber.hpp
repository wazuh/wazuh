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

#ifndef _REMOTE_SUBSCRIBER_HPP
#define _REMOTE_SUBSCRIBER_HPP

#include "epollWrapper.hpp"
#include "observer.hpp"
#include "remoteSubscriptionManager.hpp"
#include "routerProvider.hpp"
#include "socketClient.hpp"
#include <external/nlohmann/json.hpp>
#include <functional>

/**
 * @brief RemoteSubscriber class.
 *
 */
class RemoteSubscriber final
{
private:
    std::unique_ptr<SocketClient<Socket<OSPrimitives>, EpollWrapper>> m_socketClient {};
    std::unique_ptr<RemoteSubscriptionManager> m_remoteSubscriptionManager {};
    std::string m_endpointName {};
    std::atomic<bool> m_isRegistered;

public:
    /**
     * @brief Class constructor.
     *
     * @param endpoint Endpoint name.
     * @param subscriberId Subscriber ID.
     * @param callback Subscriber update callback.
     * @param socketPath Client socket path.
     * @param onConnect Callback to be called when the subscriber is connected.
     */
    explicit RemoteSubscriber(
        std::string endpoint,
        const std::string& subscriberId,
        const std::function<void(const std::vector<char>&)>& callback,
        const std::string& socketPath,
        const std::function<void()>& onConnect = []() {})
        : m_endpointName {std::move(endpoint)}
        , m_isRegistered {false}
        , m_remoteSubscriptionManager {std::make_unique<RemoteSubscriptionManager>()}
    {
        std::promise<void> promise;
        m_socketClient =
            std::make_unique<SocketClient<Socket<OSPrimitives>, EpollWrapper>>(socketPath + m_endpointName);

        m_remoteSubscriptionManager->sendInitProviderMessage(
            m_endpointName,
            [this, callback, socketClient = m_socketClient.get(), subscriberId, onConnect]()
            {
                socketClient->connect(
                    [this, callback, onConnect](const char* body, uint32_t bodySize, const char*, uint32_t)
                    {
                        if (!m_isRegistered)
                        {
                            // LCOV_EXCL_START
                            nlohmann::json jsonMessage;
                            try
                            {
                                jsonMessage = nlohmann::json::parse(body, body + bodySize);
                                if (jsonMessage.at("Result").get_ref<const std::string&>() == "OK")
                                {
                                    m_isRegistered = true;
                                    onConnect();
                                }
                                else
                                {
                                    throw std::runtime_error("Connection refused");
                                }
                            }
                            catch (const std::exception& e)
                            {
                                std::cerr << "RemoteSubscriber: Invalid result: " << e.what() << std::endl;
                            }
                            // LCOV_EXCL_STOP
                        }
                        else
                        {
                            callback(std::vector<char>(body, body + bodySize));
                        }
                    },
                    [subscriberId, socketClient]()
                    {
                        nlohmann::json jsonMessage;
                        jsonMessage["type"] = "subscribe";
                        jsonMessage["subscriberId"] = subscriberId;
                        auto jsonMessageString = jsonMessage.dump();

                        socketClient->send(jsonMessageString.c_str(), jsonMessageString.length());
                    });
            });
    }

    ~RemoteSubscriber() = default;
};

#endif // _REMOTE_SUBSCRIBER_HPP
