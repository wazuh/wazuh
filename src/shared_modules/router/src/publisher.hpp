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

#ifndef _PUBLISHER_HPP
#define _PUBLISHER_HPP

#include "filterMsgDispatcher.hpp"
#include "provider.hpp"
#include "socketServer.hpp"
#include "subscriber.hpp"
#include <external/nlohmann/json.hpp>
#include <memory>
#include <vector>

constexpr auto PUBLISHER_DISPATCH_THREAD_COUNT {1};

/**
 * @brief Publisher class.
 *
 */
class Publisher final : public Provider<const std::vector<char>&>
{
private:
    using MsgDispatcher = Utils::FilterMsgDispatcher<const std::vector<char>&>;
    std::unique_ptr<SocketServer<Socket<OSPrimitives>, EpollWrapper>> m_socketServer {};
    std::unique_ptr<MsgDispatcher> m_msgDispatcher {};

public:
    /**
     * @brief Class constructor. Initializes server socket and listen from it.
     *
     * @param endpointName Server's endpoint.
     * @param socketPath Server's socket path.
     */
    explicit Publisher(const std::string& endpointName, const std::string& socketPath)
        : m_socketServer(std::make_unique<SocketServer<Socket<OSPrimitives>, EpollWrapper>>(socketPath + endpointName))
        , m_msgDispatcher(std::make_unique<MsgDispatcher>([this, endpointName](const std::vector<char>& data)
                                                          { this->call(data); },
                                                          nullptr,
                                                          PUBLISHER_DISPATCH_THREAD_COUNT))
    {
        m_socketServer->listen(
            [this, msgDispatcher = m_msgDispatcher.get(), socketServer = m_socketServer.get()](
                const int fd, const char* body, const size_t bodySize, const char* header, const size_t headerSize)
            {
                // if the message is from the provider, push data.
                // if the message is subscriber client, register to receive data.
                // check if the last byte to check if is a subscriber or a provider

                std::string_view headerString {header, headerSize};

                if (headerSize > 0)
                {
                    if (headerString.compare("P") == 0)
                    {
                        auto message = std::vector<char>(body, body + bodySize);
                        msgDispatcher->push(message);
                    }
                }
                else
                {
                    auto jsonBody = nlohmann::json::parse(body, body + bodySize);
                    this->addSubscriber(std::make_shared<Subscriber<const std::vector<char>&>>(
                        [fd, socketServer](const std::vector<char>& message)
                        { socketServer->send(fd, message.data(), message.size()); },
                        jsonBody.at("subscriberId").get_ref<const std::string&>()));

                    const std::string responseString = R"({"Result":"OK"})";
                    socketServer->send(fd, responseString.c_str(), responseString.size());
                }
            });
    }

    /**
     * @brief Pushes data into the message dispatcher.
     *
     * @param data Data to be pushed.
     */
    void push(const std::vector<char>& data)
    {
        m_msgDispatcher->push(data);
    }

    ~Publisher() override
    {
        m_socketServer.reset();
        m_msgDispatcher->rundown();
    }
};

#endif // _PUBLISHER_HPP
