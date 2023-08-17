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

/**
 * @brief Publisher
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
     * @brief Construct a new Publisher object
     *
     * @param endpointName
     * @param socketPath
     */
    explicit Publisher(const std::string& endpointName, const std::string& socketPath)
        : m_socketServer(std::make_unique<SocketServer<Socket<OSPrimitives>, EpollWrapper>>(socketPath + endpointName))
        , m_msgDispatcher(std::make_unique<MsgDispatcher>([this, endpointName](const std::vector<char>& data)
                                                          { this->call(data); }))
    {
        m_socketServer->listen(
            [&](const int fd, const char* body, const size_t bodySize, const char* header, const size_t headerSize)
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
                        m_msgDispatcher->push(message);
                    }
                }
                else
                {
                    auto jsonBody = nlohmann::json::parse(body, body + bodySize);
                    this->addSubscriber(std::make_shared<Subscriber<const std::vector<char>&>>(
                        [this, fd](const std::vector<char>& message)
                        { m_socketServer->send(fd, message.data(), message.size()); },
                        jsonBody.at("subscriberId").get_ref<const std::string&>()));

                    const std::string responseString = R"({"Result":"OK"})";
                    m_socketServer->send(fd, responseString.c_str(), responseString.size());
                }
            });
    }

    /**
     * @brief
     *
     * @param data
     */
    void push(const std::vector<char>& data)
    {
        m_msgDispatcher->push(data);
    }

    /**
     * @brief Destroy the Publisher object
     *
     */
    ~Publisher() override
    {
        m_msgDispatcher->rundown();
    }
};

#endif // _PUBLISHER_HPP
