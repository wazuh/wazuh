/*
 * Socket DB Wrapper
 * Copyright (C) 2015, Wazuh Inc.
 * October 30, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SOCKET_DB_WRAPPER_HPP
#define _SOCKET_DB_WRAPPER_HPP

#include "json.hpp"
#include "socketClient.hpp"
#include <condition_variable>
#include <mutex>
#include <string>

auto constexpr DB_WRAPPER_QUERY_WAIT_TIME {500};

auto constexpr DB_WRAPPER_OK {"ok"};
auto constexpr DB_WRAPPER_ERROR {"err"};
auto constexpr DB_WRAPPER_UNKNOWN {"unk"};
auto constexpr DB_WRAPPER_IGNORE {"ign"};
auto constexpr DB_WRAPPER_DUE {"due"};

class SocketDBWrapper final
{
private:
    std::shared_ptr<SocketClient<Socket<OSPrimitives, SizeHeaderProtocol>, EpollWrapper>> m_dbSocket;
    std::string m_response;
    std::mutex m_mutex;
    std::condition_variable m_conditionVariable;

public:
    explicit SocketDBWrapper(const std::string& socketPath)
        : m_dbSocket {
              std::make_shared<SocketClient<Socket<OSPrimitives, SizeHeaderProtocol>, EpollWrapper>>(socketPath, true)}
    {
        m_dbSocket->connect(
            [&](const char* body, uint32_t bodySize, const char* header, uint32_t headerSize)
            {
                std::unique_lock<std::mutex> lock {m_mutex};
                m_response = std::string(body, bodySize);
                m_conditionVariable.notify_one();
            });
    }

    void query(const std::string& query, nlohmann::json& response)
    {
        std::unique_lock<std::mutex> lock {m_mutex};
        m_dbSocket->send(query.c_str(), query.size());
        auto res = m_conditionVariable.wait_for(lock, std::chrono::milliseconds(DB_WRAPPER_QUERY_WAIT_TIME));

        if (res == std::cv_status::timeout)
        {
            throw std::runtime_error("Timeout waiting for DB response");
        }

        if (m_response.empty())
        {
            throw std::runtime_error("Empty DB response");
        }

        if (0 == m_response.compare(0, 3, DB_WRAPPER_ERROR))
        {
            throw std::runtime_error("DB query error: " + m_response.substr(4));
        }

        if (0 == m_response.compare(0, 3, DB_WRAPPER_IGNORE))
        {
            throw std::runtime_error("DB query ignored: " + m_response.substr(4));
        }

        if (0 == m_response.compare(0, 3, DB_WRAPPER_UNKNOWN))
        {
            throw std::runtime_error("DB query unknown response: " + m_response.substr(4));
        }

        if (0 == m_response.compare(0, 3, DB_WRAPPER_DUE))
        {
            // TODO: Implement due response
            throw std::runtime_error("DB query with pending data");
        }

        if (0 == m_response.compare(0, 2, DB_WRAPPER_OK))
        {
            response = nlohmann::json::parse(m_response.substr(3));
        }
        else
        {
            throw std::runtime_error("DB query invalid response: " + m_response);
        }
    }
};

#endif // _SOCKET_DB_WRAPPER_HPP
