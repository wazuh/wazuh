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
    nlohmann::json m_response;
    nlohmann::json m_responsePartial;
    std::string m_exceptionStr;
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
                std::string responsePacket(body, bodySize);

                if (0 == responsePacket.compare(0, 3, DB_WRAPPER_DUE))
                {
                    try
                    {
                        m_responsePartial.push_back(nlohmann::json::parse(responsePacket.substr(4)));
                    }
                    catch (const nlohmann::detail::exception& ex)
                    {
                        m_exceptionStr = "Error parsing JSON response: " + responsePacket.substr(4) +
                                         ". Exception id: " + std::to_string(ex.id) + ". " + ex.what();
                    }
                }
                else
                {
                    if (responsePacket.empty())
                    {
                        m_exceptionStr = "Empty DB response";
                    }
                    else if (0 == responsePacket.compare(0, 3, DB_WRAPPER_ERROR))
                    {
                        m_exceptionStr = "DB query error: " + responsePacket.substr(4);
                    }
                    else if (0 == responsePacket.compare(0, 3, DB_WRAPPER_IGNORE))
                    {
                        m_exceptionStr = "DB query ignored: " + responsePacket.substr(4);
                    }
                    else if (0 == responsePacket.compare(0, 3, DB_WRAPPER_UNKNOWN))
                    {
                        m_exceptionStr = "DB query unknown response: " + responsePacket.substr(4);
                    }
                    else if (0 == responsePacket.compare(0, 2, DB_WRAPPER_OK))
                    {
                        if (!m_responsePartial.empty())
                        {
                            m_response = m_responsePartial;
                        }
                        else
                        {
                            try
                            {
                                nlohmann::json responseParsed = nlohmann::json::parse(responsePacket.substr(3));
                                if (responseParsed.type() == nlohmann::json::value_t::array)
                                {
                                    m_response = responseParsed;
                                }
                                else
                                {
                                    m_response.push_back(responseParsed);
                                }
                            }
                            catch (const nlohmann::detail::exception& ex)
                            {
                                m_exceptionStr = "Error parsing JSON response: " + responsePacket.substr(3) +
                                                 ". Exception id: " + std::to_string(ex.id) + ". " + ex.what();
                            }
                        }
                    }
                    else
                    {
                        m_exceptionStr = "DB query invalid response: " + responsePacket;
                    }
                    m_conditionVariable.notify_one();
                }
            });
    }

    void query(const std::string& query, nlohmann::json& response)
    {
        m_response.clear();
        m_responsePartial.clear();
        m_exceptionStr.clear();

        std::unique_lock<std::mutex> lock {m_mutex};
        m_dbSocket->send(query.c_str(), query.size());
        auto res = m_conditionVariable.wait_for(lock, std::chrono::milliseconds(DB_WRAPPER_QUERY_WAIT_TIME));

        if (res == std::cv_status::timeout)
        {
            throw std::runtime_error("Timeout waiting for DB response");
        }

        if (!m_exceptionStr.empty())
        {
            throw std::runtime_error(m_exceptionStr);
        }

        response = m_response;
    }
};

#endif // _SOCKET_DB_WRAPPER_HPP
