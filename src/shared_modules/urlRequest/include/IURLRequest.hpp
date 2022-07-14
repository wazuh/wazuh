/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 11, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#ifndef _URL_REQUEST_HPP
#define _URL_REQUEST_HPP

#include <functional>
#include <string>
#include "json.hpp"

enum SOCKET_TYPE
{
    SOCKET_UNIX,
    SOCKET_TCP
};

class URL
{
    public:
        virtual ~URL() = default;
        std::string unixSocketPath() const { return m_sock; }
        std::string url() const { return m_url; };
        SOCKET_TYPE socketType() const { return m_socketType; };
    protected:
        SOCKET_TYPE m_socketType;
        std::string m_url;
        std::string m_sock;
};

class HttpUnixSocketURL final : public URL
{
    public:
        HttpUnixSocketURL(const std::string& sock, std::string url)
        {
            m_socketType = SOCKET_UNIX;
            m_sock = sock;
            m_url = url;
        }
};

class HttpURL final : public URL
{
    public:
        HttpURL(const std::string &url)
        {
            m_socketType = SOCKET_TCP;
            m_url = url;
        }
};

class IURLRequest
{
    public:
        virtual ~IURLRequest() = default;
        virtual void download(const URL &url,
                              const std::string &fileName,
                              std::function<void(const std::string &)> onError = [](auto){}) = 0;

        virtual void post(const URL &url,
                          const nlohmann::json &data,
                          std::function<void(const std::string &)> onSuccess,
                          std::function<void(const std::string &)> onError = [](auto){}) = 0;

        virtual void get(const URL &url,
                         std::function<void(const std::string &)> onSuccess,
                         std::function<void(const std::string &)> onError = [](auto){}) = 0;

        virtual void update(const URL &url,
                            const nlohmann::json &data,
                            std::function<void(const std::string &)> onSuccess,
                            std::function<void(const std::string &)> onError = [](auto){}) = 0;

        virtual void delete_(const URL &url,
                            std::function<void(const std::string &)> onSuccess,
                            std::function<void(const std::string &)> onError = [](auto){}) = 0;
};

#endif // _URL_REQUEST_HPP
