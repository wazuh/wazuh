/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TCP_ENDPOINT_H_
#define _TCP_ENDPOINT_H_

#include <functional>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <uvw/tcp.hpp>
#include <uvw/timer.hpp>

#include "baseEndpoint.hpp"
#include "protocolHandler.hpp"

namespace engineserver::endpoints
{

/**
 * @brief Implements tcp server endpoint using uvw library.
 *
 */
class TCPEndpoint : public BaseEndpoint
{
private:
    int m_port;
    std::string m_ip;

    std::shared_ptr<uvw::Loop> m_loop;
    std::shared_ptr<uvw::TCPHandle> m_server;

    BaseEndpoint::ConnectionObs connectionHandler(const uvw::ListenEvent & event, uvw::TCPHandle & srv);

public:
    /**
     * @brief Construct a new TCPEndpoint object.
     *
     * @param config <ip>:<port> string with allowed ip mask and port to listen.
     */
    explicit TCPEndpoint(const std::string & config);
    ~TCPEndpoint();

    void run() override;

    void close() override;
};
} // namespace engineserver::endpoints

#endif // _TCP_ENDPOINT_H_
