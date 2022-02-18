/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SOCKET_ENDPOINT_H_
#define _SOCKET_ENDPOINT_H_

#include <functional>
#include <iostream>
#include <mutex>
#include <string>
#include <uvw/pipe.hpp>
#include <uvw/timer.hpp>

#include "baseEndpoint.hpp"
#include "protocolHandler.hpp"

namespace engineserver::endpoints
{

/**
 * @brief Implements socket endopoint using uvw library.
 *
 */
class SocketEndpoint : public BaseEndpoint
{
private:
    std::string m_path;
    std::shared_ptr<uvw::Loop> m_loop;
    std::shared_ptr<uvw::PipeHandle> m_server;

    /**
     * @brief This function handles connections and returns a connection observable that
     *  emits event observables.
     *
     * @param event
     * @param srv
     * @return BaseEndpoint::ConnectionObs
     */
    BaseEndpoint::ConnectionObs connection(const uvw::ListenEvent & event, uvw::PipeHandle & srv);

public:
    /**
     * @brief Construct a new Socket Endpoint object.
     *
     * @param config string with path to socket.
     */
    explicit SocketEndpoint(const std::string & config);
    ~SocketEndpoint();

    void run(void);
    void close(void);
};

} // namespace engineserver::endpoints

#endif // _SOCKET_ENDPOINT_H_
