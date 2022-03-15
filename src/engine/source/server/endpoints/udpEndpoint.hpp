/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _UDP_ENDPOINT_H_
#define _UDP_ENDPOINT_H_

#include <cstring>
#include <functional>
#include <glog/logging.h>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <uvw/timer.hpp>
#include <uvw/udp.hpp>

#include "baseEndpoint.hpp"
#include "protocolHandler.hpp"

namespace engineserver::endpoints
{

/**
 * @brief Implements udp server endpoint using uvw library.
 *
 */
class UDPEndpoint : public BaseEndpoint
{

private:
    unsigned int m_port;
    std::string m_ip;

    std::shared_ptr<uvw::Loop> m_loop;
    std::shared_ptr<uvw::UDPHandle> m_udpHandle;

public:
    /**
     * @brief Construct a new UDPEndpoint object.
     *
     * @param config <ip>:<port> string with allowed ip mask and port to listen.
     */
    explicit UDPEndpoint(const std::string & config, ServerOutput & eventBuffer);
    ~UDPEndpoint();

    void run(void);

    void close(void);
};

} // namespace engineserver::endpoints

#endif // _UDP_ENDPOINT_H_
