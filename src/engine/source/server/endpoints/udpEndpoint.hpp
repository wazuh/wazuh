/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _UDP_ENDPOINT_H_
#define _UDP_ENDPOINT_H_

#include <functional>
#include <iostream>
#include <mutex>
#include <string>

#include <uvw/udp.hpp>

#include "baseEndpoint.hpp"
#include "protocolHandler.hpp"

namespace engineserver::endpoints
{

class UDPEndpoint : public BaseEndpoint
{

private:
    std::shared_ptr<uvw::Loop> m_loop;
    std::shared_ptr<uvw::UDPHandle> m_handle;
    std::string m_ip;
    int m_port;

public:
    explicit UDPEndpoint(const std::string & config);
    ~UDPEndpoint();

    void run(void);
    void close(void);
};

} // namespace engineserver::endpoints

#endif // _UDP_ENDPOINT_H_
