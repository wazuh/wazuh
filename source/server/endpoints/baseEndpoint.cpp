/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "socketEndpoint.hpp"
#include "tcpEndpoint.hpp"
#include "udpEndpoint.hpp"

namespace engineserver::endpoints
{

BaseEndpoint::BaseEndpoint(const std::string & path) : m_path{path}, m_subscriber{m_subject.get_subscriber()}
{
}

BaseEndpoint::~BaseEndpoint()
{
}

rxcpp::observable<nlohmann::json> BaseEndpoint::output(void) const
{
    return this->m_subject.get_observable();
}

EndpointType stringToEndpoint(const std::string & endpointName)
{
    if (endpointName == "tcp")
    {
        return TCP;
    }
    else if (endpointName == "udp")
    {
        return UDP;
    }
    else if (endpointName == "socket")
    {
        return SOCKET;
    }
    else
    {
        throw std::invalid_argument("Error, endpoint " + endpointName + " not supported");
    }
}

std::unique_ptr<BaseEndpoint> create(const std::string & type, const std::string & config)
{
    auto endpointType = stringToEndpoint(type);
    switch (endpointType)
    {
        case TCP:
            return std::make_unique<TCPEndpoint>(config);
            break;
        case UDP:
            return std::make_unique<UDPEndpoint>(config);
            break;
        case SOCKET:
            return std::make_unique<SocketEndpoint>(config);
            break;
        default:
            throw std::runtime_error("Error, endpoint type " + std::to_string(endpointType) +
                                     " not implemented by factory Endpoint builder");
            break;
    }
}

} // namespace engineserver::endpoints
