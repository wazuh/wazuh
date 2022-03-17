/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "engineServer.hpp"

#include <logging/logging.hpp>
using std::endl;
using std::make_unique;
using std::string;
using std::vector;

using moodycamel::BlockingConcurrentQueue;

using namespace engineserver::endpoints;

namespace engineserver
{

EngineServer::EngineServer(const std::vector<std::string> & config, size_t bufferSize)
    : m_eventBuffer{bufferSize}, m_isConfigured{false}
{
    try
    {
        for (auto endpointConf : config)
        {
            const auto pos = endpointConf.find(":");

            m_endpoints[endpointConf] =
                createEndpoint(endpointConf.substr(0, pos), endpointConf.substr(pos + 1), m_eventBuffer);
        }
    }
    catch (const std::exception & e)
    {
        WAZUH_LOG_ERROR("Exception while creating server configuration: [{}]", e.what());
        return;
    }

    m_isConfigured = true;
}

std::unique_ptr<BaseEndpoint> EngineServer::createEndpoint(const string & type, const string & path,
                                                           BlockingConcurrentQueue<string> & eventBuffer) const
{
    if (type == "tcp")
    {
        return make_unique<TCPEndpoint>(path, eventBuffer);
    }
    else if (type == "udp")
    {
        return make_unique<UDPEndpoint>(path, eventBuffer);
    }
    else if (type == "datagramsocket")
    {
        return make_unique<DatagramSocketEndpoint>(path, eventBuffer);
    }
    else
    {
        throw std::runtime_error("Error, endpoint type " + type + " not implemented by factory Endpoint builder");
    }

    return nullptr;
}

// TODO: fix, only runs first endpoint because run is blocking
void EngineServer::run(void)
{
    for (auto it = m_endpoints.begin(); it != m_endpoints.end(); ++it)
    {
        it->second->run();
    }
}

void EngineServer::close(void)
{
    for (auto it = m_endpoints.begin(); it != m_endpoints.end(); ++it)
    {
        it->second->close();
    }
}

BlockingConcurrentQueue<string> & EngineServer::output()
{
    return m_eventBuffer;
}

} // namespace engineserver
