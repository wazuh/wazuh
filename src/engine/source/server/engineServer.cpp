/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "engineServer.hpp"

#include <glog/logging.h>
#include <map>
#include <memory>
#include <rxcpp/rx.hpp>
#include <vector>

#include "endpoints/baseEndpoint.hpp"
#include "endpoints/endpointFactory.hpp"
#include "json.hpp"

using namespace std;
using namespace engineserver::endpoints;

namespace engineserver
{

EngineServer::EngineServer(const size_t & bufferSize) : m_eventBuffer{bufferSize}
{
}

void EngineServer::configure(const vector<string> & config)
{
    for (auto endpointConf : config)
    {
        auto pos = endpointConf.find(":");

        this->m_endpoints[endpointConf] =
            endpoints::create(endpointConf.substr(0, pos), endpointConf.substr(pos + 1), m_eventBuffer);
    }
}

// TODO: fix, only runs first endpoint because run is blocking
void EngineServer::run(void)
{
    for (auto it = this->m_endpoints.begin(); it != this->m_endpoints.end(); ++it)
    {
        it->second->run();
    }
}

void EngineServer::close(void)
{
    for (auto it = this->m_endpoints.begin(); it != this->m_endpoints.end(); ++it)
    {
        it->second->close();
    }
}

moodycamel::BlockingConcurrentQueue<std::string> & EngineServer::output()
{
    return m_eventBuffer;
}

} // namespace engineserver
