/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "engineServer.hpp"

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
void EngineServer::configure(const vector<string> & config)
{
    vector<BaseEndpoint::EndpointObs> tmpObs;

    // <EnpointType>:<config_string> tcp:localhost:5054 socket:path/to/socket
    for (auto endpointConf : config)
    {
        auto pos = endpointConf.find(":");

        this->m_endpoints[endpointConf] = endpoints::create(endpointConf.substr(0, pos), endpointConf.substr(pos + 1));

        tmpObs.push_back(this->m_endpoints[endpointConf]->output());
    }

    auto obs = rxcpp::observable<>::iterate(tmpObs)
        // TODO: Handle endpoint server errors
        // From -> EndpointObs observable->observable->observable->event
        // Emits -> ConnectionObs observable->observable->event
        .flat_map([](BaseEndpoint::EndpointObs o) { return o; })
        // TODO: Handle endpoint connection errors
        // From -> ConnectionObs observable->observable->event
        // Emits -> EventObs observable->event
        .flat_map([](BaseEndpoint::ConnectionObs o) { return o; });

    this->m_output = obs;
}

EngineServer::EngineServer(const vector<string> & config)
{
    this->configure(config);
}

endpoints::BaseEndpoint::ConnectionObs EngineServer::output(void) const
{
    return this->m_output;
}

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
} // namespace engineserver
