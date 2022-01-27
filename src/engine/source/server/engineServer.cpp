/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "engineServer.hpp"

using namespace engineserver;

EngineServer::EngineServer(const std::vector<std::string> & config)
{
    std::vector<rxcpp::observable<nlohmann::json>> tmpObs;

    // <EnpointType>:<config_string> tcp:localhost:5054 socke:path/to/socket
    for (auto endpointConf : config)
    {
        auto pos = endpointConf.find(":");

        this->m_endpoints[endpointConf] = endpoints::create(endpointConf.substr(0, pos), endpointConf.substr(pos + 1));

        tmpObs.push_back(this->m_endpoints[endpointConf]->output());
    }

    // Build server output observable to emit json events
    auto output = tmpObs[0];
    for (auto it = ++tmpObs.begin(); it != tmpObs.end(); ++it)
    {
        output = output.merge(*it);
    }
    this->m_output = output;
}

rxcpp::observable<nlohmann::json> EngineServer::output(void) const
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
