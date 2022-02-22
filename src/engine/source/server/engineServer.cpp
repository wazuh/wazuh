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
#include "threadPool.hpp"
#include "protocolHandler.hpp"

using namespace std;
using namespace engineserver::endpoints;

namespace engineserver
{
void EngineServer::configure(const vector<string> & config, rxcpp::observe_on_one_worker & mainthread)
{
    vector<BaseEndpoint::EndpointObs> tmpObs;

    // <EnpointType>:<config_string> tcp:localhost:5054 socket:path/to/socket
    for (auto endpointConf : config)
    {
        auto pos = endpointConf.find(":");

        this->m_endpoints[endpointConf] = endpoints::create(endpointConf.substr(0, pos), endpointConf.substr(pos + 1));

        tmpObs.push_back(this->m_endpoints[endpointConf]->output());
    }

    // Emits connections
    BaseEndpoint::EndpointObs tcpServerObs = tmpObs[0];

    auto sc = rxcpp::schedulers::make_scheduler<threadpool::ThreadPool>(8);
    auto threadpoolW = rxcpp::observe_on_one_worker(sc);

    // Emits eventObservables
    BaseEndpoint::ConnectionObs tcpConnectionObs = tcpServerObs.flat_map(
        [&](BaseEndpoint::ConnectionObs o)
        {
            // This flat_map internally merges
            // on_error/on_completed emited by ConnectionObs o
            return o.on_error_resume_next(
                [&](auto eptr)
                {
                    LOG(INFO) << "Recovering from: " << rxcpp::util::what(eptr) << std::endl;
                    return rxcpp::observable<>::empty<BaseEndpoint::EventObs>();
                });
        },
        mainthread);
    engineserver::ProtocolHandler p;
    // Emits events
    rxcpp::observable<json::Document> eventObs = tcpConnectionObs.flat_map(
        [=](BaseEndpoint::EventObs o)
        {
            return o
                .on_error_resume_next(
                    [&](auto eptr)
                    {
                        LOG(INFO) << "Recovering from: " << rxcpp::util::what(eptr) << std::endl;
                        return rxcpp::observable<>::empty<BaseEndpoint::Event>();
                    })
                .observe_on(threadpoolW)
                .map([=](std::string event) {
                    LOG(INFO) << "[" << this_thread::get_id() << "]" << std::endl;
                    return p.parse(event); });
        }, threadpoolW);

    this->m_output = eventObs;
}

// EngineServer::EngineServer(const vector<string> & config)
// {
//     this->configure(config, );
// }

rxcpp::observable<json::Document> EngineServer::output(void) const
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
