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

    // Emits connections
    auto tcpServerObs = tmpObs[0];

    // Emits eventObservables
    auto tcpConnectionObs = tcpServerObs.flat_map([&](BaseEndpoint::ConnectionObs o){
        // This flat_map internally merges
        // on_error/on_completed emited by ConnectionObs o
        return o.on_error_resume_next([&](auto eptr){
            LOG(INFO) << "Error from connection: " << rxcpp::util::what(eptr) << std::endl;
            return rxcpp::observable<>::empty<BaseEndpoint::EventObs>();
        });
    }); // out subscriber  BaseEndpoint::ConnectionObs o

    // tcpServerObs <- flat_map
    // tcpServerObs --> ConnectionObs <- flat_map [tarea1, tarea2, ....] -> on_completed
    // flat_map internal_subscriber(ConnectionObs -> on_completed) -> EventsObs
    // src -> (src2 -> on_completed) -> on_next(evento) -> .... -> error )
    // src -> on_completed -> on_completed(evento) -> .... -> error )
    auto loop = rxcpp::schedulers::make_scheduler<threadpool::ThreadPool>(4);
    // Emits events
    BaseEndpoint::EventObs eventObs = tcpConnectionObs.flat_map([=](BaseEndpoint::EventObs o){

        return o.observe_on(rxcpp::serialize_same_worker(loop.create_worker()));
    });
    // auto safeEventObs = eventObs.on_error_resume_next([=](auto eptr){
    //     LOG(ERROR) << "safeEventObs treated error: e" << rxcpp::util::what(eptr) << std::endl;
    //     return eventObs;
    // });

    this->m_output = eventObs;
}

EngineServer::EngineServer(const vector<string> & config)
{
    this->configure(config);
}

endpoints::BaseEndpoint::EventObs EngineServer::output(void) const
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
