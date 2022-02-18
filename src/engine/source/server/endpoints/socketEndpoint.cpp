/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "socketEndpoint.hpp"
#include "glog/logging.h"

namespace engineserver::endpoints
{

BaseEndpoint::ConnectionObs SocketEndpoint::connection(const uvw::ListenEvent & event, uvw::PipeHandle & srv)
{
    auto client = srv.loop().resource<uvw::PipeHandle>();
    auto timer = client->loop().resource<uvw::TimerHandle>();

    auto obs = rxcpp::observable<>::create<BaseEndpoint::EventObs>(
        [client, timer, &srv](rxcpp::subscriber<BaseEndpoint::EventObs> s)
        {
            auto ph = std::make_shared<ProtocolHandler>();

            client->on<uvw::ErrorEvent>(
                [&s](const uvw::ErrorEvent & event, uvw::PipeHandle & client)
                {
                    auto e = std::runtime_error("Connection error from " + client.peer() + " due to " + event.what());
                    s.on_error(std::make_exception_ptr(e));
                });

            timer->on<uvw::TimerEvent>(
                [client, s](const auto &, auto & handler)
                {
                    LOG(INFO) << "Timeout for connection" << std::endl;
                    client->close();
                    s.on_completed();
                    handler.close();
                });

            client->on<uvw::DataEvent>(
                [s, timer, ph](const uvw::DataEvent & event, uvw::PipeHandle & client)
                {
                    if (!ph->process(event.data.get(), event.length, s))
                    {
                        timer->close();
                        client.close();
                    }
                });

            client->on<uvw::EndEvent>(
                [s](const uvw::EndEvent &, uvw::PipeHandle & client)
                {
                    std::cerr << "Client closed connection" << std::endl;
                    client.close();
                    s.on_completed();
                });

            LOG(INFO) << "Accepting client!" << std::endl;
            // TODO: configure timeout for a tcp connection
            timer->start(uvw::TimerHandle::Time{5000}, uvw::TimerHandle::Time{5000});
            srv.accept(*client);
            client->read();
        });

    return obs;
}

SocketEndpoint::SocketEndpoint(const std::string & config) : BaseEndpoint{config}
{
    std::string path = config;

    auto loop = uvw::Loop::getDefault();
    m_server = loop->resource<uvw::PipeHandle>();

    this->m_out = rxcpp::observable<>::create<BaseEndpoint::ConnectionObs>(
        [this, config](rxcpp::subscriber<BaseEndpoint::ConnectionObs> s)
        {
            this->m_server->on<uvw::ErrorEvent>(
                [s](const uvw::ErrorEvent & event, uvw::PipeHandle & socket)
                {
                    auto e = std::runtime_error("Server error due to " + std::string(event.what()));
                    s.on_error(std::make_exception_ptr(e));
                });

            this->m_server->on<uvw::ListenEvent>([s, this](const uvw::ListenEvent & e, uvw::PipeHandle & client)
                                                 { s.on_next(this->connection(e, client)); });

            LOG(INFO) << "A route has been enabled for endpoint " << config << std::endl;
        });
}

void SocketEndpoint::run(void)
{
    LOG(INFO) << "Server started in TCP Endpoint." << std::endl;
    m_server->bind(m_path);
    m_server->listen();
    m_loop->run();
}

void SocketEndpoint::close(void)
{
    m_loop->stop();                                                 /// Stops the loop
    m_loop->walk([](uvw::BaseHandle & handle) { handle.close(); }); /// Triggers every handle's close callback
    m_loop->run(); /// Runs the loop again, so every handle is able to receive its close callback
    m_loop->clear();
    m_loop->close();
}

SocketEndpoint::~SocketEndpoint()
{
    this->close();
}

} // namespace engineserver::endpoints
