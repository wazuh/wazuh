/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "tcpEndpoint.hpp"
#include "glog/logging.h"
#include "protocolHandler.hpp"
#include <cstring>
#include <iostream>

namespace engineserver::endpoints
{

BaseEndpoint::ConnectionObs TCPEndpoint::connectionHandler(const uvw::ListenEvent & event, uvw::TCPHandle & srv)
{
    auto client = srv.loop().resource<uvw::TCPHandle>();
    auto timer = client->loop().resource<uvw::TimerHandle>();

    auto obs = rxcpp::observable<>::create<BaseEndpoint::EventObs>(
        [client, timer, &srv](rxcpp::subscriber<BaseEndpoint::EventObs> s)
        {
            auto ph = std::make_shared<ProtocolHandler>();

            client->on<uvw::ErrorEvent>(
                [s](const uvw::ErrorEvent & event, uvw::TCPHandle & client)
                {
                    LOG(ERROR) << "TCP Server (" << client.sock().ip.c_str() << ":" << client.sock().port
                               << ") error: code=" << event.code() << "; name=" << event.name()
                               << "; message=" << event.what() << std::endl;
                    auto e =
                        std::runtime_error("Connection error from " + client.peer().ip + " due to " + event.what());
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
                [s, timer, ph](const uvw::DataEvent & event, uvw::TCPHandle & client)
                {
                    timer->again();
                    if (!ph->process(event.data.get(), event.length, s))
                    {
                        timer->close();
                        client.close();
                    }
                });

            client->on<uvw::EndEvent>(
                [s, timer](const uvw::EndEvent &, uvw::TCPHandle & client)
                {
                    LOG(INFO) << "Connection closed" << std::endl;
                    timer->close();
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

TCPEndpoint::TCPEndpoint(const std::string & config) : BaseEndpoint{config}
{
    auto pos = config.find(":");
    this->m_ip = config.substr(0, pos);
    this->m_port = stoi(config.substr(pos + 1));

    this->m_loop = uvw::Loop::getDefault();
    this->m_server = m_loop->resource<uvw::TCPHandle>();

    this->m_out = rxcpp::observable<>::create<BaseEndpoint::ConnectionObs>(
        [this, config](rxcpp::subscriber<BaseEndpoint::ConnectionObs> s)
        {
            this->m_server->on<uvw::ListenEvent>(
                [s, this](const uvw::ListenEvent & event, uvw::TCPHandle & client)
                {
                    LOG(INFO) << "Accepting new connection" << std::endl;
                    s.on_next(this->connectionHandler(event, client));
                });

            this->m_server->on<uvw::ErrorEvent>(
                [s](const uvw::ErrorEvent & event, uvw::TCPHandle & client)
                {
                    LOG(ERROR) << "TCP Server (" << client.sock().ip.c_str() << ":" << client.sock().port
                               << ") error: code=" << event.code() << "; name=" << event.name()
                               << "; message=" << event.what() << std::endl;
                    auto e = std::runtime_error("Server error due to " + std::string(event.what()));
                    s.on_error(std::make_exception_ptr(e));
                });

            LOG(INFO) << "A route has been enabled for endpoint " << config << std::endl;
        });
}

void TCPEndpoint::run()
{
    LOG(INFO) << "Server started in TCP Endpoint." << std::endl;
    m_server->bind(m_ip, m_port);
    m_server->listen();
    m_loop->run();
}

void TCPEndpoint::close()
{
    m_loop->stop();                                                 /// Stops the loop
    m_loop->walk([](uvw::BaseHandle & handle) { handle.close(); }); /// Triggers every handle's close callback
    m_loop->run(); /// Runs the loop again, so every handle is able to receive its close callback
    m_loop->clear();
    m_loop->close();
}

TCPEndpoint::~TCPEndpoint()
{
    this->close();
};

} // namespace engineserver::endpoints
