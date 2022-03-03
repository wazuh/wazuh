/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "tcpEndpoint.hpp"

namespace engineserver::endpoints
{

void TCPEndpoint::connectionHandler(uvw::TCPHandle & server)
{
    auto client = server.loop().resource<uvw::TCPHandle>();
    auto timer = client->loop().resource<uvw::TimerHandle>();

    auto ph = std::make_shared<ProtocolHandler>();

    client->on<uvw::ErrorEvent>(
        [](const uvw::ErrorEvent & event, uvw::TCPHandle & client)
        {
            LOG(ERROR) << "TCP ErrorEvent: endpoint (" << client.sock().ip.c_str() << ":" << client.sock().port
                       << ") error: code=" << event.code() << "; name=" << event.name() << "; message=" << event.what()
                       << std::endl;
        });

    timer->on<uvw::TimerEvent>(
        [client](const auto &, auto & handler)
        {
            LOG(INFO) << "TCP TimerEvent: Time out for connection" << std::endl;
            client->close();
            handler.close();
        });

    client->on<uvw::DataEvent>(
        [timer, ph](const uvw::DataEvent & event, uvw::TCPHandle & client)
        {
            timer->again();

            if (!ph->process(event.data.get(), event.length))
            {
                LOG(ERROR) << "TCP DataEvent: Error processing data" << std::endl;
                timer->close();
                client.close();
            }
        });

    client->on<uvw::EndEvent>(
        [timer](const uvw::EndEvent &, uvw::TCPHandle & client)
        {
            LOG(INFO) << "TCP EndEvent: Terminating connection" << std::endl;
            timer->close();
            client.close();
        });

    client->on<uvw::CloseEvent>([](const uvw::CloseEvent & event, uvw::TCPHandle & client)
                                { LOG(INFO) << "TCP CloseEvent: Connection closed" << std::endl; });

    server.accept(*client);
    LOG(INFO) << "TCP ListenEvent: Client accepted" << std::endl;

    timer->start(uvw::TimerHandle::Time{CONNECTION_TIMEOUT_MSEC}, uvw::TimerHandle::Time{CONNECTION_TIMEOUT_MSEC});

    client->read();
}

TCPEndpoint::TCPEndpoint(const std::string & config) : BaseEndpoint{config}
{
    auto pos = config.find(":");
    this->m_ip = config.substr(0, pos);
    this->m_port = stoi(config.substr(pos + 1));

    this->m_loop = uvw::Loop::getDefault();
    this->m_server = m_loop->resource<uvw::TCPHandle>();

    this->m_server->on<uvw::ListenEvent>(
        [this](const uvw::ListenEvent & event, uvw::TCPHandle & server)
        {
            LOG(INFO) << "TCP ListenEvent: stablishing new connection" << std::endl;
            this->connectionHandler(server);
        });

    this->m_server->on<uvw::ErrorEvent>(
        [](const uvw::ErrorEvent & event, uvw::TCPHandle & client)
        {
            LOG(ERROR) << "TCP ErrorEvent: endpoint(" << client.sock().ip.c_str() << ":" << client.sock().port
                       << ") error: code=" << event.code() << "; name=" << event.name() << "; message=" << event.what()
                       << std::endl;
        });

    this->m_server->on<uvw::CloseEvent>([](const uvw::CloseEvent & event, uvw::TCPHandle & client)
                                        { LOG(INFO) << "TCP CloseEvent" << std::endl; });

    LOG(INFO) << "TCP endpoint configured: " << config << std::endl;
}

void TCPEndpoint::run()
{
    m_server->bind(m_ip, m_port);
    m_server->listen();
    m_loop->run<uvw::Loop::Mode::DEFAULT>();
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
