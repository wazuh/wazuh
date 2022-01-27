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

TCPEndpoint::TCPEndpoint(const std::string & config)
    : BaseEndpoint{config}, m_loop{uvw::Loop::getDefault()}, m_handle{m_loop->resource<uvw::TCPHandle>()}
{
    auto pos = config.find(":");
    auto tmp = config.substr(pos + 1);
    pos = tmp.find(":");
    this->m_ip = tmp.substr(0, pos);
    this->m_port = stoi(tmp.substr(pos + 1));

    m_handle->on<uvw::ErrorEvent>(
        [](const uvw::ErrorEvent & event, uvw::TCPHandle & tcp)
        {
            std::cerr << "TCP Server (" << tcp.sock().ip.c_str() << ":" << tcp.sock().port
                      << ") error: code=" << event.code() << "; name=" << event.name() << "; message=" << event.what()
                      << std::endl;
        });

    m_handle->on<uvw::ListenEvent>(
        [this](const uvw::ListenEvent &, uvw::TCPHandle & srv)
        {
            auto client = srv.loop().resource<uvw::TCPHandle>();

            client->on<uvw::ErrorEvent>(
                [](const uvw::ErrorEvent & event, uvw::TCPHandle & client)
                {
                    std::cerr << "TCP Client (" << client.peer().ip.c_str() << ":" << client.peer().port
                              << ") error: code=" << event.code() << "; name=" << event.name()
                              << "; message=" << event.what() << std::endl;
                });

            client->on<uvw::DataEvent>(
                [this, &srv](const uvw::DataEvent & event, uvw::TCPHandle & client)
                {
                    auto eventObject =
                        engineserver::protocolhandler::parseEvent(std::string(event.data.get(), event.length));
                    if (!eventObject.contains("error"))
                    {
                        this->m_subscriber.on_next(eventObject);
                    }
                    else
                    {
                        // TODO: complete this case
                    }
                });

            client->on<uvw::EndEvent>([](const uvw::EndEvent &, uvw::TCPHandle & client) { client.close(); });

            srv.accept(*client);
            client->read();
        });

    m_handle->bind(this->m_ip, this->m_port);
    m_handle->listen();
}

void TCPEndpoint::run(void)
{
    std::thread t(&uvw::Loop::run, this->m_loop.get());
    t.detach();
}

void TCPEndpoint::close(void)
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
}

} // namespace engineserver::endpoints
