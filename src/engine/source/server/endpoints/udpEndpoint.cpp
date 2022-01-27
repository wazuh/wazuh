/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "udpEndpoint.hpp"

using namespace std;

namespace engineserver::endpoints
{
UDPEndpoint::UDPEndpoint(const std::string & config)
    : BaseEndpoint{config}, m_loop{uvw::Loop::getDefault()}, m_handle{m_loop->resource<uvw::UDPHandle>()}
{
    auto pos = config.find(":");
    this->m_ip = config.substr(0, pos);
    this->m_port = stoi(config.substr(pos + 1));

    this->m_handle->on<uvw::ErrorEvent>(
        [](const uvw::ErrorEvent & event, uvw::UDPHandle & udp)
        {
            std::cerr << "UDP Server (" << udp.sock().ip.c_str() << ":" << udp.sock().port
                      << ") error: code=" << event.code() << "; name=" << event.name() << "; message=" << event.what()
                      << std::endl;
        });

    this->m_handle->on<uvw::UDPDataEvent>(
        [this](const uvw::UDPDataEvent & event, uvw::UDPHandle & udp)
        {
            auto client = udp.loop().resource<uvw::UDPHandle>();

            client->on<uvw::ErrorEvent>(
                [](const uvw::ErrorEvent & event, uvw::UDPHandle & client)
                {
                    std::cerr << "UDP Client (" << client.peer().ip.c_str() << ":" << client.peer().port
                              << ") error: code=" << event.code() << "; name=" << event.name()
                              << "; message=" << event.what() << std::endl;
                });

            auto eventObject = engineserver::protocolhandler::parseEvent(std::string(event.data.get(), event.length));
            if (!eventObject.contains("error"))
            {
                this->m_subscriber.on_next(eventObject);
            }
            else
            {
                // TODO: complete this case
            }
        });

    this->m_handle->bind(this->m_ip, this->m_port);
    this->m_handle->recv();
}

void UDPEndpoint::run(void)
{
    std::thread t(&uvw::Loop::run, this->m_loop.get());
    t.detach();
}

void UDPEndpoint::close(void)
{
    m_loop->stop();                                                 /// Stops the loop
    m_loop->walk([](uvw::BaseHandle & handle) { handle.close(); }); /// Triggers every handle's close callback
    m_loop->run(); /// Runs the loop again, so every handle is able to receive its close callback
    m_loop->clear();
    m_loop->close();
}

UDPEndpoint::~UDPEndpoint()
{
    this->close();
}
} // namespace engineserver::endpoints
