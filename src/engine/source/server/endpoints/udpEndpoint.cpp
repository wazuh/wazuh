/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "udpEndpoint.hpp"

using std::endl;
using std::string;

using uvw::ErrorEvent;
using uvw::Loop;
using uvw::UDPDataEvent;
using uvw::UDPHandle;

namespace engineserver::endpoints
{

UDPEndpoint::UDPEndpoint(const string & config, ServerOutput & eventBuffer)
    : BaseEndpoint{config, eventBuffer}, m_loop{Loop::getDefault()}, m_udpHandle{m_loop->resource<UDPHandle>()}
{
    auto pos = config.find(":");
    m_ip = config.substr(0, pos);
    m_port = stoi(config.substr(pos + 1));

    auto protocolHandler = std::make_shared<ProtocolHandler>();

    m_udpHandle->on<ErrorEvent>(
        [](const ErrorEvent & event, UDPHandle & udpHandle)
        {
            LOG(ERROR) << "UDP Server (" << udpHandle.sock().ip.c_str() << ":" << udpHandle.sock().port
                       << ") error: code=" << event.code() << "; name=" << event.name() << "; message=" << event.what()
                       << endl;
        });

    m_udpHandle->on<UDPDataEvent>(
        [this, protocolHandler](const UDPDataEvent & event, UDPHandle & udpHandle)
        {
            auto client = udpHandle.loop().resource<UDPHandle>();

            client->on<ErrorEvent>(
                [](const ErrorEvent & event, UDPHandle & client)
                {
                    LOG(ERROR) << "UDP Client (" << client.peer().ip.c_str() << ":" << client.peer().port
                               << ") error: code=" << event.code() << "; name=" << event.name()
                               << "; message=" << event.what() << endl;
                });

            try
            {
                const auto result = protocolHandler->process(event.data.get(), event.length);

                if (result)
                {
                    const auto events = result.value().data();

                    while (!this->m_out.try_enqueue_bulk(events, result.value().size()))
                        ;
                }
                else
                {
                    LOG(ERROR) << "UDP DataEvent: Error processing data" << endl;
                }
            }
            catch (const std::exception & e)
            {
                LOG(ERROR) << e.what() << '\n';
            }
        });
}

void UDPEndpoint::run(void)
{
    m_udpHandle->bind(m_ip, m_port);
    m_udpHandle->recv();
    m_loop->run<Loop::Mode::DEFAULT>();
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
    close();
}

} // namespace engineserver::endpoints
