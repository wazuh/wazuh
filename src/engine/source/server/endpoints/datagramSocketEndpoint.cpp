/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "datagramSocketEndpoint.hpp"

using std::endl;
using std::string;

using uvw::ErrorEvent;
using uvw::Loop;
using uvw::UDPDataEvent;
using uvw::UDPHandle;

namespace engineserver::endpoints
{

DatagramSocketEndpoint::DatagramSocketEndpoint(const string & config, ServerOutput & eventBuffer)
    : BaseEndpoint{config, eventBuffer}, m_socketPath{config}, m_loop{Loop::getDefault()},
      m_datagramSocketHandle{m_loop->resource<DatagramSocketHandle>()}
{
    auto protocolHandler = std::make_shared<ProtocolHandler>();

    m_datagramSocketHandle->on<ErrorEvent>(
        [](const ErrorEvent & event, DatagramSocketHandle & datagramSocketHandle)
        {
            LOG(ERROR) << "Datagram Socket Server (" << datagramSocketHandle.sock().ip.c_str() << ":"
                      << datagramSocketHandle.sock().port << ") error: code=" << event.code()
                      << "; name=" << event.name() << "; message=" << event.what() << endl;
        });

    m_datagramSocketHandle->on<DatagramSocketEvent>(
        [this, protocolHandler](const DatagramSocketEvent & event, DatagramSocketHandle & datagramSocketHandle)
        {
            auto client = datagramSocketHandle.loop().resource<DatagramSocketHandle>();

            client->on<ErrorEvent>(
                [](const ErrorEvent & event, DatagramSocketHandle & client)
                {
                    LOG(ERROR) << "Datagram Socket Client (" << client.peer().ip.c_str() << ":" << client.peer().port
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
                    LOG(ERROR) << "Datagram Socket DataEvent: Error processing data" << endl;
                }
            }
            catch (const std::exception & e)
            {
                LOG(ERROR) << e.what() << '\n';
            }
        });
}

void DatagramSocketEndpoint::run(void)
{
    m_datagramSocketHandle->bind(m_socketPath); // Replace by open
    m_datagramSocketHandle->recv();
    m_loop->run<Loop::Mode::DEFAULT>();
}

void DatagramSocketEndpoint::close(void)
{
    m_loop->stop();                                                 /// Stops the loop
    m_loop->walk([](uvw::BaseHandle & handle) { handle.close(); }); /// Triggers every handle's close callback
    m_loop->run(); /// Runs the loop again, so every handle is able to receive its close callback
    m_loop->clear();
    m_loop->close();
}

DatagramSocketEndpoint::~DatagramSocketEndpoint()
{
    close();
}

} // namespace engineserver::endpoints
