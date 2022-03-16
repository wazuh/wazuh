/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "tcpEndpoint.hpp"

#include <logging/logging.hpp>

using uvw::CloseEvent;
using uvw::DataEvent;
using uvw::EndEvent;
using uvw::ErrorEvent;
using uvw::ListenEvent;
using uvw::Loop;
using uvw::TCPHandle;
using uvw::TimerEvent;
using uvw::TimerHandle;

namespace engineserver::endpoints
{

void TCPEndpoint::connectionHandler(TCPHandle & tcpHandle)
{
    auto client = tcpHandle.loop().resource<TCPHandle>();
    auto timer = client->loop().resource<TimerHandle>();

    auto protocolHandler = std::make_shared<ProtocolHandler>();

    timer->on<TimerEvent>(
        [client](const auto &, auto & handler)
        {
            WAZUH_LOG_INFO("TCP TimerEvent: Timeout for connection.");
            client->close();
            handler.close();
        });

    client->on<ErrorEvent>(
        [](const ErrorEvent & event, TCPHandle & client)
        {
            LOG(ERROR) << "TCP ErrorEvent: endpoint (" << client.sock().ip.c_str() << ":" << client.sock().port
                       << ") error: code=" << event.code() << "; name=" << event.name() << "; message=" << event.what()
                       << endl;
        });

    client->on<DataEvent>(
        [&, timer, protocolHandler](const DataEvent & event, TCPHandle & client)
        {
            // TODO: Are we moving the buffer? we should.
            timer->again();
            const auto result = protocolHandler->process(event.data.get(), event.length);
            if (result)
            {
                const auto events = result.value().data();
                while (!m_out.try_enqueue_bulk(events, result.value().size()))
                    ;
            }
            else
            {
                WAZUH_LOG_ERROR("TCP DataEvent: Error processing data.");
                timer->close();
                client.close();
            }
        });

    client->on<EndEvent>(
        [timer](const EndEvent &, TCPHandle & client)
        {
            WAZUH_LOG_INFO("TCP EndEvent: Terminating connection.");
            timer->close();
            client.close();
        });

    client->on<CloseEvent>([](const CloseEvent & event, TCPHandle & client)
        { WAZUH_LOG_INFO("TCP CloseEvent: Connection closed."); });

    tcpHandle.accept(*client);
    WAZUH_LOG_INFO("TCP ListenEvent: Client accepted.");

    timer->start(TimerHandle::Time{CONNECTION_TIMEOUT_MSEC}, TimerHandle::Time{CONNECTION_TIMEOUT_MSEC});

    client->read();
}

TCPEndpoint::TCPEndpoint(const string & config, ServerOutput & eventBuffer)
    : BaseEndpoint{config, eventBuffer}, m_loop{Loop::getDefault()}, m_tcpHandle{m_loop->resource<TCPHandle>()}
{
    const auto pos = config.find(":");
    m_ip = config.substr(0, pos);
    m_port = stoi(config.substr(pos + 1));

    m_tcpHandle->on<ErrorEvent>(
        [](const ErrorEvent & event, TCPHandle & tcpHandle)
        {
            LOG(ERROR) << "TCP ErrorEvent: endpoint(" << tcpHandle.sock().ip.c_str() << ":" << tcpHandle.sock().port
                       << ") error: code=" << event.code() << "; name=" << event.name() << "; message=" << event.what()
                       << endl;
        });

    m_tcpHandle->on<ListenEvent>(
        [this](const ListenEvent & event, TCPHandle & tcpHandle)
        {
            LOG(INFO) << "TCP ListenEvent: stablishing new connection" << endl;
            this->connectionHandler(tcpHandle);
        });

    m_tcpHandle->on<CloseEvent>([](const CloseEvent & event, TCPHandle & tcpHandle)
                                { LOG(INFO) << "TCP CloseEvent" << endl; });

    WAZUH_LOG_INFO("TCP endpoint configured: [{}]", config);
}

void TCPEndpoint::run()
{
    m_tcpHandle->bind(m_ip, m_port);
    m_tcpHandle->listen();
    m_loop->run<Loop::Mode::DEFAULT>();
}

void TCPEndpoint::close()
{
    m_loop->stop(); /// Stops the loop
    m_loop->walk(
        [](uvw::BaseHandle &handle)
        { handle.close(); }); /// Triggers every handle's close callback
    m_loop->run(); /// Runs the loop again, so every handle is able to receive
                   /// its close callback
    m_loop->clear();
    m_loop->close();
}

TCPEndpoint::~TCPEndpoint()
{
    close();
};

} // namespace engineserver::endpoints
