/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "tcpEndpoint.hpp"

#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>

#include <logging/logging.hpp>
#include <uvw/timer.hpp>

#include "protocolHandler.hpp"

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

void TCPEndpoint::connectionHandler(TCPHandle& handle)
{
    auto client = handle.loop().resource<TCPHandle>();
    auto timer = client->loop().resource<TimerHandle>();

    auto protocolHandler = std::make_shared<ProtocolHandler>();

    timer->on<TimerEvent>(
        [client](const auto&, auto& handler)
        {
            WAZUH_LOG_INFO("TCP TimerEvent: Timeout for connection.");
            client->close();
            handler.close();
        });

    client->on<ErrorEvent>(
        [](const ErrorEvent& event, TCPHandle& client)
        {
            WAZUH_LOG_ERROR("TCP ErrorEvent: endpoint[{}:{}] error: code=[{}]; "
                            "name=[{}]; message=[{}]",
                            client.peer().ip,
                            client.peer().port,
                            event.code(),
                            event.name(),
                            event.what());
        });

    client->on<DataEvent>(
        [&, timer, protocolHandler](const DataEvent& event, TCPHandle& client)
        {
            // TODO: Are we moving the buffer? we should.
            timer->again();
            const auto result {protocolHandler->process(event.data.get(), event.length)};

            if (result)
            {
                const auto events {result.value().data()};
                while (!m_out.try_enqueue_bulk(events, result.value().size()))
                    ;
            }
            else
            {
                WAZUH_LOG_ERROR("TCP DataEvent: endpoint[{}] error: Data could "
                                "not be processed.",
                                m_path);
                timer->close();
                client.close();
            }
        });

    client->on<EndEvent>(
        [timer](const EndEvent&, TCPHandle& client)
        {
            WAZUH_LOG_INFO("TCP EndEvent: Terminating connection.");
            timer->close();
            client.close();
        });

    client->on<CloseEvent>([](const CloseEvent& event, TCPHandle& client)
                           { WAZUH_LOG_INFO("TCP CloseEvent: Connection closed."); });

    handle.accept(*client);
    WAZUH_LOG_INFO("TCP ListenEvent: Client accepted.");

    timer->start(TimerHandle::Time {CONNECTION_TIMEOUT_MSEC},
                 TimerHandle::Time {CONNECTION_TIMEOUT_MSEC});

    client->read();
}

TCPEndpoint::TCPEndpoint(const std::string& config, ServerOutput& eventBuffer)
    : BaseEndpoint {config, eventBuffer}
    , m_loop {Loop::getDefault()}
    , m_handle {m_loop->resource<TCPHandle>()}
{
    const auto pos {config.find(":")};
    m_ip = config.substr(0, pos);
    m_port = stoi(config.substr(pos + 1));

    m_handle->on<ErrorEvent>(
        [](const ErrorEvent& event, TCPHandle& handle)
        {
            WAZUH_LOG_ERROR("TCP ErrorEvent: endpoint[{}:{}] error: code=[{}]; "
                            "name=[{}]; message=[{}]",
                            handle.sock().ip,
                            handle.sock().port,
                            event.code(),
                            event.name(),
                            event.what());
        });

    m_handle->on<ListenEvent>(
        [this](const ListenEvent& event, TCPHandle& handle)
        {
            WAZUH_LOG_INFO("TCP ListenEvent: stablishing new connection.");
            connectionHandler(handle);
        });

    m_handle->on<CloseEvent>([](const CloseEvent& event, TCPHandle& handle)
                             { WAZUH_LOG_INFO("TCP CloseEvent."); });

    WAZUH_LOG_INFO("TCP endpoint configured: [{}]", config);
}

void TCPEndpoint::run()
{
    m_handle->bind(m_ip, m_port);
    m_handle->listen();
    m_loop->run<Loop::Mode::DEFAULT>();
}

void TCPEndpoint::close()
{
    m_loop->stop(); /// Stops the loop
    m_loop->walk([](uvw::BaseHandle& handle)
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
