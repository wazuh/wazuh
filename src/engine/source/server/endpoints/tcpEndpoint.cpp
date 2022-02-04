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

TCPEndpoint::TCPEndpoint(const std::string & config) : BaseEndpoint{config}
{
    auto pos = config.find(":");
    this->m_ip = config.substr(0, pos);
    this->m_port = stoi(config.substr(pos + 1));
    this->m_out = rxcpp::observable<>::create<BaseEndpoint::observable_t>(
        [ip = this->m_ip, port = this->m_port](BaseEndpoint::subscriber_t s)
        {
            auto loop = uvw::Loop::getDefault();
            auto handle = loop->resource<uvw::TCPHandle>();

            handle->on<uvw::ErrorEvent>(
                [](const uvw::ErrorEvent & event, uvw::TCPHandle & tcp)
                {
                    std::cerr << "TCP Server (" << tcp.sock().ip.c_str() << ":" << tcp.sock().port
                              << ") error: code=" << event.code() << "; name=" << event.name()
                              << "; message=" << event.what() << std::endl;
                });

            handle->on<uvw::ListenEvent>(
                [s, ip, port](const uvw::ListenEvent &, uvw::TCPHandle & srv)
                {
                    s.on_next(rxcpp::observable<>::create<BaseEndpoint::event_t>(
                        [ip, port, &srv](rxcpp::subscriber<BaseEndpoint::event_t> sInner)
                        {
                            auto client = srv.loop().resource<uvw::TCPHandle>();

                            client->on<uvw::ErrorEvent>(
                                [sInner](const uvw::ErrorEvent & event, uvw::TCPHandle & client)
                                {
                                    std::cerr << "TCP Client (" << client.peer().ip.c_str() << ":" << client.peer().port
                                              << ") error: code=" << event.code() << "; name=" << event.name()
                                              << "; message=" << event.what() << std::endl;
                                    auto e = std::runtime_error("Connection error from " + client.peer().ip +
                                                                " due to " + event.what());
                                    sInner.on_error(std::make_exception_ptr(e));
                                });

                            client->on<uvw::DataEvent>(
                                [sInner, &srv](const uvw::DataEvent & event, uvw::TCPHandle & client)
                                {
                                    json::Document evt;
                                    try
                                    {
                                        evt = engineserver::protocolhandler::parseEvent(
                                            std::string(event.data.get(), event.length));
                                    }
                                    catch (std::_Nested_exception<std::invalid_argument> & e)
                                    {
                                        client.close();
                                        sInner.on_error(std::make_exception_ptr(e));
                                    }
                                    sInner.on_next(evt);
                                });

                            client->on<uvw::EndEvent>(
                                [sInner](const uvw::EndEvent &, uvw::TCPHandle & client)
                                {
                                    sInner.on_completed();
                                    client.close();
                                });

                            srv.accept(*client);
                            client->read();
                        }));
                });

            handle->bind(ip, port);
            handle->listen();
            loop->run();
        });
}

void TCPEndpoint::run(void)
{
}

void TCPEndpoint::close(void)
{
    // m_loop->stop();                                                 /// Stops the loop
    // m_loop->walk([](uvw::BaseHandle & handle) { handle.close(); }); /// Triggers every handle's close callback
    // m_loop->run(); /// Runs the loop again, so every handle is able to receive its close callback
    // m_loop->clear();
    // m_loop->close();
}

TCPEndpoint::~TCPEndpoint()
{
    // this->close();
}

} // namespace engineserver::endpoints
