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
UDPEndpoint::UDPEndpoint(const std::string & config) : BaseEndpoint{config}
{
    auto pos = config.find(":");
    this->m_ip = config.substr(0, pos);
    this->m_port = stoi(config.substr(pos + 1));
    this->m_out = rxcpp::observable<>::create<BaseEndpoint::observable_t>(
        [ip = this->m_ip, port = this->m_port](BaseEndpoint::subscriber_t s)
        {
            s.on_next(rxcpp::observable<>::create<BaseEndpoint::event_t>(
                [ip, port](rxcpp::subscriber<BaseEndpoint::event_t> sInner)
                {
                    auto loop = uvw::Loop::getDefault();
                    auto handle = loop->resource<uvw::UDPHandle>();
                    handle->on<uvw::ErrorEvent>(
                        [](const uvw::ErrorEvent & event, uvw::UDPHandle & udp)
                        {
                            std::cerr << "UDP Server (" << udp.sock().ip.c_str() << ":" << udp.sock().port
                                      << ") error: code=" << event.code() << "; name=" << event.name()
                                      << "; message=" << event.what() << std::endl;
                        });

                    handle->on<uvw::UDPDataEvent>(
                        [=](const uvw::UDPDataEvent & event, uvw::UDPHandle & udp)
                        {
                            auto client = udp.loop().resource<uvw::UDPHandle>();

                            client->on<uvw::ErrorEvent>(
                                [](const uvw::ErrorEvent & event, uvw::UDPHandle & client)
                                {
                                    std::cerr << "UDP Client (" << client.peer().ip.c_str() << ":" << client.peer().port
                                              << ") error: code=" << event.code() << "; name=" << event.name()
                                              << "; message=" << event.what() << std::endl;
                                });

                            json::Document evt;
                            try
                            {
                                evt = engineserver::protocolhandler::parseEvent(
                                    std::string(event.data.get(), event.length));
                            }
                            catch (std::_Nested_exception<std::invalid_argument> & e)
                            {
                                sInner.on_error(std::make_exception_ptr(e));
                            }
                            sInner.on_next(evt);
                        });

                    handle->bind(ip, port);
                    handle->recv();
                    loop->run();
                }));
        });
}

void UDPEndpoint::run(void)
{
}

void UDPEndpoint::close(void)
{
}

UDPEndpoint::~UDPEndpoint()
{
}
} // namespace engineserver::endpoints
