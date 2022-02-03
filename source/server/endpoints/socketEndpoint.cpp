/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "socketEndpoint.hpp"

namespace engineserver::endpoints
{

SocketEndpoint::SocketEndpoint(const std::string & config) : BaseEndpoint{config}
{
    std::string path = config;
    this->m_out = rxcpp::observable<>::create<BaseEndpoint::observable_t>(
        [=](BaseEndpoint::subscriber_t s)
        {
            s.on_next(rxcpp::observable<>::create<BaseEndpoint::event_t>(
                [path](rxcpp::subscriber<BaseEndpoint::event_t> sInner)
                {
                    auto loop = uvw::Loop::getDefault();
                    auto handle = loop->resource<uvw::PipeHandle>();

                    handle->on<uvw::ErrorEvent>(
                        [](const uvw::ErrorEvent & event, uvw::PipeHandle & socket)
                        {
                            std::cerr << "FIFO Server (" << socket.sock().c_str() << ") error: code=" << event.code()
                                      << "; name=" << event.name() << "; message=" << event.what() << std::endl;
                        });

                    handle->on<uvw::ListenEvent>(
                        [sInner](const uvw::ListenEvent &, uvw::PipeHandle & handle)
                        {
                            auto client = handle.loop().resource<uvw::PipeHandle>();

                            client->on<uvw::ErrorEvent>(
                                [](const uvw::ErrorEvent & event, uvw::PipeHandle & socket)
                                {
                                    std::cerr << "FIFO Client (" << socket.peer().c_str()
                                              << ") error: code=" << event.code() << "; name=" << event.name()
                                              << "; message=" << event.what() << std::endl;
                                });

                            client->on<uvw::DataEvent>(
                                [sInner](const uvw::DataEvent & event, uvw::PipeHandle & client)
                                {
                                    auto eventObject = engineserver::protocolhandler::parseEvent(
                                        std::string(event.data.get(), event.length));
                                    if (!eventObject.contains("error"))
                                    {
                                        sInner.on_next(eventObject);
                                    }
                                    else
                                    {
                                        // TODO: complete this case
                                    }
                                });

                            client->on<uvw::CloseEvent>([&handle](const uvw::CloseEvent &, uvw::PipeHandle &)
                                                        { handle.close(); });

                            handle.accept(*client);
                            client->read();
                        });

                    {
                        struct stat buffer;
                        if (stat(path.c_str(), &buffer) == 0)
                        {
                            remove(path.c_str());
                        }
                    }

                    handle->bind(path);
                    handle->listen();
                    loop->run();
                }));
        });
}

void SocketEndpoint::run(void)
{
}

void SocketEndpoint::close(void)
{
}

SocketEndpoint::~SocketEndpoint()
{
}

} // namespace engineserver::endpoints
