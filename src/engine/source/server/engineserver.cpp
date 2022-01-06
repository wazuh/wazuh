/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/


#include "engineserver.hpp"


using namespace engineserver;


void EngineServer::listenTCP(const int port, const std::string ip)
{
    auto tcp = m_loop->resource<uvw::TCPHandle>();

    tcp->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &event, uvw::TCPHandle &tcp) {
        printf("TCP Server (%s:%d) error: code=%d; name=%s; message=%s\n",
                                                        tcp.sock().ip.c_str(),
                                                        tcp.sock().port,
                                                        event.code(),
                                                        event.name(),
                                                        event.what());
    });

    tcp->on<uvw::ListenEvent>([this](const uvw::ListenEvent &, uvw::TCPHandle &srv) {

        auto client = srv.loop().resource<uvw::TCPHandle>();

        client->on<uvw::DataEvent>([this, &srv](const uvw::DataEvent &event, uvw::TCPHandle &client) {
            // std::string printStr(event.data.get(), event.length);
            // printf("Listen %d: %s", client.sock().port, printStr.c_str());
            // this->m_eventQueue.push(std::string(event.data.get(), event.length));

            auto obs = this->getEndpointSubject(EndpointType::TCP, client.sock().port, srv.sock().ip);
            if(obs) obs.value().get_subscriber().on_next(std::string(event.data.get(), event.length));
        });

        client->on<uvw::EndEvent>([](const uvw::EndEvent &, uvw::TCPHandle &client) {
            client.close();
        });

        client->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &event, uvw::TCPHandle &client) {
            printf("TCP Client (%s:%d) error: code=%d; name=%s; message=%s\n",
                                                    client.peer().ip.c_str(),
                                                    client.peer().port,
                                                    event.code(),
                                                    event.name(),
                                                    event.what());
        });

        srv.accept(*client);
        client->read();
    });

    tcp->bind(ip, port);
    tcp->listen();

    m_endpointList.push_back(ServerEndpoint(EndpointType::TCP, std::string()+ip+":"+std::to_string(port), tcp));
}


void EngineServer::listenUDP(const int port, const std::string ip)
{
    auto udp = m_loop->resource<uvw::UDPHandle>();

    udp->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &event, uvw::UDPHandle &udp) {
        printf("UDP Server (%s:%d) error: code=%d; name=%s; message=%s\n",
                                                        udp.sock().ip.c_str(),
                                                        udp.sock().port,
                                                        event.code(),
                                                        event.name(),
                                                        event.what());
    });

    udp->on<uvw::UDPDataEvent>([this](const uvw::UDPDataEvent &event, uvw::UDPHandle &udp) {
        auto client = udp.loop().resource<uvw::TCPHandle>();

        client->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &event, uvw::TCPHandle &client) {
            printf("UDP Client (%s:%d) error: code=%d; name=%s; message=%s\n",
                                                        client.peer().ip.c_str(),
                                                        client.peer().port,
                                                        event.code(),
                                                        event.name(),
                                                        event.what());
        });

        // std::string printStr(event.data.get(), event.length);
        // printf("Listen %d: %s", udp.sock().port, printStr.c_str());
        // this->m_eventQueue.push(std::string(event.data.get(), event.length));

        auto obs = this->getEndpointSubject(EndpointType::UDP, udp.sock().port, udp.sock().ip);
        if(obs) obs.value().get_subscriber().on_next(std::string(event.data.get(), event.length));
    });

    udp->bind(ip, port);
    udp->recv();

    m_endpointList.push_back(ServerEndpoint(EndpointType::UDP, std::string()+ip+":"+std::to_string(port), udp));
}


void EngineServer::listenSocket(const std::string path)
{
    auto socket = m_loop->resource<uvw::PipeHandle>();

    socket->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &event, uvw::PipeHandle &socket) {
        printf("FIFO Server (%s) error: code=%d; name=%s; message=%s\n",
                                                        socket.sock().c_str(),
                                                        event.code(),
                                                        event.name(),
                                                        event.what());
    });

    socket->on<uvw::ListenEvent>([this](const uvw::ListenEvent &, uvw::PipeHandle &handle) {

        auto client = handle.loop().resource<uvw::PipeHandle>();

        client->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &event, uvw::PipeHandle &socket) {
            printf("FIFO Client (%s) error: code=%d; name=%s; message=%s\n",
                                                        socket.peer().c_str(),
                                                        event.code(),
                                                        event.name(),
                                                        event.what());
        });

        client->on<uvw::CloseEvent>([&handle](const uvw::CloseEvent &, uvw::PipeHandle &) {
            handle.close();
        });

        client->on<uvw::DataEvent>([this](const uvw::DataEvent &event, uvw::PipeHandle &client) {
            auto obs = this->getEndpointSubject(EndpointType::SOCKET, client.sock());
            if(obs) obs.value().get_subscriber().on_next(std::string(event.data.get(), event.length));
        });

        handle.accept(*client);
        client->read();
    });

    {
        struct stat buffer;
        if (stat (path.c_str(), &buffer) == 0) {
            remove(path.c_str());
        }
    }

    socket->bind(path);
    socket->listen();

    m_endpointList.push_back(ServerEndpoint(EndpointType::SOCKET, path, socket));
}


void EngineServer::listenSignal(const int signum, void (*const signal_wrapper)(void *))
{
    auto signal = m_loop->resource<uvw::SignalHandle>();

    signal->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &event, uvw::SignalHandle &signal) {
        printf("Signal (%d) error: code=%d; name=%s; message=%s\n",
                    signal.signal(), event.code(), event.name(), event.what());
    });

    signal->on<uvw::SignalEvent>([signal_wrapper](const uvw::SignalEvent &event, uvw::SignalHandle &signal) {
        signal_wrapper(nullptr);
    });

    signal->start(signum);
}


void EngineServer::setTimer(const int timeout, const int repeat, void (*const callback)(void *))
{
    auto timer = m_loop->resource<uvw::TimerHandle>();

    timer->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &event, uvw::TimerHandle &timer) {
        printf("Timer error: code=%d; name=%s; message=%s\n", event.code(), event.name(), event.what());
    });

    timer->on<uvw::TimerEvent>([callback](const uvw::TimerEvent &event, uvw::TimerHandle &signal) {
        callback(nullptr);
    });

    timer->start(uvw::TimerHandle::Time{timeout}, uvw::TimerHandle::Time{repeat});
}


std::optional<rxcpp::subjects::subject<std::string>>
EngineServer::getEndpointSubject(const EndpointType type, const std::string path)
{
    std::list<ServerEndpoint>::iterator it;
    for (it = m_endpointList.begin(); it != m_endpointList.end(); ++it)
    {
        if (it->getType() != type) continue;
        if (it->getPath().compare(path)) continue;
        else return it->getSubject();
    }
    return {};
};


std::optional<rxcpp::subjects::subject<std::string>>
EngineServer::getEndpointSubject(const EndpointType type, const int port, const std::string ip)
{
    std::list<ServerEndpoint>::iterator it;

    auto path = std::string() + ip + ":" + std::to_string(port);

    for (it = m_endpointList.begin(); it != m_endpointList.end(); ++it)
    {
        if (it->getType() != type) continue;
        if (it->getPath().compare(path)) continue;
        else return it->getSubject();
    }
    return {};
};


std::optional<rxcpp::observable<std::string>>
EngineServer::getEndpointObservable(const EndpointType type, const std::string path)
{
    auto subj = getEndpointSubject(type, path);
    if(subj) return subj.value().get_observable();
    return {};
};

std::optional<rxcpp::observable<std::string>>
EngineServer::getEndpointObservable(const EndpointType type, const int port, const std::string ip)
{
    auto subj = getEndpointSubject(type, port, ip);
    if(subj) return subj.value().get_observable();
    return {};
};


void EngineServer::close(void)
{
    m_loop->walk([](uvw::BaseHandle &handle){ handle.close(); }); /// Closes all the handles
    m_loop->stop();
    m_loop->clear();
    m_loop->close();
}


EngineServer::EngineServer()
{
    m_loop = uvw::Loop::getDefault();
}


EngineServer::~EngineServer()
{
    m_loop->walk([](uvw::BaseHandle &handle){ handle.close(); }); /// Closes all the handles
    m_loop->stop();
    m_loop->clear();
    m_loop->close();
}
