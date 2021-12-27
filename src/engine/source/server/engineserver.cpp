/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include "engineserver.hpp"


/**
 * @brief Opens a TCP socket and listens for the incoming events, which are then stored on the server queue
 *
 * @param port TCP socket interface Port
 * @return std::shared_ptr<uvw::TCPHandle>
 */
std::shared_ptr<uvw::TCPHandle> EngineServer::listenTCP(const int port) {

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

        client->on<uvw::DataEvent>([this](const uvw::DataEvent &event, uvw::TCPHandle &client) {
            std::string printStr(event.data.get(), event.length);
            printf("Listen %d: %s", client.sock().port, printStr.c_str());
            this->m_eventQueue.push(std::string(event.data.get(), event.length));
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

    tcp->bind("0.0.0.0", port);
    tcp->listen();

    return tcp;
}

/**
 * @brief Opens a TCP socket and listens for the incoming events, which are then stored on the server queue
 *
 * @param ip TCP socket interface IP
 * @param port TCP socket interface Port
 * @return std::shared_ptr<uvw::TCPHandle>
 */
std::shared_ptr<uvw::TCPHandle> EngineServer::listenTCP(const std::string ip, const int port) {

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

        client->on<uvw::DataEvent>([this](const uvw::DataEvent &event, uvw::TCPHandle &client) {
            std::string printStr(event.data.get(), event.length);
            printf("Listen %d: %s", client.sock().port, printStr.c_str());
            this->m_eventQueue.push(std::string(event.data.get(), event.length));
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

    return tcp;
}

/**
 * @brief Opens a UDP socket and listens for the incoming events, which are then stored on the server queue
 *
 * @param port UDP socket interface Port
 * @return std::shared_ptr<uvw::UDPHandle>
 */
std::shared_ptr<uvw::UDPHandle> EngineServer::listenUDP(const int port) {

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

        std::string printStr(event.data.get(), event.length);
        printf("Listen %d: %s", udp.sock().port, printStr.c_str());
        this->m_eventQueue.push(std::string(event.data.get(), event.length));
    });

    udp->bind("0.0.0.0", port);
    udp->recv();

    return udp;
}

/**
 * @brief Opens a UDP socket and listens for the incoming events, which are then stored on the server queue
 *
 * @param ip UDP socket interface IP
 * @param port UDP socket interface Port
 * @return std::shared_ptr<uvw::UDPHandle>
 */
std::shared_ptr<uvw::UDPHandle> EngineServer::listenUDP(const std::string ip, const int port) {

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

        std::string printStr(event.data.get(), event.length);
        printf("Listen %d: %s", udp.sock().port, printStr.c_str());
        this->m_eventQueue.push(std::string(event.data.get(), event.length));
    });

    udp->bind(ip, port);
    udp->recv();

    return udp;
}

/**
 * @brief Opens a UNIX socket and listens for the incoming events, which are then stored on the server queue
 *
 * @param path Absolute path to the UNIX socket
 * @return std::shared_ptr<uvw::PipeHandle>
 */
std::shared_ptr<uvw::PipeHandle> EngineServer::listenSocket(const std::string path) {

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
            std::string printStr(event.data.get(), event.length);
            printf("Listen %s: %s", client.sock().c_str(), printStr.c_str());
            this->m_eventQueue.push(std::string(event.data.get(), event.length));
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

    return socket;
}

/**
 * @brief Handles a signal given its signal number and a signal wrapping function
 *
 * @param signum Number of UNIX signal to be handled
 * @return std::shared_ptr<uvw::SignalHandle>
 */
std::shared_ptr<uvw::SignalHandle> EngineServer::listenSignal(const int signum, void (*const signal_wrapper)(void *)) {

    auto signal = m_loop->resource<uvw::SignalHandle>();

    signal->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &event, uvw::SignalHandle &signal) {
        printf("Signal (%d) error: code=%d; name=%s; message=%s\n",
                    signal.signal(), event.code(), event.name(), event.what());
    });

    signal->on<uvw::SignalEvent>([signal_wrapper](const uvw::SignalEvent &event, uvw::SignalHandle &signal) {
        signal_wrapper(nullptr);
    });

    signal->start(signum);

    return signal;
}

/**
 * @brief If timeout is zero, a TimerEvent event is emitted on the next event loop
 * iteration. If repeat is non-zero, a TimerEvent event is emitted first
 * after timeout milliseconds and then repeatedly after repeat milliseconds.
 *
 * @param timeout Milliseconds before to emit an event
 * @param repeat Milliseconds between successive events
 * @param callback Callback to be called when a TimerEvent happens
 * @return std::shared_ptr<uvw::TimerHandle>
 */
std::shared_ptr<uvw::TimerHandle>
EngineServer::setTimer(const int timeout, const int repeat, void (*const callback)(void *)) {
    auto timer = m_loop->resource<uvw::TimerHandle>();

    timer->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &event, uvw::TimerHandle &timer) {
        printf("Timer error: code=%d; name=%s; message=%s\n", event.code(), event.name(), event.what());
    });

    timer->on<uvw::TimerEvent>([callback](const uvw::TimerEvent &event, uvw::TimerHandle &signal) {
        callback(nullptr);
    });

    timer->start(uvw::TimerHandle::Time{timeout}, uvw::TimerHandle::Time{repeat});

    return timer;
}

/**
 * @brief Construct a new EngineServer object
 */
EngineServer::EngineServer()
{
    m_loop = uvw::Loop::getDefault();
}

/**
 * @brief Destroy the EngineServer object
 */
EngineServer::~EngineServer()
{
    m_loop->walk([](uvw::BaseHandle &handle){ handle.close(); }); /// Closes all the handles
    m_loop->stop();
    m_loop->clear();
    m_loop->close();

    // Just for testing
    printf("\n");
    while(!m_eventQueue.empty()) {
        printf("Event: %s", m_eventQueue.front().c_str());
        m_eventQueue.pop();
    }
}
