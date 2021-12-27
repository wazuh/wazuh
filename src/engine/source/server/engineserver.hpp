/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#ifndef _ENGINESERVER_H_
#define _ENGINESERVER_H_

#include <queue>
#include <mutex>

#include "uvw/pipe.hpp"
#include "uvw/signal.hpp"
#include "uvw/tcp.hpp"
#include "uvw/timer.hpp"
#include "uvw/udp.hpp"

class EngineServer
{
private:
    std::shared_ptr<uvw::Loop>  m_loop;
    std::queue<std::string>     m_eventQueue;

    std::mutex                  queueMutex;

    void eventQueuePush(std::string event) {};
    std::string eventQueuePop(void) { return nullptr; };
    void eventQueueLock(void) {};
    void eventQueueUnlock(void) {};

public:
    EngineServer();
    ~EngineServer();

    void run(void)  { m_loop->run(); };
    void stop(void) { m_loop->stop(); };

    std::shared_ptr<uvw::TCPHandle>     listenTCP(const std::string ip, const int port);
    std::shared_ptr<uvw::TCPHandle>     listenTCP(const int port);

    std::shared_ptr<uvw::UDPHandle>     listenUDP(const std::string ip, const int port);
    std::shared_ptr<uvw::UDPHandle>     listenUDP(const int port);

    std::shared_ptr<uvw::PipeHandle>    listenSocket(const std::string path);

    std::shared_ptr<uvw::SignalHandle>  listenSignal(const int signum, void (*const signal_wrapper)(void *));

    std::shared_ptr<uvw::TimerHandle>   setTimer(const int timeout,
                                                 const int repeat,
                                                 void (*const callback)(void *));
};

#endif
