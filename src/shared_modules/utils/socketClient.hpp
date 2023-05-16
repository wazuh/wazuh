/*
 * Wazuh socket client
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SOCKET_CLIENT_HPP
#define _SOCKET_CLIENT_HPP

#include "epollWrapper.hpp"
#include "osPrimitives.hpp"
#include "socketWrapper.hpp"
#include <atomic>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <sys/epoll.h>
#include <thread>
#include <vector>

constexpr auto CLIENT_EPOLL_EVENTS = 32;

template<typename TSocket, typename TEpoll>
class SocketClient final
{
private:
    const std::string m_socketPath;
    std::thread m_mainLoopThread;
    std::shared_ptr<TEpoll> m_epoll;
    std::shared_ptr<TSocket> m_socket;
    std::atomic<bool> m_shouldStop;
    std::mutex m_mutex;
    int m_stopFD[2] = {-1, -1};

public:
    explicit SocketClient(std::string socketPath)
        : m_socketPath {std::move(socketPath)}
        , m_epoll {std::make_shared<TEpoll>()}
        , m_socket {std::make_shared<TSocket>()}
        , m_shouldStop {false}
    {
        int result = ::pipe(m_stopFD);
        if (result == -1)
        {
            throw std::runtime_error("Failed to create stop pipe");
        }
        ::fcntl(m_stopFD[0], F_SETFL, O_NONBLOCK);

        // Add pipe to stop epoll
        m_epoll->addDescriptor(m_stopFD[0], EPOLLIN | EPOLLET);
    }

    ~SocketClient()
    {
        stop();
        ::close(m_stopFD[0]);
        ::close(m_stopFD[1]);
    }

    void stop()
    {
        m_shouldStop = true;

        char dummy = 'x';
        std::ignore = ::write(m_stopFD[1], &dummy, sizeof(dummy));

        if (m_mainLoopThread.joinable())
        {
            m_mainLoopThread.join();
        }
    }

    int getSocketDescriptor() const
    {
        return m_socket->fileDescriptor();
    }

    void connect(const std::function<void(const char*, uint32_t, const char*, uint32_t)>& onRead)
    {
        // Build the address.
        auto unixAddress {UnixAddress::builder().address(m_socketPath).build()};

        // Connect to server.
        m_socket->connect(unixAddress.data());

        // Add socket to epoll.
        m_epoll->addDescriptor(m_socket->fileDescriptor(), EPOLLIN);

        m_mainLoopThread = std::thread(
            [&, onRead]()
            {
                // onRead("1234", 4);
                std::vector<struct epoll_event> events(CLIENT_EPOLL_EVENTS);
                while (!m_shouldStop)
                {
                    try
                    {
                        // Wait for events
                        auto numFDsReady = m_epoll->wait(events.data(), events.size(), -1);

                        for (int i = 0; i < numFDsReady; ++i)
                        {
                            auto eventFD {events.at(i).data.fd};
                            // If the event is on the server socket, then it's a new connection
                            if (eventFD == m_stopFD[0])
                            {
                                // Drain the byte from the stop_fd and break out of the loop
                                char dummy;
                                std::ignore = ::read(m_stopFD[0], &dummy, sizeof(dummy));
                                break;
                            }
                            else
                            {
                                auto event {events.at(i).events};
                                try
                                {
                                    if (event & EPOLLERR || event & EPOLLHUP)
                                    {
                                        throw std::runtime_error {"socket error or disconnection."};
                                    }

                                    if (event & EPOLLOUT)
                                    {
                                        if (m_socket->sendUnsentMessages() != ERROR_BUFFER_SOCKET_FULL)
                                        {
                                            std::cout << "Unsent messages sent, enable EPOLLIN" << std::endl;
                                            m_epoll->modifyDescriptor(m_socket->fileDescriptor(), EPOLLIN);
                                        }
                                    }

                                    if (event & EPOLLIN)
                                    {
                                        m_socket->read([&](const int,
                                                           const char* body,
                                                           uint32_t bodySize,
                                                           const char* header,
                                                           uint32_t headerSize)
                                                       { onRead(body, bodySize, header, headerSize); });
                                    }
                                }
                                catch (const std::exception& e)
                                {
                                    m_shouldStop = true;
                                    break;
                                }
                            }
                        }
                    }
                    catch (const std::exception& e)
                    {
                        std::cerr << "Error in epoll: " << e.what() << std::endl;
                        m_shouldStop = true;
                    }
                }
            });
    }

    void send(const char* dataBody, size_t sizeBody, const char* dataHeader = nullptr, size_t sizeHeader = 0)
    {
        if (m_socket->send(dataBody, sizeBody, dataHeader, sizeHeader) == ERROR_BUFFER_SOCKET_FULL)
        {
            m_epoll->modifyDescriptor(m_socket->fileDescriptor(), EPOLLIN | EPOLLOUT);
        }
    }
};

#endif //_SOCKET_CLIENT_HPP
