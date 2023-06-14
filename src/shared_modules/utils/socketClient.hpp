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
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <shared_mutex>
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
    std::shared_mutex m_socketMutex;

    void sendPendingMessages()
    {
        try
        {
            std::lock_guard<std::shared_mutex> lock(m_socketMutex);
            m_socket->sendUnsentMessages();
            m_epoll->modifyDescriptor(m_socket->fileDescriptor(), EPOLLIN);
        }
        catch (const std::exception& e)
        {
            std::cerr << "Failed to send pending messages: " << e.what() << std::endl;
        }
    }

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
        handleConnect();
        m_mainLoopThread = std::thread(
            [&, onRead]()
            {
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
                                        handleConnect();
                                    }

                                    if (event & EPOLLOUT)
                                    {
                                        sendPendingMessages();
                                    }

                                    if (event & EPOLLIN)
                                    {
                                        std::lock_guard<std::shared_mutex> lock(m_socketMutex);
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

    void handleConnect()
    {
        // Build the address.
        auto unixAddress {UnixAddress::builder().address(m_socketPath).build()};
        constexpr auto MAX_DELAY = 30;
        auto delay = 1;

        while (!m_shouldStop)
        {
            try
            {
                std::lock_guard<std::shared_mutex> lock(m_socketMutex);
                m_socket->connect(unixAddress.data());
                m_epoll->addDescriptor(m_socket->fileDescriptor(), EPOLLIN | EPOLLOUT);
                break;
            }
            catch (const std::exception& e)
            {
                std::cerr << "Failed to connect to socket: " << e.what() << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(delay));
                delay = std::min(delay * 2, MAX_DELAY);
            }
        }
    }

    void send(const char* dataBody, size_t sizeBody, const char* dataHeader = nullptr, size_t sizeHeader = 0)
    {
        std::shared_lock<std::shared_mutex> lock(m_socketMutex);
        try
        {
            m_socket->send(dataBody, sizeBody, dataHeader, sizeHeader);
        }
        catch (const std::exception& e)
        {
            std::cerr << "Failed to send message: " << e.what() << std::endl;
            m_epoll->modifyDescriptor(m_socket->fileDescriptor(), EPOLLIN | EPOLLOUT);
        }
    }
};

#endif //_SOCKET_CLIENT_HPP
