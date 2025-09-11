/*
 * Wazuh Utils - Singleton template
 * Copyright (C) 2015, Wazuh Inc.
 * Apr 03, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SOCKET_SERVER_HPP
#define _SOCKET_SERVER_HPP

#include "epollWrapper.hpp"
#include "osPrimitives.hpp"
#include "socketWrapper.hpp"
#include <atomic>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <sys/epoll.h>
#include <thread>
#include <unordered_map>

constexpr auto EVENTS_LIMIT = 1024;
constexpr auto EVENTS = 32;

template<typename TSocket = Socket<OSPrimitives>, typename TEpoll = EpollWrapper>
class SocketServer final
{
private:
    const std::string m_socketPath;
    std::atomic<bool> m_shouldStop {false};
    std::array<int, 2> m_stopFD = {-1, -1};
    std::unique_ptr<TEpoll> m_epoll {std::make_unique<TEpoll>()};
    std::unique_ptr<TSocket> m_listenSocket {std::make_unique<TSocket>()};
    std::unordered_map<int, std::shared_ptr<TSocket>> m_clients {};
    std::thread m_listenThread;
    std::mutex m_mutex;

    std::shared_ptr<TSocket> getClient(const int fd)
    {
        std::lock_guard lock {m_mutex};
        if (m_clients.find(fd) == m_clients.end())
        {
            return nullptr;
        }
        return m_clients.at(fd);
    }

    void removeClient(const int fd)
    {
        std::lock_guard lock {m_mutex};
        if (m_clients.find(fd) == m_clients.end())
        {
            return;
        }
        m_clients.erase(fd);
    }

    void addClient(const int fd, std::shared_ptr<TSocket> client)
    {
        std::lock_guard lock {m_mutex};
        m_clients[fd] = std::move(client);
    }

    void sendPendingMessages(std::shared_ptr<TSocket> client)
    {
        try
        {
            client->sendUnsentMessages();
            m_epoll->modifyDescriptor(client->fileDescriptor(), EPOLLIN);
        }
        catch (const std::exception&)
        {
            // Error sending pending messages
        }
    }

    void processRead(std::shared_ptr<TSocket> client,
                     const std::function<void(const int, const char*, uint32_t, const char*, uint32_t)>& onRead) const
    {
        try
        {
            client->read(onRead);
        }
        catch (const std::exception&)
        {
            // Error reading from client
        }
    }

    void processEvent(const uint32_t event,
                      const int eventFD,
                      const std::function<void(const int, const char*, uint32_t, const char*, uint32_t)>& onRead)
    {
        if (auto client {getClient(eventFD)}; client)
        {
            // If EPOLLOUT is set, then we can send data, so send pending messages.
            if (event & EPOLLOUT)
            {
                sendPendingMessages(client);
            }

            // If EPOLLIN is set, then we can read data, so process the read.
            if (event & EPOLLIN)
            {
                processRead(std::move(client), onRead);
            }

            // If EPOLLERR or EPOLLHUP is set, then remove the client(Close the connection). This removes is in the end
            // to process the max number of events.
            if (event & EPOLLERR || event & EPOLLHUP)
            {
                removeClient(eventFD);
            }
        }
    }

public:
    explicit SocketServer(std::string socketPath)
        : m_socketPath {std::move(socketPath)}
    {
        if (int result = pipe(m_stopFD.data()); result == -1)
        {
            throw std::system_error(errno, std::system_category(), "Failed to create stop pipe");
        }

        if (::fcntl(m_stopFD[0], F_SETFL, O_NONBLOCK) == -1)
        {
            throw std::system_error(errno, std::system_category(), "Failed to set stop pipe to non-blocking");
        }

        // Add pipe to stop epoll
        m_epoll->addDescriptor(m_stopFD[0], EPOLLIN | EPOLLET);
    }

    ~SocketServer()
    {
        stop();
        ::close(m_stopFD[0]);
        ::close(m_stopFD[1]);

        std::error_code ec;
        std::filesystem::remove_all(m_socketPath, ec);
        if (ec)
        {
            std::cerr << "Failed to remove socket file: " << ec.message() << std::endl;
        }
    }

    void stop()
    {
        m_shouldStop = true;

        char dummy = 'x';
        std::ignore = ::write(m_stopFD[1], &dummy, sizeof(dummy));

        if (m_listenThread.joinable())
        {
            m_listenThread.join();
        }
        m_epoll->deleteDescriptor(m_listenSocket->fileDescriptor());
        m_listenSocket->closeSocket();
    }

    void listen(const std::function<void(const int, const char*, uint32_t, const char*, uint32_t)>& onRead)
    {
        // Reset the stop flag
        m_shouldStop = false;

        // Remove any existing socket file
        std::filesystem::remove(m_socketPath);

        // Builder for the address.
        auto unixAddressBuilder {UnixAddress::builder()};
        // Instance server socket
        m_listenSocket->listen(unixAddressBuilder.address(m_socketPath).data());

        // Add server socket to epoll
        m_epoll->addDescriptor(m_listenSocket->fileDescriptor(), EPOLLIN);

        m_listenThread = std::thread(
            [this, onRead]()
            {
                std::vector<struct epoll_event> events(EVENTS);
                while (!m_shouldStop)
                {
                    // Wait for events
                    auto numFDsReady = m_epoll->wait(events.data(), events.size(), -1);

                    // Process events
                    for (int i = 0; i < numFDsReady; ++i)
                    {
                        auto eventFD {events.at(i).data.fd};
                        // If the event is on the server socket, then it's a new connection
                        if (eventFD == m_listenSocket->fileDescriptor())
                        {
                            try
                            {
                                const auto clientFD = m_listenSocket->accept();
                                addClient(clientFD, std::make_shared<TSocket>(clientFD));
                                m_epoll->addDescriptor(clientFD, EPOLLIN);
                            }
                            catch (const std::exception& e)
                            {
                                std::cerr << "Failed to initialize client socket: " << e.what() << std::endl;
                            }
                        }
                        else if (eventFD == m_stopFD[0])
                        {
                            // Drain the byte from the stop_fd and break out of the loop
                            char dummy;
                            std::ignore = ::read(m_stopFD[0], &dummy, sizeof(dummy));
                            break;
                        }
                        else
                        {
                            processEvent(events.at(i).events, eventFD, onRead);
                        }
                    }

                    // If we ran out of room in our events vector, double its size
                    if (numFDsReady == static_cast<int>(events.size()) && numFDsReady >= EVENTS_LIMIT)
                    {
                        events.resize(events.size() * 2);
                    }
                }
            });
    }

    void send(int fd, const char* dataBody, size_t sizeBody, const char* dataHeader = nullptr, size_t sizeHeader = 0)
    {
        if (auto client {getClient(fd)}; !client)
        {
            throw std::out_of_range("Client not found");
        }
        else
        {
            try
            {
                client->send(dataBody, sizeBody, dataHeader, sizeHeader);
            }
            catch (const std::exception&)
            {
                m_epoll->modifyDescriptor(fd, EPOLLIN | EPOLLOUT);
            }
        }
    }
};

#endif // _SOCKET_SERVER_HPP
