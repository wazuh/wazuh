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
#ifndef _SOCKET_WRAPPER_HPP
#define _SOCKET_WRAPPER_HPP

#include "builder.hpp"
#include "osPrimitives.hpp"
#include "packet.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

constexpr auto INVALID_SOCKET {-1};
constexpr auto SOCKET_ERROR {-1};
constexpr ssize_t PACKET_SIZE {sizeof(uint32_t)};
constexpr ssize_t HEADER_SIZE {sizeof(uint32_t)};
constexpr auto BUFFER_SIZE {8192 * 8};

enum class SocketType
{
    UNIX,
    TCP
};

// Union for unix and tcp sockets.
struct SocketAddress
{
    SocketType type;
    sockaddr* addr;
    size_t addrSize;
};

template<typename T>
class SockAddress : public Utils::Builder<T>
{
protected:
    SocketAddress m_addr {};

public:
    SockAddress() = default;
    // LCOV_EXCL_START
    virtual ~SockAddress() = default;
    // LCOV_EXCL_STOP
    SocketAddress& data()
    {
        return m_addr;
    }
};

class UnixAddress final : public SockAddress<UnixAddress>
{
private:
    sockaddr_un m_unixAddr {};

public:
    UnixAddress()
    {
        m_unixAddr.sun_family = AF_UNIX;
        m_addr.addr = reinterpret_cast<sockaddr*>(&m_unixAddr);
        m_addr.addrSize = sizeof(m_unixAddr);
    }
    UnixAddress& address(const std::string& path)
    {
        m_unixAddr.sun_family = AF_UNIX;
        std::copy(path.begin(), path.end(), m_unixAddr.sun_path);
        return *this;
    }
};

class TcpAddress final : public SockAddress<TcpAddress>
{
private:
    sockaddr_in m_tcpAddr {};

public:
    TcpAddress()
    {
        m_tcpAddr.sin_family = AF_INET;
        m_addr.addr = reinterpret_cast<sockaddr*>(&m_tcpAddr);
        m_addr.addrSize = sizeof(m_tcpAddr);
    }
    TcpAddress& address(const std::string& ip)
    {
        inet_pton(AF_INET, ip.data(), &m_tcpAddr.sin_addr);
        return *this;
    }

    TcpAddress& port(const uint16_t port)
    {
        m_tcpAddr.sin_port = htons(port);
        return *this;
    }
};

enum class SocketStatus
{
    HEADER,
    BODY
};

enum SocketError
{
    ERROR_SUCCESS = 0,
    ERROR_BUFFER_SOCKET_FULL = -1,
    ERROR_INVALID_SOCKET = -2,
    ERROR_SENDING_DATA = -3,
    ERROR_NEED_MORE_DATA = -4,
    ERROR_SHUTDOWN_SOCKET = -5,
    ERROR_READ_ONLY_HEADER = -6,
};

template<typename T>
class Socket final : public T
{
private:
    int m_sock;
    SocketStatus m_status;
    uint32_t m_readPosition;
    uint32_t m_readSize;
    uint32_t m_totalReadSize;
    std::vector<char> m_recvDataBuffer {};
    std::vector<char> m_sendDataBuffer {};
    std::queue<Packet> m_unsentPacketList {};
    std::mutex m_mutex;

public:
    explicit Socket(const int sock = INVALID_SOCKET)
        : m_sock {sock}
        , m_status {SocketStatus::HEADER}
        , m_readPosition {0}
        , m_readSize {PACKET_SIZE}
        , m_totalReadSize {0}
        , m_recvDataBuffer {}
        , m_sendDataBuffer {}
        , m_unsentPacketList {}
    {
        m_recvDataBuffer.resize(BUFFER_SIZE);
        m_sendDataBuffer.resize(BUFFER_SIZE);
    }

    virtual ~Socket()
    {
        closeSocket();
    }

    int& fileDescriptor()
    {
        return m_sock;
    }

    size_t recvBufferSize()
    {
        return m_recvDataBuffer.size();
    }

    size_t sendBufferSize()
    {
        return m_sendDataBuffer.size();
    }

    bool hasUnsentMessages()
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        return !m_unsentPacketList.empty();
    }

    void connect(const SocketAddress& connInfo)
    {
        // Close socket if it was already initialized.
        if (m_sock != INVALID_SOCKET)
        {
            T::close(m_sock);
        }

        // Create socket.
        m_sock = T::socket(connInfo.type == SocketType::UNIX ? AF_UNIX : AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (m_sock != INVALID_SOCKET)
        {
            if (T::connect(m_sock, connInfo.addr, connInfo.addrSize) < 0)
            {
                // Check if connection have some error.
                if (errno != EINPROGRESS && errno != EAGAIN)
                {
                    throw std::runtime_error {std::string("Error connecting to socket: ") + strerror(errno)};
                }
            }

            constexpr uint32_t UI_OPT {BUFFER_SIZE};
            T::setsockopt(m_sock, SOL_SOCKET, SO_RCVBUFFORCE, (const char*)&UI_OPT, sizeof(UI_OPT));
            T::setsockopt(m_sock, SOL_SOCKET, SO_SNDBUFFORCE, (const char*)&UI_OPT, sizeof(UI_OPT));
        }
        else
        {
            throw std::runtime_error {"Error creating socket."};
        }
    }

    void read(const std::function<void(const int, const char*, uint32_t, const char*, uint32_t)>& callback)
    {
        uint32_t* uip;
        ssize_t ret;
        bool dataToRead = true;

        if (m_sock != INVALID_SOCKET)
        {
            while (dataToRead)
            {
                // First read the header.
                if (SocketStatus::HEADER == m_status)
                {
                    ret = T::recv(m_sock, (char*)(m_recvDataBuffer.data() + m_readPosition), m_readSize, 0);

                    if (ret == SOCKET_ERROR)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                        {
                            // No more data to read.
                            dataToRead = false;
                        }
                        else
                        {
                            // Error reading from socket.
                            throw std::runtime_error {"Error reading from socket."};
                        }
                    }
                    else if (ret == 0)
                    {
                        // Remote shutdown / disconnect.
                        throw std::runtime_error {"Remote shutdown / disconnect."};
                    }
                    else
                    {
                        // Check if we have read the entire header.
                        if (ret != m_readSize)
                        {
                            // In this case we need to read more data, when the next read is called.
                            m_readPosition += ret;
                            m_readSize -= ret;
                        }
                        else
                        {
                            uip = (uint32_t*)m_recvDataBuffer.data();
                            m_totalReadSize = *uip;

                            if (m_totalReadSize > BUFFER_SIZE)
                            {
                                m_recvDataBuffer.resize(m_totalReadSize + 1);
                            }

                            // We have read the entire header, now we need to read the body.
                            m_readPosition = 0;
                            m_readSize = m_totalReadSize;
                            m_status = SocketStatus::BODY;
                        }
                    }
                }

                if (SocketStatus::BODY == m_status)
                {
                    ret = T::recv(m_sock, (char*)(m_recvDataBuffer.data() + m_readPosition), m_readSize, 0);

                    if (ret == SOCKET_ERROR)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                        {
                            // No more data to read.
                            dataToRead = false;
                        }
                        else
                        {
                            // Error reading from socket.
                            throw std::runtime_error {"Error reading from socket."};
                        }
                    }
                    else if (ret == 0)
                    {
                        // Remote shutdown / disconnect.
                        throw std::runtime_error {"Remote shutdown / disconnect."};
                    }
                    else
                    {
                        if (m_readSize != ret)
                        {
                            m_readSize -= ret;
                            m_readPosition += ret;
                        }
                        else
                        {
                            m_readPosition = 0;
                            m_readSize = PACKET_SIZE;
                            m_status = SocketStatus::HEADER;

                            auto headerDataSize = *reinterpret_cast<const uint32_t*>(m_recvDataBuffer.data());
                            auto offset = HEADER_SIZE + headerDataSize;

                            callback(m_sock,
                                     m_recvDataBuffer.data() + offset,
                                     m_totalReadSize - offset,
                                     m_recvDataBuffer.data() + HEADER_SIZE,
                                     headerDataSize);

                            if (m_totalReadSize > BUFFER_SIZE)
                            {
                                m_recvDataBuffer.resize(BUFFER_SIZE);
                            }
                        }
                    }
                }
            }
        }
        else
        {
            throw std::runtime_error {"Invalid socket"};
        }
    }

    int accept()
    {
        sockaddr addr {};
        socklen_t socketLength = sizeof(addr);

        auto sock = T::accept(m_sock, (struct sockaddr*)&addr, &socketLength);
        if (sock == INVALID_SOCKET)
        {
            throw std::runtime_error {"Failed to accept socket" + std::to_string(errno)};
        }

        const uint32_t uiOpt {BUFFER_SIZE};
        T::setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, (const char*)&uiOpt, sizeof(uiOpt));
        T::setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, (const char*)&uiOpt, sizeof(uiOpt));

        // Set socket to non-blocking.
        int flags = T::fcntl(sock, F_GETFL, 0);
        if (flags == -1)
        {
            throw std::runtime_error {"Failed to get socket flags"};
        }

        flags |= O_NONBLOCK;
        if (T::fcntl(sock, F_SETFL, flags) == -1)
        {
            throw std::runtime_error {"Failed to set socket flags"};
        }

        return sock;
    }

    void sendUnsentMessages()
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        while (!m_unsentPacketList.empty())
        {
            auto& packet = m_unsentPacketList.front();
            auto ret = T::send(m_sock, packet.data.get() + packet.offset, packet.size - packet.offset, MSG_NOSIGNAL);
            if (ret <= 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    throw std::runtime_error {"Waiting for socket to be ready"};
                }
                else
                {
                    throw std::system_error {errno, std::system_category(), "Error sending data to socket"};
                }
            }
            else
            {
                if (ret != packet.size)
                {
                    // In this case we need to send the rest of the data, when the next send is called.
                    packet.offset += ret;
                }
                else
                {
                    // We have sent the entire packet, remove it from the queue.
                    m_unsentPacketList.pop();
                }
            }
        }
    }

    void send(const char* dataBody, uint32_t sizeBody, const char* dataHeader = nullptr, uint32_t sizeHeader = 0)
    {
        uint32_t* uip;
        ssize_t amountSent {0};
        std::lock_guard<std::mutex> lock {m_mutex};

        if (PACKET_SIZE + HEADER_SIZE + sizeHeader + sizeBody > BUFFER_SIZE)
        {
            m_sendDataBuffer.resize(PACKET_SIZE + HEADER_SIZE + sizeHeader + sizeBody + 1);
        }

        // Add size to the header of the buffer.
        uip = (uint32_t*)m_sendDataBuffer.data();
        *uip = sizeBody + HEADER_SIZE + sizeHeader;

        // Add size to the header of the buffer.
        uip = (uint32_t*)(m_sendDataBuffer.data() + PACKET_SIZE);
        *uip = sizeHeader;

        if (sizeHeader > 0)
        {
            // Copy to vector using iterators.
            std::copy(dataHeader, dataHeader + sizeHeader, std::begin(m_sendDataBuffer) + PACKET_SIZE + HEADER_SIZE);
        }

        // Copy to vector using iterators.
        std::copy(dataBody, dataBody + sizeBody, std::begin(m_sendDataBuffer) + PACKET_SIZE + HEADER_SIZE + sizeHeader);

        // Add the header size to the total size.
        sizeBody += PACKET_SIZE + HEADER_SIZE + sizeHeader;
        // If there is data in the unsent queue, add it to the queue.
        if (!m_unsentPacketList.empty())
        {
            m_unsentPacketList.emplace(m_sendDataBuffer.data(), sizeBody);
        }
        else
        {
            // Send the data.
            while (sizeBody != amountSent)
            {
                const auto ret =
                    T::send(m_sock, m_sendDataBuffer.data() + amountSent, sizeBody - amountSent, MSG_NOSIGNAL);

                if (ret <= 0)
                {
                    m_unsentPacketList.emplace(m_sendDataBuffer.data() + amountSent, sizeBody - amountSent);
                    throw std::runtime_error {"Error sending data to socket: " + std::to_string(errno) + " " +
                                              std::string(strerror(errno))};
                }
                else
                {
                    amountSent += ret;
                }
            }
        }
    }

    void listen(const SocketAddress& connectInfo)
    {
        if (m_sock != INVALID_SOCKET)
        {
            throw std::runtime_error {"Socket already initialized"};
        }

        const auto connectType = connectInfo.type == SocketType::UNIX ? AF_UNIX : AF_INET;
        m_sock = T::socket(connectType, SOCK_STREAM | SOCK_NONBLOCK, 0);

        if (m_sock != INVALID_SOCKET)
        {
            int reuse = 1;
            if (T::setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
            {
                closeSocket();
                throw std::runtime_error {"Failed to set socket options"};
            }

            if (connectInfo.type == SocketType::UNIX)
            {
                // If the parent directory not exists. Create it.
                auto sunAddr = reinterpret_cast<const sockaddr_un*>(connectInfo.addr);

                std::filesystem::path path {sunAddr->sun_path};
                // if not exists create it.
                if (!std::filesystem::exists(path.parent_path()))
                {
                    std::filesystem::create_directories(path.parent_path());
                }
            }

            if (T::bind(m_sock, connectInfo.addr, connectInfo.addrSize) == 0 && T::listen(m_sock, SOMAXCONN) == 0)
            {
                const uint32_t uiOpt {BUFFER_SIZE};
                T::setsockopt(m_sock, SOL_SOCKET, SO_RCVBUFFORCE, (const char*)&uiOpt, sizeof(uiOpt));
                T::setsockopt(m_sock, SOL_SOCKET, SO_SNDBUFFORCE, (const char*)&uiOpt, sizeof(uiOpt));
            }
            else
            {
                closeSocket();
                throw std::runtime_error {"Failed to bind/listen socket " + std::to_string(errno)};
            }
        }
        else
        {
            throw std::runtime_error {"Failed to create socket"};
        }
    }

    void closeSocket() noexcept
    {
        if (m_sock != INVALID_SOCKET)
        {
            if (-1 == T::shutdown(m_sock, SHUT_WR))
            {
                std::cerr << "Shutdown error: " << errno << std::endl;
            }
            T::close(m_sock);
            m_sock = INVALID_SOCKET;
        }
    }
};

#endif // _SOCKET_WRAPPER_HPP
