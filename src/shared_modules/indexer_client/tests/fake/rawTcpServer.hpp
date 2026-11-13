/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_TESTS_RAW_TCP_SERVER_HPP
#define _INDEXER_CLIENT_TESTS_RAW_TCP_SERVER_HPP

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace indexer_client::testing
{
    /**
     * @brief One socket a RawTcpServer accepted.
     */
    struct AcceptedConnection
    {
        /// Client port of the connection.
        int remotePort {0};
        std::chrono::steady_clock::time_point acceptedAt;
        /// When the server saw the peer close (EOF, reset or error); absent while the connection is open.
        std::optional<std::chrono::steady_clock::time_point> eofAt;
        /// Bytes the server read (and discarded) from this connection.
        std::uint64_t bytesRead {0};
    };

    /**
     * @brief Plain TCP listener on 127.0.0.1 (ephemeral port) that accepts and never writes a byte.
     *
     * One thread polls the listening socket and the accepted ones. In reading mode every readable byte is read and
     * discarded, so a peer close is seen at once and timestamped (AcceptedConnection::eofAt). In non-reading mode the
     * accepted sockets are not read until resumeReading(); only a reset or hang-up that needs no read is seen before.
     *
     * Use the concrete SilentServer or StalledUploadServer. Thread-safe; stop() (also the destructor) never hangs,
     * whatever the peers do.
     */
    class RawTcpServer
    {
    public:
        RawTcpServer(const RawTcpServer&) = delete;
        RawTcpServer& operator=(const RawTcpServer&) = delete;
        RawTcpServer(RawTcpServer&&) = delete;
        RawTcpServer& operator=(RawTcpServer&&) = delete;

        /// Bound port.
        int port() const
        {
            return m_port;
        }

        /// "http://127.0.0.1:<port>".
        std::string baseUrl() const
        {
            return "http://127.0.0.1:" + std::to_string(m_port);
        }

        /// SO_RCVBUF of the listening socket as the kernel reports it (Linux doubles the requested value).
        int receiveBufferBytes() const
        {
            int value {0};
            socklen_t length = sizeof(value);
            ::getsockopt(m_listen, SOL_SOCKET, SO_RCVBUF, &value, &length);
            return value;
        }

        /// Sockets accepted so far.
        std::size_t acceptedCount() const
        {
            std::lock_guard lock(m_mutex);
            return m_connections.size();
        }

        /// Snapshot of every accepted socket, in accept order.
        std::vector<AcceptedConnection> connections() const
        {
            std::lock_guard lock(m_mutex);
            std::vector<AcceptedConnection> result;
            result.reserve(m_connections.size());
            for (const auto& connection : m_connections)
            {
                result.push_back(connection.info);
            }
            return result;
        }

        /// Waits until at least @p count sockets have been accepted.
        bool waitForAccepted(std::size_t count, std::chrono::milliseconds timeout) const
        {
            std::unique_lock lock(m_mutex);
            return m_cv.wait_for(lock, timeout, [&] { return m_connections.size() >= count; });
        }

        /**
         * @brief Waits for the EOF of the @p index-th accepted socket.
         *
         * @return Its EOF time, or nothing if the socket does not exist or is still open after @p timeout.
         */
        std::optional<std::chrono::steady_clock::time_point> waitForEof(std::size_t index,
                                                                        std::chrono::milliseconds timeout) const
        {
            std::unique_lock lock(m_mutex);
            m_cv.wait_for(lock,
                          timeout,
                          [&] { return index < m_connections.size() && m_connections[index].info.eofAt.has_value(); });
            if (index >= m_connections.size())
            {
                return std::nullopt;
            }
            return m_connections[index].info.eofAt;
        }

        /// Stops the thread and closes every socket. Idempotent; never waits for a peer.
        void stop()
        {
            {
                std::lock_guard lock(m_mutex);
                if (m_stopped)
                {
                    return;
                }
                m_stopped = true;
            }
            wake();
            if (m_thread.joinable())
            {
                m_thread.join();
            }
            for (auto& connection : m_connections)
            {
                closeFd(connection.fd);
            }
            closeFd(m_listen);
            closeFd(m_wakeRead);
            closeFd(m_wakeWrite);
        }

    protected:
        /**
         * @param readData Read (and discard) incoming bytes from the start.
         * @param receiveBuffer SO_RCVBUF set on the listening socket before listen(), inherited by accepted sockets.
         */
        RawTcpServer(bool readData, std::optional<int> receiveBuffer)
            : m_reading(readData)
        {
            int pipeFds[2];
            if (::pipe2(pipeFds, O_CLOEXEC | O_NONBLOCK) != 0)
            {
                throw std::runtime_error("RawTcpServer: pipe2 failed");
            }
            m_wakeRead = pipeFds[0];
            m_wakeWrite = pipeFds[1];

            m_listen = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
            if (m_listen < 0)
            {
                cleanupAndThrow("socket failed");
            }
            const int one {1};
            ::setsockopt(m_listen, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            if (receiveBuffer.has_value())
            {
                const int bytes = *receiveBuffer;
                if (::setsockopt(m_listen, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes)) != 0)
                {
                    cleanupAndThrow("SO_RCVBUF failed");
                }
            }
            sockaddr_in address {};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            if (::bind(m_listen, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
                ::listen(m_listen, 128) != 0)
            {
                cleanupAndThrow("bind/listen failed");
            }
            socklen_t length = sizeof(address);
            ::getsockname(m_listen, reinterpret_cast<sockaddr*>(&address), &length);
            m_port = ntohs(address.sin_port);
            m_thread = std::thread([this] { run(); });
        }

        ~RawTcpServer()
        {
            stop();
        }

        /// Non-reading mode: from now on read and discard like the reading mode, so EOFs are seen.
        void startReading()
        {
            {
                std::lock_guard lock(m_mutex);
                m_reading = true;
            }
            wake();
        }

    private:
        struct Connection
        {
            int fd;
            AcceptedConnection info;
        };

        static void closeFd(int& fd)
        {
            if (fd >= 0)
            {
                ::close(fd);
                fd = -1;
            }
        }

        [[noreturn]] void cleanupAndThrow(const std::string& what)
        {
            closeFd(m_listen);
            closeFd(m_wakeRead);
            closeFd(m_wakeWrite);
            throw std::runtime_error("RawTcpServer: " + what);
        }

        void wake() const
        {
            const char byte {1};
            [[maybe_unused]] const auto written = ::write(m_wakeWrite, &byte, 1);
        }

        void run()
        {
            std::vector<pollfd> fds;
            std::vector<std::size_t> owners; // fds[i + 2] belongs to m_connections[owners[i]]
            while (true)
            {
                bool reading {false};
                fds.clear();
                owners.clear();
                fds.push_back(pollfd {m_wakeRead, POLLIN, 0});
                fds.push_back(pollfd {m_listen, POLLIN, 0});
                {
                    std::lock_guard lock(m_mutex);
                    if (m_stopped)
                    {
                        return;
                    }
                    reading = m_reading;
                    for (std::size_t i = 0; i < m_connections.size(); ++i)
                    {
                        if (m_connections[i].info.eofAt.has_value())
                        {
                            continue;
                        }
                        // Without reading, only a FIN that reached the socket (nothing queued before it), a hang-up
                        // or a reset can be reported (POLLHUP/POLLERR are implicit).
                        fds.push_back(pollfd {
                            m_connections[i].fd, static_cast<short>(reading ? (POLLIN | POLLRDHUP) : POLLRDHUP), 0});
                        owners.push_back(i);
                    }
                }

                if (::poll(fds.data(), fds.size(), 1000) < 0)
                {
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    return;
                }
                if ((fds[0].revents & POLLIN) != 0)
                {
                    char drain[64];
                    while (::read(m_wakeRead, drain, sizeof(drain)) > 0)
                    {
                    }
                }
                if ((fds[1].revents & POLLIN) != 0)
                {
                    acceptAll();
                }
                for (std::size_t i = 0; i < owners.size(); ++i)
                {
                    if (fds[i + 2].revents != 0)
                    {
                        service(owners[i], reading);
                    }
                }
            }
        }

        void acceptAll()
        {
            while (true)
            {
                sockaddr_in peer {};
                socklen_t length = sizeof(peer);
                const int fd =
                    ::accept4(m_listen, reinterpret_cast<sockaddr*>(&peer), &length, SOCK_CLOEXEC | SOCK_NONBLOCK);
                if (fd < 0)
                {
                    return; // EAGAIN or a transient error: poll again
                }
                {
                    std::lock_guard lock(m_mutex);
                    m_connections.push_back(Connection {
                        fd, AcceptedConnection {ntohs(peer.sin_port), std::chrono::steady_clock::now(), {}, 0}});
                }
                m_cv.notify_all();
            }
        }

        void service(std::size_t index, bool reading)
        {
            const int fd = m_connections[index].fd; // only this thread changes fds before stop() joins it
            bool closed {!reading};                 // without reading, any event is a hang-up or an error
            std::uint64_t read {0};
            if (reading)
            {
                char buffer[64 * 1024];
                while (true)
                {
                    const auto n = ::recv(fd, buffer, sizeof(buffer), 0);
                    if (n > 0)
                    {
                        read += static_cast<std::uint64_t>(n);
                        continue;
                    }
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                    {
                        break;
                    }
                    if (n < 0 && errno == EINTR)
                    {
                        continue;
                    }
                    closed = true; // 0 = orderly EOF; any other error = reset
                    break;
                }
            }
            {
                std::lock_guard lock(m_mutex);
                auto& info = m_connections[index].info;
                info.bytesRead += read;
                if (closed)
                {
                    info.eofAt = std::chrono::steady_clock::now();
                }
            }
            m_cv.notify_all();
        }

        int m_listen {-1};
        int m_wakeRead {-1};
        int m_wakeWrite {-1};
        int m_port {0};
        std::thread m_thread;
        mutable std::mutex m_mutex;
        mutable std::condition_variable m_cv;
        bool m_stopped {false};
        bool m_reading;
        std::vector<Connection> m_connections; // fds closed only by stop(), after the join
    };

    /**
     * @brief A mute server: accepts, reads and discards everything, never answers.
     *
     * Each peer close is timestamped at once (AcceptedConnection::eofAt).
     */
    class SilentServer final : public RawTcpServer
    {
    public:
        SilentServer()
            : RawTcpServer(true, std::nullopt)
        {
        }
    };

    /**
     * @brief A server that accepts and does not read, so an upload to it stalls.
     *
     * SO_RCVBUF (64 KiB by default) is set on the listening socket before listen(), so accepted sockets inherit a
     * small window and the client's send buffer fills quickly. A client that closes with unsent data has its FIN
     * queued behind that data, so the EOF only becomes visible once the server reads: call resumeReading() (e.g.
     * right after the client cancels) and the remaining bytes are drained and the EOF timestamped. A reset is seen
     * without reading.
     */
    class StalledUploadServer final : public RawTcpServer
    {
    public:
        explicit StalledUploadServer(int receiveBuffer = 64 * 1024)
            : RawTcpServer(false, receiveBuffer)
        {
        }

        /// Starts reading (and discarding) every accepted socket, so EOFs become visible.
        void resumeReading()
        {
            startReading();
        }
    };
} // namespace indexer_client::testing

#endif // _INDEXER_CLIENT_TESTS_RAW_TCP_SERVER_HPP
