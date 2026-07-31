/*
 * Wazuh remoted module - Fake Unix Domain Socket server for tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Emulates the SizeHeaderProtocol wire format used by the Wazuh remoted
 * WazuhDBClient and TaskClient: `[uint32_t size][payload of `size` bytes]`.
 *
 * The server:
 *   - Binds a SOCK_STREAM UDS at a caller-provided path.
 *   - Accepts multiple connections in a loop.
 *   - For each request, calls the caller's responder(request) -> response.
 *   - Optionally drops responses (to simulate a hung backend for timeout tests).
 *   - Counts requests received (thread-safe).
 *   - Cleanly stops on dtor / stop() and unlinks the socket path.
 */

#ifndef _REMOTED_TEST_FAKE_UDS_SERVER_HPP
#define _REMOTED_TEST_FAKE_UDS_SERVER_HPP

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace remoted::test
{
    class FakeUdsServer
    {
    public:
        using Responder = std::function<std::string(const std::string&)>;

        FakeUdsServer(std::string path, Responder responder)
            : m_path(std::move(path))
            , m_responder(std::move(responder))
        {
            ::unlink(m_path.c_str()); // stale socket from a crashed previous run

            m_listenFd = ::socket(AF_UNIX, SOCK_STREAM, 0);
            if (m_listenFd < 0)
            {
                throw std::runtime_error(std::string("FakeUdsServer socket: ") + ::strerror(errno));
            }

            sockaddr_un addr {};
            addr.sun_family = AF_UNIX;
            if (m_path.size() >= sizeof(addr.sun_path))
            {
                ::close(m_listenFd);
                throw std::runtime_error("FakeUdsServer path too long");
            }
            std::memcpy(addr.sun_path, m_path.data(), m_path.size());

            if (::bind(m_listenFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
            {
                const int e = errno;
                ::close(m_listenFd);
                throw std::runtime_error(std::string("FakeUdsServer bind: ") + ::strerror(e));
            }
            if (::listen(m_listenFd, 8) < 0)
            {
                const int e = errno;
                ::close(m_listenFd);
                ::unlink(m_path.c_str());
                throw std::runtime_error(std::string("FakeUdsServer listen: ") + ::strerror(e));
            }

            m_thread = std::thread([this] { acceptLoop(); });
        }

        ~FakeUdsServer()
        {
            stop();
        }

        void stop()
        {
            bool expected = false;
            if (!m_stopping.compare_exchange_strong(expected, true))
            {
                return;
            }
            if (m_listenFd >= 0)
            {
                // Break accept() by shutting down the listen socket.
                ::shutdown(m_listenFd, SHUT_RDWR);
                ::close(m_listenFd);
                m_listenFd = -1;
            }
            if (m_thread.joinable())
            {
                m_thread.join();
            }
            ::unlink(m_path.c_str());
        }

        // When true, the server reads the request but never sends a response.
        // Used to trigger client-side deadline timeouts.
        void setDropResponses(bool drop)
        {
            m_dropResponses.store(drop);
        }

        size_t requestCount() const
        {
            return m_requestCount.load();
        }

    private:
        void acceptLoop()
        {
            while (!m_stopping.load())
            {
                int fd = ::accept(m_listenFd, nullptr, nullptr);
                if (fd < 0)
                {
                    if (m_stopping.load() || errno == EBADF || errno == EINVAL)
                    {
                        break;
                    }
                    continue;
                }

                // Each connection is served on its own thread so the client
                // pool can hold N sockets concurrently.
                std::thread([this, fd] { serveConnection(fd); }).detach();
            }
        }

        void serveConnection(int fd)
        {
            while (!m_stopping.load())
            {
                uint32_t size = 0;
                if (!readAll(fd, reinterpret_cast<char*>(&size), sizeof(size)))
                {
                    break;
                }
                if (size == 0 || size > (16U * 1024U * 1024U))
                {
                    break; // sanity cap: refuse absurd frames
                }

                std::vector<char> body(size);
                if (!readAll(fd, body.data(), size))
                {
                    break;
                }
                m_requestCount.fetch_add(1);

                if (m_dropResponses.load())
                {
                    continue; // deliberately hang the client's wait_for
                }

                std::string reply = m_responder(std::string(body.data(), body.size()));
                uint32_t replySize = static_cast<uint32_t>(reply.size());
                if (!writeAll(fd, reinterpret_cast<const char*>(&replySize), sizeof(replySize)))
                {
                    break;
                }
                if (!reply.empty() && !writeAll(fd, reply.data(), reply.size()))
                {
                    break;
                }
            }
            ::close(fd);
        }

        static bool readAll(int fd, char* buf, size_t n)
        {
            size_t got = 0;
            while (got < n)
            {
                ssize_t r = ::read(fd, buf + got, n - got);
                if (r > 0)
                {
                    got += static_cast<size_t>(r);
                }
                else if (r == 0)
                {
                    return false; // peer closed
                }
                else
                {
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    return false;
                }
            }
            return true;
        }

        static bool writeAll(int fd, const char* buf, size_t n)
        {
            size_t sent = 0;
            while (sent < n)
            {
                ssize_t w = ::write(fd, buf + sent, n - sent);
                if (w > 0)
                {
                    sent += static_cast<size_t>(w);
                }
                else
                {
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    return false;
                }
            }
            return true;
        }

        std::string m_path;
        Responder m_responder;
        int m_listenFd {-1};
        std::thread m_thread;
        std::atomic<bool> m_stopping {false};
        std::atomic<bool> m_dropResponses {false};
        std::atomic<size_t> m_requestCount {0};
    };

    // Convenience: build a unique UDS path per test.
    inline std::string makeUniqueSocketPath(const std::string& tag)
    {
        return "/tmp/wazuh_" + tag + "_" + std::to_string(::getpid()) + "_" +
               std::to_string(reinterpret_cast<uintptr_t>(&tag)) + ".sock";
    }
} // namespace remoted::test

#endif
