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

#ifndef _INDEXER_CLIENT_TESTS_DROP_ON_REUSE_SERVER_HPP
#define _INDEXER_CLIENT_TESTS_DROP_ON_REUSE_SERVER_HPP

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace indexer_client::testing
{
    /**
     * @brief A request as DropOnReuseServer read it, whole (request line, headers and Content-Length body).
     */
    struct RawRequest
    {
        std::string method;
        std::string target;
        std::string body;
        /// Accept order of the connection it came on (0 = the first one).
        std::size_t connection {0};
        /// Requests read before it on that connection (> 0 = the connection was reused).
        std::size_t onConnection {0};
        bool dropped {false};
    };

    /**
     * @brief Keep-alive HTTP/1.1 server on 127.0.0.1 that answers some requests and drops the others.
     *
     * Every request is read whole. A request whose target contains `dropMarker` is answered for the first
     * `answerFirst` of them and, from then on, dropped: the server closes the connection without writing a byte. That
     * is libcurl's "connection died" case: a request on a reused connection that gets no response byte is resent by
     * curl itself on a fresh connection (curl 8.20 lib/transfer.c Curl_retry_request). With `reusedOnly` only such a
     * request that arrives on a reused connection is dropped (a peer that closes idle keep-alive connections); on a new
     * one it is answered. Any other request is answered 200 with `answer(target)`, keeping the connection open. One
     * thread per connection; stop() (also the destructor) never waits for a peer.
     */
    class DropOnReuseServer final
    {
    public:
        DropOnReuseServer(std::string dropMarker,
                          std::size_t answerFirst,
                          std::function<std::string(const std::string&)> answer = {},
                          bool reusedOnly = false)
            : m_dropMarker(std::move(dropMarker))
            , m_answerFirst(answerFirst)
            , m_answer(std::move(answer))
            , m_reusedOnly(reusedOnly)
        {
            m_listen = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (m_listen < 0)
            {
                throw std::runtime_error("DropOnReuseServer: socket failed");
            }
            const int one {1};
            ::setsockopt(m_listen, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            sockaddr_in address {};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            if (::bind(m_listen, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
                ::listen(m_listen, 64) != 0)
            {
                ::close(m_listen);
                throw std::runtime_error("DropOnReuseServer: bind/listen failed");
            }
            socklen_t length = sizeof(address);
            ::getsockname(m_listen, reinterpret_cast<sockaddr*>(&address), &length);
            m_port = ntohs(address.sin_port);
            m_acceptor = std::thread([this] { acceptLoop(); });
        }

        ~DropOnReuseServer()
        {
            stop();
        }

        DropOnReuseServer(const DropOnReuseServer&) = delete;
        DropOnReuseServer& operator=(const DropOnReuseServer&) = delete;

        /// "http://127.0.0.1:<port>".
        std::string baseUrl() const
        {
            return "http://127.0.0.1:" + std::to_string(m_port);
        }

        /// Connections accepted so far.
        std::size_t accepted() const
        {
            std::lock_guard lock(m_mutex);
            return m_accepted;
        }

        /// Every request read so far, in arrival order.
        std::vector<RawRequest> requests() const
        {
            std::lock_guard lock(m_mutex);
            return m_requests;
        }

        /// The requests whose target contains `marker`.
        std::vector<RawRequest> requestsTo(const std::string& marker) const
        {
            std::vector<RawRequest> out;
            for (auto& request : requests())
            {
                if (request.target.find(marker) != std::string::npos)
                {
                    out.push_back(std::move(request));
                }
            }
            return out;
        }

        /// Waits until at least `count` requests contain `marker` in their target.
        bool waitFor(const std::string& marker, std::size_t count, std::chrono::milliseconds timeout) const
        {
            std::unique_lock lock(m_mutex);
            return m_cv.wait_for(lock,
                                 timeout,
                                 [&]
                                 {
                                     return static_cast<std::size_t>(std::count_if(
                                                m_requests.begin(),
                                                m_requests.end(),
                                                [&](const RawRequest& request)
                                                { return request.target.find(marker) != std::string::npos; })) >= count;
                                 });
        }

        /// Stops accepting, wakes and joins every thread. Idempotent.
        void stop()
        {
            if (m_stopped.exchange(true))
            {
                return;
            }
            ::shutdown(m_listen, SHUT_RDWR);
            if (m_acceptor.joinable())
            {
                m_acceptor.join();
            }
            std::vector<std::thread> workers;
            {
                std::lock_guard lock(m_mutex);
                workers.swap(m_workers);
            }
            for (auto& worker : workers)
            {
                worker.join();
            }
            ::close(m_listen);
        }

    private:
        /// Waits until `fd` is readable or the server stops; false once stopping.
        bool readable(int fd) const
        {
            while (!m_stopped.load())
            {
                pollfd entry {fd, POLLIN, 0};
                const int ready = ::poll(&entry, 1, 50);
                if (ready > 0)
                {
                    return true;
                }
                if (ready < 0 && errno != EINTR)
                {
                    return false;
                }
            }
            return false;
        }

        void acceptLoop()
        {
            while (readable(m_listen))
            {
                const int fd = ::accept4(m_listen, nullptr, nullptr, SOCK_CLOEXEC);
                if (fd < 0)
                {
                    continue;
                }
                std::lock_guard lock(m_mutex);
                const auto index = m_accepted++;
                m_workers.emplace_back([this, fd, index] { serve(fd, index); });
            }
        }

        static std::size_t contentLength(const std::string& head)
        {
            std::string lower(head);
            std::transform(lower.begin(),
                           lower.end(),
                           lower.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            const auto at = lower.find("\r\ncontent-length:");
            if (at == std::string::npos)
            {
                return 0;
            }
            return static_cast<std::size_t>(std::stoul(head.substr(at + 17)));
        }

        void serve(int fd, std::size_t connection)
        {
            std::string buffer;
            std::size_t onConnection {0};
            char chunk[16 * 1024];
            bool open {true};
            while (open)
            {
                // One whole request: the head, then Content-Length body bytes.
                std::size_t headEnd = std::string::npos;
                std::size_t total = 0;
                while (open)
                {
                    headEnd = buffer.find("\r\n\r\n");
                    if (headEnd != std::string::npos)
                    {
                        total = headEnd + 4 + contentLength(buffer.substr(0, headEnd));
                        if (buffer.size() >= total)
                        {
                            break;
                        }
                    }
                    if (!readable(fd))
                    {
                        open = false;
                        break;
                    }
                    const auto n = ::recv(fd, chunk, sizeof(chunk), 0);
                    if (n <= 0)
                    {
                        open = false;
                        break;
                    }
                    buffer.append(chunk, static_cast<std::size_t>(n));
                }
                if (!open)
                {
                    break;
                }
                RawRequest request;
                const auto lineEnd = buffer.find("\r\n");
                const auto firstSpace = buffer.find(' ');
                const auto secondSpace = buffer.find(' ', firstSpace + 1);
                request.method = buffer.substr(0, firstSpace);
                request.target = buffer.substr(firstSpace + 1, std::min(secondSpace, lineEnd) - firstSpace - 1);
                request.body = buffer.substr(headEnd + 4, total - headEnd - 4);
                request.connection = connection;
                request.onConnection = onConnection++;
                buffer.erase(0, total);

                std::string answer;
                {
                    std::lock_guard lock(m_mutex);
                    if (request.target.find(m_dropMarker) != std::string::npos)
                    {
                        request.dropped = m_marked++ >= m_answerFirst && (!m_reusedOnly || request.onConnection > 0);
                    }
                    m_requests.push_back(request);
                }
                m_cv.notify_all();
                if (request.dropped)
                {
                    break; // Closed without a byte of response.
                }
                answer = m_answer ? m_answer(request.target) : std::string("{}");
                const std::string response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
                                             std::to_string(answer.size()) + "\r\n\r\n" + answer;
                if (::send(fd, response.data(), response.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(response.size()))
                {
                    break;
                }
            }
            ::close(fd);
        }

        const std::string m_dropMarker;
        const std::size_t m_answerFirst;
        const std::function<std::string(const std::string&)> m_answer;
        const bool m_reusedOnly;
        int m_listen {-1};
        int m_port {0};
        std::atomic<bool> m_stopped {false};
        std::thread m_acceptor;
        mutable std::mutex m_mutex;
        mutable std::condition_variable m_cv;
        std::size_t m_accepted {0};
        std::size_t m_marked {0};
        std::vector<RawRequest> m_requests;
        std::vector<std::thread> m_workers;
    };
} // namespace indexer_client::testing

#endif // _INDEXER_CLIENT_TESTS_DROP_ON_REUSE_SERVER_HPP
