/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_TEST_UDS_TEST_CLIENT_HPP
#define _INVSYNC_TEST_UDS_TEST_CLIENT_HPP

#include <asio.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <system_error>
#include <thread>
#include <unistd.h>

namespace invsync::test
{
    using stream_protocol = asio::local::stream_protocol;

    /// A per-test socket path under /tmp. Short on purpose -- sockaddr_un::sun_path is ~107 bytes.
    inline std::string uniqueSocketPath(const char* tag)
    {
        static std::atomic<int> counter {0};
        return "/tmp/iss_" + std::string {tag} + "_" + std::to_string(::getpid()) + "_" +
               std::to_string(counter.fetch_add(1)) + ".sock";
    }

    /// A parsed HTTP response, as far as these tests need to look at one.
    struct Response
    {
        bool connected {false};
        int status {0};
        std::string body;
        std::string raw;

        /// Whether the response carries @p name, spelled exactly as the server writes it.
        bool hasHeader(const std::string& name) const
        {
            return raw.find("\r\n" + name + ":") != std::string::npos;
        }

        /// The value of @p name, or "" when absent.
        std::string header(const std::string& name) const
        {
            const auto at = raw.find("\r\n" + name + ":");
            if (at == std::string::npos)
            {
                return {};
            }
            const auto valueStart = raw.find(':', at) + 1;
            const auto valueEnd = raw.find("\r\n", valueStart);
            auto value = raw.substr(valueStart, valueEnd - valueStart);
            const auto firstNonSpace = value.find_first_not_of(' ');
            return firstNonSpace == std::string::npos ? std::string {} : value.substr(firstNonSpace);
        }
    };

    /**
     * @brief Sends raw bytes to a UDS and reads until EOF.
     *
     * Deliberately hand-rolled rather than reusing remoted's AsioUdsHttpClient: that lives in
     * remoted's private src/ and linking it here would recreate, inside the test target, exactly the
     * cross-module dependency the product must not have -- and would drag RESTinio, fmt and OpenSSL
     * into a binary that needs none of them.
     */
    inline Response sendRaw(const std::string& socketPath,
                            const std::string& bytes,
                            std::chrono::milliseconds timeout = std::chrono::seconds {10})
    {
        Response result;

        asio::io_context ioc;
        stream_protocol::socket socket {ioc};
        std::error_code ec;

        socket.connect(stream_protocol::endpoint {socketPath}, ec);
        if (ec)
        {
            return result;
        }
        result.connected = true;

        asio::write(socket, asio::buffer(bytes), ec);
        if (ec)
        {
            return result;
        }

        // A plain blocking read loop with a deadline enforced by a watchdog thread: simpler than an
        // async state machine, and a test that hangs is worse than one that fails.
        std::atomic_bool done {false};
        std::thread watchdog {[&]
                              {
                                  const auto deadline = std::chrono::steady_clock::now() + timeout;
                                  while (!done.load() && std::chrono::steady_clock::now() < deadline)
                                  {
                                      std::this_thread::sleep_for(std::chrono::milliseconds {5});
                                  }
                                  if (!done.load())
                                  {
                                      std::error_code ignore;
                                      socket.close(ignore);
                                  }
                              }};

        std::array<char, 4096> buffer {};
        for (;;)
        {
            const auto bytesRead = socket.read_some(asio::buffer(buffer), ec);
            if (ec)
            {
                break; // EOF or closed by the watchdog
            }
            result.raw.append(buffer.data(), bytesRead);
        }

        done.store(true);
        watchdog.join();

        if (result.raw.rfind("HTTP/1.1 ", 0) == 0)
        {
            result.status = std::stoi(result.raw.substr(9, 3));
        }
        const auto separator = result.raw.find("\r\n\r\n");
        if (separator != std::string::npos)
        {
            result.body = result.raw.substr(separator + 4);
        }

        return result;
    }

    /// Builds the same bytes remoted's client emits (see its buildRequestHead()).
    inline std::string peerRequest(const std::string& method,
                                   const std::string& path,
                                   const std::string& body,
                                   const std::string& contentType = "application/octet-stream")
    {
        std::string head {method};
        head += ' ';
        head += path;
        head += " HTTP/1.1\r\nHost: localhost\r\n";
        if (!contentType.empty())
        {
            head += "Content-Type: " + contentType + "\r\n";
        }
        head += "Content-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n";
        return head + body;
    }

} // namespace invsync::test

#endif // _INVSYNC_TEST_UDS_TEST_CLIENT_HPP
