/*
 * Wazuh remoted module - HTTP-over-UDS server for the module's test fakes
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The services remoted calls over a Unix socket (the vulnerability detector, the task manager) serve
 * through the shared uds_http_server, so the fakes that stand in for them run on it too: remoted's
 * clients are tested against the HTTP stack they meet in the field, status codes and body framing
 * included.
 *
 * That library runs route handlers inline on its I/O thread and requires them never to block. Test
 * handlers do block on purpose (a stalled service, a slow answer), so each request's handler runs on a
 * worker thread of its own and answers through the responder -- the way a real consumer hands blocking
 * work off. A blocked handler therefore never holds up another request to the same fake.
 */

#ifndef _REMOTED_MODULE_TEST_UDS_HTTP_TEST_SERVER_HPP
#define _REMOTED_MODULE_TEST_UDS_HTTP_TEST_SERVER_HPP

#include <uds_http_server/IUdsHttpServer.hpp>
#include <uds_http_server/udsHttpServerFactory.hpp>

#include <algorithm>
#include <atomic>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace remoted::test
{
    /// @brief What a test scripts for one request: fill `res` from `req`. Runs on a worker thread, so it may
    /// block. A handler that sets nothing answers 200 with an empty body; one that throws answers 500.
    using TestHandler = std::function<void(const wazuh::uds_http::HttpRequest&, wazuh::uds_http::HttpResponse&)>;

    class UdsHttpTestServer
    {
    public:
        /// @param socketPath Where to listen. The server owns the file: start() replaces a stale socket there and
        /// refuses a path that is not a socket, and teardown unlinks only the socket it bound.
        /// @param name Names the fake in the error a failed start() throws.
        UdsHttpTestServer(std::string socketPath, std::string name)
            : m_socketPath(std::move(socketPath))
            , m_name(std::move(name))
            , m_server(wazuh::uds_http::makeUdsHttpServer())
        {
        }

        /// @brief Stops taking requests, waits for every handler still running -- a stalled one for its whole
        /// stall -- and only then stops the server, so each of them still gets its answer written.
        ~UdsHttpTestServer()
        {
            // Once this returns no route lambda runs again, so the worker list can no longer grow.
            m_server->stopAccepting();

            std::vector<Worker> workers;
            {
                std::lock_guard<std::mutex> lock(m_workersMutex);
                workers.swap(m_workers);
            }
            for (auto& worker : workers)
            {
                worker.thread.join();
            }

            // Also unlinks the socket, and only the one this server bound. Nothing here may throw: this destructor
            // runs too when a fake's constructor throws after its server was built.
            m_server->stop();
        }

        UdsHttpTestServer(const UdsHttpTestServer&) = delete;
        UdsHttpTestServer& operator=(const UdsHttpTestServer&) = delete;

        /// @brief Register a route. Must be called before start().
        /// @param onArrival Runs on the I/O thread as the request arrives, before its handler (request counters,
        /// the last body seen). Must not block.
        /// @param currentHandler Returns the handler to run for this request; called on arrival, so a test may swap
        /// handlers while requests are in flight.
        void addRoute(wazuh::uds_http::Method method,
                      const std::string& path,
                      wazuh::uds_http::RouteOptions options,
                      std::function<void(const wazuh::uds_http::HttpRequest&)> onArrival,
                      std::function<TestHandler()> currentHandler)
        {
            m_server->addRoute(
                method,
                path,
                [this, onArrival = std::move(onArrival), currentHandler = std::move(currentHandler)](
                    std::shared_ptr<const wazuh::uds_http::HttpRequest> request,
                    std::shared_ptr<wazuh::uds_http::IHttpResponder> responder)
                {
                    onArrival(*request);
                    runOnWorker(std::move(request), std::move(responder), currentHandler());
                },
                std::move(options));
        }

        /// @brief Bind and start serving.
        /// @throws std::runtime_error naming the fake and the socket when the server cannot start.
        void start()
        {
            wazuh::uds_http::UdsHttpServerConfig config;
            config.socketPath = m_socketPath;
            // Route lambdas only hand the request to a worker, so one I/O thread never waits on a handler.
            config.ioThreads = 1;
            config.serverName = m_name;

            try
            {
                m_server->start(config);
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(m_name + " failed to bind " + m_socketPath + ": " + e.what());
            }
        }

    private:
        struct Worker
        {
            std::thread thread;
            std::shared_ptr<std::atomic<bool>> done;
        };

        void runOnWorker(std::shared_ptr<const wazuh::uds_http::HttpRequest> request,
                         std::shared_ptr<wazuh::uds_http::IHttpResponder> responder,
                         TestHandler handler)
        {
            auto done = std::make_shared<std::atomic<bool>>(false);

            std::lock_guard<std::mutex> lock(m_workersMutex);
            // Join the workers that already answered, so a test that sends many requests does not pile up threads.
            const auto finished = std::partition(
                m_workers.begin(), m_workers.end(), [](const Worker& worker) { return !worker.done->load(); });
            std::for_each(finished, m_workers.end(), [](Worker& worker) { worker.thread.join(); });
            m_workers.erase(finished, m_workers.end());

            m_workers.push_back({std::thread(
                                     [request = std::move(request),
                                      responder = std::move(responder),
                                      handler = std::move(handler),
                                      done]
                                     {
                                         wazuh::uds_http::HttpResponse response;
                                         if (handler)
                                         {
                                             try
                                             {
                                                 handler(*request, response);
                                             }
                                             catch (...)
                                             {
                                                 response = wazuh::uds_http::HttpResponse {};
                                                 response.status = 500;
                                             }
                                         }
                                         responder->send(std::move(response));
                                         done->store(true);
                                     }),
                                 done});
        }

        std::string m_socketPath;
        std::string m_name;
        std::unique_ptr<wazuh::uds_http::IUdsHttpServer> m_server;
        std::mutex m_workersMutex;
        std::vector<Worker> m_workers;
    };
} // namespace remoted::test

#endif // _REMOTED_MODULE_TEST_UDS_HTTP_TEST_SERVER_HPP
