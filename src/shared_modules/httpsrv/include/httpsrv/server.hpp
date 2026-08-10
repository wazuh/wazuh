/*
 * Wazuh shared modules
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SHARED_HTTPSRV_SERVER_HPP
#define _SHARED_HTTPSRV_SERVER_HPP

#include <algorithm>
#include <memory>
#include <thread>

#include <proc.hpp>

// Clamp httplib worker threads to a minimum of 2 based on available hardware.
#ifndef CPPHTTPLIB_THREAD_POOL_COUNT
#define CPPHTTPLIB_THREAD_POOL_COUNT ((std::max)(2u, cpp_get_nproc() > 1u ? cpp_get_nproc() - 1u : 1u))
#endif

#include <httplib.h>

#include <httpsrv/iserver.hpp>

namespace httpsrv
{

    class Server : public IServer<Server>
    {
    private:
        std::shared_ptr<httplib::Server> m_srv;
        std::thread m_thread;
        std::string m_id;
        std::filesystem::path m_socketPath;
        size_t m_payloadMaxBytes {0};
        bool m_enableDetailedLogging {true};

        void applyPayloadLimit();
        bool bindAndListen();

    public:
        /**
         * @param id Identifier used in logs and the worker thread name.
         * @param payloadMaxBytes Maximum accepted request body size, in bytes (0 = unlimited).
         * @param enableDetailedLogging If true, logs full request/response bodies at debug level.
         * @param threadPoolSize Number of worker threads handling accepted connections. 0 (the
         * default) keeps cpp-httplib's own default (CPPHTTPLIB_THREAD_POOL_COUNT, machine-wide).
         * Pass an explicit value to give this server instance its own pool, independent of other
         * httpsrv::Server instances in the same process -- e.g. so a slow endpoint on one socket
         * can't starve worker threads that a different, latency-sensitive socket relies on.
         */
        explicit Server(const std::string& id,
                        size_t payloadMaxBytes = 0,
                        bool enableDetailedLogging = true,
                        size_t threadPoolSize = 0);

        ~Server() override
        {
            stop();
        }

        void start(const std::filesystem::path& socketPath, bool useThread = true);

        void stop() noexcept;

        void addRoute(Method method,
                      const std::string& route,
                      const std::function<void(const httplib::Request&, httplib::Response&)>& handler);

        bool isRunning() const
        {
            return m_srv->is_running();
        }

        size_t getPayloadMaxBytes() const noexcept
        {
            return m_payloadMaxBytes;
        }
    };

} // namespace httpsrv

#endif // _SHARED_HTTPSRV_SERVER_HPP
