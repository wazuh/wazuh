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

// Clamp httplib worker threads to the [4, 16] range.
#ifndef CPPHTTPLIB_THREAD_POOL_COUNT
#define CPPHTTPLIB_THREAD_POOL_COUNT                                                                                   \
    ((std::min)(16u,                                                                                                   \
                (std::max)(4u,                                                                                         \
                           std::thread::hardware_concurrency() > 0 ? std::thread::hardware_concurrency() - 1 : 4u)))
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
        explicit Server(const std::string& id, size_t payloadMaxBytes = 0, bool enableDetailedLogging = true);

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
