/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_HTTP_HTTP_SERVER_HPP
#define _TASK_MANAGER_HTTP_HTTP_SERVER_HPP

#include "apiHandlers.hpp"
#include "upgrade/upgradeApi.hpp"

#include <uds_http_server/IUdsHttpServer.hpp>

#include <cstddef>
#include <functional>
#include <memory>
#include <string>

namespace task_manager::http
{
    /**
     * @brief The module's UDS HTTP surface.
     *
     * Routes are registered against shared_modules/uds_http_server, the transport wazuh-db and
     * inventory-sync already use, which replaced a hand-rolled dealer thread, eight worker threads
     * and an epoll wrapper.
     *
     * EVERY ROUTE IS A POST, including the reads. Routing is exact-match with no path parameters,
     * and the C clients that call this speak POST only, so a GET-shaped read surface would need
     * either query-string parsing or a second client. The one exception is the liveness probe,
     * which has no body and no caller constraint.
     *
     * HANDLERS MUST NOT BLOCK: they run inline on an I/O thread. Every route here is a bounded
     * store operation measured in microseconds, so each answers synchronously -- the same trade
     * wazuh-db's HTTP endpoints make. Nothing on this surface waits for a task to RUN; that is
     * what the queue is for.
     *
     * THE UPGRADE ROUTES ARE THE ONE EXCEPTION, and they honour the rule rather than breaking it:
     * their handler parses, hands the batch to a worker pool and returns, and the response is sent
     * from that pool through a retained responder -- possibly minutes later. They are registered
     * directly rather than through the `route()` helper below, which is synchronous by shape and
     * imposes the module's own error envelope; the upgrade routes must reproduce the retired
     * module's envelope byte for byte instead. See upgrade/upgradeApi.hpp.
     */
    class HttpServer
    {
    public:
        struct Options
        {
            std::string socketPath;
            int ioThreads {2};
            /// @brief Largest accepted body. Bulk agent-task creates are the reason this is not
            ///        simply the single-task payload cap.
            std::size_t maxBodyBytes {8UL * 1024 * 1024};
        };

        HttpServer(ApiHandlers& handlers, Options options);
        ~HttpServer();

        /**
         * @brief Attach the agent upgrade routes.
         *
         * Optional, and MUST be called before start(): the transport refuses addRoute() once bound.
         * Left unset -- by the testtool, and by any build that does not want the surface -- the two
         * routes simply do not exist and answer 404.
         */
        void setUpgradeApi(upgrade::UpgradeApi& api) noexcept { m_upgradeApi = &api; }

        HttpServer(const HttpServer&) = delete;
        HttpServer& operator=(const HttpServer&) = delete;

        /// @brief Register routes and bind. Throws with a message naming the offending path when
        ///        the socket cannot be bound.
        void start();

        /// @brief Phase 1: stop accepting, and wait for running handlers to return. Call this
        ///        BEFORE tearing down anything a handler reaches into -- that ordering is what
        ///        makes stopping the executor and closing the store safe.
        void stopAccepting() noexcept;

        /// @brief Phase 2: drain and release the I/O runtime.
        void stop() noexcept;

        /// @brief Publish the transport's bounded resources as pull metrics.
        void registerDiagnostics(metrics::TaskMetrics& metrics);

    private:
        ApiHandlers& m_handlers;
        Options m_options;
        std::unique_ptr<wazuh::uds_http::IUdsHttpServer> m_server;
        /// @brief Non-owning; the facade outlives this. Null means the routes are not registered.
        upgrade::UpgradeApi* m_upgradeApi {nullptr};
    };
} // namespace task_manager::http

#endif // _TASK_MANAGER_HTTP_HTTP_SERVER_HPP
