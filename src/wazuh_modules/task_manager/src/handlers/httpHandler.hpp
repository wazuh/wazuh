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

#ifndef _TASK_MANAGER_HANDLERS_HTTP_HANDLER_HPP
#define _TASK_MANAGER_HANDLERS_HTTP_HANDLER_HPP

#include "iHandler.hpp"
#include "udsHttpClient.hpp"

#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace task_manager::handlers
{
    /**
     * @brief Executes a task type by POSTing its payload to a consumer over a Unix socket.
     *
     * This is what "routed type" collapsed into. A routed descriptor is simply one whose handler
     * is one of these, built with a socket, a path and two deadlines -- there is no branch
     * anywhere else in the module that asks whether a type is routed or local.
     *
     * THE PAYLOAD IS THE REQUEST BODY, VERBATIM. Nothing here constructs it; whoever created the
     * row authored it. That is worth stating because the natural assumption is that the registry
     * has a body-building hook, and it does not: module knowledge moved to the PRODUCER rather
     * than disappearing.
     *
     * THE CONSUMER MUST ANSWER AT COMPLETION, not at admission. A route that returns 200 for
     * "accepted and queued" would have this handler report success while the work sat in someone
     * else's in-memory queue -- which is precisely the semantics this whole queue exists to
     * replace.
     */
    class HttpHandler final : public IHandler
    {
    public:
        struct Options
        {
            std::string socketPath;
            std::string path;
            std::chrono::milliseconds connectTimeout {2000};
            std::chrono::milliseconds requestTimeout {600000};
            /// @brief From the descriptor. False makes a 4xx retry instead of retiring the row.
            bool allowTerminalFailure {true};
        };

        explicit HttpHandler(Options options);

        HandlerResult run(const ClaimedTask& task, const StopToken& stop) override;

    private:
        /// @brief RAII lease on a client from the pool.
        class Lease
        {
        public:
            Lease(HttpHandler& handler, std::unique_ptr<UdsHttpClient> client);
            ~Lease();
            Lease(const Lease&) = delete;
            Lease& operator=(const Lease&) = delete;
            UdsHttpClient& operator*() const noexcept
            {
                return *m_client;
            }

        private:
            HttpHandler& m_handler;
            std::unique_ptr<UdsHttpClient> m_client;
        };

        Lease acquire();

        Options m_options;

        /// @brief A curl easy handle is not thread-safe, so each concurrent run needs its own.
        ///        The pool never grows past the type's concurrency cap, because that is what
        ///        bounds simultaneous runs.
        std::mutex m_mutex;
        std::vector<std::unique_ptr<UdsHttpClient>> m_idle;
    };
} // namespace task_manager::handlers

#endif // _TASK_MANAGER_HANDLERS_HTTP_HANDLER_HPP
