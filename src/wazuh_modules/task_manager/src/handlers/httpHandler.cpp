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

#include "httpHandler.hpp"

#include "registry/httpResultMapper.hpp"

#include <utility>

namespace task_manager::handlers
{
    HttpHandler::Lease::Lease(HttpHandler& handler, std::unique_ptr<UdsHttpClient> client)
        : m_handler {handler}
        , m_client {std::move(client)}
    {
    }

    HttpHandler::Lease::~Lease()
    {
        std::lock_guard lock {m_handler.m_mutex};
        m_handler.m_idle.push_back(std::move(m_client));
    }

    HttpHandler::HttpHandler(Options options)
        : m_options {std::move(options)}
    {
    }

    HttpHandler::Lease HttpHandler::acquire()
    {
        {
            std::lock_guard lock {m_mutex};
            if (!m_idle.empty())
            {
                auto client {std::move(m_idle.back())};
                m_idle.pop_back();
                return Lease {*this, std::move(client)};
            }
        }

        UdsHttpClient::Options options;
        options.socketPath = m_options.socketPath;
        options.connectTimeout = m_options.connectTimeout;
        options.requestTimeout = m_options.requestTimeout;

        return Lease {*this, std::make_unique<UdsHttpClient>(std::move(options))};
    }

    HandlerResult HttpHandler::run(const ClaimedTask& task, const StopToken& stop)
    {
        if (stop.stopRequested())
        {
            // Deferred rather than failed: nothing was attempted, so this must not cost the row an
            // attempt. The next boot picks it up unchanged.
            return HandlerResult::of(Outcome::NotReady, "shutting down before the request was sent");
        }

        auto lease {acquire()};
        const auto result {(*lease).post(m_options.path, task.payload)};

        return registry::classifyTransportResult(result, m_options.allowTerminalFailure);
    }
} // namespace task_manager::handlers
