/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_UPGRADE_API_HPP
#define _TASK_MANAGER_UPGRADE_API_HPP

#include "upgradeService.hpp"

#include <uds_http_server/IUdsHttpServer.hpp>

#include <functional>
#include <memory>

namespace task_manager::upgrade
{
    /// @brief Routes. POST-only and exact-match, like every other route on this socket.
    constexpr const char* UPGRADE_ROUTE {"/v1/agents/upgrade"};
    constexpr const char* UPGRADE_CUSTOM_ROUTE {"/v1/agents/upgrade-custom"};

    /**
     * @brief The two upgrade routes.
     *
     * TWO THINGS ABOUT THESE ROUTES ARE UNUSUAL, and both are deliberate.
     *
     * 1. THEY ANSWER 200 FOR EVERYTHING, including a body that would not parse. The response is a
     *    per-agent envelope the Server API reads by adding 1810 to each entry's code, and its HTTP
     *    client raises WazuhError(2019) on any non-2xx -- so a 400 would replace a precise
     *    per-agent message with a generic transport error. The framed socket these routes replace
     *    had no status code at all, and the envelope carried everything; that is preserved. This is
     *    why they cannot use ApiHandlers::route(), whose ApiResponse::error() shape is the module's
     *    normal one.
     *
     * 2. SHEDDING IS ALSO A 200, carrying error 4 (task manager communication) for every agent.
     *    The transport's Control-class contract suggests a bounded queue answering 503, and the
     *    signal is the same -- but the Server API already reacts to error 4 by HALVING the chunk
     *    and retrying, which is exactly the backpressure wanted, whereas a 503 raises and loses the
     *    whole chunk. Same meaning, in the dialect the peer already speaks.
     *
     * The handlers themselves parse and return; the work happens on UpgradeService's pool. Parsing
     * on the I/O thread is deliberate: it is pure and takes microseconds, so a malformed body is
     * rejected without ever consuming a queue slot.
     */
    class UpgradeApi
    {
    public:
        /**
         * @brief @param enabled Mirrors `<task-manager><upgrade_enabled>`.
         *
         * When false the routes still exist and still answer -- they simply refuse every agent with
         * UnknownError. The retired module expressed "disabled" by never binding its socket, which
         * the Server API saw as a connection failure; with the socket now shared there is nothing to
         * leave unbound, so the refusal has to be explicit rather than implied.
         */
        UpgradeApi(UpgradeService& service, std::function<Timestamp()> clock, bool enabled);

        void handleUpgrade(std::shared_ptr<const wazuh::uds_http::HttpRequest> request,
                           std::shared_ptr<wazuh::uds_http::IHttpResponder> responder);

        void handleUpgradeCustom(std::shared_ptr<const wazuh::uds_http::HttpRequest> request,
                                 std::shared_ptr<wazuh::uds_http::IHttpResponder> responder);

    private:
        /// @brief Shared body of both routes; `custom` picks which parser runs.
        void handle(const std::shared_ptr<const wazuh::uds_http::HttpRequest>& request,
                    const std::shared_ptr<wazuh::uds_http::IHttpResponder>& responder,
                    bool custom);

        UpgradeService& m_service;
        std::function<Timestamp()> m_clock;
        bool m_enabled {true};
    };
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_API_HPP
