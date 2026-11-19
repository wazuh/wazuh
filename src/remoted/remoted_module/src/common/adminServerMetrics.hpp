/*
 * Wazuh remoted module - local admin server metrics
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_COMMON_ADMIN_SERVER_METRICS_HPP
#define _REMOTED_COMMON_ADMIN_SERVER_METRICS_HPP

/**
 * @file adminServerMetrics.hpp
 * @brief Names of the local admin socket's transport pulls (`remoted.admin.server.*`) on the shared
 *        `wazuh_metrics` registry.
 *
 * Registered by the facade (registerAdminTransportDiagnostics()) over IUdsHttpServer::diagnostics():
 * the same vocabulary every uds_http_server consumer reports -- seven levels plus four shed counters.
 * The sessions.* cells are one per RouteClass member (a closed set, each spelled whole).
 */

namespace remoted::metrics
{
    constexpr auto METRIC_ADMIN_BUDGET_AVAILABLE_BYTES {"remoted.admin.server.budget.available.bytes"};
    constexpr auto METRIC_ADMIN_BUDGET_INFLIGHT_BYTES {"remoted.admin.server.budget.inflight.bytes"};
    constexpr auto METRIC_ADMIN_BUDGET_INFLIGHT_REQUESTS {"remoted.admin.server.budget.inflight.requests"};
    constexpr auto METRIC_ADMIN_SESSIONS_LIVE {"remoted.admin.server.sessions.live"};
    constexpr auto METRIC_ADMIN_SESSIONS_DATA {"remoted.admin.server.sessions.data"};
    constexpr auto METRIC_ADMIN_SESSIONS_CONTROL {"remoted.admin.server.sessions.control"};
    constexpr auto METRIC_ADMIN_SESSIONS_LIVENESS {"remoted.admin.server.sessions.liveness"};
    constexpr auto METRIC_ADMIN_REJECTED_BUDGET {"remoted.admin.server.rejected.budget"};
    constexpr auto METRIC_ADMIN_REJECTED_SESSION_CAP {"remoted.admin.server.rejected.session_cap"};
    constexpr auto METRIC_ADMIN_REJECTED_SHUTDOWN {"remoted.admin.server.rejected.shutdown"};
    constexpr auto METRIC_ADMIN_REJECTED_NO_RESPONSE {"remoted.admin.server.rejected.no_response"};
} // namespace remoted::metrics

#endif // _REMOTED_COMMON_ADMIN_SERVER_METRICS_HPP
