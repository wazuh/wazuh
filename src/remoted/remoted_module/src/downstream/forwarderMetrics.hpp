/*
 * Wazuh remoted module - Downstream forwarder metrics
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_DOWNSTREAM_FORWARDER_METRICS_HPP
#define _REMOTED_DOWNSTREAM_FORWARDER_METRICS_HPP

/**
 * @file forwarderMetrics.hpp
 * @brief The downstream failure-taxonomy catalog (`remoted.forwarder.*`) on the shared
 *        `wazuh_metrics` registry.
 *
 * Same shape as control/metrics.hpp: the counters live in the facade's metric manager, this
 * struct only caches the resolved shared_ptrs (resolve once via makeForwarderMetrics(), then
 * every inc* is a single relaxed atomic op), and a default-constructed struct is the null
 * object that counts nothing. NEVER exposed through the public HTTPS endpoint.
 *
 * One AGGREGATE family, not per downstream service: the per-endpoint
 * `remoted.http.<endpoint>.responses.503` counters already say WHICH path is failing; these
 * say WHY -- which timeout knob fired, transport vs protocol garbage, a downstream 5xx, or a
 * route contract mismatch between remoted and the service. Each counter sits at the exact
 * classification site the forwarder's throttled failure logs already use, so the metric and
 * the log line can never disagree about the cause.
 */

#include "IDownstreamClient.hpp" // remoted::downstream::DownstreamError

#include <wazuh_metrics/iManager.hpp>

#include <array>
#include <cstddef>
#include <memory>

namespace remoted::downstream
{
    // The remoted.forwarder.* failure catalog. The error.* names mirror toString(DownstreamError).
    constexpr auto METRIC_FWD_DOWNSTREAM_5XX {"remoted.forwarder.downstream_5xx"};
    constexpr auto METRIC_FWD_ROUTE_MISMATCH {"remoted.forwarder.route_mismatch"};
    constexpr auto METRIC_FWD_ERROR_CONNECT {"remoted.forwarder.error.connect"};
    constexpr auto METRIC_FWD_ERROR_CONNECT_TIMEOUT {"remoted.forwarder.error.connect_timeout"};
    constexpr auto METRIC_FWD_ERROR_WRITE_TIMEOUT {"remoted.forwarder.error.write_timeout"};
    constexpr auto METRIC_FWD_ERROR_RESPONSE_TIMEOUT {"remoted.forwarder.error.response_timeout"};
    constexpr auto METRIC_FWD_ERROR_TRANSPORT {"remoted.forwarder.error.transport"};
    constexpr auto METRIC_FWD_ERROR_PROTOCOL {"remoted.forwarder.error.protocol"};
    constexpr auto METRIC_FWD_ERROR_RESPONSE_TOO_LARGE {"remoted.forwarder.error.response_too_large"};

    /// Number of DownstreamError enumerators (None included) -- sizes the indexed counter array.
    constexpr std::size_t kDownstreamErrorCount = static_cast<std::size_t>(DownstreamError::ResponseTooLarge) + 1;

    /**
     * @brief The downstream failure counter set, pre-resolved from one manager.
     *
     * byError is indexed by static_cast<size_t>(DownstreamError), with slot 0 (None) holding
     * the downstream-5xx counter -- the same convention as the forwarder's throttle array (a
     * downstream 5xx arrives with error == None), so the hot path selects a counter exactly
     * like it selects a throttle. Default-constructed (all null) it counts nothing -- the
     * null-object the tests rely on.
     */
    struct ForwarderMetrics
    {
        std::array<std::shared_ptr<wazuh::metrics::ICounter>, kDownstreamErrorCount> byError;
        std::shared_ptr<wazuh::metrics::ICounter> routeMismatch; ///< Downstream answered 404/405.
    };

    /// Resolves the remoted.forwarder.* failure family on @p manager (creating it on first
    /// call; totals carry over on later calls because getOrCreateCounter dedupes by name).
    inline ForwarderMetrics makeForwarderMetrics(wazuh::metrics::IManager& manager)
    {
        ForwarderMetrics m;
        m.byError[static_cast<std::size_t>(DownstreamError::None)] = manager.getOrCreateCounter(
            METRIC_FWD_DOWNSTREAM_5XX, "Downstream answered a 5xx (relayed to the agent as 503)", "count");
        m.byError[static_cast<std::size_t>(DownstreamError::Connect)] = manager.getOrCreateCounter(
            METRIC_FWD_ERROR_CONNECT, "Could not connect to the downstream socket (nothing listening)", "count");
        m.byError[static_cast<std::size_t>(DownstreamError::ConnectTimeout)] = manager.getOrCreateCounter(
            METRIC_FWD_ERROR_CONNECT_TIMEOUT, "'remoted.downstream_connect_timeout' elapsed", "count");
        m.byError[static_cast<std::size_t>(DownstreamError::WriteTimeout)] = manager.getOrCreateCounter(
            METRIC_FWD_ERROR_WRITE_TIMEOUT, "'remoted.downstream_write_timeout' elapsed (peer not reading)", "count");
        m.byError[static_cast<std::size_t>(DownstreamError::ResponseTimeout)] = manager.getOrCreateCounter(
            METRIC_FWD_ERROR_RESPONSE_TIMEOUT,
            "'remoted.downstream_response_timeout' (or 'remoted.downstream_stateful_response_timeout' for /stateful) "
            "elapsed",
            "count");
        m.byError[static_cast<std::size_t>(DownstreamError::Transport)] = manager.getOrCreateCounter(
            METRIC_FWD_ERROR_TRANSPORT, "Downstream socket read/write error or unexpected close", "count");
        m.byError[static_cast<std::size_t>(DownstreamError::Protocol)] = manager.getOrCreateCounter(
            METRIC_FWD_ERROR_PROTOCOL, "The downstream response was not valid HTTP", "count");
        m.byError[static_cast<std::size_t>(DownstreamError::ResponseTooLarge)] =
            manager.getOrCreateCounter(METRIC_FWD_ERROR_RESPONSE_TOO_LARGE,
                                       "Downstream response body over 'remoted.downstream_max_response_body_size'",
                                       "count");
        m.routeMismatch = manager.getOrCreateCounter(
            METRIC_FWD_ROUTE_MISMATCH,
            "Downstream answered 404/405: mismatched route contract (versions/configuration)",
            "count");
        return m;
    }

    /// Bumps the counter for a completed downstream call that failed with @p error
    /// (error != None), or -- through slot None -- for a downstream 5xx. Null-safe.
    inline void incDownstreamFailure(const ForwarderMetrics& m, DownstreamError error)
    {
        const auto index = static_cast<std::size_t>(error);
        if (index < m.byError.size() && m.byError[index])
        {
            m.byError[index]->add();
        }
    }

    inline void incRouteMismatch(const ForwarderMetrics& m)
    {
        if (m.routeMismatch)
        {
            m.routeMismatch->add();
        }
    }

} // namespace remoted::downstream

#endif // _REMOTED_DOWNSTREAM_FORWARDER_METRICS_HPP
