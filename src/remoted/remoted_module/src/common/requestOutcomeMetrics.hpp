/*
 * Wazuh remoted module - Per-endpoint HTTP response metrics
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_COMMON_REQUEST_OUTCOME_METRICS_HPP
#define _REMOTED_COMMON_REQUEST_OUTCOME_METRICS_HPP

/**
 * @file requestOutcomeMetrics.hpp
 * @brief The per-endpoint response catalog (`remoted.http.<endpoint>.*`) on the shared
 *        `wazuh_metrics` registry.
 *
 * Same shape as control/metrics.hpp: the metrics live in the facade's metric manager, these
 * structs only cache the resolved shared_ptrs (resolve once via make() -- cold path -- then
 * every count()/observe is a single relaxed atomic op), and a default-constructed struct is
 * the null object that counts nothing. NEVER exposed through the public HTTPS endpoint.
 *
 * One shared closed status set x one prefix per endpoint (the inventory sync server's
 * RequestCounters pattern): the hot path selects a pre-resolved counter by switch and never
 * formats a metric name. Some cells are structurally zero for a given endpoint (e.g.
 * /stateless never answers 409); they are kept so every endpoint reports the same vocabulary
 * and a scraper's columns stay uniform.
 *
 * Accounting boundary: a request shed by the in-flight byte budget is refused on the
 * transport's I/O thread BEFORE any route handler runs, so it is counted ONLY by
 * `remoted.server.budget.rejected.total` -- it never reaches these per-endpoint cells. A 503
 * shed by the deferred-work limiter happens inside the endpoint's forward path and therefore
 * counts here (responses.503) AND in `remoted.forwarder.deferred.rejected.total`.
 */

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

#include "http_server/IHttpServer.hpp" // remoted::http::IHttpResponder

#include <wazuh_metrics/iManager.hpp>

namespace remoted::metrics
{
    // The remoted.http.* name catalog is built from these pieces; every name is formatted once,
    // inside make() (cold), never per request.
    constexpr auto HTTP_METRIC_PREFIX {"remoted.http."};

    /**
     * @brief The `remoted.http.<endpoint>.responses.<code>` counter family, pre-resolved.
     *
     * One counter per member of a closed status set, selected by switch. Each request is
     * counted at the single place its response is sent -- the forwarder's delivery task, the
     * forward()-time limiter shed, or the handler's own pre-forward rejection (empty body,
     * payload identity) -- so a request is never counted twice, and the family reads as
     * "every response this endpoint sent". Rejections the AUTH GATEWAY produces (401s, 413,
     * bad encoding) happen before any handler runs and are therefore visible only in
     * remoted.auth.reject.*: that family is the "why", this one is the "what the agent got".
     *
     * Default-constructed (all null) it counts nothing -- the null-object the tests rely on.
     */
    struct ResponseCounters
    {
        std::shared_ptr<wazuh::metrics::ICounter> c2xx; ///< Any success (202 for /stateless, 200 elsewhere).
        std::shared_ptr<wazuh::metrics::ICounter> c400;
        std::shared_ptr<wazuh::metrics::ICounter> c403;
        std::shared_ptr<wazuh::metrics::ICounter> c409;
        std::shared_ptr<wazuh::metrics::ICounter> c413;
        std::shared_ptr<wazuh::metrics::ICounter> c500; ///< Includes "the PostProcessor threw" fallback.
        std::shared_ptr<wazuh::metrics::ICounter> c503; ///< Downstream failures and limiter sheds -- NOT budget sheds.
        std::shared_ptr<wazuh::metrics::ICounter> other;

        /// Resolves the family for @p endpoint (e.g. "stateless") on @p manager (creating it on
        /// first call; totals carry over on later calls because getOrCreateCounter dedupes by name).
        static ResponseCounters make(wazuh::metrics::IManager& manager, const char* endpoint)
        {
            const std::string prefix = std::string {HTTP_METRIC_PREFIX} + endpoint + ".responses.";
            const std::string description = std::string {"POST /"} + endpoint + " responses sent with this status";
            const auto counter = [&](const char* code)
            {
                return manager.getOrCreateCounter(prefix + code, description, "count");
            };
            return ResponseCounters {counter("2xx"),
                                     counter("400"),
                                     counter("403"),
                                     counter("409"),
                                     counter("413"),
                                     counter("500"),
                                     counter("503"),
                                     counter("other")};
        }

        /// Counts one sent response by status. Null-safe; never formats a name.
        void count(int status) const
        {
            const auto& counter = [this, status]() -> const std::shared_ptr<wazuh::metrics::ICounter>&
            {
                if (status >= 200 && status < 300)
                {
                    return c2xx;
                }
                switch (status)
                {
                    case 400: return c400;
                    case 403: return c403;
                    case 409: return c409;
                    case 413: return c413;
                    case 500: return c500;
                    case 503: return c503;
                    default: return other;
                }
            }();
            if (counter)
            {
                counter->add();
            }
        }
    };

    /**
     * @brief One forwarded endpoint's full HTTP metric set: response counters plus an optional
     *        end-to-end latency histogram.
     *
     * The latency histogram (`remoted.http.<endpoint>.latency`, microseconds, gateway receipt
     * to response delivery) is resolved only for the endpoints whose latency actually answers a
     * tuning question (/stateless, /stateful); elsewhere it stays null and observeLatency() is
     * a no-op. Default-constructed the whole struct is the null object.
     */
    struct EndpointHttpMetrics
    {
        ResponseCounters responses;
        std::shared_ptr<wazuh::metrics::IHistogram> latency;
    };

    /// Resolves the remoted.http.<endpoint>.* family. @p withLatency additionally resolves the
    /// latency histogram (see EndpointHttpMetrics).
    inline EndpointHttpMetrics
    makeEndpointHttpMetrics(wazuh::metrics::IManager& manager, const char* endpoint, bool withLatency)
    {
        EndpointHttpMetrics m {ResponseCounters::make(manager, endpoint), nullptr};
        if (withLatency)
        {
            m.latency = manager.getOrCreateHistogram(std::string {HTTP_METRIC_PREFIX} + endpoint + ".latency",
                                                     std::string {"POST /"} + endpoint +
                                                         " end-to-end time, request receipt to response delivery",
                                                     "microseconds");
        }
        return m;
    }

    /// Records one end-to-end request duration. Null-safe (no-op without a histogram).
    inline void observeLatency(const EndpointHttpMetrics& m, std::uint64_t micros)
    {
        if (m.latency)
        {
            m.latency->observe(micros);
        }
    }

    /**
     * @brief Responder decorator that counts the status it delivers and times the request.
     *
     * For a handler that answers from several places -- and especially one whose final answer
     * arrives on someone else's thread (a downstream callback) -- instrumenting each send() site
     * is both repetitive and fragile: the next branch added upstream silently escapes the
     * accounting. Wrapping the responder once at handler entry makes the measurement structural:
     * every response, on every path, is counted exactly once by the send-once guarantee of the
     * responder underneath, and timed from the moment the handler received the request.
     *
     * Cheap by construction: one steady_clock read per request plus, per response, one relaxed
     * atomic add and one histogram observation. Null-safe -- a default-constructed
     * EndpointHttpMetrics counts nothing.
     */
    class MeteredResponder final : public remoted::http::IHttpResponder
    {
    public:
        MeteredResponder(std::shared_ptr<remoted::http::IHttpResponder> inner, const EndpointHttpMetrics& metrics)
            : m_inner {std::move(inner)}
            , m_metrics {metrics}
            , m_receivedAt {std::chrono::steady_clock::now()}
        {
        }

        void send(remoted::http::HttpResponse response) override
        {
            m_metrics.responses.count(response.status);
            observeLatency(m_metrics,
                           static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                                          std::chrono::steady_clock::now() - m_receivedAt)
                                                          .count()));
            m_inner->send(std::move(response));
        }

        /// Forwarded untouched: a streamed body is not one of the outcomes this family models,
        /// and re-routing it through send() would change what the client receives.
        void stream(remoted::http::StreamResponse response) override
        {
            m_inner->stream(std::move(response));
        }

    private:
        std::shared_ptr<remoted::http::IHttpResponder> m_inner;
        EndpointHttpMetrics m_metrics;
        std::chrono::steady_clock::time_point m_receivedAt;
    };

} // namespace remoted::metrics

#endif // _REMOTED_COMMON_REQUEST_OUTCOME_METRICS_HPP
