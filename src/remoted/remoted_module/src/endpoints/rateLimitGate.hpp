/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 14, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_RATE_LIMIT_GATE_HPP
#define _REMOTED_ENDPOINTS_RATE_LIMIT_GATE_HPP

/**
 * @file rateLimitGate.hpp
 * @brief Wraps a route handler in that endpoint's own rate limit (EndpointRateLimiter).
 *
 * A wrapper rather than a check inside each handler, for the same reason MeteredResponder is a
 * decorator: the gate must run before anything the handler does -- decoding a body, reaching
 * authd, reading the CA snapshot -- and a guard clause at the top of a handler is one refactor
 * away from being stepped over. Wrapping at route registration makes "nothing in this route runs
 * until the limiter says so" structural.
 *
 * The 429 body comes from the caller, not from here: /enroll answers in the nested
 * `{"error":{"code","message"}}` envelope and /cacerts in the flat `{"error":"..."}` one, and the
 * gate has no business choosing between them. It owns only `Retry-After`, which is not an envelope
 * question but the limiter's own refill time.
 *
 * Accounting: a refused request is counted in the endpoint's own `remoted.<endpoint>.rate_limited`
 * counter (the WHY) and, through the same MeteredResponder the handler would have used, in
 * `remoted.http.<endpoint>.responses.429` (the WHAT) -- so a 429 is visible in exactly the two
 * families every other answer of that endpoint lands in.
 */

#include "common/requestOutcomeMetrics.hpp"
#include "http_server/IHttpServer.hpp"
#include "http_server/endpointRateLimiter.hpp"
#include "remoted_module.h"

#include <functional>
#include <memory>

#include <wazuh_metrics/iManager.hpp>

namespace remoted::endpoints::ratelimit
{
    /**
     * @brief The module's own rate defaults, one per endpoint.
     *
     * They MUST stay equal to the `remote.https.*_rate_limit` defaults in
     * src/shared_modules/manager_config/schema/wazuh-manager.schema.json. The schema fills those
     * into every effective document, so these values are what a manager whose document did NOT go
     * through the schema gets -- and the two answering differently would mean the same
     * unconfigured manager is limited differently depending on how its configuration was loaded.
     *
     * /enroll is allowed the higher rate of the two even though it is the more expensive route:
     * every agent in a fleet must pass through it at least once (a bootstrap, or a mass
     * re-enrollment after a credential rotation), while /cacerts is fetched once per agent and only
     * to bootstrap trust.
     */
    constexpr int DEFAULT_ENROLL_RATE {100};
    constexpr int DEFAULT_CACERTS_RATE {50};

    /**
     * @brief Bucket depth, as a multiple of the configured rate.
     *
     * Deliberately NOT a configuration option. Real traffic does not arrive evenly spaced -- a
     * hundred agents coming back after an outage arrive in the same instant, not one every 10 ms --
     * so the bucket has to hold more than one second's worth or a perfectly acceptable load would
     * be refused on arrival pattern alone. Two seconds' worth absorbs that without raising the
     * sustained ceiling, and deriving it keeps the operator with ONE number per endpoint to reason
     * about instead of a rate/burst pair whose interaction is easy to get wrong.
     */
    constexpr double BURST_MULTIPLIER {2.0};

    /// POST /enroll's limiter settings, resolved from the C ABI (rate_limit_set / the UNSET
    /// sentinel / 0 meaning "no limit" -- see remoted_module.h).
    remoted::http::EndpointRateLimiter::Settings buildEnrollSettings(const remoted_module_config_t& config);

    /// GET /cacerts' limiter settings, same resolution.
    remoted::http::EndpointRateLimiter::Settings buildCacertsSettings(const remoted_module_config_t& config);

    /**
     * @brief Build a handler that admits through @p limiter and otherwise answers 429.
     *
     * @param inner       The route's real handler. Untouched and unaware of the limiter.
     * @param limiter     Shared with the facade, which publishes its diagnostics as pull metrics.
     *                    A disabled limiter (rate 0) makes this a thin pass-through.
     * @param rejection   Builds the 429 body in the endpoint's own error envelope. `Retry-After`
     *                    is added by the gate; the factory must not set it.
     * @param rejected    The endpoint's `remoted.<endpoint>.rate_limited` counter. May be null.
     * @param httpMetrics The endpoint's `remoted.http.<endpoint>.responses.*` family, so a 429
     *                    lands in the same place every other status of this route does. May be null.
     * @param route       Route name for the throttled log line ("POST /enroll", "GET /cacerts").
     */
    remoted::http::RouteHandler wrap(remoted::http::RouteHandler inner,
                                     std::shared_ptr<remoted::http::EndpointRateLimiter> limiter,
                                     std::function<remoted::http::HttpResponse()> rejection,
                                     std::shared_ptr<wazuh::metrics::ICounter> rejected,
                                     const remoted::metrics::EndpointHttpMetrics* httpMetrics,
                                     const char* route);

} // namespace remoted::endpoints::ratelimit

#endif // _REMOTED_ENDPOINTS_RATE_LIMIT_GATE_HPP
