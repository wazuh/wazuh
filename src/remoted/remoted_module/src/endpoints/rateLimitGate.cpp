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

#include "rateLimitGate.hpp"

#include "common/logThrottle.hpp"

#include "loggerHelper.h"

#include <string>
#include <utility>

namespace remoted::endpoints::ratelimit
{
    namespace
    {
        constexpr auto RATE_LIMIT_LOGTAG {"wazuh-manager-remoted:endpoints"};

        const LogFn& logFn()
        {
            static const LogFn instance {LogFn {RATE_LIMIT_LOGTAG}.compose("ratelimit")};
            return instance;
        }

        /// Resolves one rate from the ABI's three-way encoding: the whole group unset, this field
        /// unset, or a real value -- 0 included, which means "no limit".
        double resolveRate(int configured, bool groupSet, int moduleDefault)
        {
            if (!groupSet || configured == REMOTED_MODULE_RATE_LIMIT_UNSET)
            {
                return static_cast<double>(moduleDefault);
            }
            // Any other negative value would be a corrupted struct; treating it as the default is
            // the same fail-to-the-documented-behaviour the rest of this ABI's <=0 fields apply.
            return configured < 0 ? static_cast<double>(moduleDefault) : static_cast<double>(configured);
        }
    } // namespace

    remoted::http::EndpointRateLimiter::Settings buildEnrollSettings(const remoted_module_config_t& config)
    {
        const auto rate = resolveRate(config.enroll_rate_limit, config.rate_limit_set != 0, DEFAULT_ENROLL_RATE);
        return remoted::http::EndpointRateLimiter::Settings {rate, rate * BURST_MULTIPLIER};
    }

    remoted::http::EndpointRateLimiter::Settings buildCacertsSettings(const remoted_module_config_t& config)
    {
        const auto rate = resolveRate(config.cacerts_rate_limit, config.rate_limit_set != 0, DEFAULT_CACERTS_RATE);
        return remoted::http::EndpointRateLimiter::Settings {rate, rate * BURST_MULTIPLIER};
    }

    remoted::http::RouteHandler wrap(remoted::http::RouteHandler inner,
                                     std::shared_ptr<remoted::http::EndpointRateLimiter> limiter,
                                     std::function<remoted::http::HttpResponse()> rejection,
                                     std::shared_ptr<wazuh::metrics::ICounter> rejected,
                                     const remoted::metrics::EndpointHttpMetrics* httpMetrics,
                                     const char* route)
    {
        // Nothing to gate: hand back the original handler so a disabled limit costs literally
        // nothing per request -- not even the wrapper's own indirection.
        if (!limiter || !limiter->enabled())
        {
            return inner;
        }

        // One throttle per gate, not a file-static: /enroll and /cacerts must not silence each
        // other's line, and a static would also outlive a restart of the module within one process.
        const auto throttle = std::make_shared<remoted::common::LogThrottle>();
        const std::string routeName {route != nullptr ? route : ""};
        const auto retryAfter = std::to_string(limiter->retryAfterSeconds());

        return [inner = std::move(inner),
                limiter = std::move(limiter),
                rejection = std::move(rejection),
                rejected = std::move(rejected),
                httpMetrics,
                throttle,
                routeName,
                retryAfter](std::shared_ptr<const remoted::http::HttpRequest> request,
                            std::shared_ptr<remoted::http::IHttpResponder> responder)
        {
            // The caller is deliberately not consulted: the bucket belongs to the endpoint, so the
            // request's address, credential and body are all irrelevant to this decision -- which
            // is also why the decision can be made before any of them is read.
            if (limiter->allow())
            {
                inner(std::move(request), std::move(responder));
                return;
            }

            if (rejected)
            {
                rejected->add();
            }

            // Wrapped only on the refusal path: on the admitted path the handler wraps the
            // responder itself, and doing it here too would count every response twice.
            if (httpMetrics != nullptr)
            {
                responder = std::make_shared<remoted::metrics::MeteredResponder>(std::move(responder), *httpMetrics);
            }

            auto response =
                rejection ? rejection() : remoted::http::HttpResponse::json(429, R"({"error":"too_many_requests"})");
            response.headers.emplace_back("Retry-After", retryAfter);
            responder->send(std::move(response));

            if (const auto decision = throttle->record())
            {
                LOGFN_WARN(logFn(),
                           "%s refused %llu request(s) in the last %d s with 429: the endpoint is being asked "
                           "faster than its configured rate, which is a ceiling for this whole node and not "
                           "a per-agent one. Raise the matching 'remote.https' rate if this load is legitimate.",
                           routeName.c_str(),
                           static_cast<unsigned long long>(decision.total),
                           remoted::common::LogThrottle::kDefaultWindowSeconds);
            }
        };
    }

} // namespace remoted::endpoints::ratelimit
