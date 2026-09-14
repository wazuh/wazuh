/*
 * Wazuh remoted module - Rate-limit route gate unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 14, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Two things are verified here that the limiter's own tests cannot see:
 *   - a refused request never reaches the handler (asserted on the inner handler, not only on the
 *     status code -- "it answered 429" would also be true of a gate that did the work first), and
 *   - the ABI resolution, where 0 means "no limit", the sentinel means "module default", and a
 *     zeroed struct must still mean "module default" rather than an accidental "unlimited".
 */

#include <atomic>
#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "common/requestOutcomeMetrics.hpp"
#include "endpoints/cacertsEndpoint.hpp"
#include "endpoints/rateLimitGate.hpp"
#include "enrollment/enrollmentEndpoint.hpp"
#include "remoted_module.h"

#include <wazuh_metrics/manager.hpp>

using remoted::http::EndpointRateLimiter;
using remoted::http::HttpRequest;
using remoted::http::HttpResponse;
using remoted::http::IHttpResponder;
using remoted::http::Method;
namespace ratelimit = remoted::endpoints::ratelimit;

namespace
{
    class CapturingResponder : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            m_response = std::move(response);
            m_sent = true;
        }

        void stream(remoted::http::StreamResponse) override
        {
            FAIL() << "the gate never streams";
        }

        bool sent() const
        {
            return m_sent;
        }
        const HttpResponse& response() const
        {
            return m_response;
        }

    private:
        bool m_sent {false};
        HttpResponse m_response;
    };

    std::string header(const HttpResponse& response, const std::string& name)
    {
        for (const auto& [key, value] : response.headers)
        {
            if (key == name)
            {
                return value;
            }
        }
        return {};
    }

    std::shared_ptr<const HttpRequest> requestFrom(const std::string& ip)
    {
        HttpRequest request;
        request.method = Method::Post;
        request.target = "/enroll";
        request.remoteIp = ip;
        return std::make_shared<const HttpRequest>(request);
    }

    struct Fixture
    {
        wazuh::metrics::Manager manager;
        remoted::metrics::EndpointHttpMetrics http {
            remoted::metrics::makeEndpointHttpMetrics(manager, "enroll", /*withLatency=*/false)};
        std::shared_ptr<wazuh::metrics::ICounter> rateLimited {
            manager.getOrCreateCounter("remoted.enroll.rate_limited", "test", "count")};
        std::atomic<int> handlerCalls {0};

        remoted::http::RouteHandler gate(EndpointRateLimiter::Settings settings)
        {
            auto inner = [this](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
            {
                ++handlerCalls;
                responder->send(HttpResponse::json(200, R"({"ok":true})"));
            };
            return ratelimit::wrap(inner,
                                   std::make_shared<EndpointRateLimiter>(settings),
                                   &remoted::enrollment::rateLimitedResponse,
                                   rateLimited,
                                   &http,
                                   "POST /enroll");
        }
    };

    EndpointRateLimiter::Settings settings(double rate, double burst)
    {
        EndpointRateLimiter::Settings s;
        s.ratePerSecond = rate;
        s.burst = burst;
        return s;
    }
} // namespace

TEST(RateLimitGate, AdmittedRequestsReachTheHandlerUntouched)
{
    Fixture f;
    auto handler = f.gate(settings(10.0, 10.0));

    auto responder = std::make_shared<CapturingResponder>();
    handler(requestFrom("10.0.0.1"), responder);

    EXPECT_EQ(f.handlerCalls.load(), 1);
    EXPECT_EQ(responder->response().status, 200);
    EXPECT_EQ(f.rateLimited->get(), 0U);
}

TEST(RateLimitGate, ARefusedRequestNeverReachesTheHandler)
{
    Fixture f;
    auto handler = f.gate(settings(1.0, 1.0));

    auto first = std::make_shared<CapturingResponder>();
    handler(requestFrom("10.0.0.1"), first);
    ASSERT_EQ(f.handlerCalls.load(), 1);

    auto second = std::make_shared<CapturingResponder>();
    handler(requestFrom("10.0.0.1"), second);

    // The assertion that matters: the whole point of the limit is the work NOT done -- for
    // /enroll, an authd round trip and, on a worker, a cluster round trip to the master.
    EXPECT_EQ(f.handlerCalls.load(), 1);
    EXPECT_EQ(second->response().status, 429);
}

TEST(RateLimitGate, TheAllowanceIsTheEndpointsNotTheCallers)
{
    // A second address does NOT get its own allowance: the bucket belongs to the route, so the
    // first caller's burst is the whole fleet's. This is the behaviour the configuration reference
    // warns about, asserted here so it cannot drift back to per-client by accident.
    Fixture f;
    auto handler = f.gate(settings(1.0, 1.0));

    auto first = std::make_shared<CapturingResponder>();
    handler(requestFrom("10.0.0.1"), first);
    ASSERT_EQ(first->response().status, 200);

    auto other = std::make_shared<CapturingResponder>();
    handler(requestFrom("10.0.0.2"), other);
    EXPECT_EQ(other->response().status, 429);

    // Not even a request the transport could not attribute to an address gets a fresh allowance.
    auto anonymous = std::make_shared<CapturingResponder>();
    handler(requestFrom(""), anonymous);
    EXPECT_EQ(anonymous->response().status, 429);
    EXPECT_EQ(f.handlerCalls.load(), 1);
}

TEST(RateLimitGate, TheRefusalCarriesTheEndpointsEnvelopeAndRetryAfter)
{
    Fixture f;
    auto handler = f.gate(settings(1.0, 1.0));

    auto responder = std::make_shared<CapturingResponder>();
    handler(requestFrom("10.0.0.1"), responder);
    handler(requestFrom("10.0.0.1"), responder = std::make_shared<CapturingResponder>());

    const auto& response = responder->response();
    EXPECT_EQ(response.status, 429);
    // /enroll's own nested envelope, not a shape invented by the gate.
    EXPECT_EQ(response.body,
              R"({"error":{"code":0,"message":"Enrollment is rate limited on this manager, retry later"}})");
    EXPECT_EQ(header(response, "Content-Type"), "application/json");
    EXPECT_EQ(header(response, "Retry-After"), "1");
}

TEST(RateLimitGate, CacertsKeepsItsOwnFlatEnvelope)
{
    // Same gate, different endpoint: the body comes from the route, so /cacerts answers in the flat
    // shape its 404 and 503 already use rather than borrowing /enroll's.
    wazuh::metrics::Manager manager;
    auto inner = [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
    {
        responder->send(HttpResponse::json(200, "{}"));
    };
    auto handler = ratelimit::wrap(inner,
                                   std::make_shared<EndpointRateLimiter>(settings(1.0, 1.0)),
                                   &remoted::endpoints::cacerts::rateLimitedResponse,
                                   nullptr,
                                   nullptr,
                                   "GET /cacerts");

    auto responder = std::make_shared<CapturingResponder>();
    handler(requestFrom("10.0.0.1"), responder);
    handler(requestFrom("10.0.0.1"), responder = std::make_shared<CapturingResponder>());

    EXPECT_EQ(responder->response().status, 429);
    EXPECT_EQ(responder->response().body, R"({"error":"rate_limited"})");
    EXPECT_EQ(header(responder->response(), "Retry-After"), "1");
}

TEST(RateLimitGate, ARefusalIsCountedInBothMetricFamilies)
{
    Fixture f;
    auto handler = f.gate(settings(1.0, 1.0));

    auto responder = std::make_shared<CapturingResponder>();
    handler(requestFrom("10.0.0.1"), responder);
    handler(requestFrom("10.0.0.1"), responder = std::make_shared<CapturingResponder>());

    EXPECT_EQ(f.rateLimited->get(), 1U);         // the WHY
    EXPECT_EQ(f.http.responses.c429->get(), 1U); // the WHAT
    // 429 has a cell of its own now; before this it would have fallen into "other" alongside every
    // status outside the closed set, where a rate-limited fleet would be indistinguishable from a
    // 404 storm.
    EXPECT_EQ(f.http.responses.other->get(), 0U);
    // The ADMITTED request is not counted here: the gate deliberately wraps the responder only on
    // the refusal path, because each real endpoint wraps its own (see enrollment::makeHandler) and
    // doing it in both places would count every answer twice. This fixture's stub handler does not,
    // hence the 0 -- it is the double-counting guard being asserted, not a missing count.
    EXPECT_EQ(f.http.responses.c2xx->get(), 0U);
}

TEST(RateLimitGate, ADisabledLimiterIsAPlainPassThrough)
{
    Fixture f;
    auto handler = f.gate(settings(0.0, 0.0));

    for (int i = 0; i < 50; ++i)
    {
        auto responder = std::make_shared<CapturingResponder>();
        handler(requestFrom("10.0.0.1"), responder);
        ASSERT_EQ(responder->response().status, 200);
    }
    EXPECT_EQ(f.handlerCalls.load(), 50);
    EXPECT_EQ(f.rateLimited->get(), 0U);
}

TEST(RateLimitGate, ANullLimiterIsAPassThroughToo)
{
    std::atomic<int> calls {0};
    auto inner = [&calls](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
    {
        ++calls;
        responder->send(HttpResponse::json(200, "{}"));
    };
    auto handler = ratelimit::wrap(inner, nullptr, nullptr, nullptr, nullptr, "POST /enroll");

    auto responder = std::make_shared<CapturingResponder>();
    handler(requestFrom("10.0.0.1"), responder);

    EXPECT_EQ(calls.load(), 1);
    EXPECT_EQ(responder->response().status, 200);
}

TEST(RateLimitGate, AZeroedConfigStructMeansModuleDefaultsNotUnlimited)
{
    // remoted_module_start(NULL) and every test that zeroes the struct land here. "Unlimited"
    // would be the wrong reading: rate_limit_set is what says the four fields carry real values.
    remoted_module_config_t config {};

    const auto enroll = ratelimit::buildEnrollSettings(config);
    EXPECT_DOUBLE_EQ(enroll.ratePerSecond, static_cast<double>(ratelimit::DEFAULT_ENROLL_RATE));
    EXPECT_DOUBLE_EQ(enroll.burst, ratelimit::DEFAULT_ENROLL_RATE * ratelimit::BURST_MULTIPLIER);

    const auto cacerts = ratelimit::buildCacertsSettings(config);
    EXPECT_DOUBLE_EQ(cacerts.ratePerSecond, static_cast<double>(ratelimit::DEFAULT_CACERTS_RATE));
    EXPECT_DOUBLE_EQ(cacerts.burst, ratelimit::DEFAULT_CACERTS_RATE * ratelimit::BURST_MULTIPLIER);
}

TEST(RateLimitGate, ConfiguredZeroMeansNoLimit)
{
    remoted_module_config_t config {};
    config.rate_limit_set = 1;
    config.enroll_rate_limit = 0;
    config.cacerts_rate_limit = 0;

    EXPECT_DOUBLE_EQ(ratelimit::buildEnrollSettings(config).ratePerSecond, 0.0);
    EXPECT_DOUBLE_EQ(ratelimit::buildCacertsSettings(config).ratePerSecond, 0.0);
    EXPECT_FALSE(EndpointRateLimiter {ratelimit::buildEnrollSettings(config)}.enabled());
}

TEST(RateLimitGate, TheUnsetSentinelFallsBackToTheModuleDefault)
{
    // A document that never went through the schema (so the option is simply absent) must get the
    // same answer as one that did -- which is why these constants have to equal the schema's.
    remoted_module_config_t config {};
    config.rate_limit_set = 1;
    config.enroll_rate_limit = REMOTED_MODULE_RATE_LIMIT_UNSET;
    config.cacerts_rate_limit = REMOTED_MODULE_RATE_LIMIT_UNSET;

    EXPECT_DOUBLE_EQ(ratelimit::buildEnrollSettings(config).ratePerSecond,
                     static_cast<double>(ratelimit::DEFAULT_ENROLL_RATE));
    EXPECT_DOUBLE_EQ(ratelimit::buildCacertsSettings(config).ratePerSecond,
                     static_cast<double>(ratelimit::DEFAULT_CACERTS_RATE));
}

TEST(RateLimitGate, ConfiguredValuesAreCarriedThroughAndTheBucketIsDerived)
{
    remoted_module_config_t config {};
    config.rate_limit_set = 1;
    config.enroll_rate_limit = 5;
    config.cacerts_rate_limit = 7;

    // The rate is the only configured number; the bucket depth follows from it, so an operator
    // cannot set a burst that contradicts the rate.
    const auto enroll = ratelimit::buildEnrollSettings(config);
    EXPECT_DOUBLE_EQ(enroll.ratePerSecond, 5.0);
    EXPECT_DOUBLE_EQ(enroll.burst, 10.0);

    // The two routes are independent: one setting each, never a shared bucket.
    const auto cacerts = ratelimit::buildCacertsSettings(config);
    EXPECT_DOUBLE_EQ(cacerts.ratePerSecond, 7.0);
    EXPECT_DOUBLE_EQ(cacerts.burst, 14.0);
}
