/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Unit-tests the GET /metrics route policy (D18): the pinned contract (verb/path), the JSON dump
// of a populated registry, and the 503 when the manager is gone.
#include "endpoints/metricsEndpoint.hpp"

#include "common/metricNames.hpp"

#include <wazuh_metrics/manager.hpp>

#include <json.hpp>

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>

using invsync::http::HttpRequest;
using invsync::http::HttpResponse;
using invsync::http::IHttpResponder;
namespace metrics_endpoint = invsync::endpoints::metrics;

namespace
{
    class CapturingResponder final : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            m_response = std::move(response);
            m_sent = true;
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
        HttpResponse m_response {0, "", {}};
        bool m_sent {false};
    };

    std::shared_ptr<const HttpRequest> makeRequest()
    {
        auto request = std::make_shared<HttpRequest>();
        request->method = metrics_endpoint::method();
        request->target = metrics_endpoint::path();
        return request;
    }
} // namespace

TEST(MetricsEndpointTest, ContractIsPinned)
{
    // The facade registers exactly this; a silent drift breaks operators' curl one-liners.
    EXPECT_EQ(invsync::http::Method::Get, metrics_endpoint::method());
    EXPECT_STREQ("/metrics", metrics_endpoint::path());
}

TEST(MetricsEndpointTest, DumpsThePopulatedRegistry)
{
    const auto manager = std::make_shared<wazuh::metrics::Manager>();
    manager->getOrCreateCounter(invsync::metrics::BULK_FLUSHES, "Group-commit flushes", "count")->add(7);
    manager->getOrCreateHistogram(invsync::metrics::VD_SCAN_DURATION)->observe(1000);

    const auto handler = metrics_endpoint::makeHandler(manager);
    const auto responder = std::make_shared<CapturingResponder>();
    handler(makeRequest(), responder);

    ASSERT_TRUE(responder->sent());
    EXPECT_EQ(200, responder->response().status);

    const auto document = nlohmann::json::parse(responder->response().body);
    EXPECT_EQ("inventory_sync_server", document.at("name").get<std::string>());
    ASSERT_TRUE(document.at("metrics").is_array());

    bool sawFlushes {false};
    bool sawScanDuration {false};
    for (const auto& entry : document.at("metrics"))
    {
        if (entry.at("name") == invsync::metrics::BULK_FLUSHES)
        {
            sawFlushes = true;
            EXPECT_EQ("counter", entry.at("type").get<std::string>());
            EXPECT_EQ(7, entry.at("value").get<int>());
            EXPECT_EQ("count", entry.at("unit").get<std::string>());
        }
        if (entry.at("name") == invsync::metrics::VD_SCAN_DURATION)
        {
            sawScanDuration = true;
            EXPECT_EQ("histogram", entry.at("type").get<std::string>());
            EXPECT_EQ(1, entry.at("summary").at("count").get<int>());
        }
    }
    EXPECT_TRUE(sawFlushes);
    EXPECT_TRUE(sawScanDuration);
}

TEST(MetricsEndpointTest, AnswersServiceUnavailableWhenTheManagerIsGone)
{
    invsync::http::RouteHandler handler;
    {
        const auto manager = std::make_shared<wazuh::metrics::Manager>();
        handler = metrics_endpoint::makeHandler(manager);
    } // the weak capture expires here

    const auto responder = std::make_shared<CapturingResponder>();
    handler(makeRequest(), responder);

    ASSERT_TRUE(responder->sent());
    EXPECT_EQ(503, responder->response().status);
}
