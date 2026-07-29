/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "endpoints/syncEndpoint.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string>

using invsync::http::HttpRequest;
using invsync::http::HttpResponse;
using invsync::http::IHttpResponder;
using invsync::http::Method;

namespace
{
    /// Captures whatever the handler sends, so the endpoint can be tested with no socket at all.
    class CapturingResponder final : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            ++sendCount;
            captured = std::move(response);
        }

        int sendCount {0};
        std::optional<HttpResponse> captured;
    };

    std::shared_ptr<const HttpRequest> requestWithBody(std::string body)
    {
        auto request = std::make_shared<HttpRequest>();
        request->method = Method::Post;
        request->target = "/inventory/sync";
        request->body = std::move(body);
        return request;
    }
} // namespace

/**
 * The path and verb are a wire contract with remoted's downstream configuration, which lands in a
 * separate change. Pinning them here is what turns a silent drift into a failing test.
 */
TEST(SyncEndpointTest, PathAndMethodAreStable)
{
    EXPECT_EQ(Method::Post, invsync::endpoints::sync::method());
    EXPECT_STREQ("/inventory/sync", invsync::endpoints::sync::path());
}

TEST(SyncEndpointTest, AcceptedRequestYields202)
{
    auto handler = invsync::endpoints::sync::makeHandler();
    auto responder = std::make_shared<CapturingResponder>();

    handler(requestWithBody("some-payload"), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(202, responder->captured->status);
    EXPECT_EQ(R"({"status":"accepted"})", responder->captured->body);
}

// The stub validates nothing on purpose, so an empty body is accepted exactly like any other.
TEST(SyncEndpointTest, EmptyBodyStillYields202)
{
    auto handler = invsync::endpoints::sync::makeHandler();
    auto responder = std::make_shared<CapturingResponder>();

    handler(requestWithBody(""), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(202, responder->captured->status);
}

TEST(SyncEndpointTest, ResponseIsJson)
{
    auto handler = invsync::endpoints::sync::makeHandler();
    auto responder = std::make_shared<CapturingResponder>();

    handler(requestWithBody("x"), responder);

    ASSERT_TRUE(responder->captured.has_value());
    bool hasJsonContentType {false};
    for (const auto& [name, value] : responder->captured->headers)
    {
        if (name == "Content-Type" && value == "application/json")
        {
            hasJsonContentType = true;
        }
    }
    EXPECT_TRUE(hasJsonContentType);
}

// The transport's exactly-once contract only holds if handlers respect it too.
TEST(SyncEndpointTest, SendIsCalledExactlyOnce)
{
    auto handler = invsync::endpoints::sync::makeHandler();
    auto responder = std::make_shared<CapturingResponder>();

    handler(requestWithBody("x"), responder);

    EXPECT_EQ(1, responder->sendCount);
}

// A null request must not crash the handler: the transport never passes one today, but the stub is
// the seam future code grows from, and a null deref here would be a daemon crash.
TEST(SyncEndpointTest, NullRequestIsToleratedAndStillAnswered)
{
    auto handler = invsync::endpoints::sync::makeHandler();
    auto responder = std::make_shared<CapturingResponder>();

    handler(nullptr, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(202, responder->captured->status);
}

// The handler must not retain the payload: it is a stub that discards, and holding the request would
// silently pin the transport's byte reservation for the whole deferral.
TEST(SyncEndpointTest, HandlerDoesNotRetainTheRequest)
{
    auto handler = invsync::endpoints::sync::makeHandler();
    auto responder = std::make_shared<CapturingResponder>();

    auto request = requestWithBody("payload");
    std::weak_ptr<const HttpRequest> observer {request};

    handler(request, responder);
    request.reset();

    EXPECT_TRUE(observer.expired()) << "the handler must not keep the payload alive";
}
