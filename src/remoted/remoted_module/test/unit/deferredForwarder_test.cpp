/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 25, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "downstream/IDownstreamClient.hpp"
#include "downstream/deferredForwarder.hpp"
#include "downstream/deferredWorkLimiter.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

using namespace remoted::downstream;
using remoted::auth::AuthenticatedRequest;
using remoted::auth::Payload;
using remoted::http::HttpResponse;
using remoted::http::IHttpResponder;
using remoted::http::Method;

namespace
{
    // Records the last request + keep-alive and exposes the callback so a test can fire the response.
    class FakeDownstreamClient final : public IDownstreamClient
    {
    public:
        void sendAsync(DownstreamRequest req, std::shared_ptr<const void> keepAlive, DownstreamCallback cb) override
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            m_request = std::move(req);
            m_keepAlive = std::move(keepAlive);
            m_callback = std::move(cb);
            m_called = true;
        }

        bool called() const
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            return m_called;
        }

        DownstreamRequest request() const
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            return m_request;
        }

        // Simulate "send complete": the real client drops the keep-alive after the body is written.
        void releaseKeepAlive()
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            m_keepAlive.reset();
        }

        void fire(DownstreamError error, DownstreamResponse response)
        {
            DownstreamCallback cb;
            {
                std::lock_guard<std::mutex> lock {m_mutex};
                cb = std::move(m_callback);
            }
            ASSERT_TRUE(static_cast<bool>(cb));
            cb(error, std::move(response));
        }

    private:
        mutable std::mutex m_mutex;
        DownstreamRequest m_request;
        std::shared_ptr<const void> m_keepAlive;
        DownstreamCallback m_callback;
        bool m_called {false};
    };

    // Send-once responder that hands the response to a future (post-processing runs on a pool thread).
    class CapturingResponder final : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            if (!m_answered.exchange(true))
            {
                m_promise.set_value(std::move(response));
            }
        }
        std::future<HttpResponse> future()
        {
            return m_promise.get_future();
        }

    private:
        std::promise<HttpResponse> m_promise;
        std::atomic<bool> m_answered {false};
    };

    struct AuthReqFixture
    {
        std::shared_ptr<const AuthenticatedRequest> req;
        std::shared_ptr<std::string> buffer; // owns the payload bytes
    };

    AuthReqFixture makeAuthReq(const std::string& body, const std::string& agentId = "001")
    {
        auto buffer = std::make_shared<std::string>(body);
        AuthenticatedRequest ar;
        ar.agentId = agentId;
        ar.method = "POST";
        ar.requestTarget = "/stateless";
        ar.payload = Payload {std::string_view {*buffer}, buffer};
        return {std::make_shared<const AuthenticatedRequest>(std::move(ar)), std::move(buffer)};
    }

    // Plain data fixture; the forwarder is target-agnostic (endpoint targets live in endpoints/).
    DownstreamTarget sampleTarget()
    {
        return {"queue/sockets/some.sock", Method::Post, "/some/path", "application/x-ndjson"};
    }

    // Trivial mapper for the forwarder-mechanics tests. The per-endpoint mapping (202/400/413/503)
    // is tested in statelessEndpoint_test.cpp, not here.
    HttpResponse sampleMapper(DownstreamError, const DownstreamResponse&)
    {
        return HttpResponse::json(200, R"({"ok":true})");
    }

    // Wait until pred() is true or the deadline elapses (for the async slot release / reply).
    template<typename Pred>
    bool waitFor(Pred pred, std::chrono::milliseconds timeout = std::chrono::seconds {2})
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (pred())
            {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds {1});
        }
        return pred();
    }

    // Responder whose send() always throws -- proves a throwing responder is swallowed (logged),
    // not left to escape onto the post-processing pool's thread.
    class ThrowingResponder final : public IHttpResponder
    {
    public:
        void send(HttpResponse) override
        {
            m_called.store(true);
            throw std::runtime_error("simulated responder failure");
        }
        bool called() const
        {
            return m_called.load();
        }

    private:
        std::atomic<bool> m_called {false};
    };
} // namespace

TEST(DeferredForwarderTest, SlotFullShedsWith503WithoutCallingClient)
{
    // Declare the limiter first so it outlives the client/forwarder: a parked request keeps its Slot
    // (raw-pointing at the limiter) inside the client's callback until teardown -- same lifetime rule
    // the facade honors by member-declaration + stop() order (client stopped before the limiter).
    auto limiter = std::make_shared<DeferredWorkLimiter>(1); // capacity 1
    auto client = std::make_shared<FakeDownstreamClient>();
    DeferredForwarder forwarder {client, limiter, 1};

    // First forward takes the only slot and parks (client holds the callback, never fires).
    auto first = makeAuthReq("first");
    auto firstResponder = std::make_shared<CapturingResponder>();
    forwarder.forward(first.req, firstResponder, sampleTarget(), sampleMapper);
    EXPECT_TRUE(client->called());
    EXPECT_EQ(limiter->inFlight(), 1U);

    // Second forward finds the limiter full -> 503 inline, and the client is NOT called again.
    auto second = makeAuthReq("second");
    auto secondResponder = std::make_shared<CapturingResponder>();
    auto fut = secondResponder->future();
    forwarder.forward(second.req, secondResponder, sampleTarget(), sampleMapper);

    ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
    EXPECT_EQ(fut.get().status, 503);
}

TEST(DeferredForwarderTest, PassesTargetAndBodyToClient)
{
    // Declare the limiter first so it outlives the client/forwarder (see
    // SlotFullShedsWith503WithoutCallingClient's comment): a parked or racily-in-flight Slot
    // raw-points at the limiter, so it must never be destroyed while the client (which may still
    // be holding or about to run a callback capturing that Slot) is still alive.
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    auto client = std::make_shared<FakeDownstreamClient>();
    DeferredForwarder forwarder {client, limiter, 1};

    auto fixture = makeAuthReq("H {\"wazuh\":{}}\nE payload");
    auto responder = std::make_shared<CapturingResponder>();
    forwarder.forward(fixture.req, responder, sampleTarget(), sampleMapper);

    const auto req = client->request();
    EXPECT_EQ(req.socketPath, "queue/sockets/some.sock");
    EXPECT_EQ(req.path, "/some/path");
    EXPECT_EQ(req.contentType, "application/x-ndjson");
    EXPECT_EQ(req.method, Method::Post);
    EXPECT_EQ(req.body, "H {\"wazuh\":{}}\nE payload"); // zero-copy view of the payload
    EXPECT_EQ(req.responseTimeoutMs, 0);                // sampleTarget() sets no override
}

// The per-endpoint response deadline must survive the DownstreamTarget -> DownstreamRequest
// translation; otherwise an endpoint declaring a longer deadline would silently get the global one.
TEST(DeferredForwarderTest, TargetResponseTimeoutReachesClient)
{
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    auto client = std::make_shared<FakeDownstreamClient>();
    DeferredForwarder forwarder {client, limiter, 1};

    auto fixture = makeAuthReq("H {\"wazuh\":{}}\nE payload");
    auto responder = std::make_shared<CapturingResponder>();

    auto target = sampleTarget();
    target.responseTimeoutMs = 1234;
    forwarder.forward(fixture.req, responder, target, sampleMapper);

    EXPECT_EQ(client->request().responseTimeoutMs, 1234);
}

TEST(DeferredForwarderTest, DeliversPostProcessorResultAndReleasesSlot)
{
    // Declare the limiter first so it outlives the client/forwarder (see
    // SlotFullShedsWith503WithoutCallingClient's comment): a parked or racily-in-flight Slot
    // raw-points at the limiter, so it must never be destroyed while the client (which may still
    // be holding or about to run a callback capturing that Slot) is still alive.
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    auto client = std::make_shared<FakeDownstreamClient>();
    DeferredForwarder forwarder {client, limiter, 1};

    auto fixture = makeAuthReq("body");
    auto responder = std::make_shared<CapturingResponder>();
    auto fut = responder->future();
    forwarder.forward(fixture.req, responder, sampleTarget(), sampleMapper);

    client->fire(DownstreamError::None, DownstreamResponse {200, ""});

    ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
    EXPECT_EQ(fut.get().status, 200);                                // whatever the mapper returned
    EXPECT_TRUE(waitFor([&] { return limiter->inFlight() == 0U; })); // slot released after reply
}

TEST(DeferredForwarderTest, CustomPostProcessorReceivesRawResponse)
{
    // Declare the limiter first so it outlives the client/forwarder (see
    // SlotFullShedsWith503WithoutCallingClient's comment): a parked or racily-in-flight Slot
    // raw-points at the limiter, so it must never be destroyed while the client (which may still
    // be holding or about to run a callback capturing that Slot) is still alive.
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    auto client = std::make_shared<FakeDownstreamClient>();
    DeferredForwarder forwarder {client, limiter, 1};

    // A non-trivial post-processor that inspects the downstream body.
    PostProcessor custom = [](DownstreamError error, const DownstreamResponse& r) -> HttpResponse
    {
        if (error == DownstreamError::None && r.body == "ok")
        {
            return HttpResponse::json(200, R"({"seen":"ok"})");
        }
        return HttpResponse::json(500, R"({"seen":"other"})");
    };

    auto fixture = makeAuthReq("body");
    auto responder = std::make_shared<CapturingResponder>();
    auto fut = responder->future();
    forwarder.forward(fixture.req, responder, sampleTarget(), custom);

    client->fire(DownstreamError::None, DownstreamResponse {200, "ok"});

    ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
    const auto response = fut.get();
    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(response.body, R"({"seen":"ok"})");
}

TEST(DeferredForwarderTest, PayloadKeepAliveReleasedWhenClientReleasesIt)
{
    // Declare the limiter first so it outlives the client/forwarder (see
    // SlotFullShedsWith503WithoutCallingClient's comment): a parked or racily-in-flight Slot
    // raw-points at the limiter, so it must never be destroyed while the client (which may still
    // be holding or about to run a callback capturing that Slot) is still alive.
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    auto client = std::make_shared<FakeDownstreamClient>();
    DeferredForwarder forwarder {client, limiter, 1};

    auto fixture = makeAuthReq("body");
    std::weak_ptr<const AuthenticatedRequest> weak = fixture.req;
    auto responder = std::make_shared<CapturingResponder>();

    // Move our only shared_ptr into forward() -> the client's keep-alive becomes the sole owner.
    forwarder.forward(std::move(fixture.req), responder, sampleTarget(), sampleMapper);
    EXPECT_FALSE(weak.expired()); // the client's keep-alive holds it

    client->releaseKeepAlive();  // simulate "send complete"
    EXPECT_TRUE(weak.expired()); // payload (and its byte reservation) freed at send time
}

TEST(DeferredForwarderTest, ThrowingPostProcessorYields500InsteadOfCrashing)
{
    // Declare the limiter first so it outlives the client/forwarder (see
    // SlotFullShedsWith503WithoutCallingClient's comment): a parked or racily-in-flight Slot
    // raw-points at the limiter, so it must never be destroyed while the client (which may still
    // be holding or about to run a callback capturing that Slot) is still alive.
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    auto client = std::make_shared<FakeDownstreamClient>();
    DeferredForwarder forwarder {client, limiter, 1};

    PostProcessor throwingMapper = [](DownstreamError, const DownstreamResponse&) -> HttpResponse
    {
        throw std::runtime_error("simulated PostProcessor bug");
    };

    auto fixture = makeAuthReq("body");
    auto responder = std::make_shared<CapturingResponder>();
    auto fut = responder->future();
    forwarder.forward(fixture.req, responder, sampleTarget(), throwingMapper);

    client->fire(DownstreamError::None, DownstreamResponse {200, ""});

    // The process survives and the caller gets a safe 500 instead of a std::terminate().
    ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
    EXPECT_EQ(fut.get().status, 500);
    EXPECT_TRUE(waitFor([&] { return limiter->inFlight() == 0U; })); // slot still released
}

TEST(DeferredForwarderTest, ThrowingResponderIsSwallowed)
{
    // Declare the limiter first so it outlives the client/forwarder (see
    // SlotFullShedsWith503WithoutCallingClient's comment): a parked or racily-in-flight Slot
    // raw-points at the limiter, so it must never be destroyed while the client (which may still
    // be holding or about to run a callback capturing that Slot) is still alive.
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    auto client = std::make_shared<FakeDownstreamClient>();
    DeferredForwarder forwarder {client, limiter, 1};

    auto fixture = makeAuthReq("body");
    auto responder = std::make_shared<ThrowingResponder>();
    forwarder.forward(fixture.req, responder, sampleTarget(), sampleMapper);

    client->fire(DownstreamError::None, DownstreamResponse {200, ""});

    // send() throwing must not escape the post-processing pool's thread (no std::terminate());
    // the slot must still be released even though the reply itself was lost.
    EXPECT_TRUE(waitFor([&] { return responder->called(); }));
    EXPECT_TRUE(waitFor([&] { return limiter->inFlight() == 0U; }));
}
