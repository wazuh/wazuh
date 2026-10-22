// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

#include <api/event/identityWarningGate.hpp>
#include <base/eventParser.hpp>
#include <base/logging.hpp>
#include <memory>

#include <api/adapter/baseHandler_test.hpp>
#include <api/event/handlers.hpp>
#include <api/event/ndJsonParser.hpp>
#include <dumper/mockDumper.hpp>
#include <fastmetrics/registry.hpp>
#include <router/mockRouter.hpp>

using namespace api::adapter;
using namespace api::test;
using namespace api::event;
using namespace api::event::handlers;
using namespace router::mocks;

namespace
{
// Register fastmetrics manager once for all tests in this file
struct FastMetricsInit
{
    FastMetricsInit() { fastmetrics::registerManager(); }
};
static FastMetricsInit fastMetricsInit_;

// Agent metadata cache instance for the parser/handler, mirroring production (5-minute TTL).
std::shared_ptr<agentcache::AgentMetadataCache> makeAgentMetadataCache()
{
    return std::make_shared<agentcache::AgentMetadataCache>(std::chrono::seconds {300});
}

// Build the same error JSON the handler builds, but without hardcoding the parser message.
// This keeps the test resilient to tweaks in parseNDJson() error wording.
std::string makeBadRequestBodyFromParser(std::string_view body)
{
    try
    {
        // Single-hook API: pass an empty hook to validate parsing only.
        protocol::EventHook noop {};
        protocol::parseNDJson(body, "000", noop, makeAgentMetadataCache());

        // If it didn't throw, this helper was used incorrectly for a "bad request" test.
        return "{\"error\": \"Expected parser error but parseNDJson() succeeded\", \"code\": 400}";
    }
    catch (const std::exception& e)
    {
        json::Json out;
        out.setString(e.what(), "/error");
        out.setInt(400, "/code");
        return out.str();
    }
}
} // namespace

using EventHandlerTest = BaseHandlerTest<::router::IRouterAPI, MockRouterAPI>;

TEST_P(EventHandlerTest, Handler)
{
    auto [reqGetter, handlerGetter, resGetter, mocker] = GetParam();
    handlerTest(reqGetter, handlerGetter, resGetter, m_iHandler, m_mockHandler, mocker);
}

using HandlerT = Params<::router::IRouterAPI, MockRouterAPI>;

// Valid NDJson payloads:
//  - First line: H {json}\n
//  - Each event starts with: E <ossec_event>
// The enriched-event header is wrapped under a top-level "wazuh" object; the AgentMetadataCache
// validates /wazuh/agent/id against the explicit trusted id carried by the request.
static const std::string HDR1 = R"({"wazuh":{"agent":{"name":"worker","id":"000"}}})";
static const std::string EV1 = "1:/etc/passwd:File modified md5=abc";
static const std::string EV2 = "2:/var/log/auth.log:sshd[12345]: Failed password for root from 1.2.3.4 port 22";

INSTANTIATE_TEST_SUITE_P(Api,
                         EventHandlerTest,
                         ::testing::Values(
                             /***********************************************************************
                              * PushEvent
                              **********************************************************************/
                             // Success (1 event)
                             HandlerT(
                                 []()
                                 {
                                     httplib::Request req;
                                     req.headers.emplace("X-Wazuh-Agent-Id", "000");
                                     req.headers.emplace("Content-Type", "plain/text");
                                     req.body = std::string("H ") + HDR1 + "\n" + "E " + EV1 + "\n";
                                     return req;
                                 },
                                 [](const std::shared_ptr<::router::IRouterAPI>& orchestrator)
                                 {
                                     // Nice mock: handler always may call dump->dump()
                                     auto dumper = std::make_shared<testing::NiceMock<dumper::mocks::MockDumper>>();
                                     return pushEvent(orchestrator, dumper, makeAgentMetadataCache());
                                 },
                                 []()
                                 {
                                     httplib::Response res;
                                     res.status = httplib::StatusCode::OK_200;
                                     return res;
                                 },
                                 [](auto& mock) { EXPECT_CALL(mock, postEvent(testing::_)); }),

                             // Error parsing event (invalid NDJson body -> parser throws -> handler returns 400)
                             HandlerT(
                                 []()
                                 {
                                     httplib::Request req;
                                     req.headers.emplace("X-Wazuh-Agent-Id", "000");
                                     req.headers.emplace("Content-Type", "application/json");
                                     req.body = "event"; // invalid: missing newline after header
                                     return req;
                                 },
                                 [](const std::shared_ptr<::router::IRouterAPI>& orchestrator)
                                 {
                                     auto dumper = std::make_shared<testing::NiceMock<dumper::mocks::MockDumper>>();
                                     return pushEvent(orchestrator, dumper, makeAgentMetadataCache());
                                 },
                                 []()
                                 {
                                     httplib::Response res;
                                     res.status = httplib::StatusCode::BadRequest_400;

                                     const std::string expectedBody = makeBadRequestBodyFromParser("event");
                                     res.set_content(expectedBody, "application/json");

                                     return res;
                                 },
                                 [](auto& mock) { /* no postEvent expected */ }),

                             // Success multiple events
                             HandlerT(
                                 []()
                                 {
                                     httplib::Request req;
                                     req.headers.emplace("X-Wazuh-Agent-Id", "000");
                                     req.headers.emplace("Content-Type", "plain/text");
                                     req.body = std::string("H ") + HDR1 + "\n" + "E " + EV1 + "\n" + "E " + EV2 + "\n";
                                     return req;
                                 },
                                 [](const std::shared_ptr<::router::IRouterAPI>& orchestrator)
                                 {
                                     auto dumper = std::make_shared<testing::NiceMock<dumper::mocks::MockDumper>>();
                                     return pushEvent(orchestrator, dumper, makeAgentMetadataCache());
                                 },
                                 []()
                                 {
                                     httplib::Response res;
                                     res.status = httplib::StatusCode::OK_200;
                                     return res;
                                 },
                                 [](auto& mock) { EXPECT_CALL(mock, postEvent(testing::_)).Times(2); }),

                             // Error parsing event (second header found where parser expects event marker)
                             HandlerT(
                                 []()
                                 {
                                     httplib::Request req;
                                     req.headers.emplace("X-Wazuh-Agent-Id", "000");
                                     req.headers.emplace("Content-Type", "plain/text");
                                     req.body =
                                         std::string("H ") + HDR1 + "\n" + "H " + HDR1 + "\n" + "E " + EV1 + "\n";
                                     return req;
                                 },
                                 [](const std::shared_ptr<::router::IRouterAPI>& orchestrator)
                                 {
                                     auto dumper = std::make_shared<testing::NiceMock<dumper::mocks::MockDumper>>();
                                     return pushEvent(orchestrator, dumper, makeAgentMetadataCache());
                                 },
                                 []()
                                 {
                                     httplib::Response res;
                                     res.status = httplib::StatusCode::BadRequest_400;

                                     const std::string badBody =
                                         std::string("H ") + HDR1 + "\n" + "H " + HDR1 + "\n" + "E " + EV1 + "\n";
                                     const std::string expectedBody = makeBadRequestBodyFromParser(badBody);
                                     res.set_content(expectedBody, "application/json");

                                     return res;
                                 },
                                 [](auto& mock) { /* no postEvent expected */ }),

                             // Success with trailing newline: dump receives body without final newline
                             HandlerT(
                                 []()
                                 {
                                     httplib::Request req;
                                     req.headers.emplace("X-Wazuh-Agent-Id", "000");
                                     req.headers.emplace("Content-Type", "plain/text");
                                     req.body = std::string("H ") + HDR1 + "\n" + "E " + EV1 + "\n";
                                     return req;
                                 },
                                 [](const std::shared_ptr<::router::IRouterAPI>& orchestrator)
                                 {
                                     auto dumper = std::make_shared<testing::StrictMock<dumper::mocks::MockDumper>>();

                                     const std::string expectedDumped = std::string("H ") + HDR1 + "\n" + "E " + EV1;

                                     EXPECT_CALL(*dumper, dump(testing::A<std::string_view>()))
                                         .WillOnce(
                                             testing::Invoke([expectedDumped](std::string_view v)
                                                             { EXPECT_EQ(v, std::string_view {expectedDumped}); }));

                                     // inner handler stores only weak_ptr, so keep dump alive by capturing it
                                     auto inner = pushEvent(orchestrator, dumper, makeAgentMetadataCache());
                                     return [dumper, inner](const httplib::Request& req, httplib::Response& res) mutable
                                     {
                                         inner(req, res);
                                     };
                                 },
                                 []()
                                 {
                                     httplib::Response res;
                                     res.status = httplib::StatusCode::OK_200;
                                     return res;
                                 },
                                 [](auto& mock) { EXPECT_CALL(mock, postEvent(testing::_)); }),

                             // Success multiple events: ensure postEvent called twice
                             HandlerT(
                                 []()
                                 {
                                     httplib::Request req;
                                     req.headers.emplace("X-Wazuh-Agent-Id", "000");
                                     req.headers.emplace("Content-Type", "plain/text");
                                     req.body = std::string("H ") + HDR1 + "\n" + "E " + EV1 + "\n" + "E " + EV2 + "\n";
                                     return req;
                                 },
                                 [](const std::shared_ptr<::router::IRouterAPI>& orchestrator)
                                 {
                                     auto dumper = std::make_shared<testing::NiceMock<dumper::mocks::MockDumper>>();
                                     return pushEvent(orchestrator, dumper, makeAgentMetadataCache());
                                 },
                                 []()
                                 {
                                     httplib::Response res;
                                     res.status = httplib::StatusCode::OK_200;
                                     return res;
                                 },
                                 [](auto& mock) { EXPECT_CALL(mock, postEvent(testing::_)).Times(2); })));

class EventIdentityTest : public ::testing::Test
{
protected:
    std::shared_ptr<testing::NiceMock<MockRouterAPI>> router = std::make_shared<testing::NiceMock<MockRouterAPI>>();
    std::shared_ptr<agentcache::AgentMetadataCache> cache = makeAgentMetadataCache();
    api::adapter::RouteHandler handler;
    std::shared_ptr<fastmetrics::ICounter> rejected;

    void SetUp() override
    {
        logging::testInit();
        handler = pushEvent(router, {}, cache);
        rejected = fastmetrics::manager().getOrCreateCounter(fastmetrics::names::AGENT_CACHE_REJECTED_IDENTITY);
    }

    static std::string batch(std::string_view id = "001")
    {
        return "H {\"wazuh\":{\"agent\":{\"id\":\"" + std::string(id) + "\"}}}\nE 1:syslog:hello\n";
    }

    httplib::Response send(const httplib::Headers& headers, std::string body = batch())
    {
        httplib::Request request;
        request.headers = headers;
        request.body = std::move(body);
        httplib::Response response;
        handler(request, response);
        return response;
    }

    void expectIdentityRejection(const httplib::Headers& headers, std::string body = batch())
    {
        const auto before = rejected->get();
        const auto size = cache->size();
        const auto response = send(headers, std::move(body));
        EXPECT_EQ(response.status, 400);
        EXPECT_EQ(cache->size(), size);
        EXPECT_EQ(rejected->get(), before + 1);
        json::Json error {std::string_view(response.body)};
        EXPECT_EQ(error.getInt("/code"), 400);
        std::string_view message;
        ASSERT_EQ(error.getString(message, "/error"), json::RetGet::Success);
        EXPECT_EQ(message.find("NDJson parser error, "), 0u);
        EXPECT_EQ(message.find("NDJson parser error, ", 1), std::string_view::npos);
    }
};

TEST_F(EventIdentityTest, RejectsMissingRepeatedOrInvalidCarrier)
{
    EXPECT_CALL(*router, postEvent(testing::_)).Times(0);
    expectIdentityRejection({});
    expectIdentityRejection({{"X-Wazuh-Agent-Id", "001"}, {"x-wazuh-agent-id", "001"}});
    expectIdentityRejection({{"X-Wazuh-Agent-Id", "001"}, {"X-Wazuh-Agent-Id", "002"}});
    for (const auto id : {"", "1", "0001", "abc", "001,002", "4294967296", "10000000000", "001\r\n"})
    {
        SCOPED_TRACE(id);
        expectIdentityRejection({{"X-Wazuh-Agent-Id", id}});
    }
}

TEST_F(EventIdentityTest, AcceptsCanonicalCarrierAndPreservesIdentity)
{
    const auto before = rejected->get();
    for (const auto id : {"000", "001", "1000", "4294967295"})
    {
        EXPECT_CALL(*router, postEvent(testing::_))
            .WillOnce(
                [id](::router::IngestEvent&& event)
                {
                    std::string_view actual;
                    ASSERT_EQ(event.first->getString(actual, "/wazuh/agent/id"), json::RetGet::Success);
                    EXPECT_EQ(actual, id);
                    auto merged = base::eventParsers::parseLegacyEvent(event.second, *event.first);
                    ASSERT_EQ(merged->getString(actual, "/wazuh/agent/id"), json::RetGet::Success);
                    EXPECT_EQ(actual, id);
                });
        EXPECT_EQ(send({{"x-wazuh-agent-id", id}}, batch(id)).status, 200);
    }
    EXPECT_EQ(rejected->get(), before);
}

TEST_F(EventIdentityTest, RejectsAmbiguousOrMismatchedHeader)
{
    EXPECT_CALL(*router, postEvent(testing::_)).Times(0);
    for (const auto header : {R"({})",
                              R"({"wazuh":{"agent":{"id":1}}})",
                              R"({"wazuh":{"agent":{"id":"1"}}})",
                              R"({"wazuh":{"agent":{"id":"002"}}})",
                              R"({"wazuh":{"agent":{"id":"001","id":"001"}}})",
                              R"({"wazuh":{"agent":{"id":"001"},"agent":{"id":"002"}}})",
                              R"({"wazuh":{"agent":{"id":"001"}},"wazuh":{"agent":{"id":"001"}}})",
                              R"({"wazuh":{"agent":{"id":"001"}},"\u0077azuh":{"agent":{"id":"002"}}})"})
    {
        expectIdentityRejection({{"X-Wazuh-Agent-Id", "001"}}, std::string("H ") + header + "\nE 1:syslog:hello\n");
    }
}

TEST_F(EventIdentityTest, CachedHeaderCannotBypassCarrierValidation)
{
    EXPECT_CALL(*router, postEvent(testing::_)).Times(1);
    EXPECT_EQ(send({{"X-Wazuh-Agent-Id", "001"}}).status, 200);
    const auto original = cache->getOrParse("001", R"({"wazuh":{"agent":{"id":"001"}}})").first;
    expectIdentityRejection({});
    expectIdentityRejection({{"X-Wazuh-Agent-Id", "001"}, {"x-wazuh-agent-id", "001"}});
    expectIdentityRejection({{"X-Wazuh-Agent-Id", "002"}});
    EXPECT_EQ(cache->getOrParse("001", R"({"wazuh":{"agent":{"id":"001"}}})").first, original);
}

TEST_F(EventIdentityTest, AcceptsOffPathMetadata)
{
    EXPECT_CALL(*router, postEvent(testing::_)).Times(1);
    const auto before = rejected->get();
    const std::string body =
        R"(H {"wazuh":{"agent":{"id":"001"},"x":1,"x":2},"wazuh\u0000x":{},"wazuh/agent":{},"deep":)"
        + std::string(json::Json::MAX_DEPTH - 1, '[') + "0" + std::string(json::Json::MAX_DEPTH - 1, ']')
        + "}\nE 1:syslog:hello\n";
    EXPECT_EQ(send({{"X-Wazuh-Agent-Id", "001"}}, body).status, 200);
    EXPECT_EQ(rejected->get(), before);
}

TEST_F(EventIdentityTest, GenericParserFailuresDoNotCountAsIdentity)
{
    const auto before = rejected->get();
    for (const auto body :
         {"H {invalid\nE 1:syslog:x\n", "H {}", "not an H line\n", "H {\"wazuh\":{\"agent\":{\"id\":\"001\"}}}\nstray"})
    {
        const auto response = send({{"X-Wazuh-Agent-Id", "001"}}, body);
        EXPECT_EQ(response.status, 400);
        EXPECT_NO_THROW((void)json::Json(std::string_view(response.body)));
    }
    EXPECT_CALL(*router, postEvent(testing::_))
        .WillOnce([](::router::IngestEvent&&) { throw std::runtime_error("hook \"failure\"\n"); });
    const auto response = send({{"X-Wazuh-Agent-Id", "001"}});
    EXPECT_EQ(response.status, 400);
    EXPECT_NO_THROW((void)json::Json(std::string_view(response.body)));
    EXPECT_EQ(rejected->get(), before);
}

TEST_F(EventIdentityTest, ParseFailureWarningIsThrottled)
{
    const auto before = rejected->get();
    testing::internal::CaptureStderr();
    for (int i = 0; i < 2; ++i)
    {
        EXPECT_EQ(send({{"X-Wazuh-Agent-Id", "001"}}, "H {invalid\nE 1:syslog:x\n").status, 400);
    }
    const auto output = testing::internal::GetCapturedStderr();
    const std::string warning = "Failed to parse request {\"agent_id\":\"001\"}";
    const auto first = output.find(warning);
    EXPECT_NE(first, std::string::npos) << output;
    EXPECT_EQ(output.find(warning, first + 1), std::string::npos) << output;
    EXPECT_EQ(rejected->get(), before);
}

TEST_F(EventIdentityTest, HeaderOnlyAndLaterInvalidBatchesRetainValidHeader)
{
    EXPECT_CALL(*router, postEvent(testing::_)).Times(0);
    const auto before = rejected->get();
    const auto headerOnly = batch().substr(0, batch().find('\n') + 1);
    EXPECT_EQ(send({{"X-Wazuh-Agent-Id", "001"}}, headerOnly).status, 200);
    EXPECT_EQ(cache->size(), 1u);
    cache->clear();
    EXPECT_EQ(send({{"X-Wazuh-Agent-Id", "001"}}, headerOnly + "stray").status, 400);
    EXPECT_EQ(cache->size(), 1u);
    EXPECT_EQ(rejected->get(), before);
}

TEST(IdentityWarningGateTest, ThrottlesAcrossThreadsAndAtBoundary)
{
    IdentityWarningGate gate;
    const auto start = std::chrono::steady_clock::time_point(std::chrono::milliseconds(750));
    std::atomic<int> warnings {0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 16; ++i)
    {
        threads.emplace_back(
            [&]()
            {
                if (gate.allow(start))
                {
                    ++warnings;
                }
            });
    }
    for (auto& thread : threads)
    {
        thread.join();
    }
    EXPECT_EQ(warnings.load(), 1);
    EXPECT_FALSE(gate.allow(start + std::chrono::seconds(89)));
    EXPECT_FALSE(gate.allow(start + std::chrono::seconds(90) - std::chrono::nanoseconds(1)));
    EXPECT_TRUE(gate.allow(start + std::chrono::seconds(90)));
    EXPECT_FALSE(gate.allow(start + std::chrono::seconds(90)));
}

TEST_F(EventIdentityTest, UnavailableRouterRemainsServerError)
{
    const auto before = rejected->get();
    router.reset();
    EXPECT_EQ(send({}).status, 500);
    EXPECT_EQ(rejected->get(), before);
}
