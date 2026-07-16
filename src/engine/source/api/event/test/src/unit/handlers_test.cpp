#include <gtest/gtest.h>

#include <chrono>
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
        protocol::parseNDJson(body, noop, makeAgentMetadataCache());

        // If it didn't throw, this helper was used incorrectly for a "bad request" test.
        return "{\"error\": \"Expected parser error but parseNDJson() succeeded\", \"code\": 400}";
    }
    catch (const std::exception& e)
    {
        std::string out;
        out += "{\"error\": \"";
        out += e.what();
        out += "\", \"code\": 400}";
        return out;
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
// extracts the agent id from /wazuh/agent/id, so the header must carry it there.
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
