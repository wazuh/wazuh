#include <gtest/gtest.h>

#include <api/adapter/baseHandler_test.hpp>
#include <api/event/handlers.hpp>
#include <api/event/ndJsonParser.hpp>
#include <archiver/mockArchiver.hpp>
#include <rawevtindexer/mockraweventindexer.hpp>
#include <router/mockRouter.hpp>

using namespace api::adapter;
using namespace api::test;
using namespace api::event;
using namespace api::event::handlers;
using namespace router::mocks;

namespace
{
// Build the same error JSON the handler builds, but without hardcoding the parser message.
// This keeps the test resilient to tweaks in parseNDJson() error wording.
std::string makeBadRequestBodyFromParser(std::string_view body)
{
    try
    {
        protocol::EventHooks hooks {protocol::EventHook {}, protocol::EventHook {}};
        hooks[0] = nullptr;
        hooks[1] = nullptr;

        protocol::parseNDJson(body, hooks);

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

// Valid NDJson payloads for the new parser:
//  - First line: H {json}\n
//  - Each event starts with: E <ossec_event>
static const std::string HDR1 = R"({"agent":{"name":"worker","id":"000"}})";
static const std::string EV1 = "1:/etc/passwd:File modified md5=abc";
static const std::string EV2 = "2:/var/log/auth.log:sshd[12345]: Failed password for root from 1.2.3.4 port 22";

INSTANTIATE_TEST_SUITE_P(
    Api,
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
                // Use Nice mocks because the handler always calls archiver->archive(),
                // and rawIndexer may be null/disabled depending on the test.
                auto archiver = std::make_shared<testing::NiceMock<archiver::mocks::MockArchiver>>();
                std::shared_ptr<::raweventindexer::IRawEventIndexer> rawIndexer; // nullptr => raw indexing disabled
                return pushEvent(orchestrator, archiver, rawIndexer);
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
                auto archiver = std::make_shared<testing::NiceMock<archiver::mocks::MockArchiver>>();
                std::shared_ptr<::raweventindexer::IRawEventIndexer> rawIndexer; // nullptr
                return pushEvent(orchestrator, archiver, rawIndexer);
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
                auto archiver = std::make_shared<testing::NiceMock<archiver::mocks::MockArchiver>>();
                std::shared_ptr<::raweventindexer::IRawEventIndexer> rawIndexer; // nullptr
                return pushEvent(orchestrator, archiver, rawIndexer);
            },
            []()
            {
                httplib::Response res;
                res.status = httplib::StatusCode::OK_200;
                return res;
            },
            [](auto& mock) { EXPECT_CALL(mock, postEvent(testing::_)).Times(2); }),

        // Success (1 event) + raw indexer enabled -> index() is called
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
                auto archiver = std::make_shared<testing::NiceMock<archiver::mocks::MockArchiver>>();

                auto rawIndexer = std::make_shared<testing::NiceMock<raweventindexer::mocks::MockRawEventIndexer>>();
                ON_CALL(*rawIndexer, isEnabled()).WillByDefault(testing::Return(true));

                // Disambiguate overload: handler calls index(std::string) (rawDoc.str()).
                EXPECT_CALL(*rawIndexer, index(testing::A<const std::string&>())).Times(1);

                return pushEvent(orchestrator, archiver, rawIndexer);
            },
            []()
            {
                httplib::Response res;
                res.status = httplib::StatusCode::OK_200;
                return res;
            },
            [](auto& mock) { EXPECT_CALL(mock, postEvent(testing::_)); }),

        // Error parsing event (second header found where parser expects event marker)
        HandlerT(
            []()
            {
                httplib::Request req;
                req.headers.emplace("Content-Type", "plain/text");
                req.body = std::string("H ") + HDR1 + "\n" + "H " + HDR1 + "\n" + "E " + EV1 + "\n";
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& orchestrator)
            {
                auto archiver = std::make_shared<testing::NiceMock<archiver::mocks::MockArchiver>>();
                std::shared_ptr<::raweventindexer::IRawEventIndexer> rawIndexer;
                return pushEvent(orchestrator, archiver, rawIndexer);
            },
            []()
            {
                httplib::Response res;
                res.status = httplib::StatusCode::BadRequest_400;

                const std::string badBody = std::string("H ") + HDR1 + "\n" + "H " + HDR1 + "\n" + "E " + EV1 + "\n";
                const std::string expectedBody = makeBadRequestBodyFromParser(badBody);
                res.set_content(expectedBody, "application/json");

                return res;
            },
            [](auto& mock) { /* no postEvent expected */ }),

        // Success with trailing newline: archiver receives body without final newline
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
                auto archiver = std::make_shared<testing::StrictMock<archiver::mocks::MockArchiver>>();

                const std::string expectedArchived = std::string("H ") + HDR1 + "\n" + "E " + EV1;

                // Disambiguate overload: handler calls archive(std::string_view).
                EXPECT_CALL(*archiver, archive(testing::A<std::string_view>()))
                    .WillOnce(testing::Invoke([expectedArchived](std::string_view v)
                                              { EXPECT_EQ(v, std::string_view {expectedArchived}); }));

                std::shared_ptr<::raweventindexer::IRawEventIndexer> rawIndexer;
                return pushEvent(orchestrator, archiver, rawIndexer);
            },
            []()
            {
                httplib::Response res;
                res.status = httplib::StatusCode::OK_200;
                return res;
            },
            [](auto& mock) { EXPECT_CALL(mock, postEvent(testing::_)); }),

        // Success multiple events + raw indexer enabled -> index() called per event
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
                auto archiver = std::make_shared<testing::NiceMock<archiver::mocks::MockArchiver>>();

                auto rawIndexer = std::make_shared<testing::StrictMock<raweventindexer::mocks::MockRawEventIndexer>>();
                EXPECT_CALL(*rawIndexer, isEnabled()).Times(1).WillOnce(testing::Return(true));
                EXPECT_CALL(*rawIndexer, index(testing::A<const std::string&>())).Times(2);

                return pushEvent(orchestrator, archiver, rawIndexer);
            },
            []()
            {
                httplib::Response res;
                res.status = httplib::StatusCode::OK_200;
                return res;
            },
            [](auto& mock) { EXPECT_CALL(mock, postEvent(testing::_)).Times(2); })));
