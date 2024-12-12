#include <gtest/gtest.h>

#include <api/adapter/baseHandler_test.hpp>
#include <api/event/handlers.hpp>
#include <router/mockRouter.hpp>

using namespace api::adapter;
using namespace api::test;
using namespace api::event;
using namespace api::event::handlers;
using namespace router::mocks;

using EventHandlerTest = BaseHandlerTest<::router::IRouterAPI, MockRouterAPI>;

TEST_P(EventHandlerTest, Handler)
{
    auto [reqGetter, handlerGetter, resGetter, mocker] = GetParam();
    handlerTest(reqGetter, handlerGetter, resGetter, m_iHandler, m_mockHandler, mocker);
}

using HandlerT = Params<::router::IRouterAPI, MockRouterAPI>;

INSTANTIATE_TEST_SUITE_P(Api,
                         EventHandlerTest,
                         ::testing::Values(
                             /***********************************************************************
                              * PushEvent
                              **********************************************************************/
                             // Success
                             HandlerT(
                                 []()
                                 {
                                     httplib::Request req;
                                     req.headers.emplace("Content-Type", "plain/text");
                                     req.body = "event";

                                     return req;
                                 },
                                 [](const std::shared_ptr<::router::IRouterAPI>& orchestrator)
                                 {
                                     return pushEvent(orchestrator,
                                                      [](auto&&)
                                                      {
                                                          std::queue<base::Event> events;
                                                          auto event = std::make_shared<json::Json>();
                                                          events.push(event);
                                                          return events;
                                                      });
                                 },
                                 []()
                                 {
                                     httplib::Response res;
                                     res.status = httplib::StatusCode::OK_200;
                                     return res;
                                 },
                                 [](auto& mock) { EXPECT_CALL(mock, postEvent(testing::_)); }),
                             // Error parsing event
                             HandlerT(
                                 []()
                                 {
                                     httplib::Request req;
                                     req.headers.emplace("Content-Type", "plain/text");
                                     req.body = "invalid event";

                                     return req;
                                 },
                                 [](const std::shared_ptr<::router::IRouterAPI>& orchestrator)
                                 {
                                     return pushEvent(orchestrator,
                                                      [](auto&&) -> std::queue<base::Event>
                                                      { throw std::runtime_error("error"); });
                                 },
                                 []()
                                 {
                                     httplib::Response res;
                                     res.status = httplib::StatusCode::BadRequest_400;
                                     res.body = "error";
                                     return res;
                                 },
                                 [](auto& mock) {}),
                             // Success multiple events
                             HandlerT(
                                 []()
                                 {
                                     httplib::Request req;
                                     req.headers.emplace("Content-Type", "plain/text");
                                     req.body = "event";

                                     return req;
                                 },
                                 [](const std::shared_ptr<::router::IRouterAPI>& orchestrator)
                                 {
                                     return pushEvent(orchestrator,
                                                      [](auto&&)
                                                      {
                                                          std::queue<base::Event> events;
                                                          auto event = std::make_shared<json::Json>();
                                                          events.push(event);
                                                          events.push(event);
                                                          return events;
                                                      });
                                 },
                                 []()
                                 {
                                     httplib::Response res;
                                     res.status = httplib::StatusCode::OK_200;
                                     return res;
                                 },
                                 [](auto& mock) { EXPECT_CALL(mock, postEvent(testing::_)).Times(2); })));
