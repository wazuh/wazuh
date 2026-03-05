#include <gtest/gtest.h>

#include <api/adapter/baseHandler_test.hpp>
#include <api/router/handlers.hpp>
#include <base/json.hpp>
#include <eMessages/router.pb.h>
#include <router/mockRouter.hpp>

using namespace api::adapter;
using namespace api::test;
using namespace api::router;
using namespace api::router::handlers;
using namespace ::router::mocks;

using RouterHandlerTest = BaseHandlerTest<::router::IRouterAPI, MockRouterAPI>;

TEST_P(RouterHandlerTest, Handler)
{
    auto [reqGetter, handlerGetter, resGetter, mocker] = GetParam();
    handlerTest(reqGetter, handlerGetter, resGetter, m_iHandler, m_mockHandler, mocker);
}

using HandlerT = Params<::router::IRouterAPI, MockRouterAPI>;

INSTANTIATE_TEST_SUITE_P(
    Api,
    RouterHandlerTest,
    ::testing::Values(
        /***********************************************************************
         * RoutePost
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::router::RoutePost_Request protoReq;
                protoReq.mutable_route()->set_name("name");
                protoReq.mutable_route()->set_namespaceid("policy");
                protoReq.mutable_route()->set_filter("filter");
                protoReq.mutable_route()->set_priority(1);
                return createRequest<eEngine::router::RoutePost_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routePost(router); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, postEntry(testing::_)).WillOnce(testing::Return(base::noError())); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::router::RoutePost_Request protoReq;
                protoReq.mutable_route()->set_name("name");
                protoReq.mutable_route()->set_namespaceid("policy");
                protoReq.mutable_route()->set_filter("filter");
                protoReq.mutable_route()->set_priority(1);
                return createRequest<eEngine::router::RoutePost_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routePost(router); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            { EXPECT_CALL(mock, postEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routePost(router); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing route
        HandlerT(
            []()
            {
                json::Json jsonReq;
                jsonReq.setObject();
                httplib::Request req;
                req.body = jsonReq.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routePost(router); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /route"); },
            [](auto&) {}),
        // Invalid policy
        HandlerT(
            []()
            {
                json::Json jsonReq;
                jsonReq.setObject("/route");
                jsonReq.setString("filter/name/0", "/route/filter");
                jsonReq.setString("not-valid", "/route/namespaceId");
                jsonReq.setInt(1, "/route/priority");
                httplib::Request req;
                req.body = jsonReq.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routePost(router); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Invalid namespace id: Invalid namespace ID: not-valid");
            },
            [](auto&) {}),
        // Invalid filter
        HandlerT(
            []()
            {
                json::Json jsonReq;
                jsonReq.setObject("/route");
                jsonReq.setString("testing", "/route/namespaceId");
                jsonReq.setInt(1, "/route/priority");
                httplib::Request req;
                req.body = jsonReq.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routePost(router); },
            []()
            { return userErrorResponse<eEngine::GenericStatus_Response>("Invalid filter name: Name cannot be empty"); },
            [](auto&) {}),
        // Invalid priority (default 0)
        HandlerT(
            []()
            {
                json::Json jsonReq;
                jsonReq.setObject("/route");
                jsonReq.setString("testing", "/route/namespaceId");
                jsonReq.setString("filter/name/0", "/route/filter");
                httplib::Request req;
                req.body = jsonReq.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routePost(router); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock, postEntry(testing::_))
                    .WillOnce(testing::Invoke(
                        [](const ::router::prod::EntryPost& entry)
                        {
                            EXPECT_EQ(entry.priority(), 0);
                            return base::noError();
                        }));
            }),
        // Route with description
        HandlerT(
            []()
            {
                eEngine::router::RoutePost_Request protoReq;
                protoReq.mutable_route()->set_name("name");
                protoReq.mutable_route()->set_namespaceid("policy");
                protoReq.mutable_route()->set_filter("filter");
                protoReq.mutable_route()->set_priority(1);
                protoReq.mutable_route()->set_description("description");
                return createRequest<eEngine::router::RoutePost_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routePost(router); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, postEntry(testing::_)).WillOnce(testing::Return(base::noError())); }),
        /***********************************************************************
         * RouteDelete
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::router::RouteDelete_Request protoReq;
                protoReq.set_name("name");
                return createRequest<eEngine::router::RouteDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routeDelete(router); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, deleteEntry(testing::_)).WillOnce(testing::Return(base::noError())); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::router::RouteDelete_Request protoReq;
                protoReq.set_name("name");
                return createRequest<eEngine::router::RouteDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routeDelete(router); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            { EXPECT_CALL(mock, deleteEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routeDelete(router); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Invalid name
        HandlerT(
            []()
            {
                json::Json jsonReq;
                jsonReq.setObject();
                httplib::Request req;
                req.body = jsonReq.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routeDelete(router); },
            []()
            { return userErrorResponse<eEngine::GenericStatus_Response>("Invalid name name: Name cannot be empty"); },
            [](auto&) {}),
        /***********************************************************************
         * RouteReload
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::router::RouteReload_Request protoReq;
                protoReq.set_name("name");
                return createRequest<eEngine::router::RouteReload_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routeReload(router); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, reloadEntry(testing::_)).WillOnce(testing::Return(base::noError())); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::router::RouteReload_Request protoReq;
                protoReq.set_name("name");
                return createRequest<eEngine::router::RouteReload_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routeReload(router); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            { EXPECT_CALL(mock, reloadEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routeReload(router); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Invalid name
        HandlerT(
            []()
            {
                json::Json jsonReq;
                jsonReq.setObject();
                httplib::Request req;
                req.body = jsonReq.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routeReload(router); },
            []()
            { return userErrorResponse<eEngine::GenericStatus_Response>("Invalid name name: Name cannot be empty"); },
            [](auto&) {}),
        /***********************************************************************
         * RoutePatchPriority
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::router::RoutePatchPriority_Request protoReq;
                protoReq.set_name("name");
                protoReq.set_priority(1);
                return createRequest<eEngine::router::RoutePatchPriority_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routePatchPriority(router); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            { EXPECT_CALL(mock, changeEntryPriority(testing::_, 1)).WillOnce(testing::Return(base::noError())); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::router::RoutePatchPriority_Request protoReq;
                protoReq.set_name("name");
                protoReq.set_priority(1);
                return createRequest<eEngine::router::RoutePatchPriority_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routePatchPriority(router); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            {
                EXPECT_CALL(mock, changeEntryPriority(testing::_, 1)).WillOnce(testing::Return(base::Error {"error"}));
            }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routePatchPriority(router); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Invalid name
        HandlerT(
            []()
            {
                json::Json jsonReq;
                jsonReq.setObject();
                httplib::Request req;
                req.body = jsonReq.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routePatchPriority(router); },
            []()
            { return userErrorResponse<eEngine::GenericStatus_Response>("Invalid name name: Name cannot be empty"); },
            [](auto&) {})));

// TODO: add separate tests for routeGet and tableGet
