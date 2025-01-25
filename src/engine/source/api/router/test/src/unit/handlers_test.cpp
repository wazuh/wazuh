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
                protoReq.mutable_route()->set_policy("policy");
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
                protoReq.mutable_route()->set_policy("policy");
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
                jsonReq.setInt(1, "/route/priority");
                httplib::Request req;
                req.body = jsonReq.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return routePost(router); },
            []()
            { return userErrorResponse<eEngine::GenericStatus_Response>("Invalid policy name: Name cannot be empty"); },
            [](auto&) {}),
        // Invalid filter
        HandlerT(
            []()
            {
                json::Json jsonReq;
                jsonReq.setObject("/route");
                jsonReq.setString("policy/name/0", "/route/policy");
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
                jsonReq.setString("policy/name/0", "/route/policy");
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
                protoReq.mutable_route()->set_policy("policy");
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
            [](auto& mock) {
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
            [](auto&) {}),
        /***********************************************************************
         * ChangeEpsSettings
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::router::EpsUpdate_Request protoReq;
                protoReq.set_eps(1);
                protoReq.set_refresh_interval(1);
                return createRequest<eEngine::router::EpsUpdate_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return changeEpsSettings(router); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, changeEpsSettings(1, 1)).WillOnce(testing::Return(base::noError())); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::router::EpsUpdate_Request protoReq;
                protoReq.set_eps(1);
                protoReq.set_refresh_interval(1);
                return createRequest<eEngine::router::EpsUpdate_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return changeEpsSettings(router); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            { EXPECT_CALL(mock, changeEpsSettings(1, 1)).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return changeEpsSettings(router); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        /***********************************************************************
         * GetEpsSettings
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::router::EpsGet_Request protoReq;
                return createRequest<eEngine::router::EpsGet_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return getEpsSettings(router); },
            []()
            {
                eEngine::router::EpsGet_Response protoRes;
                protoRes.set_eps(1);
                protoRes.set_refresh_interval(1);
                protoRes.set_enabled(true);
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::router::EpsGet_Response>(protoRes);
            },
            [](auto& mock)
            { EXPECT_CALL(mock, getEpsSettings()).WillOnce(testing::Return(std::make_tuple(1, 1, true))); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::router::EpsGet_Request protoReq;
                return createRequest<eEngine::router::EpsGet_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return getEpsSettings(router); },
            []() { return userErrorResponse<eEngine::router::EpsGet_Response>("error"); },
            [](auto& mock) { EXPECT_CALL(mock, getEpsSettings()).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return getEpsSettings(router); },
            []()
            {
                return userErrorResponse<eEngine::router::EpsGet_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        /***********************************************************************
         * ActivateEpsLimiter
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::router::EpsEnable_Request protoReq;
                return createRequest<eEngine::router::EpsEnable_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return activateEpsLimiter(router); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, activateEpsCounter(true)).WillOnce(testing::Return(base::noError())); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::router::EpsEnable_Request protoReq;
                return createRequest<eEngine::router::EpsEnable_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return activateEpsLimiter(router); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            { EXPECT_CALL(mock, activateEpsCounter(true)).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return activateEpsLimiter(router); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        /***********************************************************************
         * DeactivateEpsLimiter
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::router::EpsEnable_Request protoReq;
                return createRequest<eEngine::router::EpsEnable_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return deactivateEpsLimiter(router); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            { EXPECT_CALL(mock, activateEpsCounter(false)).WillOnce(testing::Return(base::noError())); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::router::EpsEnable_Request protoReq;
                return createRequest<eEngine::router::EpsEnable_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return deactivateEpsLimiter(router); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            { EXPECT_CALL(mock, activateEpsCounter(false)).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::router::IRouterAPI>& router) { return deactivateEpsLimiter(router); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {})));

// TODO: add separate tests for routeGet and tableGet
