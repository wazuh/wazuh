#include <gtest/gtest.h>

#include <functional>
#include <string>
#include <stdexcept>

#include <api/adapter/baseHandler_test.hpp>
#include <api/tester/handlers.hpp>
#include <base/json.hpp>
#include <cmstore/mockcmstore.hpp>
#include <eMessages/tester.pb.h>
#include <router/mockTester.hpp>

using namespace api::adapter;
using namespace api::test;
using namespace api::tester;
using namespace api::tester::handlers;
using namespace ::tester::mocks;

using TesterHandlerTest = BaseHandlerTest<::router::ITesterAPI, MockTesterAPI>;

namespace
{
::router::test::Entry makeEntry(std::string name, std::string nsId)
{
    ::router::test::EntryPost post(std::move(name), cm::store::NamespaceId {std::move(nsId)}, 0);
    return ::router::test::Entry {post};
}

httplib::Response makeOkResponse()
{
    eEngine::GenericStatus_Response protoRes;
    protoRes.set_status(eEngine::ReturnStatus::OK);
    return userResponse<eEngine::GenericStatus_Response>(protoRes);
}

struct LogtestDeleteCase
{
    std::string name;
    std::function<void(MockTesterAPI&, cm::store::MockICMstore&)> mocker;
    std::function<httplib::Response()> expectedResponse;
};
} // namespace

TEST_P(TesterHandlerTest, Handler)
{
    auto [reqGetter, handlerGetter, resGetter, mocker] = GetParam();
    handlerTest(reqGetter, handlerGetter, resGetter, m_iHandler, m_mockHandler, mocker);
}

using HandlerT = Params<::router::ITesterAPI, MockTesterAPI>;

INSTANTIATE_TEST_SUITE_P(
    Api,
    TesterHandlerTest,
    ::testing::Values(
        /***********************************************************************
         * SessionPost
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::tester::SessionPost_Request protoReq;
                protoReq.mutable_session()->set_name("name");
                protoReq.mutable_session()->set_namespaceid("policy");
                protoReq.mutable_session()->set_lifetime(10);
                protoReq.mutable_session()->set_description("some_description");
                return createRequest<eEngine::tester::SessionPost_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::ITesterAPI>& tester) { return sessionPost(tester); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            { EXPECT_CALL(mock, postTestEntry(testing::_)).WillOnce(testing::Return(base::noError())); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::tester::SessionPost_Request protoReq;
                protoReq.mutable_session()->set_name("name");
                protoReq.mutable_session()->set_namespaceid("policy");
                protoReq.mutable_session()->set_lifetime(10);
                return createRequest<eEngine::tester::SessionPost_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::ITesterAPI>& tester) { return sessionPost(tester); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            { EXPECT_CALL(mock, postTestEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::router::ITesterAPI>& tester) { return sessionPost(tester); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing session
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
            [](const std::shared_ptr<::router::ITesterAPI>& tester) { return sessionPost(tester); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /session"); },
            [](auto&) {}),
        // Invalid policy
        HandlerT(
            []()
            {
                json::Json jsonReq;
                jsonReq.setObject("/session");
                jsonReq.setInt(10, "/route/lifetime");
                httplib::Request req;
                req.body = jsonReq.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<::router::ITesterAPI>& tester) { return sessionPost(tester); },
            []() {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Invalid policy name: Invalid namespace ID: ");
            },
            [](auto&) {}),
        // Invalid filter
        HandlerT(
            []()
            {
                json::Json jsonReq;
                jsonReq.setObject("/session");
                jsonReq.setString("not-valid", "/session/namespaceId");
                jsonReq.setInt(10, "/session/lifetime");
                httplib::Request req;
                req.body = jsonReq.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<::router::ITesterAPI>& tester) { return sessionPost(tester); },
            []() {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Invalid policy name: Invalid namespace ID: not-valid");
            },
            [](auto&) {}),
        // Route with description
        HandlerT(
            []()
            {
                eEngine::tester::SessionPost_Request protoReq;
                protoReq.mutable_session()->set_name("name");
                protoReq.mutable_session()->set_namespaceid("policy");
                protoReq.mutable_session()->set_lifetime(10);
                protoReq.mutable_session()->set_description("description");
                return createRequest<eEngine::tester::SessionPost_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::ITesterAPI>& tester) { return sessionPost(tester); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            { EXPECT_CALL(mock, postTestEntry(testing::_)).WillOnce(testing::Return(base::noError())); }),
        /***********************************************************************
         * SessionDelete
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::tester::SessionDelete_Request protoReq;
                protoReq.set_name("name");
                return createRequest<eEngine::tester::SessionDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::ITesterAPI>& tester) { return sessionDelete(tester); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            { EXPECT_CALL(mock, deleteTestEntry(testing::_)).WillOnce(testing::Return(base::noError())); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::tester::SessionDelete_Request protoReq;
                protoReq.set_name("name");
                return createRequest<eEngine::tester::SessionDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::ITesterAPI>& tester) { return sessionDelete(tester); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            { EXPECT_CALL(mock, deleteTestEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::router::ITesterAPI>& tester) { return sessionDelete(tester); },
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
            [](const std::shared_ptr<::router::ITesterAPI>& tester) { return sessionDelete(tester); },
            []()
            { return userErrorResponse<eEngine::GenericStatus_Response>("Invalid name name: Name cannot be empty"); },
            [](auto&) {}),
        /***********************************************************************
         * SessionReload
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::tester::SessionReload_Request protoReq;
                protoReq.set_name("name");
                return createRequest<eEngine::tester::SessionReload_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::ITesterAPI>& tester) { return sessionReload(tester); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            { EXPECT_CALL(mock, reloadTestEntry(testing::_)).WillOnce(testing::Return(base::noError())); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::tester::SessionReload_Request protoReq;
                protoReq.set_name("name");
                return createRequest<eEngine::tester::SessionReload_Request>(protoReq);
            },
            [](const std::shared_ptr<::router::ITesterAPI>& tester) { return sessionReload(tester); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            { EXPECT_CALL(mock, reloadTestEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::router::ITesterAPI>& tester) { return sessionReload(tester); },
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
            [](const std::shared_ptr<::router::ITesterAPI>& tester) { return sessionReload(tester); },
            []()
            { return userErrorResponse<eEngine::GenericStatus_Response>("Invalid name name: Name cannot be empty"); },
            [](auto&) {})));

// TODO: add separate tests for routeGet tableGet and runPost (need more than one mock)

class LogtestDeleteTest : public ::testing::TestWithParam<LogtestDeleteCase>
{
};

TEST_P(LogtestDeleteTest, Handler)
{
    auto tester = std::make_shared<MockTesterAPI>();
    auto store = std::make_shared<cm::store::MockICMstore>();

    eEngine::tester::LogtestDelete_Request protoReq;
    auto req = createRequest<eEngine::tester::LogtestDelete_Request>(protoReq);

    const auto& testCase = GetParam();
    testCase.mocker(*tester, *store);

    auto handler = logtestDelete(tester, store);
    httplib::Response res;
    handler(req, res);

    auto expected = testCase.expectedResponse();
    EXPECT_EQ(res.status, expected.status);
    EXPECT_EQ(res.body, expected.body);
}

INSTANTIATE_TEST_SUITE_P(
    Api,
    LogtestDeleteTest,
    ::testing::Values(
        LogtestDeleteCase {
            "SessionMissingReturnsOk",
            [](auto& tester, auto& store)
            {
                EXPECT_CALL(tester, getTestEntry("testing")).WillOnce(::testing::Return(base::Error {"not found"}));
                EXPECT_CALL(store, existsNamespace(::testing::_)).Times(0);
                EXPECT_CALL(store, deleteNamespace(::testing::_)).Times(0);
                EXPECT_CALL(tester, deleteTestEntry(::testing::_)).Times(0);
            },
            []() { return makeOkResponse(); },
        },
        LogtestDeleteCase {
            "NamespaceExistsDeletesNamespaceAndSession",
            [](auto& tester, auto& store)
            {
                const auto entry = makeEntry("testing", "policy_validate_x");
                EXPECT_CALL(tester, getTestEntry("testing")).WillOnce(::testing::Return(entry));
                EXPECT_CALL(store, existsNamespace(::testing::_)).WillOnce(::testing::Return(true));
                EXPECT_CALL(store, deleteNamespace(::testing::_)).WillOnce(::testing::Return());
                EXPECT_CALL(tester, deleteTestEntry("testing")).WillOnce(::testing::Return(base::noError()));
            },
            []() { return makeOkResponse(); },
        },
        LogtestDeleteCase {
            "NamespaceMissingDeletesSessionOnly",
            [](auto& tester, auto& store)
            {
                const auto entry = makeEntry("testing", "policy_validate_x");
                EXPECT_CALL(tester, getTestEntry("testing")).WillOnce(::testing::Return(entry));
                EXPECT_CALL(store, existsNamespace(::testing::_)).WillOnce(::testing::Return(false));
                EXPECT_CALL(store, deleteNamespace(::testing::_)).Times(0);
                EXPECT_CALL(tester, deleteTestEntry("testing")).WillOnce(::testing::Return(base::noError()));
            },
            []() { return makeOkResponse(); },
        },
        LogtestDeleteCase {
            "NamespaceDeleteFailsReturnsError",
            [](auto& tester, auto& store)
            {
                const auto entry = makeEntry("testing", "policy_validate_x");
                EXPECT_CALL(tester, getTestEntry("testing")).WillOnce(::testing::Return(entry));
                EXPECT_CALL(store, existsNamespace(::testing::_)).WillOnce(::testing::Return(true));
                EXPECT_CALL(store, deleteNamespace(::testing::_))
                    .WillOnce(::testing::Throw(std::runtime_error {"boom"}));
                EXPECT_CALL(tester, deleteTestEntry(::testing::_)).Times(0);
            },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Cleanup: failed deleting namespace 'policy_validate_x': boom");
            },
        },
        LogtestDeleteCase {
            "SessionDeleteFailsReturnsError",
            [](auto& tester, auto& store)
            {
                const auto entry = makeEntry("testing", "policy_validate_x");
                EXPECT_CALL(tester, getTestEntry("testing")).WillOnce(::testing::Return(entry));
                EXPECT_CALL(store, existsNamespace(::testing::_)).WillOnce(::testing::Return(true));
                EXPECT_CALL(store, deleteNamespace(::testing::_)).WillOnce(::testing::Return());
                EXPECT_CALL(tester, deleteTestEntry("testing"))
                    .WillOnce(::testing::Return(base::Error {"session locked"}));
            },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Cleanup: failed deleting session 'testing': session locked");
            },
        }),
    [](const testing::TestParamInfo<LogtestDeleteCase>& info) { return info.param.name; });
