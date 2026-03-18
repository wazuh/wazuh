#include <gtest/gtest.h>

#include <functional>
#include <stdexcept>
#include <string>

#include <api/adapter/baseHandler_test.hpp>
#include <api/tester/handlers.hpp>
#include <base/json.hpp>
#include <cmstore/mockcmstore.hpp>
#include <eMessages/tester.pb.h>
#include <router/mockTester.hpp>
#include <schemf/mockSchema.hpp>

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

httplib::Response makeRunPostSuccessResponse(const std::string& jsonBody = R"({})")
{
    eEngine::tester::RunPost_Response protoRes;
    protoRes.set_status(eEngine::ReturnStatus::OK);

    auto structOrErr = eMessage::eMessageFromJson<google::protobuf::Struct>(jsonBody);
    if (std::holds_alternative<base::Error>(structOrErr))
    {
        throw std::logic_error("Failed to build expected success response payload");
    }

    *protoRes.mutable_result()->mutable_output() = std::get<google::protobuf::Struct>(structOrErr);
    return userResponse<eEngine::tester::RunPost_Response>(protoRes);
}

::router::test::Output makeOutput(const std::string& jsonBody = R"({})")
{
    ::router::test::Output output;
    output.event() = std::make_shared<json::Json>(jsonBody.c_str());
    return output;
}

struct LogtestDeleteCase
{
    std::string name;
    std::function<void(MockTesterAPI&, cm::store::MockICMstore&)> mocker;
    std::function<httplib::Response()> expectedResponse;
};

struct LogtestPostCase
{
    std::string name;
    std::function<eEngine::tester::PublicRunPost_Request()> makeReq;
    std::function<void(MockTesterAPI&)> mocker;
    std::function<httplib::Response()> expectedResponse;
    std::function<std::shared_ptr<schemf::IValidator>()> makeSchema;
};

std::shared_ptr<schemf::IValidator> makeSchemaValidator(bool shouldValidate)
{
    auto schema = std::make_shared<schemf::mocks::MockSchema>();
    EXPECT_CALL(*schema, validate(testing::_, testing::Matcher<const json::Json&>(testing::_)))
        .WillRepeatedly(
            [shouldValidate](const auto&, const auto&) -> base::RespOrError<schemf::ValidationResult>
            {
                if (shouldValidate)
                {
                    return schemf::ValidationResult {};
                }

                return base::Error {"schema validation failed"};
            });

    return schema;
}
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
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Invalid policy name: Invalid namespace ID: ");
            },
            [](auto&) {}),
        // Invalid namespace ID
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
            []()
            {
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

class LogtestPostTest : public ::testing::TestWithParam<LogtestPostCase>
{
};

TEST_P(LogtestPostTest, Handler)
{
    auto tester = std::make_shared<MockTesterAPI>();
    const auto& testCase = GetParam();
    testCase.mocker(*tester);

    std::shared_ptr<schemf::IValidator> schema = testCase.makeSchema();

    auto handler = publicRunPost(tester, base::eventParsers::parsePublicEvent, schema);

    auto protoReq = testCase.makeReq();
    auto req = createRequest<eEngine::tester::PublicRunPost_Request>(protoReq);

    httplib::Response res;
    handler(req, res);

    auto expected = testCase.expectedResponse();
    EXPECT_EQ(res.status, expected.status);
    EXPECT_EQ(res.body, expected.body);
}

INSTANTIATE_TEST_SUITE_P(
    Api,
    LogtestPostTest,
    ::testing::Values(
        // Success case with valid metadata and NONE trace level
        LogtestPostCase {
            "Success",
            []()
            {
                eEngine::tester::PublicRunPost_Request protoReq;
                protoReq.set_queue(1);
                protoReq.set_location("/var/log/test");
                protoReq.set_event("some event");
                protoReq.set_trace_level("NONE");
                protoReq.set_space("test-session");

                google::protobuf::Struct meta;
                auto& wazuhValue = (*meta.mutable_fields())["wazuh"];
                auto* wazuhStruct = wazuhValue.mutable_struct_value();
                (*wazuhStruct->mutable_fields())["agent_name"].set_string_value("AgentName");
                *protoReq.mutable_metadata() = meta;
                return protoReq;
            },
            [](auto& tester)
            {
                EXPECT_CALL(tester, ingestTest(testing::_, testing::_))
                    .WillOnce(
                        [](auto&&, auto&&)
                        {
                            std::promise<base::RespOrError<::router::test::Output>> p;
                            p.set_value(makeOutput(R"({"status":"ok"})"));
                            return p.get_future();
                        });
            },
            []() { return makeRunPostSuccessResponse(R"({"status":"ok"})"); },
            // Schema: validation OK, fields exist
            []() { return makeSchemaValidator(true); },
        },
        // Fail case with invalid metadata
        LogtestPostCase {
            "Failed metadata",
            []()
            {
                eEngine::tester::PublicRunPost_Request protoReq;
                protoReq.set_queue(1);
                protoReq.set_location("/var/log/test");
                protoReq.set_event("some event");
                protoReq.set_trace_level("NONE");

                google::protobuf::Struct meta;
                (*meta.mutable_fields())["notwazuh.agent"].set_string_value("RandomField");
                *protoReq.mutable_metadata() = meta;
                return protoReq;
            },
            [](auto& tester) { EXPECT_CALL(tester, ingestTest(testing::_, testing::_)).Times(0); },
            []()
            { return userErrorResponse<eEngine::tester::RunPost_Response>("Metadata must be a non-empty object with 'wazuh' as root"); },
            []() { return makeSchemaValidator(false); },
        },
        LogtestPostCase {
            "QueueZero",
            []()
            {
                eEngine::tester::PublicRunPost_Request protoReq;
                protoReq.set_queue(0);
                protoReq.set_location("/var/log/test");
                protoReq.set_event("some event");
                protoReq.set_trace_level("NONE");

                google::protobuf::Struct meta;
                (*meta.mutable_fields())["foo"].set_string_value("bar");
                *protoReq.mutable_metadata() = meta;

                return protoReq;
            },
            [](auto& tester)
            {
                // Handler should fail before calling ingestTest
                EXPECT_CALL(tester, ingestTest(testing::_, testing::_)).Times(0);
            },
            []()
            {
                return userErrorResponse<eEngine::tester::RunPost_Response>(
                    "queue is required and must be non-zero (1..255)");
            },
            []() { return makeSchemaValidator(true); },
        },
        LogtestPostCase {
            "QueueTooHigh",
            []()
            {
                eEngine::tester::PublicRunPost_Request protoReq;
                protoReq.set_queue(300);
                protoReq.set_location("/var/log/test");
                protoReq.set_event("some event");
                protoReq.set_trace_level("NONE");

                google::protobuf::Struct meta;
                (*meta.mutable_fields())["foo"].set_string_value("bar");
                *protoReq.mutable_metadata() = meta;

                return protoReq;
            },
            [](auto& tester) { EXPECT_CALL(tester, ingestTest(testing::_, testing::_)).Times(0); },
            []()
            { return userErrorResponse<eEngine::tester::RunPost_Response>("Invalid queue: 300 (must be 1..255)"); },
            []() { return makeSchemaValidator(true); },
        },
        LogtestPostCase {
            "Ok Without Metadata",
            []()
            {
                eEngine::tester::PublicRunPost_Request protoReq;
                protoReq.set_queue(1);
                protoReq.set_location("/var/log/test");
                protoReq.set_event("some event");
                protoReq.set_trace_level("NONE");
                protoReq.set_space("test-session");
                // No metadata set
                return protoReq;
            },
            [](auto& tester)
            {
                EXPECT_CALL(tester, ingestTest(testing::_, testing::_))
                    .WillOnce(
                        [](auto&&, auto&&)
                        {
                            std::promise<base::RespOrError<::router::test::Output>> p;
                            p.set_value(makeOutput(R"({"status":"ok"})"));
                            return p.get_future();
                        });
            },
            []() { return makeRunPostSuccessResponse(R"({"status":"ok"})"); },
            []() { return makeSchemaValidator(true); },
        },
        LogtestPostCase {
            "Failed metadata type",
            []()
            {
                eEngine::tester::PublicRunPost_Request protoReq;
                protoReq.set_queue(1);
                protoReq.set_location("/var/log/test");
                protoReq.set_event("   ");
                protoReq.set_trace_level("NONE");

                google::protobuf::Struct meta;
                auto& wazuhValue = (*meta.mutable_fields())["wazuh"];
                auto* wazuhStruct = wazuhValue.mutable_struct_value();
                (*wazuhStruct->mutable_fields())["foo"].set_string_value("bar");
                *protoReq.mutable_metadata() = meta;

                return protoReq;
            },
            [](auto& tester) { EXPECT_CALL(tester, ingestTest(testing::_, testing::_)).Times(0); },
            []()
            {
                return userErrorResponse<eEngine::tester::RunPost_Response>(
                    "Metadata field 'wazuh.foo' doesn't exist or doesn't match the expected one from the schema");
            },
            []() { return makeSchemaValidator(false); },
        },
        LogtestPostCase {
            "EmptyEvent",
            []()
            {
                eEngine::tester::PublicRunPost_Request protoReq;
                protoReq.set_queue(1);
                protoReq.set_location("/var/log/test");
                protoReq.set_event("   ");
                protoReq.set_trace_level("NONE");

                google::protobuf::Struct meta;
                auto& wazuhValue = (*meta.mutable_fields())["wazuh"];
                auto* wazuhStruct = wazuhValue.mutable_struct_value();
                (*wazuhStruct->mutable_fields())["foo"].set_string_value("bar");
                *protoReq.mutable_metadata() = meta;

                return protoReq;
            },
            [](auto& tester) { EXPECT_CALL(tester, ingestTest(testing::_, testing::_)).Times(0); },
            []()
            { return userErrorResponse<eEngine::tester::RunPost_Response>("event is required and cannot be empty"); },
            []() { return makeSchemaValidator(true); },
        }));

class LogtestDeleteTest : public ::testing::TestWithParam<LogtestDeleteCase>
{
};

TEST_P(LogtestDeleteTest, Handler)
{
    auto tester = std::make_shared<MockTesterAPI>();
    auto store = std::make_shared<cm::store::MockICMstore>();

    eEngine::tester::LogtestDelete_Request protoReq;
    protoReq.set_space("test");
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
                EXPECT_CALL(tester, getTestEntry("test")).WillOnce(::testing::Return(base::Error {"not found"}));
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
                const auto entry = makeEntry("test", "policy_validate_x");
                EXPECT_CALL(tester, getTestEntry("test")).WillOnce(::testing::Return(entry));
                EXPECT_CALL(store, existsNamespace(::testing::_)).WillOnce(::testing::Return(true));
                EXPECT_CALL(store, deleteNamespace(::testing::_)).WillOnce(::testing::Return());
                EXPECT_CALL(tester, deleteTestEntry("test")).WillOnce(::testing::Return(base::noError()));
            },
            []() { return makeOkResponse(); },
        },
        LogtestDeleteCase {
            "NamespaceMissingDeletesSessionOnly",
            [](auto& tester, auto& store)
            {
                const auto entry = makeEntry("test", "policy_validate_x");
                EXPECT_CALL(tester, getTestEntry("test")).WillOnce(::testing::Return(entry));
                EXPECT_CALL(store, existsNamespace(::testing::_)).WillOnce(::testing::Return(false));
                EXPECT_CALL(store, deleteNamespace(::testing::_)).Times(0);
                EXPECT_CALL(tester, deleteTestEntry("test")).WillOnce(::testing::Return(base::noError()));
            },
            []() { return makeOkResponse(); },
        },
        LogtestDeleteCase {
            "NamespaceDeleteFailsReturnsError",
            [](auto& tester, auto& store)
            {
                const auto entry = makeEntry("test", "policy_validate_x");
                EXPECT_CALL(tester, getTestEntry("test")).WillOnce(::testing::Return(entry));
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
                const auto entry = makeEntry("test", "policy_validate_x");
                EXPECT_CALL(tester, getTestEntry("test")).WillOnce(::testing::Return(entry));
                EXPECT_CALL(store, existsNamespace(::testing::_)).WillOnce(::testing::Return(true));
                EXPECT_CALL(store, deleteNamespace(::testing::_)).WillOnce(::testing::Return());
                EXPECT_CALL(tester, deleteTestEntry("test"))
                    .WillOnce(::testing::Return(base::Error {"session locked"}));
            },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Cleanup: failed deleting session 'test': session locked");
            },
        }),
    [](const testing::TestParamInfo<LogtestDeleteCase>& info) { return info.param.name; });

TEST(LogtestDeleteMissingSpace, MissingSpaceReturnsError)
{
    auto tester = std::make_shared<MockTesterAPI>();
    auto store = std::make_shared<cm::store::MockICMstore>();

    eEngine::tester::LogtestDelete_Request protoReq;
    // space is not set (empty)
    auto req = createRequest<eEngine::tester::LogtestDelete_Request>(protoReq);

    auto handler = logtestDelete(tester, store);
    httplib::Response res;
    handler(req, res);

    auto expected = userErrorResponse<eEngine::GenericStatus_Response>("space is required and cannot be empty");
    EXPECT_EQ(res.status, expected.status);
    EXPECT_EQ(res.body, expected.body);
}
