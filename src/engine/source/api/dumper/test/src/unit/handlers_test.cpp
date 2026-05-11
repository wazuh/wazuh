#include <gtest/gtest.h>

#include <api/adapter/baseHandler_test.hpp>
#include <api/dumper/handlers.hpp>
#include <dumper/mockDumper.hpp>
#include <eMessages/event_dumper.pb.h>

using namespace api::adapter;
using namespace api::test;
using namespace api::dumper;
using namespace api::dumper::handlers;
using namespace ::dumper::mocks;

using DumperHandlerTest = BaseHandlerTest<::dumper::IDumper, MockDumper>;
using DumperHandlerT = Params<::dumper::IDumper, MockDumper>;

TEST_P(DumperHandlerTest, Handler)
{
    auto [reqGetter, handlerGetter, resGetter, mocker] = GetParam();
    handlerTest(reqGetter, handlerGetter, resGetter, m_iHandler, m_mockHandler, mocker);
}

INSTANTIATE_TEST_SUITE_P(
    Api,
    DumperHandlerTest,
    ::testing::Values(
        /***********************************************************************
         * ActivateDumper
         **********************************************************************/
        // Success
        DumperHandlerT(
            []()
            {
                eEngine::event_dumper::EventDumperActivate_Request protoReq;
                return createRequest<eEngine::event_dumper::EventDumperActivate_Request>(protoReq);
            },
            [](const std::shared_ptr<::dumper::IDumper>& dumper) { return activateDumper(dumper); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, activate()); }),
        // Wrong request type
        DumperHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::dumper::IDumper>& dumper) { return activateDumper(dumper); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        /***********************************************************************
         * DeactivateDumper
         **********************************************************************/
        // Success
        DumperHandlerT(
            []()
            {
                eEngine::event_dumper::EventDumperDeactivate_Request protoReq;
                return createRequest<eEngine::event_dumper::EventDumperDeactivate_Request>(protoReq);
            },
            [](const std::shared_ptr<::dumper::IDumper>& dumper) { return deactivateDumper(dumper); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, deactivate()); }),
        // Wrong request type
        DumperHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::dumper::IDumper>& dumper) { return deactivateDumper(dumper); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        /***********************************************************************
         * GetDumperStatus
         **********************************************************************/
        // Success
        DumperHandlerT(
            []()
            {
                eEngine::event_dumper::EventDumperStatus_Request protoReq;
                return createRequest<eEngine::event_dumper::EventDumperStatus_Request>(protoReq);
            },
            [](const std::shared_ptr<::dumper::IDumper>& dumper) { return getDumperStatus(dumper); },
            []()
            {
                eEngine::event_dumper::EventDumperStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.set_active(true);
                return userResponse<eEngine::event_dumper::EventDumperStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, isActive()).WillOnce(testing::Return(true)); }),
        // Wrong request type
        DumperHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::dumper::IDumper>& dumper) { return getDumperStatus(dumper); },
            []()
            {
                return userErrorResponse<eEngine::event_dumper::EventDumperStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {})));
