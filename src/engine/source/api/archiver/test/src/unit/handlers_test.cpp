#include <gtest/gtest.h>

#include <api/adapter/baseHandler_test.hpp>
#include <api/archiver/handlers.hpp>
#include <archiver/mockArchiver.hpp>
#include <eMessages/archiver.pb.h>

using namespace api::adapter;
using namespace api::test;
using namespace api::archiver;
using namespace api::archiver::handlers;
using namespace ::archiver::mocks;

using ArchiverHandlerTest = BaseHandlerTest<::archiver::IArchiver, MockArchiver>;
using ArchiverHandlerT = Params<::archiver::IArchiver, MockArchiver>;

TEST_P(ArchiverHandlerTest, Handler)
{
    auto [reqGetter, handlerGetter, resGetter, mocker] = GetParam();
    handlerTest(reqGetter, handlerGetter, resGetter, m_iHandler, m_mockHandler, mocker);
}

INSTANTIATE_TEST_SUITE_P(
    Api,
    ArchiverHandlerTest,
    ::testing::Values(
        /***********************************************************************
         * ActivateArchiver
         **********************************************************************/
        // Success
        ArchiverHandlerT(
            []()
            {
                eEngine::archiver::ArchiverActivate_Request protoReq;
                return createRequest<eEngine::archiver::ArchiverActivate_Request>(protoReq);
            },
            [](const std::shared_ptr<::archiver::IArchiver>& archiver) { return activateArchiver(archiver); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, activate()); }),
        // Wrong request type
        ArchiverHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::archiver::IArchiver>& archiver) { return activateArchiver(archiver); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        /***********************************************************************
         * DeactivateArchiver
         **********************************************************************/
        // Success
        ArchiverHandlerT(
            []()
            {
                eEngine::archiver::ArchiverDeactivate_Request protoReq;
                return createRequest<eEngine::archiver::ArchiverDeactivate_Request>(protoReq);
            },
            [](const std::shared_ptr<::archiver::IArchiver>& archiver) { return deactivateArchiver(archiver); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, deactivate()); }),
        // Wrong request type
        ArchiverHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::archiver::IArchiver>& archiver) { return deactivateArchiver(archiver); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        /***********************************************************************
         * GetArchiverStatus
         **********************************************************************/
        // Success
        ArchiverHandlerT(
            []()
            {
                eEngine::archiver::ArchiverStatus_Request protoReq;
                return createRequest<eEngine::archiver::ArchiverStatus_Request>(protoReq);
            },
            [](const std::shared_ptr<::archiver::IArchiver>& archiver) { return getArchiverStatus(archiver); },
            []()
            {
                eEngine::archiver::ArchiverStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.set_active(true);
                return userResponse<eEngine::archiver::ArchiverStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, isActive()).WillOnce(testing::Return(true)); }),
        // Wrong request type
        ArchiverHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::archiver::IArchiver>& archiver) { return getArchiverStatus(archiver); },
            []()
            {
                return userErrorResponse<eEngine::archiver::ArchiverStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {})));
