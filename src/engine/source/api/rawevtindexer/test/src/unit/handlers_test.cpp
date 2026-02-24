#include <gtest/gtest.h>

#include <api/adapter/baseHandler_test.hpp>
#include <api/rawevtindexer/handlers.hpp>
#include <eMessages/rawevtindexer.pb.h>
#include <rawevtindexer/mockraweventindexer.hpp>

using namespace api::adapter;
using namespace api::test;
using namespace api::rawevtindexer;
using namespace api::rawevtindexer::handlers;
using namespace ::raweventindexer::mocks;

using RawEventIndexerHandlerTest = BaseHandlerTest<::raweventindexer::IRawEventIndexer, MockRawEventIndexer>;
using RawEventIndexerHandlerT = Params<::raweventindexer::IRawEventIndexer, MockRawEventIndexer>;

TEST_P(RawEventIndexerHandlerTest, Handler)
{
    auto [reqGetter, handlerGetter, resGetter, mocker] = GetParam();
    handlerTest(reqGetter, handlerGetter, resGetter, m_iHandler, m_mockHandler, mocker);
}

INSTANTIATE_TEST_SUITE_P(
    Api,
    RawEventIndexerHandlerTest,
    ::testing::Values(
        /***********************************************************************
         * EnableRawEventIndexer
         **********************************************************************/
        // Success
        RawEventIndexerHandlerT(
            []()
            {
                eEngine::rawevtindexer::RawEvtIndexerEnable_Request protoReq;
                return createRequest<eEngine::rawevtindexer::RawEvtIndexerEnable_Request>(protoReq);
            },
            [](const std::shared_ptr<::raweventindexer::IRawEventIndexer>& rawIndexer)
            { return enableRawEventIndexer(rawIndexer); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, enable()); }),
        // Wrong request type
        RawEventIndexerHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::raweventindexer::IRawEventIndexer>& rawIndexer)
            { return enableRawEventIndexer(rawIndexer); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),

        /***********************************************************************
         * DisableRawEventIndexer
         **********************************************************************/
        // Success
        RawEventIndexerHandlerT(
            []()
            {
                eEngine::rawevtindexer::RawEvtIndexerDisable_Request protoReq;
                return createRequest<eEngine::rawevtindexer::RawEvtIndexerDisable_Request>(protoReq);
            },
            [](const std::shared_ptr<::raweventindexer::IRawEventIndexer>& rawIndexer)
            { return disableRawEventIndexer(rawIndexer); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, disable()); }),
        // Wrong request type
        RawEventIndexerHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::raweventindexer::IRawEventIndexer>& rawIndexer)
            { return disableRawEventIndexer(rawIndexer); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),

        /***********************************************************************
         * GetRawEventIndexerStatus
         **********************************************************************/
        // Success
        RawEventIndexerHandlerT(
            []()
            {
                eEngine::rawevtindexer::RawEvtIndexerStatus_Request protoReq;
                return createRequest<eEngine::rawevtindexer::RawEvtIndexerStatus_Request>(protoReq);
            },
            [](const std::shared_ptr<::raweventindexer::IRawEventIndexer>& rawIndexer)
            { return getRawEventIndexerStatus(rawIndexer); },
            []()
            {
                eEngine::rawevtindexer::RawEvtIndexerStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.set_enabled(true);
                return userResponse<eEngine::rawevtindexer::RawEvtIndexerStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, isEnabled()).WillOnce(testing::Return(true)); }),
        // Wrong request type
        RawEventIndexerHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::raweventindexer::IRawEventIndexer>& rawIndexer)
            { return getRawEventIndexerStatus(rawIndexer); },
            []()
            {
                return userErrorResponse<eEngine::rawevtindexer::RawEvtIndexerStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {})));
