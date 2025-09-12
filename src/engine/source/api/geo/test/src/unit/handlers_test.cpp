#include <gtest/gtest.h>

#include <api/adapter/baseHandler_test.hpp>
#include <api/geo/handlers.hpp>
#include <eMessages/geo.pb.h>
#include <geo/mockManager.hpp>

using namespace api::adapter;
using namespace api::test;
using namespace api::geo;
using namespace api::geo::handlers;
using namespace ::geo::mocks;

using GeoHandlerTest = BaseHandlerTest<::geo::IManager, MockManager>;

TEST_P(GeoHandlerTest, Handler)
{
    auto [reqGetter, handlerGetter, resGetter, mocker] = GetParam();
    handlerTest(reqGetter, handlerGetter, resGetter, m_iHandler, m_mockHandler, mocker);
}

using HandlerT = Params<::geo::IManager, MockManager>;

INSTANTIATE_TEST_SUITE_P(
    Api,
    GeoHandlerTest,
    ::testing::Values(
        /***********************************************************************
         * AddDb
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::geo::DbPost_Request protoReq;
                protoReq.set_path("path");
                protoReq.set_type("city");
                return createRequest<eEngine::geo::DbPost_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return addDb(geoManager); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            { EXPECT_CALL(mock, addDb(testing::_, testing::_)).WillOnce(testing::Return(base::noError())); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::geo::DbPost_Request protoReq;
                protoReq.set_path("path");
                protoReq.set_type("city");
                return createRequest<eEngine::geo::DbPost_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return addDb(geoManager); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            { EXPECT_CALL(mock, addDb(testing::_, testing::_)).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return addDb(geoManager); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Empty path
        HandlerT(
            []()
            {
                eEngine::geo::DbPost_Request protoReq;
                protoReq.set_path("");
                protoReq.set_type("city");
                return createRequest<eEngine::geo::DbPost_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return addDb(geoManager); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Path cannot be empty"); },
            [](auto&) {}),
        // Invalid type
        HandlerT(
            []()
            {
                eEngine::geo::DbPost_Request protoReq;
                protoReq.set_path("path");
                protoReq.set_type("invalid");
                return createRequest<eEngine::geo::DbPost_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return addDb(geoManager); },
            []()
            { return userErrorResponse<eEngine::GenericStatus_Response>("Invalid geo::Type name string 'invalid'"); },
            [](auto&) {}),
        /***********************************************************************
         * DelDb
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::geo::DbDelete_Request protoReq;
                protoReq.set_path("path");
                return createRequest<eEngine::geo::DbDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return delDb(geoManager); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, removeDb(testing::_)).WillOnce(testing::Return(base::noError())); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::geo::DbDelete_Request protoReq;
                protoReq.set_path("path");
                return createRequest<eEngine::geo::DbDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return delDb(geoManager); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            { EXPECT_CALL(mock, removeDb(testing::_)).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return delDb(geoManager); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Empty path
        HandlerT(
            []()
            {
                eEngine::geo::DbDelete_Request protoReq;
                protoReq.set_path("");
                return createRequest<eEngine::geo::DbDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return delDb(geoManager); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Path cannot be empty"); },
            [](auto&) {}),
        /***********************************************************************
         * ListDb
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::geo::DbList_Request protoReq;
                return createRequest<eEngine::geo::DbList_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return listDb(geoManager); },
            []()
            {
                eEngine::geo::DbList_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                std::vector<::geo::DbInfo> dbs = {{"path0", "name0", ::geo::Type::CITY},
                                                  {"path1", "name1", ::geo::Type::ASN}};
                for (const auto& db : dbs)
                {
                    auto* dbResponse = protoRes.add_entries();
                    dbResponse->set_path(db.path);
                    dbResponse->set_name(db.name);
                    dbResponse->set_type(::geo::typeName(db.type));
                }
                return userResponse<eEngine::geo::DbList_Response>(protoRes);
            },
            [](auto& mock)
            {
                std::vector<::geo::DbInfo> dbs = {{"path0", "name0", ::geo::Type::CITY},
                                                  {"path1", "name1", ::geo::Type::ASN}};
                EXPECT_CALL(mock, listDbs()).WillOnce(testing::Return(dbs));
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
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return listDb(geoManager); },
            []()
            {
                return userErrorResponse<eEngine::geo::DbList_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        /***********************************************************************
         * RemoteUpsertDb
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::geo::DbRemoteUpsert_Request protoReq;
                protoReq.set_path("path");
                protoReq.set_type("city");
                protoReq.set_dburl("dburl");
                protoReq.set_hashurl("hashurl");
                return createRequest<eEngine::geo::DbRemoteUpsert_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return remoteUpsertDb(geoManager); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock, remoteUpsertDb(testing::_, testing::_, testing::_, testing::_))
                    .WillOnce(testing::Return(base::noError()));
            }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::geo::DbRemoteUpsert_Request protoReq;
                protoReq.set_path("path");
                protoReq.set_type("city");
                protoReq.set_dburl("dburl");
                protoReq.set_hashurl("hashurl");
                return createRequest<eEngine::geo::DbRemoteUpsert_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return remoteUpsertDb(geoManager); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            {
                EXPECT_CALL(mock, remoteUpsertDb(testing::_, testing::_, testing::_, testing::_))
                    .WillOnce(testing::Return(base::Error {"error"}));
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
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return remoteUpsertDb(geoManager); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Empty path
        HandlerT(
            []()
            {
                eEngine::geo::DbRemoteUpsert_Request protoReq;
                protoReq.set_path("");
                protoReq.set_type("city");
                protoReq.set_dburl("dburl");
                protoReq.set_hashurl("hashurl");
                return createRequest<eEngine::geo::DbRemoteUpsert_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return remoteUpsertDb(geoManager); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Path is mandatory"); },
            [](auto&) {}),
        // Empty dburl
        HandlerT(
            []()
            {
                eEngine::geo::DbRemoteUpsert_Request protoReq;
                protoReq.set_path("path");
                protoReq.set_type("city");
                protoReq.set_dburl("");
                protoReq.set_hashurl("hashurl");
                return createRequest<eEngine::geo::DbRemoteUpsert_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return remoteUpsertDb(geoManager); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Dburl is mandatory"); },
            [](auto&) {}),
        // Empty hashurl
        HandlerT(
            []()
            {
                eEngine::geo::DbRemoteUpsert_Request protoReq;
                protoReq.set_path("path");
                protoReq.set_type("city");
                protoReq.set_dburl("dburl");
                protoReq.set_hashurl("");
                return createRequest<eEngine::geo::DbRemoteUpsert_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return remoteUpsertDb(geoManager); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Hashurl is mandatory"); },
            [](auto&) {})));
