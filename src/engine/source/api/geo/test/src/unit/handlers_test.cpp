#include <gtest/gtest.h>

#include <api/adapter/baseHandler_test.hpp>
#include <api/geo/handlers.hpp>
#include <eMessages/geo.pb.h>

#include <google/protobuf/struct.pb.h>
#include <google/protobuf/util/message_differencer.h>

#include <geo/mockLocator.hpp>
#include <geo/mockManager.hpp>

using namespace api::adapter;
using namespace api::test;
using namespace api::geo;
using namespace api::geo::handlers;
using namespace ::geo::mocks;

using GeoHandlerTest = BaseHandlerTest<::geo::IManager, MockManager>;

namespace
{
google::protobuf::Struct makeDbGetDataStruct(bool withCity, bool withAsn)
{
    google::protobuf::Struct root;

    google::protobuf::Struct geo;
    if (withCity)
    {
        (*geo.mutable_fields())["city_name"].set_string_value("Mountain View");
    }

    google::protobuf::Struct asn;
    if (withAsn)
    {
        (*asn.mutable_fields())["number"].set_number_value(15169);
    }

    (*root.mutable_fields())["geo"].mutable_struct_value()->CopyFrom(geo);
    (*root.mutable_fields())["as"].mutable_struct_value()->CopyFrom(asn);

    return root;
}

// Helper function to compare protobuf responses instead of raw strings
template<typename T>
bool compareProtoResponses(const std::string& actual, const std::string& expected)
{
    auto actualProto = eMessage::eMessageFromJson<T>(actual);
    auto expectedProto = eMessage::eMessageFromJson<T>(expected);

    if (std::holds_alternative<base::Error>(actualProto) || std::holds_alternative<base::Error>(expectedProto))
    {
        return false;
    }

    return google::protobuf::util::MessageDifferencer::Equals(std::get<T>(actualProto), std::get<T>(expectedProto));
}
} // namespace

TEST_P(GeoHandlerTest, Handler)
{
    auto [reqGetter, handlerGetter, resGetter, mocker] = GetParam();

    // Custom handler test for GetDb to compare protobuf messages instead of strings
    auto request = reqGetter();
    RouteHandler routeHandler;
    auto expectedResponse = resGetter();
    ASSERT_NO_THROW(routeHandler = handlerGetter(m_iHandler));

    mocker(*m_mockHandler);
    httplib::Response response;
    ASSERT_NO_THROW(routeHandler(request, response));

    EXPECT_EQ(response.status, expectedResponse.status);

    // Check if this is a GetDb request by looking at the request body
    bool isGetDbRequest = request.body.find("\"ip\"") != std::string::npos;

    if (isGetDbRequest && response.status == httplib::StatusCode::OK_200)
    {
        // For GetDb responses, compare protobuf messages to avoid key ordering issues
        EXPECT_TRUE(compareProtoResponses<eEngine::geo::DbGet_Response>(response.body, expectedResponse.body))
            << "Actual: " << response.body << "\nExpected: " << expectedResponse.body;
    }
    else
    {
        // For other responses, compare strings directly
        EXPECT_EQ(response.body, expectedResponse.body);
    }

    // Expired handler test
    m_iHandler.reset();
    m_mockHandler.reset();
    httplib::Response expiredResponse;
    ASSERT_NO_THROW(routeHandler(request, expiredResponse));
    auto expectedExpiredResponse =
        internalErrorResponse<eEngine::GenericStatus_Response>("Error: Handler is not initialized");
    EXPECT_EQ(expiredResponse.status, expectedExpiredResponse.status);
}

using HandlerT = Params<::geo::IManager, MockManager>;

INSTANTIATE_TEST_SUITE_P(
    Api,
    GeoHandlerTest,
    ::testing::Values(
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

                std::vector<::geo::DbInfo> dbs = {
                    {"path0", "name0", "hash0", 1769111225, ::geo::Type::CITY},
                    {"path1", "name1", "hash1", 1769111225, ::geo::Type::ASN}};

                for (const auto& db : dbs)
                {
                    auto* dbResponse = protoRes.add_entries();
                    dbResponse->set_path(db.path);
                    dbResponse->set_name(db.name);
                    dbResponse->set_hash(db.hash);
                    dbResponse->set_createdat(db.createdAt);
                    dbResponse->set_type(::geo::typeName(db.type));
                }

                return userResponse<eEngine::geo::DbList_Response>(protoRes);
            },
            [](auto& mock)
            {
                std::vector<::geo::DbInfo> dbs = {
                    {"path0", "name0", "hash0", 1769111225, ::geo::Type::CITY},
                    {"path1", "name1", "hash1", 1769111225, ::geo::Type::ASN}};

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
         * GetDb
         **********************************************************************/
        // Success with both CITY and ASN data
        HandlerT(
            []()
            {
                eEngine::geo::DbGet_Request protoReq;
                protoReq.set_ip("1.2.3.4");
                return createRequest<eEngine::geo::DbGet_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return getDb(geoManager); },
            []()
            {
                eEngine::geo::DbGet_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);

                protoRes.mutable_data()->CopyFrom(makeDbGetDataStruct(/*withCity=*/true, /*withAsn=*/true));

                return userResponse<eEngine::geo::DbGet_Response>(protoRes);
            },
            [](auto& mock)
            {
                auto cityLocator = std::make_shared<::geo::mocks::MockLocator>();
                auto asnLocator = std::make_shared<::geo::mocks::MockLocator>();

                // City data
                json::Json cityJson;
                cityJson.setString("Mountain View", "/city_name");
                EXPECT_CALL(*cityLocator, getAll("1.2.3.4"))
                    .WillOnce(testing::Return(base::RespOrError<json::Json>(cityJson)));

                // ASN data
                json::Json asnJson;
                asnJson.setInt(15169, "/number");
                EXPECT_CALL(*asnLocator, getAll("1.2.3.4"))
                    .WillOnce(testing::Return(base::RespOrError<json::Json>(asnJson)));

                EXPECT_CALL(mock, getLocator(::geo::Type::CITY))
                    .WillOnce(testing::Return(base::RespOrError<std::shared_ptr<::geo::ILocator>>(cityLocator)));
                EXPECT_CALL(mock, getLocator(::geo::Type::ASN))
                    .WillOnce(testing::Return(base::RespOrError<std::shared_ptr<::geo::ILocator>>(asnLocator)));
            }),

        // Success with only CITY data (ASN database not available)
        HandlerT(
            []()
            {
                eEngine::geo::DbGet_Request protoReq;
                protoReq.set_ip("1.2.3.4");
                return createRequest<eEngine::geo::DbGet_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return getDb(geoManager); },
            []()
            {
                eEngine::geo::DbGet_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);

                protoRes.mutable_data()->CopyFrom(makeDbGetDataStruct(/*withCity=*/true, /*withAsn=*/false));

                return userResponse<eEngine::geo::DbGet_Response>(protoRes);
            },
            [](auto& mock)
            {
                auto cityLocator = std::make_shared<::geo::mocks::MockLocator>();

                json::Json cityJson;
                cityJson.setString("Mountain View", "/city_name");
                EXPECT_CALL(*cityLocator, getAll("1.2.3.4"))
                    .WillOnce(testing::Return(base::RespOrError<json::Json>(cityJson)));

                EXPECT_CALL(mock, getLocator(::geo::Type::CITY))
                    .WillOnce(testing::Return(base::RespOrError<std::shared_ptr<::geo::ILocator>>(cityLocator)));
                EXPECT_CALL(mock, getLocator(::geo::Type::ASN))
                    .WillOnce(testing::Return(base::Error {"Type 'asn' does not have a database"}));
            }),

        // Success with only ASN data (IP not found in CITY)
        HandlerT(
            []()
            {
                eEngine::geo::DbGet_Request protoReq;
                protoReq.set_ip("1.2.3.4");
                return createRequest<eEngine::geo::DbGet_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return getDb(geoManager); },
            []()
            {
                eEngine::geo::DbGet_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);

                protoRes.mutable_data()->CopyFrom(makeDbGetDataStruct(/*withCity=*/false, /*withAsn=*/true));

                return userResponse<eEngine::geo::DbGet_Response>(protoRes);
            },
            [](auto& mock)
            {
                auto cityLocator = std::make_shared<::geo::mocks::MockLocator>();
                auto asnLocator = std::make_shared<::geo::mocks::MockLocator>();

                EXPECT_CALL(*cityLocator, getAll("1.2.3.4"))
                    .WillOnce(testing::Return(base::Error {"No data found for the IP address"}));

                json::Json asnJson;
                asnJson.setInt(15169, "/number");
                EXPECT_CALL(*asnLocator, getAll("1.2.3.4"))
                    .WillOnce(testing::Return(base::RespOrError<json::Json>(asnJson)));

                EXPECT_CALL(mock, getLocator(::geo::Type::CITY))
                    .WillOnce(testing::Return(base::RespOrError<std::shared_ptr<::geo::ILocator>>(cityLocator)));
                EXPECT_CALL(mock, getLocator(::geo::Type::ASN))
                    .WillOnce(testing::Return(base::RespOrError<std::shared_ptr<::geo::ILocator>>(asnLocator)));
            }),

        // Empty IP
        HandlerT(
            []()
            {
                eEngine::geo::DbGet_Request protoReq;
                protoReq.set_ip("");
                return createRequest<eEngine::geo::DbGet_Request>(protoReq);
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return getDb(geoManager); },
            []() { return userErrorResponse<eEngine::geo::DbGet_Response>("IP cannot be empty"); },
            [](auto&) {}),

        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::geo::IManager>& geoManager) { return getDb(geoManager); },
            []()
            {
                return userErrorResponse<eEngine::geo::DbGet_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {})));
