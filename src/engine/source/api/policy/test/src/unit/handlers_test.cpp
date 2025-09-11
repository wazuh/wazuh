#include <gtest/gtest.h>

#include <api/adapter/baseHandler_test.hpp>
#include <api/policy/handlers.hpp>
#include <api/policy/mockPolicy.hpp>
#include <base/json.hpp>
#include <eMessages/policy.pb.h>

using namespace api::adapter;
using namespace api::test;
using namespace api::policy;
using namespace api::policy::handlers;
using namespace api::policy::mocks;

using PolicyHandlerTest = BaseHandlerTest<IPolicy, MockPolicy>;

TEST_P(PolicyHandlerTest, Handler)
{
    auto [reqGetter, handlerGetter, resGetter, mocker] = GetParam();
    handlerTest(reqGetter, handlerGetter, resGetter, m_iHandler, m_mockHandler, mocker);
}

using HandlerT = Params<IPolicy, MockPolicy>;

INSTANTIATE_TEST_SUITE_P(
    Api,
    PolicyHandlerTest,
    ::testing::Values(
        /***********************************************************************
         * StorePost
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::policy::StorePost_Request protoReq;
                protoReq.set_policy("policy");
                return createRequest<eEngine::policy::StorePost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return storePost(policyManager); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, create(testing::_)).WillOnce(testing::Return(base::noError())); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::policy::StorePost_Request protoReq;
                protoReq.set_policy("policy");
                return createRequest<eEngine::policy::StorePost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return storePost(policyManager); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock) { EXPECT_CALL(mock, create(testing::_)).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return storePost(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing /policy
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return storePost(policyManager); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /policy"); },
            [](auto&) {}),
        // Invalid policy name
        HandlerT(
            []()
            {
                eEngine::policy::StorePost_Request protoReq;
                protoReq.set_policy("");
                return createRequest<eEngine::policy::StorePost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return storePost(policyManager); },
            []()
            { return userErrorResponse<eEngine::GenericStatus_Response>("Invalid policy name: Name cannot be empty"); },
            [](auto&) {}),
        /***********************************************************************
         * StoreDelete
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::policy::StoreDelete_Request protoReq;
                protoReq.set_policy("policy");
                return createRequest<eEngine::policy::StoreDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return storeDelete(policyManager); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, del(testing::_)).WillOnce(testing::Return(base::noError())); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::policy::StoreDelete_Request protoReq;
                protoReq.set_policy("policy");
                return createRequest<eEngine::policy::StoreDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return storeDelete(policyManager); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock) { EXPECT_CALL(mock, del(testing::_)).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return storeDelete(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing /policy
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return storeDelete(policyManager); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /policy"); },
            [](auto&) {}),
        // Invalid policy name
        HandlerT(
            []()
            {
                eEngine::policy::StoreDelete_Request protoReq;
                protoReq.set_policy("");
                return createRequest<eEngine::policy::StoreDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return storeDelete(policyManager); },
            []()
            { return userErrorResponse<eEngine::GenericStatus_Response>("Invalid policy name: Name cannot be empty"); },
            [](auto&) {}),
        /***********************************************************************
         * StoreGet
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::policy::StoreGet_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.add_namespaces("ns0");
                protoReq.add_namespaces("ns1");
                return createRequest<eEngine::policy::StoreGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return storeGet(policyManager); },
            []()
            {
                eEngine::policy::StoreGet_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.set_data("policy");
                return userResponse<eEngine::policy::StoreGet_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock, get(testing::_, testing::_))
                    .WillOnce(testing::Return(base::RespOrError<std::string> {"policy"}));
            }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::policy::StoreGet_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.add_namespaces("ns0");
                protoReq.add_namespaces("ns1");
                return createRequest<eEngine::policy::StoreGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return storeGet(policyManager); },
            []() { return userErrorResponse<eEngine::policy::StoreGet_Response>("error"); },
            [](auto& mock)
            { EXPECT_CALL(mock, get(testing::_, testing::_)).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return storeGet(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::StoreGet_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing /policy
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return storeGet(policyManager); },
            []() { return userErrorResponse<eEngine::policy::StoreGet_Response>("Missing /policy"); },
            [](auto&) {}),
        // Invalid policy name
        HandlerT(
            []()
            {
                eEngine::policy::StoreGet_Request protoReq;
                protoReq.set_policy("");
                return createRequest<eEngine::policy::StoreGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return storeGet(policyManager); },
            []() {
                return userErrorResponse<eEngine::policy::StoreGet_Response>(
                    "Invalid policy name: Name cannot be empty");
            },
            [](auto&) {}),
        // Invalid namespace name
        HandlerT(
            []()
            {
                eEngine::policy::StoreGet_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.add_namespaces("ns/0");
                return createRequest<eEngine::policy::StoreGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return storeGet(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::StoreGet_Response>(
                    "Error in namespace name: NamespaceId must have only one part and cannot be empty");
            },
            [](auto&) {}),
        /***********************************************************************
         * PolicyAssetPost
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::policy::AssetPost_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                protoReq.set_asset("asset");
                return createRequest<eEngine::policy::AssetPost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetPost(policyManager); },
            []()
            {
                eEngine::policy::AssetPost_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::policy::AssetPost_Response>(protoRes);
            },
            [](auto& mock) {
                EXPECT_CALL(mock, addAsset(testing::_, testing::_, testing::_))
                    .WillOnce(testing::Return(std::string("")));
            }),
        // Success with warning
        HandlerT(
            []()
            {
                eEngine::policy::AssetPost_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                protoReq.set_asset("asset");
                return createRequest<eEngine::policy::AssetPost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetPost(policyManager); },
            []()
            {
                eEngine::policy::AssetPost_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.set_warning("warning");
                return userResponse<eEngine::policy::AssetPost_Response>(protoRes);
            },
            [](auto& mock) {
                EXPECT_CALL(mock, addAsset(testing::_, testing::_, testing::_))
                    .WillOnce(testing::Return(std::string("warning")));
            }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::policy::AssetPost_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                protoReq.set_asset("asset");
                return createRequest<eEngine::policy::AssetPost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetPost(policyManager); },
            []() { return userErrorResponse<eEngine::policy::AssetPost_Response>("error"); },
            [](auto& mock) {
                EXPECT_CALL(mock, addAsset(testing::_, testing::_, testing::_))
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetPost(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::AssetPost_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing /policy
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetPost(policyManager); },
            []() { return userErrorResponse<eEngine::policy::AssetPost_Response>("Missing /policy"); },
            [](auto&) {}),
        // Invalid policy name
        HandlerT(
            []()
            {
                eEngine::policy::AssetPost_Request protoReq;
                protoReq.set_policy("");
                return createRequest<eEngine::policy::AssetPost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetPost(policyManager); },
            []() {
                return userErrorResponse<eEngine::policy::AssetPost_Response>(
                    "Invalid policy name: Name cannot be empty");
            },
            [](auto&) {}),
        // Missing /namespace
        HandlerT(
            []()
            {
                eEngine::policy::AssetPost_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_asset("asset");
                return createRequest<eEngine::policy::AssetPost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetPost(policyManager); },
            []() { return userErrorResponse<eEngine::policy::AssetPost_Response>("Missing /namespace"); },
            [](auto&) {}),
        // Invalid namespace name
        HandlerT(
            []()
            {
                eEngine::policy::AssetPost_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns/0");
                protoReq.set_asset("asset");
                return createRequest<eEngine::policy::AssetPost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetPost(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::AssetPost_Response>(
                    "Invalid namespace name: NamespaceId must have only one part and cannot be empty");
            },
            [](auto&) {}),
        // Missing /asset
        HandlerT(
            []()
            {
                eEngine::policy::AssetPost_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                return createRequest<eEngine::policy::AssetPost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetPost(policyManager); },
            []() { return userErrorResponse<eEngine::policy::AssetPost_Response>("Missing /asset"); },
            [](auto&) {}),
        // Invalid asset name
        HandlerT(
            []()
            {
                eEngine::policy::AssetPost_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                protoReq.set_asset("");
                return createRequest<eEngine::policy::AssetPost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetPost(policyManager); },
            []() {
                return userErrorResponse<eEngine::policy::AssetPost_Response>(
                    "Invalid asset name: Name cannot be empty");
            },
            [](auto&) {}),
        /***********************************************************************
         * PolicyAssetDelete
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::policy::AssetDelete_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                protoReq.set_asset("asset");
                return createRequest<eEngine::policy::AssetDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetDelete(policyManager); },
            []()
            {
                eEngine::policy::AssetDelete_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::policy::AssetDelete_Response>(protoRes);
            },
            [](auto& mock) {
                EXPECT_CALL(mock, delAsset(testing::_, testing::_, testing::_))
                    .WillOnce(testing::Return(std::string("")));
            }),
        // Success with warning
        HandlerT(
            []()
            {
                eEngine::policy::AssetDelete_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                protoReq.set_asset("asset");
                return createRequest<eEngine::policy::AssetDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetDelete(policyManager); },
            []()
            {
                eEngine::policy::AssetDelete_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.set_warning("warning");
                return userResponse<eEngine::policy::AssetDelete_Response>(protoRes);
            },
            [](auto& mock) {
                EXPECT_CALL(mock, delAsset(testing::_, testing::_, testing::_))
                    .WillOnce(testing::Return(std::string("warning")));
            }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::policy::AssetDelete_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                protoReq.set_asset("asset");
                return createRequest<eEngine::policy::AssetDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetDelete(policyManager); },
            []() { return userErrorResponse<eEngine::policy::AssetDelete_Response>("error"); },
            [](auto& mock) {
                EXPECT_CALL(mock, delAsset(testing::_, testing::_, testing::_))
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetDelete(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::AssetDelete_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing /policy
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetDelete(policyManager); },
            []() { return userErrorResponse<eEngine::policy::AssetDelete_Response>("Missing /policy"); },
            [](auto&) {}),
        // Invalid policy name
        HandlerT(
            []()
            {
                eEngine::policy::AssetDelete_Request protoReq;
                protoReq.set_policy("");
                return createRequest<eEngine::policy::AssetDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetDelete(policyManager); },
            []() {
                return userErrorResponse<eEngine::policy::AssetDelete_Response>(
                    "Invalid policy name: Name cannot be empty");
            },
            [](auto&) {}),
        // Missing /namespace
        HandlerT(
            []()
            {
                eEngine::policy::AssetDelete_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_asset("asset");
                return createRequest<eEngine::policy::AssetDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetDelete(policyManager); },
            []() { return userErrorResponse<eEngine::policy::AssetDelete_Response>("Missing /namespace"); },
            [](auto&) {}),
        // Invalid namespace name
        HandlerT(
            []()
            {
                eEngine::policy::AssetDelete_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns/0");
                protoReq.set_asset("asset");
                return createRequest<eEngine::policy::AssetDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetDelete(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::AssetDelete_Response>(
                    "Invalid namespace name: NamespaceId must have only one part and cannot be empty");
            },
            [](auto&) {}),
        // Missing /asset
        HandlerT(
            []()
            {
                eEngine::policy::AssetDelete_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                return createRequest<eEngine::policy::AssetDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetDelete(policyManager); },
            []() { return userErrorResponse<eEngine::policy::AssetDelete_Response>("Missing /asset"); },
            [](auto&) {}),
        // Invalid asset name
        HandlerT(
            []()
            {
                eEngine::policy::AssetDelete_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                protoReq.set_asset("");
                return createRequest<eEngine::policy::AssetDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetDelete(policyManager); },
            []() {
                return userErrorResponse<eEngine::policy::AssetDelete_Response>(
                    "Invalid asset name: Name cannot be empty");
            },
            [](auto&) {}),
        /***********************************************************************
         * PolicyAssetGet
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::policy::AssetGet_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                return createRequest<eEngine::policy::AssetGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetGet(policyManager); },
            []()
            {
                eEngine::policy::AssetGet_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.add_data("decoder/asset/0");
                return userResponse<eEngine::policy::AssetGet_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock, listAssets(testing::_, testing::_))
                    .WillOnce(testing::Return(std::list<base::Name> {base::Name("decoder/asset/0")}));
            }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::policy::AssetGet_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                return createRequest<eEngine::policy::AssetGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetGet(policyManager); },
            []() { return userErrorResponse<eEngine::policy::AssetGet_Response>("error"); },
            [](auto& mock) {
                EXPECT_CALL(mock, listAssets(testing::_, testing::_)).WillOnce(testing::Return(base::Error {"error"}));
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetGet(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::AssetGet_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing /policy
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetGet(policyManager); },
            []() { return userErrorResponse<eEngine::policy::AssetGet_Response>("Missing /policy"); },
            [](auto&) {}),
        // Invalid policy name
        HandlerT(
            []()
            {
                eEngine::policy::AssetGet_Request protoReq;
                protoReq.set_policy("");
                return createRequest<eEngine::policy::AssetGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetGet(policyManager); },
            []() {
                return userErrorResponse<eEngine::policy::AssetGet_Response>(
                    "Invalid policy name: Name cannot be empty");
            },
            [](auto&) {}),
        // Missing /namespace
        HandlerT(
            []()
            {
                eEngine::policy::AssetGet_Request protoReq;
                protoReq.set_policy("policy");
                return createRequest<eEngine::policy::AssetGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetGet(policyManager); },
            []() { return userErrorResponse<eEngine::policy::AssetGet_Response>("Missing /namespace"); },
            [](auto&) {}),
        // Invalid namespace name
        HandlerT(
            []()
            {
                eEngine::policy::AssetGet_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns/0");
                return createRequest<eEngine::policy::AssetGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyAssetGet(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::AssetGet_Response>(
                    "Invalid namespace name: NamespaceId must have only one part and cannot be empty");
            },
            [](auto&) {}),
        /***********************************************************************
         * PolicyCleanDeleted
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::policy::AssetCleanDeleted_Request protoReq;
                protoReq.set_policy("policy");
                return createRequest<eEngine::policy::AssetCleanDeleted_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyCleanDeleted(policyManager); },
            []()
            {
                eEngine::policy::AssetCleanDeleted_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.set_data("deleted assets");
                return userResponse<eEngine::policy::AssetCleanDeleted_Response>(protoRes);
            },
            [](auto& mock)
            { EXPECT_CALL(mock, cleanDeleted(testing::_)).WillOnce(testing::Return(std::string("deleted assets"))); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::policy::AssetCleanDeleted_Request protoReq;
                protoReq.set_policy("policy");
                return createRequest<eEngine::policy::AssetCleanDeleted_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyCleanDeleted(policyManager); },
            []() { return userErrorResponse<eEngine::policy::AssetCleanDeleted_Response>("error"); },
            [](auto& mock)
            { EXPECT_CALL(mock, cleanDeleted(testing::_)).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyCleanDeleted(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::AssetCleanDeleted_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing /policy
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyCleanDeleted(policyManager); },
            []() { return userErrorResponse<eEngine::policy::AssetCleanDeleted_Response>("Missing /policy"); },
            [](auto&) {}),
        // Invalid policy name
        HandlerT(
            []()
            {
                eEngine::policy::AssetCleanDeleted_Request protoReq;
                protoReq.set_policy("");
                return createRequest<eEngine::policy::AssetCleanDeleted_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyCleanDeleted(policyManager); },
            []() {
                return userErrorResponse<eEngine::policy::AssetCleanDeleted_Response>(
                    "Invalid policy name: Name cannot be empty");
            },
            [](auto&) {}),
        /***********************************************************************
         * PolicyDefaultParentGet
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentGet_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                return createRequest<eEngine::policy::DefaultParentGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentGet(policyManager); },
            []()
            {
                eEngine::policy::DefaultParentGet_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.add_data("decoder/parent/0");
                return userResponse<eEngine::policy::DefaultParentGet_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock, getDefaultParent(testing::_, testing::_))
                    .WillOnce(testing::Return(std::list<base::Name> {base::Name("decoder/parent/0")}));
            }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentGet_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                return createRequest<eEngine::policy::DefaultParentGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentGet(policyManager); },
            []() { return userErrorResponse<eEngine::policy::DefaultParentGet_Response>("error"); },
            [](auto& mock) {
                EXPECT_CALL(mock, getDefaultParent(testing::_, testing::_))
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentGet(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::DefaultParentGet_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing /policy
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentGet(policyManager); },
            []() { return userErrorResponse<eEngine::policy::DefaultParentGet_Response>("Missing /policy"); },
            [](auto&) {}),
        // Invalid policy name
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentGet_Request protoReq;
                protoReq.set_policy("");
                return createRequest<eEngine::policy::DefaultParentGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentGet(policyManager); },
            []() {
                return userErrorResponse<eEngine::policy::DefaultParentGet_Response>(
                    "Invalid policy name: Name cannot be empty");
            },
            [](auto&) {}),
        // Missing /namespace
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentGet_Request protoReq;
                protoReq.set_policy("policy");
                return createRequest<eEngine::policy::DefaultParentGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentGet(policyManager); },
            []() { return userErrorResponse<eEngine::policy::DefaultParentGet_Response>("Missing /namespace"); },
            [](auto&) {}),
        // Invalid namespace name
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentGet_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns/0");
                return createRequest<eEngine::policy::DefaultParentGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentGet(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::DefaultParentGet_Response>(
                    "Invalid namespace name: NamespaceId must have only one part and cannot be empty");
            },
            [](auto&) {}),
        /***********************************************************************
         * PolicyDefaultParentPost
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentPost_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                protoReq.set_parent("parent");
                return createRequest<eEngine::policy::DefaultParentPost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentPost(policyManager); },
            []()
            {
                eEngine::policy::DefaultParentPost_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::policy::DefaultParentPost_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock, setDefaultParent(testing::_, testing::_, testing::_))
                    .WillOnce(testing::Return(std::string("")));
            }),
        // Success with warning
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentPost_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                protoReq.set_parent("parent");
                return createRequest<eEngine::policy::DefaultParentPost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentPost(policyManager); },
            []()
            {
                eEngine::policy::DefaultParentPost_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.set_warning("warning");
                return userResponse<eEngine::policy::DefaultParentPost_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock, setDefaultParent(testing::_, testing::_, testing::_))
                    .WillOnce(testing::Return(std::string("warning")));
            }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentPost_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                protoReq.set_parent("parent");
                return createRequest<eEngine::policy::DefaultParentPost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentPost(policyManager); },
            []() { return userErrorResponse<eEngine::policy::DefaultParentPost_Response>("error"); },
            [](auto& mock)
            {
                EXPECT_CALL(mock, setDefaultParent(testing::_, testing::_, testing::_))
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentPost(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::DefaultParentPost_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing /policy
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentPost(policyManager); },
            []() { return userErrorResponse<eEngine::policy::DefaultParentPost_Response>("Missing /policy"); },
            [](auto&) {}),
        // Invalid policy name
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentPost_Request protoReq;
                protoReq.set_policy("");
                return createRequest<eEngine::policy::DefaultParentPost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentPost(policyManager); },
            []() {
                return userErrorResponse<eEngine::policy::DefaultParentPost_Response>(
                    "Invalid policy name: Name cannot be empty");
            },
            [](auto&) {}),
        // Missing /namespace
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentPost_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_parent("parent");
                return createRequest<eEngine::policy::DefaultParentPost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentPost(policyManager); },
            []() { return userErrorResponse<eEngine::policy::DefaultParentPost_Response>("Missing /namespace"); },
            [](auto&) {}),
        // Invalid namespace name
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentPost_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns/0");
                protoReq.set_parent("parent");
                return createRequest<eEngine::policy::DefaultParentPost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentPost(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::DefaultParentPost_Response>(
                    "Invalid namespace name: NamespaceId must have only one part and cannot be empty");
            },
            [](auto&) {}),
        // Missing /parent
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentPost_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                return createRequest<eEngine::policy::DefaultParentPost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentPost(policyManager); },
            []() { return userErrorResponse<eEngine::policy::DefaultParentPost_Response>("Missing /parent"); },
            [](auto&) {}),
        // Invalid parent name
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentPost_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                protoReq.set_parent("");
                return createRequest<eEngine::policy::DefaultParentPost_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentPost(policyManager); },
            []() {
                return userErrorResponse<eEngine::policy::DefaultParentPost_Response>(
                    "Invalid parent name: Name cannot be empty");
            },
            [](auto&) {}),
        /***********************************************************************
         * PolicyDefaultParentDelete
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentDelete_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                protoReq.set_parent("parent");
                return createRequest<eEngine::policy::DefaultParentDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentDelete(policyManager); },
            []()
            {
                eEngine::policy::DefaultParentDelete_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::policy::DefaultParentDelete_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock, delDefaultParent(testing::_, testing::_, testing::_))
                    .WillOnce(testing::Return(std::string("")));
            }),
        // Success with warning
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentDelete_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                protoReq.set_parent("parent");
                return createRequest<eEngine::policy::DefaultParentDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentDelete(policyManager); },
            []()
            {
                eEngine::policy::DefaultParentDelete_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.set_warning("warning");
                return userResponse<eEngine::policy::DefaultParentDelete_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock, delDefaultParent(testing::_, testing::_, testing::_))
                    .WillOnce(testing::Return(std::string("warning")));
            }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentDelete_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                protoReq.set_parent("parent");
                return createRequest<eEngine::policy::DefaultParentDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentDelete(policyManager); },
            []() { return userErrorResponse<eEngine::policy::DefaultParentDelete_Response>("error"); },
            [](auto& mock)
            {
                EXPECT_CALL(mock, delDefaultParent(testing::_, testing::_, testing::_))
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentDelete(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::DefaultParentDelete_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing /policy
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentDelete(policyManager); },
            []() { return userErrorResponse<eEngine::policy::DefaultParentDelete_Response>("Missing /policy"); },
            [](auto&) {}),
        // Invalid policy name
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentDelete_Request protoReq;
                protoReq.set_policy("");
                return createRequest<eEngine::policy::DefaultParentDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentDelete(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::DefaultParentDelete_Response>(
                    "Invalid policy name: Name cannot be empty");
            },
            [](auto&) {}),
        // Missing /namespace
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentDelete_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_parent("parent");
                return createRequest<eEngine::policy::DefaultParentDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentDelete(policyManager); },
            []() { return userErrorResponse<eEngine::policy::DefaultParentDelete_Response>("Missing /namespace"); },
            [](auto&) {}),
        // Invalid namespace name
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentDelete_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns/0");
                protoReq.set_parent("parent");
                return createRequest<eEngine::policy::DefaultParentDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentDelete(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::DefaultParentDelete_Response>(
                    "Invalid namespace name: NamespaceId must have only one part and cannot be empty");
            },
            [](auto&) {}),
        // Missing /parent
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentDelete_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                return createRequest<eEngine::policy::DefaultParentDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentDelete(policyManager); },
            []() { return userErrorResponse<eEngine::policy::DefaultParentDelete_Response>("Missing /parent"); },
            [](auto&) {}),
        // Invalid parent name
        HandlerT(
            []()
            {
                eEngine::policy::DefaultParentDelete_Request protoReq;
                protoReq.set_policy("policy");
                protoReq.set_namespace_("ns");
                protoReq.set_parent("");
                return createRequest<eEngine::policy::DefaultParentDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyDefaultParentDelete(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::DefaultParentDelete_Response>(
                    "Invalid parent name: Name cannot be empty");
            },
            [](auto&) {}),
        /***********************************************************************
         * PoliciesGet
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::policy::PoliciesGet_Request protoReq;
                return createRequest<eEngine::policy::PoliciesGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policiesGet(policyManager); },
            []()
            {
                eEngine::policy::PoliciesGet_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.add_data("policy/policy/0");
                return userResponse<eEngine::policy::PoliciesGet_Response>(protoRes);
            },
            [](auto& mock) {
                EXPECT_CALL(mock, list())
                    .WillOnce(testing::Return(std::vector<base::Name> {base::Name("policy/policy/0")}));
            }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::policy::PoliciesGet_Request protoReq;
                return createRequest<eEngine::policy::PoliciesGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policiesGet(policyManager); },
            []() { return userErrorResponse<eEngine::policy::PoliciesGet_Response>("error"); },
            [](auto& mock) { EXPECT_CALL(mock, list()).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policiesGet(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::PoliciesGet_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        /***********************************************************************
         * NamespacesGet
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::policy::NamespacesGet_Request protoReq;
                protoReq.set_policy("policy");
                return createRequest<eEngine::policy::NamespacesGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyNamespacesGet(policyManager); },
            []()
            {
                eEngine::policy::NamespacesGet_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.add_data("ns0");
                return userResponse<eEngine::policy::NamespacesGet_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock, listNamespaces(testing::_))
                    .WillOnce(testing::Return(std::list<store::NamespaceId> {store::NamespaceId("ns0")}));
            }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::policy::NamespacesGet_Request protoReq;
                protoReq.set_policy("policy");
                return createRequest<eEngine::policy::NamespacesGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyNamespacesGet(policyManager); },
            []() { return userErrorResponse<eEngine::policy::NamespacesGet_Response>("error"); },
            [](auto& mock)
            { EXPECT_CALL(mock, listNamespaces(testing::_)).WillOnce(testing::Return(base::Error {"error"})); }),
        // Wrong request type
        HandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyNamespacesGet(policyManager); },
            []()
            {
                return userErrorResponse<eEngine::policy::NamespacesGet_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing /policy
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
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyNamespacesGet(policyManager); },
            []() { return userErrorResponse<eEngine::policy::NamespacesGet_Response>("Missing /policy"); },
            [](auto&) {}),
        // Invalid policy name
        HandlerT(
            []()
            {
                eEngine::policy::NamespacesGet_Request protoReq;
                protoReq.set_policy("");
                return createRequest<eEngine::policy::NamespacesGet_Request>(protoReq);
            },
            [](const std::shared_ptr<IPolicy>& policyManager) { return policyNamespacesGet(policyManager); },
            []() {
                return userErrorResponse<eEngine::policy::NamespacesGet_Response>(
                    "Invalid policy name: Name cannot be empty");
            },
            [](auto&) {})));
