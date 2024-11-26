#include <gtest/gtest.h>

#include <api/adapter/baseHandler_test.hpp>
#include <api/catalog/handlers.hpp>
#include <api/catalog/mockCatalog.hpp>
#include <eMessages/catalog.pb.h>

using namespace api::adapter;
using namespace api::test;
using namespace api::catalog;
using namespace api::catalog::handlers;
using namespace api::catalog::mocks;

using CatalogHandlerTest = BaseHandlerTest<ICatalog, MockCatalog>;

TEST_P(CatalogHandlerTest, Handler)
{
    auto [reqGetter, handlerGetter, resGetter, mocker] = GetParam();
    handlerTest(reqGetter, handlerGetter, resGetter, m_iHandler, m_mockHandler, mocker);
}

using HandlerT = Params<ICatalog, MockCatalog>;

INSTANTIATE_TEST_SUITE_P(
    Api,
    CatalogHandlerTest,
    ::testing::Values(
        /***********************************************************************
         * PostResource
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::catalog::ResourcePost_Request protoReq;
                protoReq.set_type(api::catalog::Resource::Type::decoder);
                protoReq.set_format(api::catalog::Resource::Format::json);
                protoReq.set_content("content");
                protoReq.set_namespaceid("ns");
                return createRequest<eEngine::catalog::ResourcePost_Request>(protoReq);
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePost(catalog); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) {
                EXPECT_CALL(mock, postResource(testing::_, testing::_, testing::_))
                    .WillOnce(testing::Return(base::noError()));
            }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::catalog::ResourcePost_Request protoReq;
                protoReq.set_type(api::catalog::Resource::Type::decoder);
                protoReq.set_format(api::catalog::Resource::Format::json);
                protoReq.set_content("content");
                protoReq.set_namespaceid("ns");
                return createRequest<eEngine::catalog::ResourcePost_Request>(protoReq);
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePost(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            {
                EXPECT_CALL(mock, postResource(testing::_, testing::_, testing::_))
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
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePost(catalog); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Invalid type param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("invalid", "/type");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePost(catalog); },
            []()
            { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /type parameter or is invalid"); },
            [](auto&) {}),
        // Missing type param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setObject();
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePost(catalog); },
            []()
            { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /type parameter or is invalid"); },
            [](auto&) {}),
        // Invalid format param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("decoder", "/type");
                reqBody.setString("invalid", "/format");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePost(catalog); },
            []()
            { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /format parameter or is invalid"); },
            [](auto&) {}),
        // Missing format param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("decoder", "/type");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePost(catalog); },
            []()
            { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /format parameter or is invalid"); },
            [](auto&) {}),
        // Missing content param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("decoder", "/type");
                reqBody.setString("json", "/format");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePost(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /content parameter"); },
            [](auto&) {}),
        // Invalid namespaceid param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("decoder", "/type");
                reqBody.setString("json", "/format");
                reqBody.setString("ns", "/content");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePost(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /namespace parameter"); },
            [](auto&) {}),
        /***********************************************************************
         * GetResource
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::catalog::ResourceGet_Request protoReq;
                protoReq.set_name("decoder/test/0");
                protoReq.set_format(api::catalog::Resource::Format::yaml);
                protoReq.set_namespaceid("ns");
                return createRequest<eEngine::catalog::ResourceGet_Request>(protoReq);
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceGet(catalog); },
            []()
            {
                eEngine::catalog::ResourceGet_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.set_content("content");
                return userResponse<eEngine::catalog::ResourceGet_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock, getResource(testing::_, testing::_))
                    .WillOnce(testing::Return(base::RespOrError<std::string> {"content"}));
            }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::catalog::ResourceGet_Request protoReq;
                protoReq.set_name("decoder/test/0");
                protoReq.set_format(api::catalog::Resource::Format::yaml);
                protoReq.set_namespaceid("ns");
                return createRequest<eEngine::catalog::ResourceGet_Request>(protoReq);
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceGet(catalog); },
            []() { return userErrorResponse<eEngine::catalog::ResourceGet_Response>("error"); },
            [](auto& mock) {
                EXPECT_CALL(mock, getResource(testing::_, testing::_)).WillOnce(testing::Return(base::Error {"error"}));
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
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceGet(catalog); },
            []()
            {
                return userErrorResponse<eEngine::catalog::ResourceGet_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing name param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setObject();
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceGet(catalog); },
            []() { return userErrorResponse<eEngine::catalog::ResourceGet_Response>("Missing /name parameter"); },
            [](auto&) {}),
        // Invalid format param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("decoder/test/0", "/name");
                reqBody.setString("invalid", "/format");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceGet(catalog); },
            []() {
                return userErrorResponse<eEngine::catalog::ResourceGet_Response>(
                    "Missing or invalid /format parameter");
            },
            [](auto&) {}),
        // Missing format param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("decoder/test/0", "/name");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceGet(catalog); },
            []() {
                return userErrorResponse<eEngine::catalog::ResourceGet_Response>(
                    "Missing or invalid /format parameter");
            },
            [](auto&) {}),
        // Missing namespaceid param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("decoder/test/0", "/name");
                reqBody.setString("yaml", "/format");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceGet(catalog); },
            []()
            { return userErrorResponse<eEngine::catalog::ResourceGet_Response>("Missing /namespaceid parameter"); },
            [](auto&) {}),
        /***********************************************************************
         * DeleteResource
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::catalog::ResourceDelete_Request protoReq;
                protoReq.set_name("decoder/test/0");
                protoReq.set_namespaceid("ns");
                return createRequest<eEngine::catalog::ResourceDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceDelete(catalog); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            { EXPECT_CALL(mock, deleteResource(testing::_, testing::_)).WillOnce(testing::Return(base::noError())); }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::catalog::ResourceDelete_Request protoReq;
                protoReq.set_name("decoder/test/0");
                protoReq.set_namespaceid("ns");
                return createRequest<eEngine::catalog::ResourceDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceDelete(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock) {
                EXPECT_CALL(mock, deleteResource(testing::_, testing::_))
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
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceDelete(catalog); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing name param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setObject();
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceDelete(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /name parameter"); },
            [](auto&) {}),
        // Missing namespaceid param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("decoder/test/0", "/name");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceDelete(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /namespaceid parameter"); },
            [](auto&) {}),
        /***********************************************************************
         * PutResource
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::catalog::ResourcePut_Request protoReq;
                protoReq.set_name("decoder/test/0");
                protoReq.set_format(api::catalog::Resource::Format::yaml);
                protoReq.set_content("content");
                protoReq.set_namespaceid("ns");
                return createRequest<eEngine::catalog::ResourcePut_Request>(protoReq);
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePut(catalog); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) {
                EXPECT_CALL(mock, putResource(testing::_, testing::_, testing::_))
                    .WillOnce(testing::Return(base::noError()));
            }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::catalog::ResourcePut_Request protoReq;
                protoReq.set_name("decoder/test/0");
                protoReq.set_format(api::catalog::Resource::Format::yaml);
                protoReq.set_content("content");
                protoReq.set_namespaceid("ns");
                return createRequest<eEngine::catalog::ResourcePut_Request>(protoReq);
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePut(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            {
                EXPECT_CALL(mock, putResource(testing::_, testing::_, testing::_))
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
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePut(catalog); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing name param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setObject();
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePut(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /name parameter"); },
            [](auto&) {}),
        // Invalid format param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("decoder/test/0", "/name");
                reqBody.setString("invalid", "/format");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePut(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing or invalid /format parameter"); },
            [](auto&) {}),
        // Missing format param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("decoder/test/0", "/name");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePut(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing or invalid /format parameter"); },
            [](auto&) {}),
        // Missing content param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("decoder/test/0", "/name");
                reqBody.setString("yaml", "/format");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePut(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /content parameter"); },
            [](auto&) {}),
        // Missing namespaceid param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("decoder/test/0", "/name");
                reqBody.setString("yaml", "/format");
                reqBody.setString("content", "/content");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourcePut(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /namespaceid parameter"); },
            [](auto&) {}),
        /***********************************************************************
         * ValidateResource
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::catalog::ResourceValidate_Request protoReq;
                protoReq.set_name("decoder/test/0");
                protoReq.set_format(api::catalog::Resource::Format::yaml);
                protoReq.set_content("content");
                protoReq.set_namespaceid("ns");
                return createRequest<eEngine::catalog::ResourceValidate_Request>(protoReq);
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceValidate(catalog); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock, validateResource(testing::_, testing::_, testing::_))
                    .WillOnce(testing::Return(base::noError()));
            }),
        // Handler Error
        HandlerT(
            []()
            {
                eEngine::catalog::ResourceValidate_Request protoReq;
                protoReq.set_name("decoder/test/0");
                protoReq.set_format(api::catalog::Resource::Format::yaml);
                protoReq.set_content("content");
                protoReq.set_namespaceid("ns");
                return createRequest<eEngine::catalog::ResourceValidate_Request>(protoReq);
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceValidate(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("error"); },
            [](auto& mock)
            {
                EXPECT_CALL(mock, validateResource(testing::_, testing::_, testing::_))
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
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceValidate(catalog); },
            []()
            {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {}),
        // Missing name param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setObject();
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceValidate(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /name parameter"); },
            [](auto&) {}),
        // Invalid format param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("decoder/test/0", "/name");
                reqBody.setString("invalid", "/format");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceValidate(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing or invalid /format parameter"); },
            [](auto&) {}),
        // Missing format param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("decoder/test/0", "/name");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceValidate(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing or invalid /format parameter"); },
            [](auto&) {}),
        // Missing content param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("decoder/test/0", "/name");
                reqBody.setString("yaml", "/format");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceValidate(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /content parameter"); },
            [](auto&) {}),
        // Missing namespaceid param
        HandlerT(
            []()
            {
                json::Json reqBody;
                reqBody.setString("decoder/test/0", "/name");
                reqBody.setString("yaml", "/format");
                reqBody.setString("content", "/content");
                httplib::Request req;
                req.body = reqBody.str();
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return resourceValidate(catalog); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("Missing /namespaceid parameter"); },
            [](auto&) {}),
        /***********************************************************************
         * GetNamespaces
         **********************************************************************/
        // Success
        HandlerT(
            []()
            {
                eEngine::catalog::NamespacesGet_Request protoReq;
                return createRequest<eEngine::catalog::NamespacesGet_Request>(protoReq);
            },
            [](const std::shared_ptr<ICatalog>& catalog) { return getNamespaces(catalog); },
            []()
            {
                eEngine::catalog::NamespacesGet_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.add_namespaces("ns1");
                protoRes.add_namespaces("ns2");
                return userResponse<eEngine::catalog::NamespacesGet_Response>(protoRes);
            },
            [](auto& mock) {
                EXPECT_CALL(mock, getAllNamespaces())
                    .WillOnce(testing::Return(std::vector<store::NamespaceId> {"ns1", "ns2"}));
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
            [](const std::shared_ptr<ICatalog>& catalog) { return getNamespaces(catalog); },
            []()
            {
                return userErrorResponse<eEngine::catalog::NamespacesGet_Response>(
                    "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\nnot json proto "
                    "reque\n^");
            },
            [](auto&) {})));
