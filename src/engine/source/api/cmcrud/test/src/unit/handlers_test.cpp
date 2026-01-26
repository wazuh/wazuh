#include <eMessages/crud.pb.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <api/adapter/baseHandler_test.hpp>
#include <api/cmcrud/handlers.hpp>

#include <cmcrud/mockcmcrud.hpp>

using namespace api::adapter;
using namespace api::test;
using namespace api::cmcrud;
using namespace api::cmcrud::handlers;
using namespace cm::crud;

namespace eContent = ::com::wazuh::api::engine::content;
namespace eEngine = ::com::wazuh::api::engine;

using CmCrudHandlerTest = BaseHandlerTest<cm::crud::ICrudService, cm::crud::MockCrudService>;
using CmCrudHandlerT = Params<cm::crud::ICrudService, cm::crud::MockCrudService>;

constexpr const char* kParseErrorMsg = "Failed to parse protobuff json request: INVALID_ARGUMENT:Unexpected token.\n"
                                       "not json proto reque\n^";

// resourceValidate handler messages
constexpr const char* kTypeRequiredMsg = "Field /type is required";
constexpr const char* kResourceRequiredMsg = "Field /resource cannot be empty";
constexpr const char* kTypeUnsupportedMsg = "Unsupported value for /type";

TEST_P(CmCrudHandlerTest, Handler)
{
    auto [reqGetter, handlerGetter, resGetter, mocker] = GetParam();
    handlerTest(reqGetter, handlerGetter, resGetter, m_iHandler, m_mockHandler, mocker);
}

INSTANTIATE_TEST_SUITE_P(
    Api,
    CmCrudHandlerTest,
    ::testing::Values(
        /***********************************************************************
         * namespaceList
         **********************************************************************/
        // Success
        CmCrudHandlerT(
            []()
            {
                eContent::namespaceGet_Request protoReq;
                return createRequest<eContent::namespaceGet_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return namespaceList(crud); },
            []()
            {
                eContent::namespaceGet_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                auto* spaces = protoRes.mutable_spaces();
                spaces->Add("draft");
                spaces->Add("custom");
                return userResponse<eContent::namespaceGet_Response>(protoRes);
            },
            [](auto& mock)
            {
                std::vector<cm::store::NamespaceId> spaces;
                spaces.emplace_back("draft");
                spaces.emplace_back("custom");
                EXPECT_CALL(mock, listNamespaces()).WillOnce(::testing::Return(spaces));
            }),
        // Wrong request type
        CmCrudHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return namespaceList(crud); },
            []() { return userErrorResponse<eContent::namespaceGet_Response>(kParseErrorMsg); },
            [](auto&) {}),

        /***********************************************************************
         * namespaceCreate
         **********************************************************************/
        // Success
        CmCrudHandlerT(
            []()
            {
                eContent::namespacePost_Request protoReq;
                protoReq.set_space("draft");
                return createRequest<eContent::namespacePost_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return namespaceCreate(crud); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock,
                            createNamespace(::testing::Truly([](const cm::store::NamespaceId& nsId)
                                                             { return nsId.toStr() == "draft"; })));
            }),
        // Wrong request type
        CmCrudHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return namespaceCreate(crud); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>(kParseErrorMsg); },
            [](auto&) {}),

        /***********************************************************************
         * namespaceDelete
         **********************************************************************/
        // Success
        CmCrudHandlerT(
            []()
            {
                eContent::namespaceDelete_Request protoReq;
                protoReq.set_space("draft");
                return createRequest<eContent::namespaceDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return namespaceDelete(crud); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock,
                            deleteNamespace(::testing::Truly([](const cm::store::NamespaceId& nsId)
                                                             { return nsId.toStr() == "draft"; })));
            }),
        // Wrong request type
        CmCrudHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return namespaceDelete(crud); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>(kParseErrorMsg); },
            [](auto&) {}),

        /***********************************************************************
         * policyUpsert
         **********************************************************************/
        // Success
        CmCrudHandlerT(
            []()
            {
                eContent::policyPost_Request protoReq;
                protoReq.set_space("draft");
                protoReq.set_ymlcontent("policy: test");
                return createRequest<eContent::policyPost_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return policyUpsert(crud); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock,
                            upsertPolicy(::testing::Truly([](const cm::store::NamespaceId& nsId)
                                                          { return nsId.toStr() == "draft"; }),
                                         ::testing::_));
            }),
        // Wrong request type
        CmCrudHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return policyUpsert(crud); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>(kParseErrorMsg); },
            [](auto&) {}),

        /***********************************************************************
         * policyDelete
         **********************************************************************/
        // Success
        CmCrudHandlerT(
            []()
            {
                eContent::policyDelete_Request protoReq;
                protoReq.set_space("draft");
                return createRequest<eContent::policyDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return policyDelete(crud); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock,
                            deletePolicy(::testing::Truly([](const cm::store::NamespaceId& nsId)
                                                          { return nsId.toStr() == "draft"; })));
            }),
        // Wrong request type
        CmCrudHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return policyDelete(crud); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>(kParseErrorMsg); },
            [](auto&) {}),

        /***********************************************************************
         * resourceList
         **********************************************************************/
        // Success (decoder)
        CmCrudHandlerT(
            []()
            {
                eContent::resourceList_Request protoReq;
                protoReq.set_space("draft");
                protoReq.set_type("decoder");
                return createRequest<eContent::resourceList_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceList(crud); },
            []()
            {
                eContent::resourceList_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);

                auto* resources = protoRes.mutable_resources();
                auto* item = resources->Add();
                item->set_uuid("uuid-1");
                item->set_name("decoder/apache_access");

                return userResponse<eContent::resourceList_Response>(protoRes);
            },
            [](auto& mock)
            {
                std::vector<cm::crud::ResourceSummary> list;
                cm::crud::ResourceSummary r;
                r.uuid = "uuid-1";
                r.name = "decoder/apache_access";
                list.emplace_back(std::move(r));

                EXPECT_CALL(mock,
                            listResources(::testing::Truly([](const cm::store::NamespaceId& nsId)
                                                           { return nsId.toStr() == "draft"; }),
                                          cm::store::ResourceType::DECODER))
                    .WillOnce(::testing::Return(list));
            }),
        // Wrong request type
        CmCrudHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceList(crud); },
            []() { return userErrorResponse<eContent::resourceList_Response>(kParseErrorMsg); },
            [](auto&) {}),

        /***********************************************************************
         * resourceGet
         **********************************************************************/
        // Success
        CmCrudHandlerT(
            []()
            {
                eContent::resourceGet_Request protoReq;
                protoReq.set_space("draft");
                protoReq.set_uuid("uuid-1");
                return createRequest<eContent::resourceGet_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceGet(crud); },
            []()
            {
                eContent::resourceGet_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.set_content("yml: content");
                return userResponse<eContent::resourceGet_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock,
                            getResourceByUUID(::testing::Truly([](const cm::store::NamespaceId& nsId)
                                                               { return nsId.toStr() == "draft"; }),
                                              "uuid-1",
                                              false))
                    .WillOnce(::testing::Return("yml: content"));
            }),
        // Wrong request type
        CmCrudHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceGet(crud); },
            []() { return userErrorResponse<eContent::resourceGet_Response>(kParseErrorMsg); },
            [](auto&) {}),

        /***********************************************************************
         * resourceUpsert
         **********************************************************************/
        // Success (decoder)
        CmCrudHandlerT(
            []()
            {
                eContent::resourcePost_Request protoReq;
                protoReq.set_space("draft");
                protoReq.set_type("decoder");
                protoReq.set_ymlcontent("some: yaml");
                return createRequest<eContent::resourcePost_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceUpsert(crud); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock,
                            upsertResource(::testing::Truly([](const cm::store::NamespaceId& nsId)
                                                            { return nsId.toStr() == "draft"; }),
                                           cm::store::ResourceType::DECODER,
                                           ::testing::_));
            }),
        // Wrong request type
        CmCrudHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceUpsert(crud); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>(kParseErrorMsg); },
            [](auto&) {}),

        /***********************************************************************
         * resourceDelete
         **********************************************************************/
        // Success
        CmCrudHandlerT(
            []()
            {
                eContent::resourceDelete_Request protoReq;
                protoReq.set_space("draft");
                protoReq.set_uuid("uuid-1");
                return createRequest<eContent::resourceDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceDelete(crud); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock,
                            deleteResourceByUUID(::testing::Truly([](const cm::store::NamespaceId& nsId)
                                                                  { return nsId.toStr() == "draft"; }),
                                                 "uuid-1"));
            }),
        // Wrong request type
        CmCrudHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceDelete(crud); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>(kParseErrorMsg); },
            [](auto&) {}),

        /***********************************************************************
         * resourceValidate (public, no namespace)
         **********************************************************************/
        // Success (decoder)
        CmCrudHandlerT(
            []()
            {
                eContent::resourceValidate_Request protoReq;
                protoReq.set_type("decoder");

                auto& fields = *protoReq.mutable_resource()->mutable_fields();
                fields["id"].set_string_value("11111111-1111-4111-8111-111111111111");
                fields["name"].set_string_value("decoder/test");

                return createRequest<eContent::resourceValidate_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, validateResource(cm::store::ResourceType::DECODER, ::testing::_)); }),

        /*** Missing /type ***/
        CmCrudHandlerT(
            []()
            {
                eContent::resourceValidate_Request protoReq;

                // Optional: set resource so this case is strictly testing missing /type
                auto& fields = *protoReq.mutable_resource()->mutable_fields();
                fields["id"].set_string_value("11111111-1111-4111-8111-111111111111");

                return createRequest<eContent::resourceValidate_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>(kTypeRequiredMsg); },
            [](auto&) {}),

        /*** Missing /resource ***/
        CmCrudHandlerT(
            []()
            {
                eContent::resourceValidate_Request protoReq;
                protoReq.set_type("decoder");
                // No resource fields set => fields_size() == 0
                return createRequest<eContent::resourceValidate_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>(kResourceRequiredMsg); },
            [](auto&) {}),

        /*** Unsupported type (not recognized) ***/
        CmCrudHandlerT(
            []()
            {
                eContent::resourceValidate_Request protoReq;
                protoReq.set_type("not-a-real-type");

                // Must include non-empty resource or you'll get "resource required" first
                auto& fields = *protoReq.mutable_resource()->mutable_fields();
                fields["id"].set_string_value("11111111-1111-4111-8111-111111111111");

                return createRequest<eContent::resourceValidate_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>(kTypeUnsupportedMsg); },
            [](auto&) {}),

        /*** Defined but not allowed in phase-1 validate (e.g. undefined) ***/
        CmCrudHandlerT(
            []()
            {
                eContent::resourceValidate_Request protoReq;
                protoReq.set_type("undefined");

                auto& fields = *protoReq.mutable_resource()->mutable_fields();
                fields["id"].set_string_value("11111111-1111-4111-8111-111111111111");

                return createRequest<eContent::resourceValidate_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>(kTypeUnsupportedMsg); },
            [](auto&) {}),

        /*** Service throws -> user error ***/
        CmCrudHandlerT(
            []()
            {
                eContent::resourceValidate_Request protoReq;
                protoReq.set_type("integration");

                auto& fields = *protoReq.mutable_resource()->mutable_fields();
                fields["id"].set_string_value("bad");
                fields["name"].set_string_value("integration/test");

                return createRequest<eContent::resourceValidate_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>("validation failed"); },
            [](auto& mock)
            {
                EXPECT_CALL(mock, validateResource(cm::store::ResourceType::INTEGRATION, ::testing::_))
                    .WillOnce(::testing::Throw(std::runtime_error("validation failed")));
            }),

        /*** Wrong request type ***/
        CmCrudHandlerT(
            []()
            {
                httplib::Request req;
                req.body = "not json proto request";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>(kParseErrorMsg); },
            [](auto&) {})));
