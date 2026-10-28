// SPDX-License-Identifier: AGPL-3.0-or-later
#include <eMessages/crud.pb.h>
#include <eMessages/eMessage.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <api/adapter/baseHandler_test.hpp>
#include <api/adapter/helpers.hpp>
#include <api/cmcrud/handlers.hpp>

#include <cmcrud/mockcmcrud.hpp>
#include <router/mockTester.hpp>

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

// resourceGet / resourceDelete handler messages
constexpr const char* kUuidRequiredMsg = "Field /uuid cannot be empty";
constexpr const char* kUuidInvalidMsg = "Field /uuid is not a valid identifier";

// resourceValidate handler messages
constexpr const char* kTypeRequiredMsg = "Field /type is required";
constexpr const char* kResourceRequiredMsg = "Field /resource cannot be empty";
constexpr const char* kTypeUnsupportedMsg = "Unsupported value for /type";
constexpr const char* kBodyOverAbsoluteLimitMsg = "Request body exceeds maximum allowed document size of 100000 bytes";
constexpr const char* kBodyOverTypeLimitMsg =
    "Request body exceeds maximum allowed size of 20000 bytes for type 'decoder'";

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
                auto structOrErr = eMessage::eMessageFromJson<google::protobuf::Struct>(R"({"policy":"test"})");
                if (std::holds_alternative<base::Error>(structOrErr))
                {
                    throw std::runtime_error(std::get<base::Error>(structOrErr).message);
                }
                protoReq.mutable_jsoncontent()->CopyFrom(std::get<google::protobuf::Struct>(structOrErr));
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
            []() { return helpers::buildJsonContentResponse(json::Json {R"({"id":"uuid-1","name":"decoder/test"})"}); },
            [](auto& mock)
            {
                EXPECT_CALL(mock,
                            getResourceByUUID(::testing::Truly([](const cm::store::NamespaceId& nsId)
                                                               { return nsId.toStr() == "draft"; }),
                                              "uuid-1"))
                    .WillOnce(::testing::Return(json::Json {R"({"id":"uuid-1","name":"decoder/test"})"}));
            }),
        // Opaque identifiers: a UUIDv5 or any custom string reaches the service unchanged
        CmCrudHandlerT(
            []()
            {
                eContent::resourceGet_Request protoReq;
                protoReq.set_space("draft");
                protoReq.set_uuid("6093809a-6285-5cf8-9284-63bd68f796e9");
                return createRequest<eContent::resourceGet_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceGet(crud); },
            []()
            {
                return helpers::buildJsonContentResponse(
                    json::Json {R"({"id":"6093809a-6285-5cf8-9284-63bd68f796e9"})"});
            },
            [](auto& mock)
            {
                EXPECT_CALL(mock, getResourceByUUID(::testing::_, "6093809a-6285-5cf8-9284-63bd68f796e9"))
                    .WillOnce(::testing::Return(json::Json {R"({"id":"6093809a-6285-5cf8-9284-63bd68f796e9"})"}));
            }),
        // Empty uuid
        CmCrudHandlerT(
            []()
            {
                eContent::resourceGet_Request protoReq;
                protoReq.set_space("draft");
                return createRequest<eContent::resourceGet_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceGet(crud); },
            []() { return userErrorResponse<eContent::resourceGet_Response>(kUuidRequiredMsg); },
            [](auto& mock) { EXPECT_CALL(mock, getResourceByUUID(::testing::_, ::testing::_)).Times(0); }),
        // Invalid uuid (control character): rejected before reaching the service
        CmCrudHandlerT(
            []()
            {
                eContent::resourceGet_Request protoReq;
                protoReq.set_space("draft");
                protoReq.set_uuid("bad\nid");
                return createRequest<eContent::resourceGet_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceGet(crud); },
            []() { return userErrorResponse<eContent::resourceGet_Response>(kUuidInvalidMsg); },
            [](auto& mock) { EXPECT_CALL(mock, getResourceByUUID(::testing::_, ::testing::_)).Times(0); }),
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
                auto structOrErr = eMessage::eMessageFromJson<google::protobuf::Struct>(
                    R"({"name":"decoder/test","id":"11111111-1111-4111-8111-111111111111"})");
                if (std::holds_alternative<base::Error>(structOrErr))
                {
                    throw std::runtime_error(std::get<base::Error>(structOrErr).message);
                }
                protoReq.mutable_jsoncontent()->CopyFrom(std::get<google::protobuf::Struct>(structOrErr));
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
        // Empty uuid
        CmCrudHandlerT(
            []()
            {
                eContent::resourceDelete_Request protoReq;
                protoReq.set_space("draft");
                return createRequest<eContent::resourceDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceDelete(crud); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>(kUuidRequiredMsg); },
            [](auto& mock) { EXPECT_CALL(mock, deleteResourceByUUID(::testing::_, ::testing::_)).Times(0); }),
        // Invalid uuid (control character): rejected before reaching the service
        CmCrudHandlerT(
            []()
            {
                eContent::resourceDelete_Request protoReq;
                protoReq.set_space("draft");
                protoReq.set_uuid("bad\tid");
                return createRequest<eContent::resourceDelete_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceDelete(crud); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>(kUuidInvalidMsg); },
            [](auto& mock) { EXPECT_CALL(mock, deleteResourceByUUID(::testing::_, ::testing::_)).Times(0); }),
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
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud, 20'000, 100'000); },
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
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud, 20'000, 100'000); },
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
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud, 20'000, 100'000); },
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
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud, 20'000, 100'000); },
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
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud, 20'000, 100'000); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>(kTypeUnsupportedMsg); },
            [](auto&) {}),

        /*** Output is a resource type but not validatable: same answer as an unknown type ***/
        CmCrudHandlerT(
            []()
            {
                eContent::resourceValidate_Request protoReq;
                protoReq.set_type("output");

                auto& fields = *protoReq.mutable_resource()->mutable_fields();
                fields["id"].set_string_value("11111111-1111-4111-8111-111111111111");
                fields["name"].set_string_value("output/test/0");

                return createRequest<eContent::resourceValidate_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud, 20'000, 100'000); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>(kTypeUnsupportedMsg); },
            [](auto& mock) { EXPECT_CALL(mock, validateResource(::testing::_, ::testing::_)).Times(0); }),

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
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud, 20'000, 100'000); },
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
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud, 20'000, 100'000); },
            []() { return userErrorResponse<eEngine::GenericStatus_Response>(kParseErrorMsg); },
            [](auto&) {}),

        /***********************************************************************
         * resourceValidate – size limits
         **********************************************************************/

        /*** Body over absolute limit: rejected before proto parse ***/
        CmCrudHandlerT(
            []()
            {
                httplib::Request req;
                req.body = std::string(100001, 'X');
                req.set_header("Content-Type", "plain/text");
                return req;
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud, 20'000, 100'000); },
            []()
            {
                auto resp = userErrorResponse<eEngine::GenericStatus_Response>(kBodyOverAbsoluteLimitMsg);
                resp.status = httplib::StatusCode::PayloadTooLarge_413;
                return resp;
            },
            [](auto& mock) { EXPECT_CALL(mock, validateResource(::testing::_, ::testing::_)).Times(0); }),

        /*** Non-KVDB body over general limit: rejected after type is known ***/
        CmCrudHandlerT(
            []()
            {
                eContent::resourceValidate_Request protoReq;
                protoReq.set_type("decoder");

                auto& fields = *protoReq.mutable_resource()->mutable_fields();
                fields["id"].set_string_value("11111111-1111-4111-8111-111111111111");
                fields["padding"].set_string_value(std::string(51000, 'A'));

                return createRequest<eContent::resourceValidate_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud, 20'000, 100'000); },
            []()
            {
                auto resp = userErrorResponse<eEngine::GenericStatus_Response>(kBodyOverTypeLimitMsg);
                resp.status = httplib::StatusCode::PayloadTooLarge_413;
                return resp;
            },
            [](auto& mock) { EXPECT_CALL(mock, validateResource(::testing::_, ::testing::_)).Times(0); }),

        /*** KVDB body over general limit but under KVDB limit: allowed ***/
        CmCrudHandlerT(
            []()
            {
                eContent::resourceValidate_Request protoReq;
                protoReq.set_type("kvdb");

                auto& fields = *protoReq.mutable_resource()->mutable_fields();
                fields["id"].set_string_value("82e215c4-988a-4f64-8d15-b98b2fc03a4f");
                fields["title"].set_string_value("test_kvdb");
                auto& contentFields = *fields["content"].mutable_struct_value()->mutable_fields();
                contentFields["blob"].set_string_value(std::string(51000, 'A'));
                fields["enabled"].set_bool_value(true);

                return createRequest<eContent::resourceValidate_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud, 20'000, 100'000); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, validateResource(cm::store::ResourceType::KVDB, ::testing::_)); }),

        /*** KVDB limit unlimited (0): over general limit is still allowed for KVDB ***/
        CmCrudHandlerT(
            []()
            {
                eContent::resourceValidate_Request protoReq;
                protoReq.set_type("kvdb");

                auto& fields = *protoReq.mutable_resource()->mutable_fields();
                fields["id"].set_string_value("82e215c4-988a-4f64-8d15-b98b2fc03a4f");
                fields["title"].set_string_value("test_kvdb_unlimited");
                auto& contentFields = *fields["content"].mutable_struct_value()->mutable_fields();
                contentFields["blob"].set_string_value(std::string(51000, 'A'));
                fields["enabled"].set_bool_value(true);

                return createRequest<eContent::resourceValidate_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud, 20'000, 0); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, validateResource(cm::store::ResourceType::KVDB, ::testing::_)); }),

        /*** KVDB with small body: passes ***/
        CmCrudHandlerT(
            []()
            {
                eContent::resourceValidate_Request protoReq;
                protoReq.set_type("kvdb");

                auto& fields = *protoReq.mutable_resource()->mutable_fields();
                fields["id"].set_string_value("82e215c4-988a-4f64-8d15-b98b2fc03a4f");
                fields["title"].set_string_value("test_kvdb");
                auto& contentFields = *fields["content"].mutable_struct_value()->mutable_fields();
                contentFields["key"].set_string_value("value");
                fields["enabled"].set_bool_value(true);

                return createRequest<eContent::resourceValidate_Request>(protoReq);
            },
            [](const std::shared_ptr<cm::crud::ICrudService>& crud) { return resourceValidate(crud, 20'000, 100'000); },
            []()
            {
                eEngine::GenericStatus_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                return userResponse<eEngine::GenericStatus_Response>(protoRes);
            },
            [](auto& mock) { EXPECT_CALL(mock, validateResource(cm::store::ResourceType::KVDB, ::testing::_)); })));

/***********************************************************************
 * policyValidate: the session's previous namespace
 **********************************************************************/
namespace
{
constexpr const char* kIntegrationUuid = "550e8400-e29b-41d4-a716-446655440001";

httplib::Request makePolicyValidateRequest()
{
    httplib::Request request;
    request.body = R"({"load_in_tester": true, "space": "standard", "full_policy": {"title": "p"}})";
    request.set_header("Content-Type", "application/json");
    return request;
}

cm::store::dataType::Policy makeValidatedPolicy(bool withIntegration)
{
    std::vector<std::string> integrations;
    if (withIntegration)
    {
        integrations.emplace_back(kIntegrationUuid);
    }
    return cm::store::dataType::Policy(
        "p", true, "", std::move(integrations), {}, {}, {}, "standard", "", false, false, true);
}

::router::test::Entry makeTestEntry(const std::string& name, const std::string& nsId)
{
    ::router::test::EntryPost post(name, cm::store::NamespaceId {nsId}, 0);
    return ::router::test::Entry {post};
}

auto namespaceNamed(const std::string& name)
{
    return ::testing::Truly([name](const cm::store::NamespaceId& nsId) { return nsId.toStr() == name; });
}

auto testerNamespace()
{
    return ::testing::Truly([](const cm::store::NamespaceId& nsId)
                            { return ::router::test::isTesterOwnedNamespace(nsId); });
}
} // namespace

TEST(PolicyValidateTesterNamespace, PromoteRefusesToReplaceAForeignNamespace)
{
    auto crud = std::make_shared<cm::crud::MockCrudService>();
    auto testerApi = std::make_shared<::tester::mocks::MockTesterAPI>();

    EXPECT_CALL(*crud, importNamespace(testerNamespace(), ::testing::_, ::testing::_, ::testing::_))
        .WillOnce(::testing::Return(makeValidatedPolicy(true)));
    EXPECT_CALL(*testerApi, postTestEntry(::testing::_)).WillOnce(::testing::Return(base::noError()));
    EXPECT_CALL(*testerApi, getTestEntry("standard"))
        .WillOnce(::testing::Return(makeTestEntry("standard", "cmsync_standard_abcdef")));
    EXPECT_CALL(*testerApi, deleteTestEntry("standard")).Times(0);
    EXPECT_CALL(*testerApi, renameTestEntry(::testing::_, ::testing::_)).Times(0);
    // The temporary session and namespace are cleaned up; the synchronized namespace is never touched
    EXPECT_CALL(*testerApi, deleteTestEntry(::testing::StartsWith("logtest_")))
        .WillOnce(::testing::Return(base::noError()));
    EXPECT_CALL(*crud, deleteNamespace(testerNamespace())).Times(1);
    EXPECT_CALL(*crud, deleteNamespace(namespaceNamed("cmsync_standard_abcdef"))).Times(0);

    httplib::Response res;
    policyValidate(crud, testerApi)(makePolicyValidateRequest(), res);

    const auto expected = userErrorResponse<eEngine::GenericStatus_Response>(
        "Refusing to replace space 'standard': its namespace 'cmsync_standard_abcdef' was not created by the tester");
    EXPECT_EQ(res.status, expected.status);
    EXPECT_EQ(res.body, expected.body);
}

TEST(PolicyValidateTesterNamespace, DeleteOldRefusesToDeleteAForeignNamespace)
{
    auto crud = std::make_shared<cm::crud::MockCrudService>();
    auto testerApi = std::make_shared<::tester::mocks::MockTesterAPI>();

    // No integrations: nothing is loaded and the old session would be wiped
    EXPECT_CALL(*crud, importNamespace(testerNamespace(), ::testing::_, ::testing::_, ::testing::_))
        .WillOnce(::testing::Return(makeValidatedPolicy(false)));
    EXPECT_CALL(*testerApi, postTestEntry(::testing::_)).Times(0);
    EXPECT_CALL(*crud, deleteNamespace(testerNamespace())).Times(1);
    EXPECT_CALL(*testerApi, getTestEntry("standard"))
        .WillOnce(::testing::Return(makeTestEntry("standard", "cmsync_standard_abcdef")));
    EXPECT_CALL(*testerApi, deleteTestEntry(::testing::_)).Times(0);
    EXPECT_CALL(*crud, deleteNamespace(namespaceNamed("cmsync_standard_abcdef"))).Times(0);

    httplib::Response res;
    policyValidate(crud, testerApi)(makePolicyValidateRequest(), res);

    const auto expected = userErrorResponse<eEngine::GenericStatus_Response>(
        "Refusing to replace space 'standard': its namespace 'cmsync_standard_abcdef' was not created by the tester");
    EXPECT_EQ(res.status, expected.status);
    EXPECT_EQ(res.body, expected.body);
}

TEST(PolicyValidateTesterNamespace, PromoteReplacesATesterNamespace)
{
    auto crud = std::make_shared<cm::crud::MockCrudService>();
    auto testerApi = std::make_shared<::tester::mocks::MockTesterAPI>();

    EXPECT_CALL(*crud, importNamespace(testerNamespace(), ::testing::_, ::testing::_, ::testing::_))
        .WillOnce(::testing::Return(makeValidatedPolicy(true)));
    // The session says which route made it, whoever the caller is
    const auto describedByRoute = [](const ::router::test::EntryPost& post)
    {
        return post.description().has_value() && post.description().value() == "Created by /content/validate/policy";
    };
    EXPECT_CALL(*testerApi, postTestEntry(::testing::Truly(describedByRoute)))
        .WillOnce(::testing::Return(base::noError()));
    EXPECT_CALL(*testerApi, getTestEntry("standard"))
        .WillOnce(::testing::Return(makeTestEntry("standard", "logtest_aaaaaa")));
    EXPECT_CALL(*testerApi, deleteTestEntry("standard")).WillOnce(::testing::Return(base::noError()));
    EXPECT_CALL(*testerApi, renameTestEntry(::testing::StartsWith("logtest_"), "standard"))
        .WillOnce(::testing::Return(base::noError()));
    EXPECT_CALL(*crud, deleteNamespace(namespaceNamed("logtest_aaaaaa"))).Times(1);

    httplib::Response res;
    policyValidate(crud, testerApi)(makePolicyValidateRequest(), res);

    eEngine::GenericStatus_Response protoRes;
    protoRes.set_status(eEngine::ReturnStatus::OK);
    const auto expected = userResponse<eEngine::GenericStatus_Response>(protoRes);
    EXPECT_EQ(res.status, expected.status);
    EXPECT_EQ(res.body, expected.body);
}
