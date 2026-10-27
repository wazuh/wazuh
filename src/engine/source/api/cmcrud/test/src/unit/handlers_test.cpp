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

/*******************************************************************************
 * policyValidate: tester session replacement and deletion
 ******************************************************************************/

namespace
{
using ::testing::_;
using ::testing::Return;
using ::testing::Throw;
using ::testing::Truly;

constexpr const char* kDecoderUuid = "a1f330f4-8012-48ab-9949-c5d76edaf9b1";
constexpr const char* kIntegUuid = "a1f330f4-8012-48ab-9949-c5d76edaf9b2";

std::string policyJson(bool enabled, bool withIntegration)
{
    return fmt::format(R"({{"metadata":{{"title":"t"}},"enabled":{},"root_decoder":"{}","integrations":[{}],)"
                       R"("filters":[],"enrichments":[],"index_unclassified_events":false,)"
                       R"("index_discarded_events":false,"outputs":[]}})",
                       enabled ? "true" : "false",
                       kDecoderUuid,
                       withIntegration ? fmt::format("\"{}\"", kIntegUuid) : "");
}

httplib::Request policyValidateRequest(bool loadInTester, bool enabled, bool withIntegration, const std::string& space)
{
    httplib::Request req;
    req.body = fmt::format(R"({{"load_in_tester":{},"space":"{}","full_policy":{{"policy":{},"resources":{{}}}}}})",
                           loadInTester ? "true" : "false",
                           space,
                           policyJson(enabled, withIntegration));
    req.set_header("Content-Type", "plain/text");
    return req;
}

cm::store::dataType::Policy policyOf(bool enabled, bool withIntegration)
{
    return cm::store::dataType::Policy::fromJson(json::Json {policyJson(enabled, withIntegration).c_str()});
}

::router::test::Entry entryOn(const std::string& name, const std::string& ns)
{
    return ::router::test::Entry {::router::test::EntryPost {name, cm::store::NamespaceId {ns}, 0}};
}

auto isTempNs = [](const cm::store::NamespaceId& ns)
{
    return ns.toStr().rfind("logtest_", 0) == 0;
};
auto isNs = [](const std::string& expected)
{
    return [expected](const cm::store::NamespaceId& ns)
    {
        return ns.toStr() == expected;
    };
};

class PolicyValidateHandlerTest : public ::testing::Test
{
protected:
    std::shared_ptr<cm::crud::MockCrudService> m_crud;
    std::shared_ptr<::tester::mocks::MockTesterAPI> m_tester;

    void SetUp() override
    {
        logging::testInit();
        m_crud = std::make_shared<cm::crud::MockCrudService>();
        m_tester = std::make_shared<::tester::mocks::MockTesterAPI>();
    }

    httplib::Response run(const httplib::Request& req)
    {
        httplib::Response res;
        policyValidate(m_crud, m_tester)(req, res);
        return res;
    }

    static void expectOk(const httplib::Response& res)
    {
        eEngine::GenericStatus_Response protoRes;
        protoRes.set_status(eEngine::ReturnStatus::OK);
        const auto expected = userResponse<eEngine::GenericStatus_Response>(protoRes);
        EXPECT_EQ(res.status, expected.status);
        EXPECT_EQ(res.body, expected.body);
    }

    static void expectError(const httplib::Response& res, const std::string& message)
    {
        const auto expected = userErrorResponse<eEngine::GenericStatus_Response>(message);
        EXPECT_EQ(res.status, expected.status);
        EXPECT_EQ(res.body, expected.body);
    }
};
} // namespace

TEST_F(PolicyValidateHandlerTest, PromoteReplacesPreviousSessionAndDeletesItsNamespace)
{
    EXPECT_CALL(*m_crud, importNamespace(Truly(isTempNs), _, _, true)).WillOnce(Return(policyOf(true, true)));
    EXPECT_CALL(*m_tester, postTestEntry(_)).WillOnce(Return(base::noError()));
    EXPECT_CALL(*m_tester, replaceTestEntry(_, "s"))
        .WillOnce(Return(std::optional<::router::test::Entry> {entryOn("s", "logtest_old")}));
    EXPECT_CALL(*m_crud, deleteNamespace(Truly(isNs("logtest_old")))).Times(1);
    EXPECT_CALL(*m_tester, deleteTestEntry(_)).Times(0);

    expectOk(run(policyValidateRequest(true, true, true, "s")));
}

TEST_F(PolicyValidateHandlerTest, PromoteWithoutPreviousSessionDeletesNothing)
{
    EXPECT_CALL(*m_crud, importNamespace(Truly(isTempNs), _, _, true)).WillOnce(Return(policyOf(true, true)));
    EXPECT_CALL(*m_tester, postTestEntry(_)).WillOnce(Return(base::noError()));
    EXPECT_CALL(*m_tester, replaceTestEntry(_, "s")).WillOnce(Return(std::optional<::router::test::Entry> {}));
    EXPECT_CALL(*m_crud, deleteNamespace(_)).Times(0);
    EXPECT_CALL(*m_tester, deleteTestEntry(_)).Times(0);

    expectOk(run(policyValidateRequest(true, true, true, "s")));
}

TEST_F(PolicyValidateHandlerTest, PromoteFailureCleansTempResources)
{
    EXPECT_CALL(*m_crud, importNamespace(Truly(isTempNs), _, _, true)).WillOnce(Return(policyOf(true, true)));
    EXPECT_CALL(*m_tester, postTestEntry(_)).WillOnce(Return(base::noError()));
    EXPECT_CALL(*m_tester, replaceTestEntry(_, "s")).WillOnce(Return(base::Error {"swap failed"}));
    EXPECT_CALL(*m_tester, deleteTestEntry(::testing::StartsWith("logtest_"))).WillOnce(Return(base::noError()));
    EXPECT_CALL(*m_crud, deleteNamespace(Truly(isTempNs))).Times(1);

    expectError(run(policyValidateRequest(true, true, true, "s")), "swap failed");
}

TEST_F(PolicyValidateHandlerTest, PromoteSucceedsWhenPreviousNamespaceCannotBeDeleted)
{
    EXPECT_CALL(*m_crud, importNamespace(Truly(isTempNs), _, _, true)).WillOnce(Return(policyOf(true, true)));
    EXPECT_CALL(*m_tester, postTestEntry(_)).WillOnce(Return(base::noError()));
    EXPECT_CALL(*m_tester, replaceTestEntry(_, "s"))
        .WillOnce(Return(std::optional<::router::test::Entry> {entryOn("s", "logtest_old")}));
    EXPECT_CALL(*m_crud, deleteNamespace(Truly(isNs("logtest_old"))))
        .WillOnce(Throw(std::runtime_error {"active references detected"}));
    EXPECT_CALL(*m_tester, deleteTestEntry(_)).Times(0);

    expectOk(run(policyValidateRequest(true, true, true, "s")));
}

TEST_F(PolicyValidateHandlerTest, DisabledPolicyExtractsPreviousSessionAndDeletesItsNamespace)
{
    EXPECT_CALL(*m_crud, importNamespace(Truly(isTempNs), _, _, true)).WillOnce(Return(policyOf(false, true)));
    EXPECT_CALL(*m_tester, postTestEntry(_)).WillOnce(Return(base::noError()));
    EXPECT_CALL(*m_tester, deleteTestEntry(::testing::StartsWith("logtest_"))).WillOnce(Return(base::noError()));
    EXPECT_CALL(*m_crud, deleteNamespace(Truly(isTempNs))).Times(1);
    EXPECT_CALL(*m_tester, extractTestEntry("s"))
        .WillOnce(Return(std::optional<::router::test::Entry> {entryOn("s", "logtest_old")}));
    EXPECT_CALL(*m_crud, deleteNamespace(Truly(isNs("logtest_old")))).Times(1);
    EXPECT_CALL(*m_tester, replaceTestEntry(_, _)).Times(0);

    expectOk(run(policyValidateRequest(true, false, true, "s")));
}

TEST_F(PolicyValidateHandlerTest, DisabledPolicyNamespaceDeleteFailureIsAnError)
{
    EXPECT_CALL(*m_crud, importNamespace(Truly(isTempNs), _, _, true)).WillOnce(Return(policyOf(false, true)));
    EXPECT_CALL(*m_tester, postTestEntry(_)).WillOnce(Return(base::noError()));
    EXPECT_CALL(*m_tester, deleteTestEntry(::testing::StartsWith("logtest_"))).WillOnce(Return(base::noError()));
    EXPECT_CALL(*m_crud, deleteNamespace(Truly(isTempNs))).Times(1);
    EXPECT_CALL(*m_tester, extractTestEntry("s"))
        .WillOnce(Return(std::optional<::router::test::Entry> {entryOn("s", "logtest_old")}));
    EXPECT_CALL(*m_crud, deleteNamespace(Truly(isNs("logtest_old")))).WillOnce(Throw(std::runtime_error {"boom"}));

    expectError(run(policyValidateRequest(true, false, true, "s")),
                "Cleanup: failed deleting namespace 'logtest_old': boom");
}

TEST_F(PolicyValidateHandlerTest, DisabledPolicyWithoutPreviousSessionIsOk)
{
    EXPECT_CALL(*m_crud, importNamespace(Truly(isTempNs), _, _, true)).WillOnce(Return(policyOf(false, true)));
    EXPECT_CALL(*m_tester, postTestEntry(_)).WillOnce(Return(base::noError()));
    EXPECT_CALL(*m_tester, deleteTestEntry(::testing::StartsWith("logtest_"))).WillOnce(Return(base::noError()));
    EXPECT_CALL(*m_crud, deleteNamespace(Truly(isTempNs))).Times(1);
    EXPECT_CALL(*m_tester, extractTestEntry("s")).WillOnce(Return(std::optional<::router::test::Entry> {}));

    expectOk(run(policyValidateRequest(true, false, true, "s")));
}

TEST_F(PolicyValidateHandlerTest, DisabledPolicyExtractFailureIsAnError)
{
    EXPECT_CALL(*m_crud, importNamespace(Truly(isTempNs), _, _, true)).WillOnce(Return(policyOf(false, true)));
    EXPECT_CALL(*m_tester, postTestEntry(_)).WillOnce(Return(base::noError()));
    EXPECT_CALL(*m_tester, deleteTestEntry(::testing::StartsWith("logtest_"))).WillOnce(Return(base::noError()));
    EXPECT_CALL(*m_crud, deleteNamespace(Truly(isTempNs))).Times(1);
    EXPECT_CALL(*m_tester, extractTestEntry("s")).WillOnce(Return(base::Error {"worker gone"}));

    expectError(run(policyValidateRequest(true, false, true, "s")),
                "Cleanup: failed deleting session 's': worker gone");
}
