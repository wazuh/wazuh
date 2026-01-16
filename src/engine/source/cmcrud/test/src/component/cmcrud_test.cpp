#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/error.hpp>
#include <base/json.hpp>
#include <builder/mockValidator.hpp>
#include <cmstore/mockcmstore.hpp>

#include <cmcrud/cmcrudservice.hpp>

using ::testing::_;
using ::testing::HasSubstr;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::Throw;
using ::testing::Truly;

namespace cm::crud::test
{

using builder::mocks::MockValidator;
using cm::crud::CrudService;
using cm::store::MockICMstore;
using cm::store::MockICMstoreNS;
using cm::store::NamespaceId;
using cm::store::ResourceType;

// ---------------------------------------------------------------------
// YAML fixtures for realistic resources
// ---------------------------------------------------------------------

static constexpr const char* kPolicyYAML = R"(
type: "policy"
title: "Development 0.0.1"
default_parent: "decoder/integration/0"
root_decoder: "decoder/wazuh-core-message/0"
integrations:
  - "42e28392-4f5e-473d-89e8-c9030e6fedc2"
  - "a7fe64a2-0a03-414f-8692-8441bdfe6f69"
  - "5c1df6b6-1458-4b2e-9001-96f67a8b12c8"
  - "f61133f5-90b9-49ed-b1d5-0b88cb04355e"
  - "369c3128-9715-4a30-9ff9-22fcac87688b"
)";

static constexpr const char* kIntegrationYAML = R"(
id: "5c1df6b6-1458-4b2e-9001-96f67a8b12c8"
title: "windows"
enabled: true
category: "security"
default_parent: "3f086ce2-32a4-42b0-be7e-40dcfb9c6160"
decoders:
  - "85853f26-5779-469b-86c4-c47ee7d400b4"
  - "4aa06596-5ba9-488c-8354-2475705e1257"
  - "4da71af3-fff5-4b67-90d6-51db9e15bc47"
  - "6f8bd7d2-8516-4b2b-a6f1-cc924513c404"
kvdbs: []
)";

static constexpr const char* kKVDBYAML = R"(
id: "82e215c4-988a-4f64-8d15-b98b2fc03a4f"
date: "2025-10-06T13:32:19Z"
title: "windows_kerberos_status_code_to_code_name"
author: "Wazuh Inc."
content:
  "0x0": "KDC_ERR_NONE"
  "0x1": "KDC_ERR_NAME_EXP"
  "0x2": "KDC_ERR_SERVICE_EXP"
  "0x3": "KDC_ERR_BAD_PVNO"
  "0x4": "KDC_ERR_C_OLD_MAST_KVNO"
  "0x5": "KDC_ERR_S_OLD_MAST_KVNO"
  "0x6": "KDC_ERR_C_PRINCIPAL_UNKNOWN"
enabled: true
)";

static constexpr const char* kDecoderYAML = R"(
name: decoder/syslog/0
id: "3f086ce2-32a4-42b0-be7e-40dcfb9c6160"
metadata:
  module: syslog
  title: "Syslog Decoder event"
parse|event.original:
  - "<event.start/ISO8601Z> <tmp.hostname/fqdn> <TAG/alphanumeric/->: <message>"
normalize:
  - map:
    - event.kind: event
)";

// ---------------------------------------------------------------------
// Helper: build a CrudService + MockValidator + Mock store
// ---------------------------------------------------------------------

struct CmCrudStack
{
    std::shared_ptr<NiceMock<MockValidator>> validator;
    std::shared_ptr<NiceMock<MockICMstore>> store;
    CrudService service;

    CmCrudStack()
        : validator(std::make_shared<NiceMock<MockValidator>>())
        , store(std::make_shared<NiceMock<MockICMstore>>())
        , service(store, validator)
    {
    }
};

// ---------------------------------------------------------------------
// Policy: success path end-to-end
// ---------------------------------------------------------------------

TEST(CrudService_Component, UpsertPolicy_Success_EndToEnd)
{
    CmCrudStack stack;

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(ReturnRef(nsId));

    EXPECT_CALL(*stack.store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*stack.validator, softPolicyValidate(_, _)).Times(1).WillOnce(Return(base::noError()));
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(stack.service.upsertPolicy(nsId, kPolicyYAML));
}

// ---------------------------------------------------------------------
// Policy: builder error propagates through CrudService
// ---------------------------------------------------------------------

TEST(CrudService_Component, UpsertPolicy_BuilderErrorIsPropagated)
{
    CmCrudStack stack;

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(ReturnRef(nsId));

    EXPECT_CALL(*stack.store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*stack.validator, softPolicyValidate(_, _))
        .Times(1)
        .WillOnce(Return(base::Error {"policy failed at builder"}));

    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(0);

    try
    {
        stack.service.upsertPolicy(nsId, kPolicyYAML);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& ex)
    {
        const std::string msg {ex.what()};
        EXPECT_THAT(msg, HasSubstr("Failed to upsert policy in namespace 'dev'"));
        EXPECT_THAT(msg, HasSubstr("policy failed at builder"));
    }
}

// ---------------------------------------------------------------------
// Integration: success path end-to-end (create vs UUID)
// ---------------------------------------------------------------------

TEST(CrudService_Component, UpsertIntegration_Success_EndToEnd)
{
    CmCrudStack stack;

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(ReturnRef(nsId));

    EXPECT_CALL(*stack.store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*stack.validator, softIntegrationValidate(_, _)).Times(1).WillOnce(Return(base::noError()));

    EXPECT_CALL(*nsPtr, assetExistsByUUID("5c1df6b6-1458-4b2e-9001-96f67a8b12c8")).Times(1).WillOnce(Return(false));

    EXPECT_CALL(*nsPtr, createResource("windows", ResourceType::INTEGRATION, _)).Times(1);
    EXPECT_CALL(*nsPtr, updateResourceByUUID(_, _)).Times(0);

    EXPECT_NO_THROW(stack.service.upsertResource(nsId, ResourceType::INTEGRATION, kIntegrationYAML));
}

// ---------------------------------------------------------------------
// Integration: builder error is propagated
// ---------------------------------------------------------------------

TEST(CrudService_Component, UpsertIntegration_BuilderErrorIsPropagated)
{
    CmCrudStack stack;

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(ReturnRef(nsId));

    EXPECT_CALL(*stack.store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*stack.validator, softIntegrationValidate(_, _))
        .Times(1)
        .WillOnce(Return(base::Error {"integration failed at builder"}));

    EXPECT_CALL(*nsPtr, assetExistsByUUID(_)).Times(0);
    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);
    EXPECT_CALL(*nsPtr, updateResourceByUUID(_, _)).Times(0);

    try
    {
        stack.service.upsertResource(nsId, ResourceType::INTEGRATION, kIntegrationYAML);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& ex)
    {
        const std::string msg {ex.what()};
        EXPECT_THAT(msg, HasSubstr("Failed to upsert resource of type"));
        EXPECT_THAT(msg, HasSubstr("namespace 'dev'"));
        EXPECT_THAT(msg, HasSubstr("integration failed at builder"));
    }
}

// ---------------------------------------------------------------------
// KVDB: success path (validation is done by KVDB::fromJson in service path)
// ---------------------------------------------------------------------

TEST(CrudService_Component, UpsertKVDB_Success_EndToEnd)
{
    CmCrudStack stack;

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*stack.store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*nsPtr, assetExistsByUUID("82e215c4-988a-4f64-8d15-b98b2fc03a4f")).Times(1).WillOnce(Return(false));

    EXPECT_CALL(*nsPtr, createResource("windows_kerberos_status_code_to_code_name", ResourceType::KVDB, _)).Times(1);
    EXPECT_CALL(*nsPtr, updateResourceByUUID(_, _)).Times(0);

    EXPECT_NO_THROW(stack.service.upsertResource(nsId, ResourceType::KVDB, kKVDBYAML));
}

// ---------------------------------------------------------------------
// Decoder asset: builder error is propagated
// ---------------------------------------------------------------------

TEST(CrudService_Component, UpsertDecoder_BuilderAssetErrorIsPropagated)
{
    CmCrudStack stack;

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(ReturnRef(nsId));

    EXPECT_CALL(*stack.store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*stack.validator, validateAsset(_, _))
        .Times(1)
        .WillOnce(Return(base::Error {"asset validation failed at builder"}));

    EXPECT_CALL(*nsPtr, assetExistsByName(_)).Times(0);
    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);
    EXPECT_CALL(*nsPtr, updateResourceByName(_, _, _)).Times(0);

    try
    {
        stack.service.upsertResource(nsId, ResourceType::DECODER, kDecoderYAML);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& ex)
    {
        const std::string msg {ex.what()};
        EXPECT_THAT(msg, HasSubstr("Failed to upsert resource of type 'decoder' in namespace 'dev'"));
        EXPECT_THAT(msg, HasSubstr("asset validation failed at builder"));
    }
}

// ---------------------------------------------------------------------
// Decoder asset: success path, create vs update by name
// ---------------------------------------------------------------------

TEST(CrudService_Component, UpsertDecoder_Success_CreateByName)
{
    CmCrudStack stack;

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(ReturnRef(nsId));

    EXPECT_CALL(*stack.store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*stack.validator, validateAsset(_, _)).Times(1).WillOnce(Return(base::noError()));

    EXPECT_CALL(*nsPtr, assetExistsByName(_)).Times(1).WillOnce(Return(false));

    EXPECT_CALL(*nsPtr, createResource("decoder/syslog/0", ResourceType::DECODER, _)).Times(1);
    EXPECT_CALL(*nsPtr, updateResourceByName(_, _, _)).Times(0);

    EXPECT_NO_THROW(stack.service.upsertResource(nsId, ResourceType::DECODER, kDecoderYAML));
}

TEST(CrudService_Component, UpsertDecoder_Success_UpdateByName)
{
    CmCrudStack stack;

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(ReturnRef(nsId));

    EXPECT_CALL(*stack.store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*stack.validator, validateAsset(_, _)).Times(1).WillOnce(Return(base::noError()));

    EXPECT_CALL(*nsPtr, assetExistsByName(_)).Times(1).WillOnce(Return(true));

    EXPECT_CALL(*nsPtr, updateResourceByName("decoder/syslog/0", ResourceType::DECODER, _)).Times(1);
    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);

    EXPECT_NO_THROW(stack.service.upsertResource(nsId, ResourceType::DECODER, kDecoderYAML));
}

// ---------------------------------------------------------------------
// KVDB: validation failures prevent store mutation
// ---------------------------------------------------------------------

TEST(CrudService_Component, UpsertKVDB_ContentNotObject_Throws_NoMutation)
{
    CmCrudStack stack;

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    // In case the service resolves NS before parsing/validating
    ON_CALL(*stack.store, getNS(_)).WillByDefault(Return(nsPtr));

    // No builder validator should be touched for KVDB
    EXPECT_CALL(*stack.validator, validateAssetShallow(_)).Times(0);
    EXPECT_CALL(*stack.validator, validateAsset(_, _)).Times(0);
    EXPECT_CALL(*stack.validator, softIntegrationValidate(_, _)).Times(0);
    EXPECT_CALL(*stack.validator, softPolicyValidate(_, _)).Times(0);

    // No store mutation should happen if schema fails
    EXPECT_CALL(*nsPtr, assetExistsByUUID(_)).Times(0);
    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);
    EXPECT_CALL(*nsPtr, updateResourceByUUID(_, _)).Times(0);

    static constexpr const char* kBadKvdbYaml = R"(
    id: "82e215c4-988a-4f64-8d15-b98b2fc03a4f"
    title: "windows_kerberos_status_code_to_code_name"
    content: [ "0x0", "0x1" ]   # <-- invalid: must be an object
    enabled: true
    )";

    try
    {
        stack.service.upsertResource(nsId, ResourceType::KVDB, kBadKvdbYaml);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& ex)
    {
        EXPECT_THAT(std::string {ex.what()}, HasSubstr("KVDB content must be a JSON object"));
    }
}

TEST(CrudService_Component, UpsertKVDB_InvalidUUID_Throws_NoMutation)
{
    CmCrudStack stack;

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    ON_CALL(*stack.store, getNS(_)).WillByDefault(Return(nsPtr));

    EXPECT_CALL(*stack.validator, validateAssetShallow(_)).Times(0);
    EXPECT_CALL(*stack.validator, validateAsset(_, _)).Times(0);
    EXPECT_CALL(*stack.validator, softIntegrationValidate(_, _)).Times(0);
    EXPECT_CALL(*stack.validator, softPolicyValidate(_, _)).Times(0);

    EXPECT_CALL(*nsPtr, assetExistsByUUID(_)).Times(0);
    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);
    EXPECT_CALL(*nsPtr, updateResourceByUUID(_, _)).Times(0);

    static constexpr const char* kBadKvdbUuidYaml = R"(
    id: "not-a-uuid"
    title: "windows_kerberos_status_code_to_code_name"
    content:
      "0x0": "KDC_ERR_NONE"
    enabled: true
    )";

    try
    {
        stack.service.upsertResource(nsId, ResourceType::KVDB, kBadKvdbUuidYaml);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& ex)
    {
        EXPECT_THAT(std::string {ex.what()}, HasSubstr("UUIDv4"));
    }
}

// ---------------------------------------------------------------------
// Integration: validation failures prevent store mutation
// ---------------------------------------------------------------------

TEST(CrudService_Component, UpsertIntegration_InvalidCategory_Throws_NoValidator_NoMutation)
{
    CmCrudStack stack;

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    ON_CALL(*stack.store, getNS(_)).WillByDefault(Return(nsPtr));

    EXPECT_CALL(*stack.validator, softIntegrationValidate(_, _)).Times(0);

    EXPECT_CALL(*nsPtr, assetExistsByUUID(_)).Times(0);
    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);
    EXPECT_CALL(*nsPtr, updateResourceByUUID(_, _)).Times(0);

    static constexpr const char* kBadCategoryIntegrationYaml = R"(
    id: "5c1df6b6-1458-4b2e-9001-96f67a8b12c8"
    title: "windows"
    enabled: true
    category: "ossec"  # <-- invalid
    decoders: []
    kvdbs: []
    )";

    try
    {
        stack.service.upsertResource(nsId, ResourceType::INTEGRATION, kBadCategoryIntegrationYaml);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& ex)
    {
        EXPECT_THAT(std::string {ex.what()}, HasSubstr("category"));
        EXPECT_THAT(std::string {ex.what()}, HasSubstr("not valid"));
    }
}

TEST(CrudService_Component, UpsertIntegration_InvalidDecoderUUID_Throws_NoValidator_NoMutation)
{
    CmCrudStack stack;

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    ON_CALL(*stack.store, getNS(_)).WillByDefault(Return(nsPtr));

    EXPECT_CALL(*stack.validator, softIntegrationValidate(_, _)).Times(0);

    EXPECT_CALL(*nsPtr, assetExistsByUUID(_)).Times(0);
    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);
    EXPECT_CALL(*nsPtr, updateResourceByUUID(_, _)).Times(0);

    static constexpr const char* kBadDecoderUuidIntegrationYaml = R"(
    id: "5c1df6b6-1458-4b2e-9001-96f67a8b12c8"
    title: "windows"
    enabled: true
    category: "security"
    decoders:
      - "not-a-uuid"   # <-- invalid
    kvdbs: []
    )";

    try
    {
        stack.service.upsertResource(nsId, ResourceType::INTEGRATION, kBadDecoderUuidIntegrationYaml);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& ex)
    {
        EXPECT_THAT(std::string {ex.what()}, HasSubstr("UUIDv4"));
    }
}

TEST(CrudService_Component, UpsertIntegration_InvalidKVDBUUID_Throws_NoValidator_NoMutation)
{
    CmCrudStack stack;

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    ON_CALL(*stack.store, getNS(_)).WillByDefault(Return(nsPtr));

    EXPECT_CALL(*stack.validator, softIntegrationValidate(_, _)).Times(0);

    EXPECT_CALL(*nsPtr, assetExistsByUUID(_)).Times(0);
    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);
    EXPECT_CALL(*nsPtr, updateResourceByUUID(_, _)).Times(0);

    static constexpr const char* kBadKvdbUuidIntegrationYaml = R"(
    id: "5c1df6b6-1458-4b2e-9001-96f67a8b12c8"
    title: "windows"
    enabled: true
    category: "security"
    decoders: []
    kvdbs:
      - "not-a-uuid"   # <-- invalid
    )";

    try
    {
        stack.service.upsertResource(nsId, ResourceType::INTEGRATION, kBadKvdbUuidIntegrationYaml);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& ex)
    {
        EXPECT_THAT(std::string {ex.what()}, HasSubstr("UUIDv4"));
    }
}

} // namespace cm::crud::test
