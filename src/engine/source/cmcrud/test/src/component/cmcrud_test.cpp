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
using cm::store::MockICMStoreNSReader;
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
enable_decoders: true
category: "ossec"
default_parent: "decoder/windows/0"
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
// Helper: build a CrudService + MockValidator stack
// ---------------------------------------------------------------------

struct CmCrudStack
{
    std::shared_ptr<NiceMock<MockValidator>> builderValidator;
    std::shared_ptr<NiceMock<MockICMstore>> store;
    CrudService service;

    CmCrudStack()
        : builderValidator(std::make_shared<NiceMock<MockValidator>>())
        , store(std::make_shared<NiceMock<MockICMstore>>())
        , service(store, builderValidator)
    {
    }
};

// ---------------------------------------------------------------------
// Policy: success path end-to-end
// ---------------------------------------------------------------------

TEST(CrudService_Component, UpsertPolicy_Success_EndToEnd)
{
    CmCrudStack stack;

    const std::string nsName {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    // Store must resolve the namespace
    EXPECT_CALL(*stack.store, getNS(Truly([&nsName](const NamespaceId& id) { return id.toStr() == nsName; })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    // Builder validator is invoked by CrudService
    EXPECT_CALL(*stack.builderValidator, softPolicyValidate(_, _)).Times(1).WillOnce(Return(base::noError()));

    // Once policy is validated, it must be written to the namespace
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(stack.service.upsertPolicy(nsName, kPolicyYAML));
}

// ---------------------------------------------------------------------
// Policy: builder error propagates through CrudService
// ---------------------------------------------------------------------

TEST(CrudService_Component, UpsertPolicy_BuilderErrorIsPropagated)
{
    CmCrudStack stack;

    const std::string nsName {"dev"};
    NamespaceId nsId {nsName};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*stack.store, getNS(Truly([&nsName](const NamespaceId& id) { return id.toStr() == nsName; })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(ReturnRef(nsId));

    base::OptError builderErr = base::Error {"policy failed at builder"};

    EXPECT_CALL(*stack.builderValidator, softPolicyValidate(_, _)).Times(1).WillOnce(Return(builderErr));

    // When validation fails, no write should be performed
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(0);

    try
    {
        stack.service.upsertPolicy(nsName, kPolicyYAML);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& ex)
    {
        const std::string msg {ex.what()};
        EXPECT_THAT(msg, HasSubstr("Failed to upsert policy in namespace 'dev'"));
        EXPECT_THAT(msg, HasSubstr("policy failed at builder"));
        EXPECT_THAT(msg, HasSubstr("Policy validation failed in namespace 'dev'"));
    }
}

// ---------------------------------------------------------------------
// Integration: success path end-to-end (create vs UUID)
// ---------------------------------------------------------------------

TEST(CrudService_Component, UpsertIntegration_Success_EndToEnd)
{
    CmCrudStack stack;

    const std::string nsName {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*stack.store, getNS(Truly([&nsName](const NamespaceId& id) { return id.toStr() == nsName; })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    // Builder validation goes through CrudService
    EXPECT_CALL(*stack.builderValidator, softIntegrationValidate(_, _)).Times(1).WillOnce(Return(base::noError()));

    // Integration YAML has a UUID; if it does not exist, we must create it
    EXPECT_CALL(*nsPtr, assetExistsByUUID("5c1df6b6-1458-4b2e-9001-96f67a8b12c8")).Times(1).WillOnce(Return(false));

    EXPECT_CALL(*nsPtr, createResource("windows", ResourceType::INTEGRATION, _)).Times(1);
    EXPECT_CALL(*nsPtr, updateResourceByUUID(_, _)).Times(0);

    EXPECT_NO_THROW(stack.service.upsertResource(nsName, ResourceType::INTEGRATION, kIntegrationYAML));
}

// ---------------------------------------------------------------------
// Integration: builder error is propagated with integration name + namespace
// ---------------------------------------------------------------------

TEST(CrudService_Component, UpsertIntegration_BuilderErrorIsPropagated)
{
    CmCrudStack stack;

    const std::string nsName {"dev"};
    NamespaceId nsId {nsName};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*stack.store, getNS(Truly([&nsName](const NamespaceId& id) { return id.toStr() == nsName; })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(ReturnRef(nsId));

    base::OptError builderErr = base::Error {"integration failed at builder"};

    EXPECT_CALL(*stack.builderValidator, softIntegrationValidate(_, _)).Times(1).WillOnce(Return(builderErr));

    // No resource mutation should happen when validation fails
    EXPECT_CALL(*nsPtr, assetExistsByUUID(_)).Times(0);
    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);
    EXPECT_CALL(*nsPtr, updateResourceByUUID(_, _)).Times(0);

    try
    {
        stack.service.upsertResource(nsName, ResourceType::INTEGRATION, kIntegrationYAML);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& ex)
    {
        const std::string msg {ex.what()};
        EXPECT_THAT(msg, HasSubstr("Failed to upsert resource of type"));
        EXPECT_THAT(msg, HasSubstr("namespace 'dev'"));
        EXPECT_THAT(msg, HasSubstr("windows")); // integration title
        EXPECT_THAT(msg, HasSubstr("integration failed at builder"));
    }
}

// ---------------------------------------------------------------------
// KVDB: success path (no builder validation, only storage behaviour)
// ---------------------------------------------------------------------

TEST(CrudService_Component, UpsertKVDB_Success_EndToEnd)
{
    CmCrudStack stack;

    const std::string nsName {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*stack.store, getNS(Truly([&nsName](const NamespaceId& id) { return id.toStr() == nsName; })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*stack.builderValidator, softPolicyValidate(_, _)).Times(0);
    EXPECT_CALL(*stack.builderValidator, softIntegrationValidate(_, _)).Times(0);
    EXPECT_CALL(*stack.builderValidator, validateAsset(_, _)).Times(0);

    EXPECT_CALL(*nsPtr, assetExistsByUUID("82e215c4-988a-4f64-8d15-b98b2fc03a4f")).Times(1).WillOnce(Return(false));

    EXPECT_CALL(*nsPtr, createResource("windows_kerberos_status_code_to_code_name", ResourceType::KVDB, _)).Times(1);
    EXPECT_CALL(*nsPtr, updateResourceByUUID(_, _)).Times(0);

    EXPECT_NO_THROW(stack.service.upsertResource(nsName, ResourceType::KVDB, kKVDBYAML));
}

// ---------------------------------------------------------------------
// Decoder asset: builder error is propagated through CrudService
// ---------------------------------------------------------------------

TEST(CrudService_Component, UpsertDecoder_BuilderAssetErrorIsPropagated)
{
    CmCrudStack stack;

    const std::string nsName {"dev"};
    NamespaceId nsId {nsName};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*stack.store, getNS(Truly([&nsName](const NamespaceId& id) { return id.toStr() == nsName; })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(ReturnRef(nsId));

    base::OptError builderErr = base::Error {"asset validation failed at builder"};

    EXPECT_CALL(*stack.builderValidator, validateAsset(_, _)).Times(1).WillOnce(Return(builderErr));

    EXPECT_CALL(*nsPtr, assetExistsByName(_)).Times(0);
    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);
    EXPECT_CALL(*nsPtr, updateResourceByName(_, _, _)).Times(0);

    try
    {
        stack.service.upsertResource(nsName, ResourceType::DECODER, kDecoderYAML);
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

    const std::string nsName {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*stack.store, getNS(Truly([&nsName](const NamespaceId& id) { return id.toStr() == nsName; })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*stack.builderValidator, validateAsset(_, _)).Times(1).WillOnce(Return(base::noError()));

    EXPECT_CALL(*nsPtr, assetExistsByName(_)).Times(1).WillOnce(Return(false));

    EXPECT_CALL(*nsPtr, createResource("decoder/syslog/0", ResourceType::DECODER, _)).Times(1);
    EXPECT_CALL(*nsPtr, updateResourceByName(_, _, _)).Times(0);

    EXPECT_NO_THROW(stack.service.upsertResource(nsName, ResourceType::DECODER, kDecoderYAML));
}

TEST(CrudService_Component, UpsertDecoder_Success_UpdateByName)
{
    CmCrudStack stack;

    const std::string nsName {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*stack.store, getNS(Truly([&nsName](const NamespaceId& id) { return id.toStr() == nsName; })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*stack.builderValidator, validateAsset(_, _)).Times(1).WillOnce(Return(base::noError()));

    EXPECT_CALL(*nsPtr, assetExistsByName(_)).Times(1).WillOnce(Return(true));

    EXPECT_CALL(*nsPtr, updateResourceByName("decoder/syslog/0", ResourceType::DECODER, _)).Times(1);
    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);

    EXPECT_NO_THROW(stack.service.upsertResource(nsName, ResourceType::DECODER, kDecoderYAML));
}

} // namespace cm::crud::test
