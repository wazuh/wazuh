#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/json.hpp>
#include <builder/ivalidator.hpp>
#include <builder/mockValidator.hpp>
#include <cmstore/detail.hpp>
#include <cmstore/mockcmstore.hpp>

#include <cmcrud/cmcrudservice.hpp>
#include <cmcrud/mockcmcrud.hpp>

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
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

// Integration example (YAML version of the JSON payload)
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

// KVDB example (YAML version of the JSON payload)
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

// Policy example (YAML version of the JSON payload)
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

// Minimal decoder asset example (YAML)
static constexpr const char* kDecoderYAML = R"(
name: decoder/syslog/0
id: "3f086ce2-32a4-42b0-be7e-40dcfb9c6160"
enabled: true
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
// Constructor tests
// ---------------------------------------------------------------------

TEST(CrudService_Unit, Construction_NullStoreThrows)
{
    std::shared_ptr<cm::store::ICMStore> nullStore;
    auto validator = std::make_shared<NiceMock<MockValidator>>();

    EXPECT_THROW(CrudService service(nullStore, validator), std::invalid_argument);
}

TEST(CrudService_Unit, Construction_NullValidatorThrows)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    std::shared_ptr<builder::IValidator> nullValidator;

    EXPECT_THROW(CrudService service(store, nullValidator), std::invalid_argument);
}

// ---------------------------------------------------------------------
// listNamespaces
// ---------------------------------------------------------------------

TEST(CrudService_Unit, ListNamespaces_ForwardsToStore)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    std::vector<NamespaceId> expected;
    expected.emplace_back("ns1");
    expected.emplace_back("ns2");

    EXPECT_CALL(*store, getNamespaces()).Times(1).WillOnce(Return(expected));

    auto result = service.listNamespaces();
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0].toStr(), "ns1");
    EXPECT_EQ(result[1].toStr(), "ns2");
}

// ---------------------------------------------------------------------
// createNamespace
// ---------------------------------------------------------------------

TEST(CrudService_Unit, CreateNamespace_Success)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};

    EXPECT_CALL(*store, createNamespace(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1);

    EXPECT_NO_THROW(service.createNamespace(nsId));
}

TEST(CrudService_Unit, CreateNamespace_StoreFailureIsWrapped)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};

    EXPECT_CALL(*store, createNamespace(_)).Times(1).WillOnce(Throw(std::runtime_error {"low-level error"}));

    try
    {
        service.createNamespace(nsId);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("Failed to create namespace 'dev'"));
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("low-level error"));
    }
}

// ---------------------------------------------------------------------
// deleteNamespace
// ---------------------------------------------------------------------

TEST(CrudService_Unit, DeleteNamespace_Success)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};

    EXPECT_CALL(*store, deleteNamespace(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1);

    EXPECT_NO_THROW(service.deleteNamespace(nsId));
}

TEST(CrudService_Unit, DeleteNamespace_StoreFailureIsWrapped)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};

    EXPECT_CALL(*store, deleteNamespace(_)).Times(1).WillOnce(Throw(std::runtime_error {"low-level error"}));

    try
    {
        service.deleteNamespace(nsId);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("Failed to delete namespace 'dev'"));
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("low-level error"));
    }
}

// ---------------------------------------------------------------------
// upsertPolicy
// ---------------------------------------------------------------------

TEST(CrudService_Unit, UpsertPolicy_Success)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*nsPtr, getNamespaceId()).Times(1).WillOnce(testing::ReturnRef(nsId));

    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*validator, softPolicyValidate(_, _)).Times(1).WillOnce(Return(base::noError()));
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(service.upsertPolicy(nsId, kPolicyYAML));
}

TEST(CrudService_Unit, UpsertPolicy_ValidationFailureIsWrapped)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*nsPtr, getNamespaceId()).Times(1).WillOnce(testing::ReturnRef(nsId));

    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*validator, softPolicyValidate(_, _)).Times(1).WillOnce(Return(base::Error {"validation error"}));
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(0);

    try
    {
        service.upsertPolicy(nsId, kPolicyYAML);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("Failed to upsert policy in namespace 'dev'"));
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("validation error"));
    }
}

// ---------------------------------------------------------------------
// deletePolicy
// ---------------------------------------------------------------------

TEST(CrudService_Unit, DeletePolicy_Success)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*nsPtr, deletePolicy()).Times(1);

    EXPECT_NO_THROW(service.deletePolicy(nsId));
}

// ---------------------------------------------------------------------
// listResources
// ---------------------------------------------------------------------

TEST(CrudService_Unit, ListResources_Success)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};
    auto nsReader = std::make_shared<NiceMock<MockICMStoreNSReader>>();

    EXPECT_CALL(*store, getNSReader(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsReader));

    std::vector<std::tuple<std::string, std::string>> collection;
    collection.emplace_back("uuid-1", "decoder/syslog/0");
    collection.emplace_back("uuid-2", "decoder/other/0");

    EXPECT_CALL(*nsReader, getCollection(ResourceType::DECODER)).Times(1).WillOnce(Return(collection));

    EXPECT_CALL(*nsReader, resolveHashFromUUID("uuid-1")).Times(1).WillOnce(Return("hash-1"));
    EXPECT_CALL(*nsReader, resolveHashFromUUID("uuid-2")).Times(1).WillOnce(Return("hash-2"));

    auto result = service.listResources(nsId, ResourceType::DECODER);
    ASSERT_EQ(result.size(), 2u);

    EXPECT_EQ(result[0].uuid, "uuid-1");
    EXPECT_EQ(result[0].name, "decoder/syslog/0");
    EXPECT_EQ(result[0].hash, "hash-1");

    EXPECT_EQ(result[1].uuid, "uuid-2");
    EXPECT_EQ(result[1].name, "decoder/other/0");
    EXPECT_EQ(result[1].hash, "hash-2");
}

TEST(CrudService_Unit, ListResources_MissingNamespaceThrows)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};

    EXPECT_CALL(*store, getNSReader(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(std::shared_ptr<cm::store::ICMStoreNSReader> {}));

    EXPECT_THROW(service.listResources(nsId, ResourceType::DECODER), std::runtime_error);
}

// ---------------------------------------------------------------------
// getResourceByUUID - Integration
// ---------------------------------------------------------------------

TEST(CrudService_Unit, GetResourceByUUID_Integration)
{
    using ::testing::HasSubstr;

    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};
    const std::string uuid {"5c1df6b6-1458-4b2e-9001-96f67a8b12c8"};

    auto nsReader = std::make_shared<NiceMock<MockICMStoreNSReader>>();

    ON_CALL(*store, getNSReader(_)).WillByDefault(Return(nsReader));
    ON_CALL(*nsReader, resolveNameFromUUID(uuid))
        .WillByDefault(Return(std::make_tuple(std::string {"windows"}, ResourceType::INTEGRATION)));

    json::Json integrationJson {R"(
    {
      "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
      "title": "windows",
      "enabled": true,
      "category": "security",
      "default_parent": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "decoders": [
        "85853f26-5779-469b-86c4-c47ee7d400b4"
      ],
      "kvdbs": []
    })"};

    auto integ = cm::store::dataType::Integration::fromJson(integrationJson, /*requireUUID:*/ true);

    EXPECT_CALL(*nsReader, getIntegrationByUUID(uuid)).Times(1).WillOnce(Return(integ));

    const std::string yaml = service.getResourceByUUID(nsId, uuid, false);

    EXPECT_THAT(yaml, HasSubstr("windows"));
    EXPECT_THAT(yaml, HasSubstr("5c1df6b6-1458-4b2e-9001-96f67a8b12c8"));
}

// ---------------------------------------------------------------------
// getResourceByUUID - KVDB
// ---------------------------------------------------------------------

TEST(CrudService_Unit, GetResourceByUUID_KVDB)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};
    const std::string uuid {"82e215c4-988a-4f64-8d15-b98b2fc03a4f"};

    auto nsReader = std::make_shared<NiceMock<MockICMStoreNSReader>>();

    EXPECT_CALL(*store, getNSReader(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsReader));

    EXPECT_CALL(*nsReader, resolveNameFromUUID(uuid))
        .Times(1)
        .WillOnce(Return(std::make_tuple("windows_kerberos_status_code_to_code_name", ResourceType::KVDB)));

    json::Json kvdbJson {R"(
    {
      "id": "82e215c4-988a-4f64-8d15-b98b2fc03a4f",
      "title": "windows_kerberos_status_code_to_code_name",
      "content": {
        "0x0": "KDC_ERR_NONE",
        "0x1": "KDC_ERR_NAME_EXP"
      },
      "enabled": true
    })"};

    auto kvdb = cm::store::dataType::KVDB::fromJson(kvdbJson, /*requireUUID:*/ true);

    EXPECT_CALL(*nsReader, getKVDBByUUID(uuid)).Times(1).WillOnce(Return(kvdb));

    const std::string yaml = service.getResourceByUUID(nsId, uuid, false);

    EXPECT_THAT(yaml, ::testing::HasSubstr("windows_kerberos_status_code_to_code_name"));
    EXPECT_THAT(yaml, ::testing::HasSubstr("82e215c4-988a-4f64-8d15-b98b2fc03a4f"));
}

// ---------------------------------------------------------------------
// getResourceByUUID - Asset (decoder)
// ---------------------------------------------------------------------

TEST(CrudService_Unit, GetResourceByUUID_Decoder)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};
    const std::string uuid {"3f086ce2-32a4-42b0-be7e-40dcfb9c6160"};

    auto nsReader = std::make_shared<NiceMock<MockICMStoreNSReader>>();

    EXPECT_CALL(*store, getNSReader(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsReader));

    EXPECT_CALL(*nsReader, resolveNameFromUUID(uuid))
        .Times(1)
        .WillOnce(Return(std::make_tuple("decoder/syslog/0", ResourceType::DECODER)));

    json::Json assetJson {R"(
    {
      "name": "decoder/syslog/0",
      "id": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "metadata": { "module": "syslog" }
    })"};

    EXPECT_CALL(*nsReader, getAssetByUUID(uuid)).Times(1).WillOnce(Return(assetJson));

    const std::string yaml = service.getResourceByUUID(nsId, uuid, false);

    EXPECT_THAT(yaml, ::testing::HasSubstr("decoder/syslog/0"));
    EXPECT_THAT(yaml, ::testing::HasSubstr("3f086ce2-32a4-42b0-be7e-40dcfb9c6160"));
}

// ---------------------------------------------------------------------
// upsertResource - Integration (create vs update)
// ---------------------------------------------------------------------

TEST(CrudService_Unit, UpsertIntegration_CreateWhenUUIDDoesNotExist)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(testing::ReturnRef(nsId));
    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*validator, softIntegrationValidate(_, _)).Times(1).WillOnce(Return(base::noError()));

    EXPECT_CALL(*nsPtr, assetExistsByUUID("5c1df6b6-1458-4b2e-9001-96f67a8b12c8")).Times(1).WillOnce(Return(false));

    EXPECT_CALL(*nsPtr, createResource("windows", ResourceType::INTEGRATION, _)).Times(1);
    EXPECT_CALL(*nsPtr, updateResourceByUUID(_, _)).Times(0);

    EXPECT_NO_THROW(service.upsertResource(nsId, ResourceType::INTEGRATION, kIntegrationYAML));
}

TEST(CrudService_Unit, UpsertIntegration_UpdateWhenUUIDExists)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(testing::ReturnRef(nsId));
    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*validator, softIntegrationValidate(_, _)).Times(1).WillOnce(Return(base::noError()));

    EXPECT_CALL(*nsPtr, assetExistsByUUID("5c1df6b6-1458-4b2e-9001-96f67a8b12c8")).Times(1).WillOnce(Return(true));

    EXPECT_CALL(*nsPtr, updateResourceByUUID("5c1df6b6-1458-4b2e-9001-96f67a8b12c8", _)).Times(1);
    EXPECT_CALL(*nsPtr, createResource("windows", ResourceType::INTEGRATION, _)).Times(0);

    EXPECT_NO_THROW(service.upsertResource(nsId, ResourceType::INTEGRATION, kIntegrationYAML));
}

// ---------------------------------------------------------------------
// upsertResource - KVDB (create vs update)
// ---------------------------------------------------------------------

TEST(CrudService_Unit, UpsertKVDB_CreateWhenUUIDDoesNotExist)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*nsPtr, assetExistsByUUID("82e215c4-988a-4f64-8d15-b98b2fc03a4f")).Times(1).WillOnce(Return(false));

    EXPECT_CALL(*nsPtr, createResource("windows_kerberos_status_code_to_code_name", ResourceType::KVDB, _)).Times(1);
    EXPECT_CALL(*nsPtr, updateResourceByUUID(_, _)).Times(0);

    EXPECT_NO_THROW(service.upsertResource(nsId, ResourceType::KVDB, kKVDBYAML));
}

TEST(CrudService_Unit, UpsertKVDB_UpdateWhenUUIDExists)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*nsPtr, assetExistsByUUID("82e215c4-988a-4f64-8d15-b98b2fc03a4f")).Times(1).WillOnce(Return(true));

    EXPECT_CALL(*nsPtr, updateResourceByUUID("82e215c4-988a-4f64-8d15-b98b2fc03a4f", _)).Times(1);
    EXPECT_CALL(*nsPtr, createResource("windows_kerberos_status_code_to_code_name", ResourceType::KVDB, _)).Times(0);

    EXPECT_NO_THROW(service.upsertResource(nsId, ResourceType::KVDB, kKVDBYAML));
}

// ---------------------------------------------------------------------
// upsertResource - Asset (decoder) create vs update by name
// ---------------------------------------------------------------------

TEST(CrudService_Unit, UpsertDecoder_CreateWhenNameDoesNotExist)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(testing::ReturnRef(nsId));
    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*validator, validateAsset(_, _)).Times(1).WillOnce(Return(base::noError()));
    EXPECT_CALL(*nsPtr, assetExistsByName(_)).Times(1).WillOnce(Return(false));

    EXPECT_CALL(*nsPtr, createResource("decoder/syslog/0", ResourceType::DECODER, _)).Times(1);
    EXPECT_CALL(*nsPtr, updateResourceByName("decoder/syslog/0", ResourceType::DECODER, _)).Times(0);

    EXPECT_NO_THROW(service.upsertResource(nsId, ResourceType::DECODER, kDecoderYAML));
}

TEST(CrudService_Unit, UpsertDecoder_UpdateWhenNameExists)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(testing::ReturnRef(nsId));
    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*validator, validateAsset(_, _)).Times(1).WillOnce(Return(base::noError()));
    EXPECT_CALL(*nsPtr, assetExistsByName(_)).Times(1).WillOnce(Return(true));

    EXPECT_CALL(*nsPtr, updateResourceByName("decoder/syslog/0", ResourceType::DECODER, _)).Times(1);
    EXPECT_CALL(*nsPtr, createResource("decoder/syslog/0", ResourceType::DECODER, _)).Times(0);

    EXPECT_NO_THROW(service.upsertResource(nsId, ResourceType::DECODER, kDecoderYAML));
}

// ---------------------------------------------------------------------
// deleteResourceByUUID
// ---------------------------------------------------------------------

TEST(CrudService_Unit, DeleteResourceByUUID_Success)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    const NamespaceId nsId {"dev"};
    const std::string uuid {"some-uuid"};

    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*nsPtr, deleteResourceByUUID(uuid)).Times(1);

    EXPECT_NO_THROW(service.deleteResourceByUUID(nsId, uuid));
}

// ---------------------------------------------------------------------
// validateResource
// ---------------------------------------------------------------------

TEST(CrudService_Unit, ValidateResource_Decoder_CallsValidateAssetShallow)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    static constexpr const char* kDecoderJsonStr = R"(
    {
      "name": "decoder/syslog/0",
      "id": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "enabled": true,
      "metadata": { "module": "syslog" }
    })";

    json::Json payload {kDecoderJsonStr};
    payload = cm::store::detail::adaptDecoder(payload);
    EXPECT_CALL(*validator, validateAssetShallow(_)).Times(1).WillOnce(Return(base::noError()));

    EXPECT_NO_THROW(service.validateResource(ResourceType::DECODER, payload));
}

TEST(CrudService_Unit, ValidateResource_Decoder_ValidationFailureThrows)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    static constexpr const char* kDecoderJsonStr = R"(
    {
      "name": "decoder/syslog/0",
      "id": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "enabled": true,
      "metadata": { "module": "syslog" }
    })";

    json::Json payload {kDecoderJsonStr};
    payload = cm::store::detail::adaptDecoder(payload);
    EXPECT_CALL(*validator, validateAssetShallow(_)).Times(1).WillOnce(Return(base::Error {"bad asset"}));

    try
    {
        service.validateResource(ResourceType::DECODER, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("bad asset"));
    }
}

TEST(CrudService_Unit, ValidateResource_Integration_SuccessDoesNotTouchValidator)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    static constexpr const char* kIntegrationJsonStr = R"(
    {
      "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
      "title": "windows",
      "enabled": true,
      "category": "security",
      "default_parent": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "decoders": [
        "85853f26-5779-469b-86c4-c47ee7d400b4"
      ],
      "kvdbs": []
    })";

    json::Json payload {kIntegrationJsonStr};

    EXPECT_CALL(*validator, validateAssetShallow(_)).Times(0);
    EXPECT_CALL(*validator, validateAsset(_, _)).Times(0);
    EXPECT_CALL(*validator, softIntegrationValidate(_, _)).Times(0);
    EXPECT_CALL(*validator, softPolicyValidate(_, _)).Times(0);

    EXPECT_NO_THROW(service.validateResource(ResourceType::INTEGRATION, payload));
}

TEST(CrudService_Unit, ValidateResource_KVDB_SuccessDoesNotTouchValidator)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    static constexpr const char* kKvdbJsonStr = R"(
    {
      "id": "82e215c4-988a-4f64-8d15-b98b2fc03a4f",
      "title": "windows_kerberos_status_code_to_code_name",
      "content": {
        "0x0": "KDC_ERR_NONE",
        "0x1": "KDC_ERR_NAME_EXP"
      },
      "enabled": true
    })";

    json::Json payload {kKvdbJsonStr};

    EXPECT_CALL(*validator, validateAssetShallow(_)).Times(0);

    EXPECT_NO_THROW(service.validateResource(ResourceType::KVDB, payload));
}

// ---------------------------------------------------------------------
// validateResource - KVDB validation failures
// ---------------------------------------------------------------------

TEST(CrudService_Unit, ValidateResource_KVDB_MissingId_Throws)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    static constexpr const char* kKvdbMissingIdStr = R"(
    {
      "title": "windows_kerberos_status_code_to_code_name",
      "content": { "0x0": "KDC_ERR_NONE" },
      "enabled": true
    })";

    json::Json payload {kKvdbMissingIdStr};

    try
    {
        service.validateResource(ResourceType::KVDB, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("KVDB"));
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("id"));
    }
}

TEST(CrudService_Unit, ValidateResource_KVDB_ContentNotObject_Throws)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    static constexpr const char* kKvdbBadContentStr = R"(
    {
      "id": "82e215c4-988a-4f64-8d15-b98b2fc03a4f",
      "title": "windows_kerberos_status_code_to_code_name",
      "content": "not-an-object",
      "enabled": true
    })";

    json::Json payload {kKvdbBadContentStr};

    try
    {
        service.validateResource(ResourceType::KVDB, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("KVDB content"));
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("JSON object"));
    }
}

TEST(CrudService_Unit, ValidateResource_KVDB_MissingEnabled_Throws)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    static constexpr const char* kKvdbMissingEnabledStr = R"(
    {
      "id": "82e215c4-988a-4f64-8d15-b98b2fc03a4f",
      "title": "windows_kerberos_status_code_to_code_name",
      "content": { "0x0": "KDC_ERR_NONE" }
    })";

    json::Json payload {kKvdbMissingEnabledStr};

    try
    {
        service.validateResource(ResourceType::KVDB, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("KVDB"));
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("enabled"));
    }
}

// ---------------------------------------------------------------------
// validateResource - Integration validation failures
// ---------------------------------------------------------------------

TEST(CrudService_Unit, ValidateResource_Integration_InvalidDecoderUUID_Throws)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    static constexpr const char* kIntegrationBadDecoderUUIDStr = R"(
    {
      "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
      "title": "windows",
      "enabled": true,
      "category": "security",
      "default_parent": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "decoders": [ "NOT-A-UUID" ],
      "kvdbs": []
    })";

    json::Json payload {kIntegrationBadDecoderUUIDStr};

    try
    {
        service.validateResource(ResourceType::INTEGRATION, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("Decoder"));
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("UUID"));
    }
}

TEST(CrudService_Unit, ValidateResource_Integration_InvalidKVDBUUID_Throws)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    static constexpr const char* kIntegrationBadKVDBUUIDStr = R"(
    {
      "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
      "title": "windows",
      "enabled": true,
      "category": "security",
      "default_parent": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "decoders": [
        "85853f26-5779-469b-86c4-c47ee7d400b4"
      ],
      "kvdbs": [ "NOT-A-UUID" ]
    })";

    json::Json payload {kIntegrationBadKVDBUUIDStr};

    try
    {
        service.validateResource(ResourceType::INTEGRATION, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("KVDB"));
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("UUID"));
    }
}

TEST(CrudService_Unit, ValidateResource_Integration_InvalidCategory_Throws)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    auto validator = std::make_shared<NiceMock<MockValidator>>();
    CrudService service {store, validator};

    static constexpr const char* kIntegrationBadCategoryStr = R"(
    {
      "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
      "title": "windows",
      "enabled": true,
      "category": "ossec",
      "default_parent": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "decoders": [
        "85853f26-5779-469b-86c4-c47ee7d400b4"
      ],
      "kvdbs": []
    })";

    json::Json payload {kIntegrationBadCategoryStr};

    try
    {
        service.validateResource(ResourceType::INTEGRATION, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("category"));
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("not valid"));
    }
}

} // namespace cm::crud::test
