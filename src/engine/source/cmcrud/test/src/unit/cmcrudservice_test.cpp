#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/json.hpp>
#include <base/logging.hpp>
#include <builder/ivalidator.hpp>
#include <builder/mockValidator.hpp>
#include <cmstore/detail.hpp>
#include <cmstore/mockcmstore.hpp>

#include <cmcrud/cmcrudservice.hpp>
#include <cmcrud/mockcmcrud.hpp>

using ::testing::_;
using ::testing::HasSubstr;
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

// Common base: store + validator + service
class CrudServiceBase : public ::testing::Test
{
protected:
    void SetUp() override
    {
        store = std::make_shared<NiceMock<MockICMstore>>();
        validator = std::make_shared<NiceMock<MockValidator>>();
        service = std::make_unique<CrudService>(store, validator);
    }

    void TearDown() override {}

    std::shared_ptr<NiceMock<MockICMstore>> store;
    std::shared_ptr<NiceMock<MockValidator>> validator;
    std::unique_ptr<CrudService> service;
};

// Constructor tests
class CrudServiceCtorTest : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }
    void TearDown() override {}
};

// Namespace management tests
class CrudServiceNamespaceTest : public CrudServiceBase
{
};

// Policy tests
class CrudServicePolicyTest : public CrudServiceBase
{
};

// List-resources tests
class CrudServiceListResourcesTest : public CrudServiceBase
{
};

// Get-resource-by-UUID tests
class CrudServiceGetResourceTest : public CrudServiceBase
{
};

// Upsert Integration tests
class CrudServiceUpsertIntegrationTest : public CrudServiceBase
{
};

// Upsert KVDB tests
class CrudServiceUpsertKVDBTest : public CrudServiceBase
{
};

// Upsert Decoder / Asset tests
class CrudServiceUpsertDecoderTest : public CrudServiceBase
{
};

// Delete-resource tests
class CrudServiceDeleteResourceTest : public CrudServiceBase
{
};

// Validate-resource tests
class CrudServiceValidateResourceTest : public CrudServiceBase
{
};

// Import-namespace tests
class CrudServiceImportNamespaceTest : public CrudServiceBase
{
};

// ---------------------------------------------------------------------
// JSON fixtures for realistic resources
// ---------------------------------------------------------------------

static constexpr const char* kIntegrationJson = R"({
  "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
  "metadata": {
    "title": "windows"
  },
  "enabled": true,
  "category": "security",
  "default_parent": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
  "decoders": [
    "85853f26-5779-469b-86c4-c47ee7d400b4",
    "4aa06596-5ba9-488c-8354-2475705e1257",
    "4da71af3-fff5-4b67-90d6-51db9e15bc47",
    "6f8bd7d2-8516-4b2b-a6f1-cc924513c404"
  ],
  "kvdbs": []
})";

static constexpr const char* kKVDBJson = R"({
  "id": "82e215c4-988a-4f64-8d15-b98b2fc03a4f",
  "date": "2025-10-06T13:32:19Z",
  "metadata": {
    "title": "windows_kerberos_status_code_to_code_name"
  },
  "author": "Wazuh Inc.",
  "content": {
    "0x0": "KDC_ERR_NONE",
    "0x1": "KDC_ERR_NAME_EXP",
    "0x2": "KDC_ERR_SERVICE_EXP",
    "0x3": "KDC_ERR_BAD_PVNO",
    "0x4": "KDC_ERR_C_OLD_MAST_KVNO",
    "0x5": "KDC_ERR_S_OLD_MAST_KVNO",
    "0x6": "KDC_ERR_C_PRINCIPAL_UNKNOWN"
  },
  "enabled": true
})";

static constexpr const char* kPolicyJson = R"({
  "type": "policy",
  "enabled": true,
  "title": "Development 0.0.1",
  "hash": "cmcrud-unit-test-hash",
  "default_parent": "decoder/integration/0",
  "root_decoder": "decoder/wazuh-core-message/0",
  "integrations": [
    "42e28392-4f5e-473d-89e8-c9030e6fedc2",
    "a7fe64a2-0a03-414f-8692-8441bdfe6f69",
    "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
    "f61133f5-90b9-49ed-b1d5-0b88cb04355e",
    "369c3128-9715-4a30-9ff9-22fcac87688b"
  ],
  "filters": [],
  "enrichments": [],
  "index_unclassified_events": false,
  "index_discarded_events": false
})";

static constexpr const char* kArrayJSON = R"([
  {
    "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8"
  }
])";

static constexpr const char* kDecoderJson = R"({
  "name": "decoder/syslog/0",
  "id": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
  "enabled": true,
  "metadata": {
    "module": "syslog",
    "title": "Syslog Decoder event"
  },
  "parse|event.original": [
    "<event.start/ISO8601Z> <tmp.hostname/fqdn> <TAG/alphanumeric/->: <message>"
  ],
  "normalize": [
    {
      "map": [
        {
          "event.kind": "event"
        }
      ]
    }
  ]
})";

// Minimal filter asset example (JSON)
static constexpr const char* kFilterJson = R"({
  "name": "filter/pre-filter/0",
  "id": "f1111111-1111-4111-a111-111111111111",
  "enabled": true,
  "type": "pre-filter",
  "metadata": {
    "title": "Test Pre-Filter"
  },
  "check": "$host.os.platform == 'ubuntu'"
})";

json::Json makeJsonPayload(const char* raw)
{
    return json::Json {raw};
}

std::string getStringOrEmpty(const json::Json& json, std::string_view path)
{
    std::string value;
    if (json.getString(value, path) != json::RetGet::Success)
    {
        return "";
    }
    return value;
}

// ---------------------------------------------------------------------
// Constructor tests
// ---------------------------------------------------------------------

TEST_F(CrudServiceCtorTest, Construction_NullStoreThrows)
{
    std::shared_ptr<cm::store::ICMStore> nullStore;
    auto validator = std::make_shared<NiceMock<MockValidator>>();

    EXPECT_THROW(CrudService service(nullStore, validator), std::invalid_argument);
}

TEST_F(CrudServiceCtorTest, Construction_NullValidatorThrows)
{
    auto store = std::make_shared<NiceMock<MockICMstore>>();
    std::shared_ptr<builder::IValidator> nullValidator;

    EXPECT_THROW(CrudService service(store, nullValidator), std::invalid_argument);
}

// ---------------------------------------------------------------------
// listNamespaces
// ---------------------------------------------------------------------

TEST_F(CrudServiceNamespaceTest, ListNamespaces_ForwardsToStore)
{
    std::vector<NamespaceId> expected;
    expected.emplace_back("ns1");
    expected.emplace_back("ns2");

    EXPECT_CALL(*store, getNamespaces()).Times(1).WillOnce(Return(expected));

    auto result = service->listNamespaces();
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0].toStr(), "ns1");
    EXPECT_EQ(result[1].toStr(), "ns2");
}

// ---------------------------------------------------------------------
// createNamespace
// ---------------------------------------------------------------------

TEST_F(CrudServiceNamespaceTest, CreateNamespace_Success)
{
    const NamespaceId nsId {"dev"};

    EXPECT_CALL(*store, createNamespace(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1);

    EXPECT_NO_THROW(service->createNamespace(nsId));
}

TEST_F(CrudServiceNamespaceTest, CreateNamespace_StoreFailureIsWrapped)
{
    const NamespaceId nsId {"dev"};

    EXPECT_CALL(*store, createNamespace(_)).Times(1).WillOnce(Throw(std::runtime_error {"low-level error"}));

    try
    {
        service->createNamespace(nsId);
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

TEST_F(CrudServiceNamespaceTest, DeleteNamespace_Success)
{
    const NamespaceId nsId {"dev"};

    EXPECT_CALL(*store, deleteNamespace(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1);

    EXPECT_NO_THROW(service->deleteNamespace(nsId));
}

TEST_F(CrudServiceNamespaceTest, DeleteNamespace_StoreFailureIsWrapped)
{
    const NamespaceId nsId {"dev"};

    EXPECT_CALL(*store, deleteNamespace(_)).Times(1).WillOnce(Throw(std::runtime_error {"low-level error"}));

    try
    {
        service->deleteNamespace(nsId);
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

TEST_F(CrudServicePolicyTest, UpsertPolicy_Success)
{
    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*nsPtr, getNamespaceId()).Times(1).WillOnce(testing::ReturnRef(nsId));

    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*validator, softPolicyValidate(_, _)).Times(1).WillOnce(Return(base::noError()));
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(service->upsertPolicy(nsId, makeJsonPayload(kPolicyJson)));
}

TEST_F(CrudServicePolicyTest, UpsertPolicy_AcceptsJsonPayload)
{
    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*nsPtr, getNamespaceId()).Times(1).WillOnce(testing::ReturnRef(nsId));

    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*validator, softPolicyValidate(_, _)).Times(1).WillOnce(Return(base::noError()));
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(service->upsertPolicy(nsId, makeJsonPayload(kPolicyJson)));
}

TEST_F(CrudServicePolicyTest, UpsertPolicy_ValidationFailureIsWrapped)
{
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
        service->upsertPolicy(nsId, makeJsonPayload(kPolicyJson));
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("Failed to upsert policy in namespace 'dev'"));
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("validation error"));
    }
}

TEST_F(CrudServicePolicyTest, UpsertPolicy_TopLevelArrayIsRejected)
{
    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*validator, softPolicyValidate(_, _)).Times(0);
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(0);

    try
    {
        service->upsertPolicy(nsId, makeJsonPayload(kArrayJSON));
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("Policy JSON must be an object"));
    }
}

TEST_F(CrudServicePolicyTest, UpsertPolicy_InvalidOriginSpaceIsRejected)
{
    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    constexpr auto kPolicyWithInvalidOriginSpace = R"({
  "type": "policy",
  "enabled": true,
  "metadata": {
    "title": "Development 0.0.1"
  },
  "hash": "cmcrud-unit-test-hash",
  "default_parent": "decoder/integration/0",
  "root_decoder": "decoder/wazuh-core-message/0",
  "origin_space": "../bad-space",
  "integrations": [
    "42e28392-4f5e-473d-89e8-c9030e6fedc2"
  ],
  "filters": [],
  "enrichments": [],
  "index_unclassified_events": false,
  "index_discarded_events": false
})";

    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*validator, softPolicyValidate(_, _)).Times(0);
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(0);

    try
    {
        service->upsertPolicy(nsId, makeJsonPayload(kPolicyWithInvalidOriginSpace));
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("origin_space"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("invalid characters"));
    }
}

// ---------------------------------------------------------------------
// deletePolicy
// ---------------------------------------------------------------------

TEST_F(CrudServicePolicyTest, DeletePolicy_Success)
{
    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*nsPtr, deletePolicy()).Times(1);

    EXPECT_NO_THROW(service->deletePolicy(nsId));
}

// ---------------------------------------------------------------------
// listResources
// ---------------------------------------------------------------------

TEST_F(CrudServiceListResourcesTest, ListResources_Success)
{
    const NamespaceId nsId {"dev"};
    auto nsReader = std::make_shared<NiceMock<MockICMStoreNSReader>>();

    EXPECT_CALL(*store, getNSReader(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsReader));

    std::vector<std::tuple<std::string, std::string>> collection;
    collection.emplace_back("uuid-1", "decoder/syslog/0");
    collection.emplace_back("uuid-2", "decoder/other/0");

    EXPECT_CALL(*nsReader, getCollection(ResourceType::DECODER)).Times(1).WillOnce(Return(collection));

    auto result = service->listResources(nsId, ResourceType::DECODER);
    ASSERT_EQ(result.size(), 2u);

    EXPECT_EQ(result[0].uuid, "uuid-1");
    EXPECT_EQ(result[0].name, "decoder/syslog/0");
    EXPECT_EQ(result[1].uuid, "uuid-2");
    EXPECT_EQ(result[1].name, "decoder/other/0");
}

TEST_F(CrudServiceListResourcesTest, ListResources_MissingNamespaceThrows)
{
    const NamespaceId nsId {"dev"};

    EXPECT_CALL(*store, getNSReader(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(std::shared_ptr<cm::store::ICMStoreNSReader> {}));

    EXPECT_THROW(service->listResources(nsId, ResourceType::DECODER), std::runtime_error);
}

// ---------------------------------------------------------------------
// getResourceByUUID - Integration
// ---------------------------------------------------------------------

TEST_F(CrudServiceGetResourceTest, GetResourceByUUID_Integration)
{
    const NamespaceId nsId {"dev"};
    const std::string uuid {"5c1df6b6-1458-4b2e-9001-96f67a8b12c8"};

    auto nsReader = std::make_shared<NiceMock<MockICMStoreNSReader>>();

    ON_CALL(*store, getNSReader(_)).WillByDefault(Return(nsReader));
    ON_CALL(*nsReader, resolveNameFromUUID(uuid))
        .WillByDefault(Return(std::make_tuple(std::string {"windows"}, ResourceType::INTEGRATION)));

    json::Json integrationJson {R"(
    {
      "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
      "metadata": {
        "title": "windows"
      },
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

    const auto result = service->getResourceByUUID(nsId, uuid);

    EXPECT_EQ(getStringOrEmpty(result, "/id"), "5c1df6b6-1458-4b2e-9001-96f67a8b12c8");
    EXPECT_EQ(getStringOrEmpty(result, "/metadata/title"), "windows");
}

TEST_F(CrudServiceGetResourceTest, GetResourceByUUID_Integration_ReturnsJsonObject)
{
    const NamespaceId nsId {"dev"};
    const std::string uuid {"5c1df6b6-1458-4b2e-9001-96f67a8b12c8"};

    auto nsReader = std::make_shared<NiceMock<MockICMStoreNSReader>>();

    ON_CALL(*store, getNSReader(_)).WillByDefault(Return(nsReader));
    ON_CALL(*nsReader, resolveNameFromUUID(uuid))
        .WillByDefault(Return(std::make_tuple(std::string {"windows"}, ResourceType::INTEGRATION)));

    json::Json integrationJson {R"(
    {
      "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
      "metadata": {
        "title": "windows"
      },
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

    const auto result = service->getResourceByUUID(nsId, uuid);

    EXPECT_TRUE(result.isObject());
    EXPECT_EQ(getStringOrEmpty(result, "/id"), "5c1df6b6-1458-4b2e-9001-96f67a8b12c8");
    EXPECT_EQ(getStringOrEmpty(result, "/metadata/title"), "windows");
}

// ---------------------------------------------------------------------
// getResourceByUUID - KVDB
// ---------------------------------------------------------------------

TEST_F(CrudServiceGetResourceTest, GetResourceByUUID_KVDB)
{
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
      "metadata": {
        "title": "windows_kerberos_status_code_to_code_name"
      },
      "content": {
        "0x0": "KDC_ERR_NONE",
        "0x1": "KDC_ERR_NAME_EXP"
      },
      "enabled": true
    })"};

    auto kvdb = cm::store::dataType::KVDB::fromJson(kvdbJson, /*requireUUID:*/ true);

    EXPECT_CALL(*nsReader, getKVDBByUUID(uuid)).Times(1).WillOnce(Return(kvdb));

    const auto result = service->getResourceByUUID(nsId, uuid);

    EXPECT_EQ(getStringOrEmpty(result, "/id"), "82e215c4-988a-4f64-8d15-b98b2fc03a4f");
    EXPECT_EQ(getStringOrEmpty(result, "/metadata/title"), "windows_kerberos_status_code_to_code_name");
}

// ---------------------------------------------------------------------
// getResourceByUUID - Asset (decoder)
// ---------------------------------------------------------------------

TEST_F(CrudServiceGetResourceTest, GetResourceByUUID_Decoder)
{
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

    const auto result = service->getResourceByUUID(nsId, uuid);

    EXPECT_EQ(getStringOrEmpty(result, "/name"), "decoder/syslog/0");
    EXPECT_EQ(getStringOrEmpty(result, "/id"), "3f086ce2-32a4-42b0-be7e-40dcfb9c6160");
}

// ---------------------------------------------------------------------
// upsertResource - Integration (create vs update)
// ---------------------------------------------------------------------

TEST_F(CrudServiceUpsertIntegrationTest, UpsertIntegration_CreateWhenUUIDDoesNotExist)
{
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

    EXPECT_NO_THROW(service->upsertResource(nsId, ResourceType::INTEGRATION, makeJsonPayload(kIntegrationJson)));
}

TEST_F(CrudServiceUpsertIntegrationTest, UpsertIntegration_UpdateWhenUUIDExists)
{
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

    EXPECT_NO_THROW(service->upsertResource(nsId, ResourceType::INTEGRATION, makeJsonPayload(kIntegrationJson)));
}

TEST_F(CrudServiceUpsertIntegrationTest, UpsertIntegration_AcceptsJsonPayloadAndPassesJsonToStore)
{
    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(testing::ReturnRef(nsId));
    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*validator, softIntegrationValidate(_, _)).Times(1).WillOnce(Return(base::noError()));

    EXPECT_CALL(*nsPtr, assetExistsByUUID("5c1df6b6-1458-4b2e-9001-96f67a8b12c8")).Times(1).WillOnce(Return(false));

    EXPECT_CALL(*nsPtr,
                createResource("windows",
                               ResourceType::INTEGRATION,
                               Truly(
                                   [](const json::Json& content)
                                   {
                                       return content.isObject() && content.isBool("/enabled")
                                              && content.isString("/metadata/title")
                                              && getStringOrEmpty(content, "/metadata/title") == "windows";
                                   })))
        .Times(1);
    EXPECT_CALL(*nsPtr, updateResourceByUUID(_, _)).Times(0);

    EXPECT_NO_THROW(service->upsertResource(nsId, ResourceType::INTEGRATION, makeJsonPayload(kIntegrationJson)));
}

// ---------------------------------------------------------------------
// upsertResource - KVDB (create vs update)
// ---------------------------------------------------------------------

TEST_F(CrudServiceUpsertKVDBTest, UpsertKVDB_CreateWhenUUIDDoesNotExist)
{
    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*nsPtr, assetExistsByUUID("82e215c4-988a-4f64-8d15-b98b2fc03a4f")).Times(1).WillOnce(Return(false));

    EXPECT_CALL(*nsPtr, createResource("windows_kerberos_status_code_to_code_name", ResourceType::KVDB, _)).Times(1);
    EXPECT_CALL(*nsPtr, updateResourceByUUID(_, _)).Times(0);

    EXPECT_NO_THROW(service->upsertResource(nsId, ResourceType::KVDB, makeJsonPayload(kKVDBJson)));
}

TEST_F(CrudServiceUpsertKVDBTest, UpsertKVDB_UpdateWhenUUIDExists)
{
    const NamespaceId nsId {"dev"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*nsPtr, assetExistsByUUID("82e215c4-988a-4f64-8d15-b98b2fc03a4f")).Times(1).WillOnce(Return(true));

    EXPECT_CALL(*nsPtr, updateResourceByUUID("82e215c4-988a-4f64-8d15-b98b2fc03a4f", _)).Times(1);
    EXPECT_CALL(*nsPtr, createResource("windows_kerberos_status_code_to_code_name", ResourceType::KVDB, _)).Times(0);

    EXPECT_NO_THROW(service->upsertResource(nsId, ResourceType::KVDB, makeJsonPayload(kKVDBJson)));
}

// ---------------------------------------------------------------------
// upsertResource - Asset (decoder) create vs update by name
// ---------------------------------------------------------------------

TEST_F(CrudServiceUpsertDecoderTest, UpsertDecoder_CreateWhenNameDoesNotExist)
{
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

    EXPECT_NO_THROW(service->upsertResource(nsId, ResourceType::DECODER, makeJsonPayload(kDecoderJson)));
}

TEST_F(CrudServiceUpsertDecoderTest, UpsertDecoder_UpdateWhenNameExists)
{
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

    EXPECT_NO_THROW(service->upsertResource(nsId, ResourceType::DECODER, makeJsonPayload(kDecoderJson)));
}

// ---------------------------------------------------------------------
// deleteResourceByUUID
// ---------------------------------------------------------------------

TEST_F(CrudServiceDeleteResourceTest, DeleteResourceByUUID_Success)
{
    const NamespaceId nsId {"dev"};
    const std::string uuid {"some-uuid"};

    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

    EXPECT_CALL(*store, getNS(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .Times(1)
        .WillOnce(Return(nsPtr));

    EXPECT_CALL(*nsPtr, deleteResourceByUUID(uuid)).Times(1);

    EXPECT_NO_THROW(service->deleteResourceByUUID(nsId, uuid));
}

// ---------------------------------------------------------------------
// validateResource
// ---------------------------------------------------------------------

TEST_F(CrudServiceValidateResourceTest, ValidateResource_Decoder_CallsValidateAssetShallow)
{
    static constexpr const char* kDecoderJsonStr = R"(
    {
      "name": "decoder/my-decoder/0",
      "id": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "enabled": true,
      "metadata": { "module": "syslog" }
    })";

    json::Json payload {kDecoderJsonStr};
    EXPECT_CALL(*validator, validateAssetShallow(_)).Times(1).WillOnce(Return(base::noError()));

    EXPECT_NO_THROW(service->validateResource(ResourceType::DECODER, payload));
}

TEST_F(CrudServiceValidateResourceTest, ValidateResource_Decoder_InvalidNameThrowsBeforeValidation)
{
    static constexpr const char* kDecoderJsonStr = R"(
    {
      "name": "decoder/my decoder/0",
      "id": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "enabled": true,
      "metadata": { "module": "syslog" }
    })";

    json::Json payload {kDecoderJsonStr};

    EXPECT_CALL(*validator, validateAssetShallow(_)).Times(0);

    try
    {
        service->validateResource(ResourceType::DECODER, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Invalid resource name"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("decoder/my decoder/0"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("decoder"));
    }
}

TEST_F(CrudServiceValidateResourceTest, ValidateResource_Decoder_ValidationFailureThrows)
{
    static constexpr const char* kDecoderJsonStr = R"(
    {
      "name": "decoder/syslog/0",
      "id": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "enabled": true,
      "metadata": { "module": "syslog" }
    })";

    json::Json payload {kDecoderJsonStr};
    EXPECT_CALL(*validator, validateAssetShallow(_)).Times(1).WillOnce(Return(base::Error {"bad asset"}));

    try
    {
        service->validateResource(ResourceType::DECODER, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("bad asset"));
    }
}

TEST_F(CrudServiceValidateResourceTest, ValidateResource_Filter_InvalidNameThrowsBeforeValidation)
{
    static constexpr const char* kFilterJsonStr = R"(
    {
      "name": "filter/bad filter/0",
      "id": "f1111111-1111-4111-a111-111111111111",
      "enabled": true,
      "type": "pre-filter",
      "metadata": { "title": "Test Pre-Filter" },
      "check": "$host.os.platform == 'ubuntu'"
    })";

    json::Json payload {kFilterJsonStr};

    EXPECT_CALL(*validator, validateAssetShallow(_)).Times(0);

    try
    {
        service->validateResource(ResourceType::FILTER, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Invalid resource name"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("filter/bad filter/0"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("filter"));
    }
}

TEST_F(CrudServiceValidateResourceTest, ValidateResource_Integration_SuccessDoesNotTouchValidator)
{
    static constexpr const char* kIntegrationJsonStr = R"(
    {
      "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
      "metadata": {
        "title": "windows-security"
      },
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

    EXPECT_NO_THROW(service->validateResource(ResourceType::INTEGRATION, payload));
}

TEST_F(CrudServiceValidateResourceTest, ValidateResource_Integration_InvalidNameThrows)
{
    static constexpr const char* kIntegrationJsonStr = R"(
    {
      "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
      "metadata": {
        "title": "bad integration"
      },
      "enabled": true,
      "category": "security",
      "default_parent": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "decoders": [
        "85853f26-5779-469b-86c4-c47ee7d400b4"
      ],
      "kvdbs": []
    })";

    json::Json payload {kIntegrationJsonStr};

    try
    {
        service->validateResource(ResourceType::INTEGRATION, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Invalid resource name"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("bad integration"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("integration"));
    }
}

TEST_F(CrudServiceValidateResourceTest, ValidateResource_KVDB_SuccessDoesNotTouchValidator)
{
    static constexpr const char* kKvdbJsonStr = R"(
    {
      "id": "82e215c4-988a-4f64-8d15-b98b2fc03a4f",
      "metadata": {
        "title": "windows-kerberos_status_code_to_code_name"
      },
      "content": {
        "0x0": "KDC_ERR_NONE",
        "0x1": "KDC_ERR_NAME_EXP"
      },
      "enabled": true
    })";

    json::Json payload {kKvdbJsonStr};

    EXPECT_CALL(*validator, validateAssetShallow(_)).Times(0);

    EXPECT_NO_THROW(service->validateResource(ResourceType::KVDB, payload));
}

TEST_F(CrudServiceValidateResourceTest, ValidateResource_KVDB_InvalidNameThrows)
{
    static constexpr const char* kKvdbJsonStr = R"(
    {
      "id": "82e215c4-988a-4f64-8d15-b98b2fc03a4f",
      "metadata": {
        "title": "bad/kvdb"
      },
      "content": {
        "0x0": "KDC_ERR_NONE"
      },
      "enabled": true
    })";

    json::Json payload {kKvdbJsonStr};

    try
    {
        service->validateResource(ResourceType::KVDB, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Invalid resource name"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("bad/kvdb"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("kvdb"));
    }
}

// ---------------------------------------------------------------------
// validateResource - KVDB validation failures
// ---------------------------------------------------------------------

TEST_F(CrudServiceValidateResourceTest, ValidateResource_KVDB_MissingId_Throws)
{
    static constexpr const char* kKvdbMissingIdStr = R"(
    {
      "metadata": {
        "title": "windows_kerberos_status_code_to_code_name"
      },
      "content": { "0x0": "KDC_ERR_NONE" },
      "enabled": true
    })";

    json::Json payload {kKvdbMissingIdStr};

    try
    {
        service->validateResource(ResourceType::KVDB, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("KVDB"));
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("id"));
    }
}

TEST_F(CrudServiceValidateResourceTest, ValidateResource_KVDB_ContentNotObject_Throws)
{
    static constexpr const char* kKvdbBadContentStr = R"(
    {
      "id": "82e215c4-988a-4f64-8d15-b98b2fc03a4f",
      "metadata": {
        "title": "windows_kerberos_status_code_to_code_name"
      },
      "content": "not-an-object",
      "enabled": true
    })";

    json::Json payload {kKvdbBadContentStr};

    try
    {
        service->validateResource(ResourceType::KVDB, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("KVDB content"));
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("JSON object"));
    }
}

TEST_F(CrudServiceValidateResourceTest, ValidateResource_KVDB_MissingEnabled_Throws)
{
    static constexpr const char* kKvdbMissingEnabledStr = R"(
    {
      "id": "82e215c4-988a-4f64-8d15-b98b2fc03a4f",
      "metadata": {
        "title": "windows_kerberos_status_code_to_code_name"
      },
      "content": { "0x0": "KDC_ERR_NONE" }
    })";

    json::Json payload {kKvdbMissingEnabledStr};

    try
    {
        service->validateResource(ResourceType::KVDB, payload);
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

TEST_F(CrudServiceValidateResourceTest, ValidateResource_Integration_InvalidDecoderUUID_Throws)
{
    static constexpr const char* kIntegrationBadDecoderUUIDStr = R"(
    {
      "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
      "metadata": {
        "title": "windows"
      },
      "enabled": true,
      "category": "security",
      "default_parent": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "decoders": [ "NOT-A-UUID" ],
      "kvdbs": []
    })";

    json::Json payload {kIntegrationBadDecoderUUIDStr};

    try
    {
        service->validateResource(ResourceType::INTEGRATION, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("Decoder"));
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("UUID"));
    }
}

TEST_F(CrudServiceValidateResourceTest, ValidateResource_Integration_InvalidKVDBUUID_Throws)
{
    static constexpr const char* kIntegrationBadKVDBUUIDStr = R"(
    {
      "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
      "metadata": {
        "title": "windows"
      },
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
        service->validateResource(ResourceType::INTEGRATION, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("KVDB"));
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("UUID"));
    }
}

TEST_F(CrudServiceValidateResourceTest, ValidateResource_Integration_InvalidCategory_Throws)
{
    static constexpr const char* kIntegrationBadCategoryStr = R"(
    {
      "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
      "metadata": {
        "title": "windows"
      },
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
        service->validateResource(ResourceType::INTEGRATION, payload);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("category"));
        EXPECT_THAT(std::string {e.what()}, ::testing::HasSubstr("not valid"));
    }
}

// ---------------------------------------------------------------------
// importNamespace (component-based)
// ---------------------------------------------------------------------

TEST_F(CrudServiceImportNamespaceTest, ImportNamespace_Success_WithFilters)
{
    const NamespaceId nsId {"imported"};
    auto nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();
    auto nsReader = std::static_pointer_cast<cm::store::ICMStoreNSReader>(nsPtr);

    EXPECT_CALL(*store, existsNamespace(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .WillOnce(Return(false));
    EXPECT_CALL(*store, createNamespace(Truly([&nsId](const NamespaceId& id) { return id.toStr() == nsId.toStr(); })))
        .WillOnce(Return(nsPtr));

    std::vector<json::Json> kvdbs;
    std::vector<json::Json> decoders;
    std::vector<json::Json> integrations;
    std::vector<json::Json> filters;

    // Add a filter
    filters.emplace_back(makeJsonPayload(kFilterJson));

    // Expect filter creation
    EXPECT_CALL(*nsPtr, createResource("filter/pre-filter/0", ResourceType::FILTER, _)).Times(1);

    // Expect policy upsert
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(
        service->importNamespace(nsId, kvdbs, decoders, filters, integrations, makeJsonPayload(kPolicyJson), true));
}

// =========================================================================
// importNamespace – vector (component) overload – extended coverage
// =========================================================================

class CrudServiceImportNsFromVectorTest : public CrudServiceBase
{
protected:
    const NamespaceId nsId {"imported"};
    std::shared_ptr<NiceMock<MockICMstoreNS>> nsPtr;

    void SetUp() override
    {
        CrudServiceBase::SetUp();

        nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();

        ON_CALL(*store, existsNamespace(_)).WillByDefault(Return(false));
        ON_CALL(*store, createNamespace(_)).WillByDefault(Return(nsPtr));
        ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(testing::ReturnRef(nsId));
    }
};

// Helpers inside the fixture scope

// A decoder whose name first-part is intentionally wrong
static constexpr const char* kDecoderJsonWrongPrefix = R"({
  "name": "filter/syslog/0",
  "id": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
  "enabled": true,
  "metadata": {"module": "syslog", "title": "Syslog Decoder"}
})";

// A filter whose name first-part is intentionally wrong
static constexpr const char* kFilterJsonWrongPrefix = R"({
  "name": "decoder/pre-filter/0",
  "id": "f1111111-1111-4111-a111-111111111111",
  "enabled": true,
  "type": "pre-filter",
  "metadata": {"title": "Test Pre-Filter"}
})";

// Reject when namespace already exists

TEST_F(CrudServiceImportNsFromVectorTest, AlreadyExists_Throws)
{
    EXPECT_CALL(*store, existsNamespace(_)).WillOnce(Return(true));
    EXPECT_CALL(*store, createNamespace(_)).Times(0);

    try
    {
        service->importNamespace(nsId, {}, {}, {}, {}, makeJsonPayload(kPolicyJson), /*softValidation=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("already exists"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("imported"));
    }
}

// Import KVDB resources

TEST_F(CrudServiceImportNsFromVectorTest, ImportsKVDB)
{
    std::vector<json::Json> kvdbs = {makeJsonPayload(kKVDBJson)};

    EXPECT_CALL(*nsPtr, createResource("windows_kerberos_status_code_to_code_name", ResourceType::KVDB, _)).Times(1);
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(
        service->importNamespace(nsId, kvdbs, {}, {}, {}, makeJsonPayload(kPolicyJson), /*softValidation=*/true));
}

// Import decoder resources

TEST_F(CrudServiceImportNsFromVectorTest, ImportsDecoder)
{
    std::vector<json::Json> decoders = {makeJsonPayload(kDecoderJson)};

    EXPECT_CALL(*nsPtr, createResource("decoder/syslog/0", ResourceType::DECODER, _)).Times(1);
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(
        service->importNamespace(nsId, {}, decoders, {}, {}, makeJsonPayload(kPolicyJson), /*softValidation=*/true));
}

// Import filter resources

TEST_F(CrudServiceImportNsFromVectorTest, ImportsFilter)
{
    std::vector<json::Json> filters = {makeJsonPayload(kFilterJson)};

    EXPECT_CALL(*nsPtr, createResource("filter/pre-filter/0", ResourceType::FILTER, _)).Times(1);
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(
        service->importNamespace(nsId, {}, {}, filters, {}, makeJsonPayload(kPolicyJson), /*softValidation=*/true));
}

// Import integration resources

TEST_F(CrudServiceImportNsFromVectorTest, ImportsIntegration)
{
    std::vector<json::Json> integrations = {makeJsonPayload(kIntegrationJson)};

    EXPECT_CALL(*nsPtr, createResource("windows", ResourceType::INTEGRATION, _)).Times(1);
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(service->importNamespace(
        nsId, {}, {}, {}, integrations, makeJsonPayload(kPolicyJson), /*softValidation=*/true));
}

TEST_F(CrudServiceImportNsFromVectorTest, InvalidDecoderNameThrowsBeforeCreate)
{
    static constexpr const char* kDecoderJsonInvalidName = R"({
      "name": "decoder/my decoder/0",
      "id": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "enabled": true,
      "metadata": {"module": "syslog", "title": "Syslog Decoder"}
    })";

    std::vector<json::Json> decoders = {makeJsonPayload(kDecoderJsonInvalidName)};

    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);

    try
    {
        service->importNamespace(nsId, {}, decoders, {}, {}, makeJsonPayload(kPolicyJson), /*softValidation=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Invalid resource name"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("decoder/my decoder/0"));
    }
}

TEST_F(CrudServiceImportNsFromVectorTest, InvalidIntegrationNameThrowsBeforeCreate)
{
    static constexpr const char* kIntegrationJsonInvalidName = R"({
      "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
      "metadata": {"title": "bad/integration"},
      "enabled": true,
      "category": "security",
      "default_parent": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "decoders": [],
      "kvdbs": []
    })";

    std::vector<json::Json> integrations = {makeJsonPayload(kIntegrationJsonInvalidName)};

    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);

    try
    {
        service->importNamespace(nsId, {}, {}, {}, integrations, makeJsonPayload(kPolicyJson), /*softValidation=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Invalid resource name"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("bad/integration"));
    }
}

// Policy is upserted after all resources

TEST_F(CrudServiceImportNsFromVectorTest, PolicyUpsertedAfterResources)
{
    std::vector<json::Json> kvdbs = {makeJsonPayload(kKVDBJson)};
    std::vector<json::Json> decoders = {makeJsonPayload(kDecoderJson)};

    ::testing::InSequence seq;
    EXPECT_CALL(*nsPtr, createResource("windows_kerberos_status_code_to_code_name", ResourceType::KVDB, _)).Times(1);
    EXPECT_CALL(*nsPtr, createResource("decoder/syslog/0", ResourceType::DECODER, _)).Times(1);
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(
        service->importNamespace(nsId, kvdbs, decoders, {}, {}, makeJsonPayload(kPolicyJson), /*softValidation=*/true));
}

// softValidation=false → decoder is validated

TEST_F(CrudServiceImportNsFromVectorTest, SoftValidationFalse_ValidatesDecoder)
{
    std::vector<json::Json> decoders = {makeJsonPayload(kDecoderJson)};

    EXPECT_CALL(*validator, validateAsset(_, _)).Times(1).WillOnce(Return(base::noError()));
    EXPECT_CALL(*validator, softPolicyValidate(_, _)).Times(1).WillOnce(Return(base::noError()));
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(
        service->importNamespace(nsId, {}, decoders, {}, {}, makeJsonPayload(kPolicyJson), /*softValidation=*/false));
}

// softValidation=false → filter is validated

TEST_F(CrudServiceImportNsFromVectorTest, SoftValidationFalse_ValidatesFilter)
{
    std::vector<json::Json> filters = {makeJsonPayload(kFilterJson)};

    EXPECT_CALL(*validator, validateAsset(_, _)).Times(1).WillOnce(Return(base::noError()));
    EXPECT_CALL(*validator, softPolicyValidate(_, _)).Times(1).WillOnce(Return(base::noError()));
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(
        service->importNamespace(nsId, {}, {}, filters, {}, makeJsonPayload(kPolicyJson), /*softValidation=*/false));
}

// softValidation=false → integration is validated

TEST_F(CrudServiceImportNsFromVectorTest, SoftValidationFalse_ValidatesIntegration)
{
    std::vector<json::Json> integrations = {makeJsonPayload(kIntegrationJson)};

    EXPECT_CALL(*validator, softIntegrationValidate(_, _)).Times(1).WillOnce(Return(base::noError()));
    EXPECT_CALL(*validator, softPolicyValidate(_, _)).Times(1).WillOnce(Return(base::noError()));
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(service->importNamespace(
        nsId, {}, {}, {}, integrations, makeJsonPayload(kPolicyJson), /*softValidation=*/false));
}

// softValidation=false → policy is validated

TEST_F(CrudServiceImportNsFromVectorTest, SoftValidationFalse_ValidatesPolicy)
{
    EXPECT_CALL(*validator, softPolicyValidate(_, _)).Times(1).WillOnce(Return(base::noError()));
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(
        service->importNamespace(nsId, {}, {}, {}, {}, makeJsonPayload(kPolicyJson), /*softValidation=*/false));
}

// softValidation=true → no validator calls at all

TEST_F(CrudServiceImportNsFromVectorTest, SoftValidationTrue_SkipsAllValidation)
{
    std::vector<json::Json> decoders = {makeJsonPayload(kDecoderJson)};
    std::vector<json::Json> filters = {makeJsonPayload(kFilterJson)};
    std::vector<json::Json> integrations = {makeJsonPayload(kIntegrationJson)};

    EXPECT_CALL(*validator, validateAsset(_, _)).Times(0);
    EXPECT_CALL(*validator, softIntegrationValidate(_, _)).Times(0);
    EXPECT_CALL(*validator, softPolicyValidate(_, _)).Times(0);
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(service->importNamespace(
        nsId, {}, decoders, filters, integrations, makeJsonPayload(kPolicyJson), /*softValidation=*/true));
}

// Decoder name prefix mismatch → throws

TEST_F(CrudServiceImportNsFromVectorTest, DecoderNamePrefixMismatch_Throws)
{
    std::vector<json::Json> decoders = {makeJsonPayload(kDecoderJsonWrongPrefix)};

    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);

    try
    {
        service->importNamespace(nsId, {}, decoders, {}, {}, makeJsonPayload(kPolicyJson), /*softValidation=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("must start with prefix"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("decoder"));
    }
}

// Filter name prefix mismatch → throws

TEST_F(CrudServiceImportNsFromVectorTest, FilterNamePrefixMismatch_Throws)
{
    std::vector<json::Json> filters = {makeJsonPayload(kFilterJsonWrongPrefix)};

    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);

    try
    {
        service->importNamespace(nsId, {}, {}, filters, {}, makeJsonPayload(kPolicyJson), /*softValidation=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("must start with prefix"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("filter"));
    }
}

// =========================================================================
// importNamespace – JSON document overload
// =========================================================================

// JSON document constants

// Minimal valid import document: empty resources, minimal valid policy.
static constexpr const char* kMinimalImportDoc = R"({
  "policy": {
    "enabled": true,
    "root_decoder": "decoder/wazuh-core-message/0",
    "integrations": [],
    "filters": [],
    "enrichments": [],
    "index_unclassified_events": false,
    "index_discarded_events": false
  },
  "resources": {}
})";

// Import document containing a single KVDB resource.
static constexpr const char* kImportDocWithKVDB = R"({
  "policy": {
    "enabled": true,
    "root_decoder": "decoder/wazuh-core-message/0",
    "integrations": [],
    "filters": [],
    "enrichments": [],
    "index_unclassified_events": false,
    "index_discarded_events": false
  },
  "resources": {
    "kvdbs": [
      {
        "id": "82e215c4-988a-4f64-8d15-b98b2fc03a4f",
        "metadata": {"title": "test_kvdb"},
        "content": {"0x0": "KDC_ERR_NONE"},
        "enabled": true
      }
    ]
  }
})";

// Import document containing a single decoder resource.
static constexpr const char* kImportDocWithDecoder = R"({
  "policy": {
    "enabled": true,
    "root_decoder": "decoder/wazuh-core-message/0",
    "integrations": [],
    "filters": [],
    "enrichments": [],
    "index_unclassified_events": false,
    "index_discarded_events": false
  },
  "resources": {
    "decoders": [
      {
        "name": "decoder/syslog/0",
        "id": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
        "enabled": true,
        "metadata": {"module": "syslog", "title": "Syslog Decoder"}
      }
    ]
  }
})";

// Import document containing a single filter resource.
static constexpr const char* kImportDocWithFilter = R"({
  "policy": {
    "enabled": true,
    "root_decoder": "decoder/wazuh-core-message/0",
    "integrations": [],
    "filters": [],
    "enrichments": [],
    "index_unclassified_events": false,
    "index_discarded_events": false
  },
  "resources": {
    "filters": [
      {
        "name": "filter/pre-filter/0",
        "id": "f1111111-1111-4111-a111-111111111111",
        "enabled": true,
        "type": "pre-filter",
        "metadata": {"title": "Test Pre-Filter"}
      }
    ]
  }
})";

// Import document containing a single output resource.
static constexpr const char* kImportDocWithOutput = R"({
  "policy": {
    "enabled": true,
    "root_decoder": "decoder/wazuh-core-message/0",
    "integrations": [],
    "filters": [],
    "enrichments": [],
    "index_unclassified_events": false,
    "index_discarded_events": false
  },
  "resources": {
    "outputs": [
      {
        "name": "output/indexer/0",
        "id": "b1111111-1111-4111-a111-111111111111",
        "enabled": true,
        "metadata": {"title": "Indexer Output"}
      }
    ]
  }
})";

// Import document containing a single integration resource.
static constexpr const char* kImportDocWithIntegration = R"({
  "policy": {
    "enabled": true,
    "root_decoder": "decoder/wazuh-core-message/0",
    "integrations": [],
    "filters": [],
    "enrichments": [],
    "index_unclassified_events": false,
    "index_discarded_events": false
  },
  "resources": {
    "integrations": [
      {
        "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
        "metadata": {"title": "windows"},
        "enabled": true,
        "category": "security",
        "default_parent": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
        "decoders": [],
        "kvdbs": []
      }
    ]
  }
})";

// Fixture

class CrudServiceImportNsFromDocTest : public CrudServiceBase
{
protected:
    const NamespaceId nsId {"imported"};
    std::shared_ptr<NiceMock<MockICMstoreNS>> nsPtr;
    std::shared_ptr<cm::store::ICMStoreNSReader> nsReader;

    void SetUp() override
    {
        logging::testInit();
        CrudServiceBase::SetUp();

        nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();
        nsReader = std::static_pointer_cast<cm::store::ICMStoreNSReader>(nsPtr);

        ON_CALL(*store, existsNamespace(_)).WillByDefault(Return(false));
        ON_CALL(*store, createNamespace(_)).WillByDefault(Return(nsPtr));
        ON_CALL(*store, getNS(_)).WillByDefault(Return(nsPtr));
        ON_CALL(*store, getNSReader(_)).WillByDefault(Return(nsReader));
        ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(testing::ReturnRef(nsId));
        // getPolicy() is called once at the end of the JSON overload to build the return value.
        ON_CALL(*nsPtr, getPolicy()).WillByDefault(Return(makeReturnPolicy()));
    }

    static cm::store::dataType::Policy makeReturnPolicy()
    {
        return cm::store::dataType::Policy::fromJson(json::Json {kMinimalImportDoc}.getJson("/policy").value());
    }
};

// Happy path – empty resources

TEST_F(CrudServiceImportNsFromDocTest, Success_EmptyResources)
{
    ON_CALL(*nsPtr, getPolicy()).WillByDefault(Return(makeReturnPolicy()));

    EXPECT_CALL(*store, existsNamespace(_)).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*store, createNamespace(_)).Times(1).WillOnce(Return(nsPtr));
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);
    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);

    EXPECT_NO_THROW(service->importNamespace(nsId, kMinimalImportDoc, "", /*force=*/true));
}

// Destination namespace already exists → throws

TEST_F(CrudServiceImportNsFromDocTest, NamespaceAlreadyExists_Throws)
{
    EXPECT_CALL(*store, existsNamespace(_)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*store, createNamespace(_)).Times(0);

    try
    {
        service->importNamespace(nsId, kMinimalImportDoc, "", /*force=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("already exists"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("imported"));
    }
}

// Invalid JSON document → throws

TEST_F(CrudServiceImportNsFromDocTest, InvalidJson_Throws)
{
    EXPECT_CALL(*store, createNamespace(_)).Times(0);

    try
    {
        service->importNamespace(nsId, "{ this is not json }", "", /*force=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Invalid JSON"));
    }
}

// Missing /policy key → throws

TEST_F(CrudServiceImportNsFromDocTest, MissingPolicyKey_Throws)
{
    EXPECT_CALL(*store, createNamespace(_)).Times(0);

    constexpr const char* kDoc = R"({"resources": {}})";

    try
    {
        service->importNamespace(nsId, kDoc, "", /*force=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("policy"));
    }
}

// Missing /resources key → throws

TEST_F(CrudServiceImportNsFromDocTest, MissingResourcesKey_Throws)
{
    EXPECT_CALL(*store, createNamespace(_)).Times(0);

    constexpr const char* kDoc = R"({"policy": {"enabled": true}})";

    try
    {
        service->importNamespace(nsId, kDoc, "", /*force=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("resources"));
    }
}

// /policy is not an object → throws

TEST_F(CrudServiceImportNsFromDocTest, PolicyNotObject_Throws)
{
    EXPECT_CALL(*store, createNamespace(_)).Times(0);

    constexpr const char* kDoc = R"({"policy": "not-an-object", "resources": {}})";

    try
    {
        service->importNamespace(nsId, kDoc, "", /*force=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("policy"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("object"));
    }
}

// /resources is not an object → throws

TEST_F(CrudServiceImportNsFromDocTest, ResourcesNotObject_Throws)
{
    EXPECT_CALL(*store, createNamespace(_)).Times(0);

    constexpr const char* kDoc = R"({"policy": {"enabled": true}, "resources": [1,2,3]})";

    try
    {
        service->importNamespace(nsId, kDoc, "", /*force=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("resources"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("object"));
    }
}

// Root object has extra keys → throws

TEST_F(CrudServiceImportNsFromDocTest, ExtraRootKeys_Throws)
{
    EXPECT_CALL(*store, createNamespace(_)).Times(0);

    constexpr const char* kDoc = R"({"policy": {}, "resources": {}, "extra": "key"})";

    try
    {
        service->importNamespace(nsId, kDoc, "", /*force=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("2 keys"));
    }
}

// Namespace created before resources are imported

TEST_F(CrudServiceImportNsFromDocTest, CreatesNamespaceBeforeImport)
{
    ON_CALL(*nsPtr, getPolicy()).WillByDefault(Return(makeReturnPolicy()));

    {
        ::testing::InSequence seq;
        EXPECT_CALL(*store, existsNamespace(_)).WillOnce(Return(false));
        EXPECT_CALL(*store, createNamespace(_)).WillOnce(Return(nsPtr));
        EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

        EXPECT_NO_THROW(service->importNamespace(nsId, kMinimalImportDoc, "", /*force=*/true));
    }

    ::testing::Mock::VerifyAndClearExpectations(nsPtr.get());
}

// Import KVDB resource

TEST_F(CrudServiceImportNsFromDocTest, ImportsKVDB)
{
    ON_CALL(*nsPtr, getPolicy()).WillByDefault(Return(makeReturnPolicy()));

    EXPECT_CALL(*nsPtr, createResource("test_kvdb", ResourceType::KVDB, _)).Times(1);

    EXPECT_NO_THROW(service->importNamespace(nsId, kImportDocWithKVDB, "", /*force=*/true));
}

// Import decoder resource

TEST_F(CrudServiceImportNsFromDocTest, ImportsDecoder)
{
    ON_CALL(*nsPtr, getPolicy()).WillByDefault(Return(makeReturnPolicy()));

    EXPECT_CALL(*nsPtr, createResource("decoder/syslog/0", ResourceType::DECODER, _)).Times(1);

    EXPECT_NO_THROW(service->importNamespace(nsId, kImportDocWithDecoder, "", /*force=*/true));
}

// Import filter resource

TEST_F(CrudServiceImportNsFromDocTest, ImportsFilter)
{
    ON_CALL(*nsPtr, getPolicy()).WillByDefault(Return(makeReturnPolicy()));

    EXPECT_CALL(*nsPtr, createResource("filter/pre-filter/0", ResourceType::FILTER, _)).Times(1);

    EXPECT_NO_THROW(service->importNamespace(nsId, kImportDocWithFilter, "", /*force=*/true));
}

// Import output resource

TEST_F(CrudServiceImportNsFromDocTest, ImportsOutput)
{
    ON_CALL(*nsPtr, getPolicy()).WillByDefault(Return(makeReturnPolicy()));

    EXPECT_CALL(*nsPtr, createResource("output/indexer/0", ResourceType::OUTPUT, _)).Times(1);

    EXPECT_NO_THROW(service->importNamespace(nsId, kImportDocWithOutput, "", /*force=*/true));
}

// Import integration resource

TEST_F(CrudServiceImportNsFromDocTest, ImportsIntegration)
{
    ON_CALL(*nsPtr, getPolicy()).WillByDefault(Return(makeReturnPolicy()));

    EXPECT_CALL(*nsPtr, createResource("windows", ResourceType::INTEGRATION, _)).Times(1);

    EXPECT_NO_THROW(service->importNamespace(nsId, kImportDocWithIntegration, "", /*force=*/true));
}

TEST_F(CrudServiceImportNsFromDocTest, InvalidKVDBNameThrowsBeforeCreate)
{
    static constexpr const char* kImportDocWithInvalidKVDB = R"({
      "policy": {
        "enabled": true,
        "root_decoder": "decoder/wazuh-core-message/0",
        "integrations": [],
        "filters": [],
        "enrichments": [],
        "index_unclassified_events": false,
        "index_discarded_events": false
      },
      "resources": {
        "kvdbs": [
          {
            "id": "82e215c4-988a-4f64-8d15-b98b2fc03a4f",
            "metadata": {"title": "bad kvdb"},
            "content": {"0x0": "KDC_ERR_NONE"},
            "enabled": true
          }
        ]
      }
    })";

    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);

    try
    {
        service->importNamespace(nsId, kImportDocWithInvalidKVDB, "", /*force=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Failed to import namespace"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Invalid resource name"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("bad kvdb"));
    }
}

TEST_F(CrudServiceImportNsFromDocTest, InvalidDecoderNameThrowsBeforeCreate)
{
    static constexpr const char* kImportDocWithInvalidDecoder = R"({
      "policy": {
        "enabled": true,
        "root_decoder": "decoder/wazuh-core-message/0",
        "integrations": [],
        "filters": [],
        "enrichments": [],
        "index_unclassified_events": false,
        "index_discarded_events": false
      },
      "resources": {
        "decoders": [
          {
            "name": "decoder/my:decoder/0",
            "id": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
            "enabled": true,
            "metadata": {"module": "syslog", "title": "Syslog Decoder"}
          }
        ]
      }
    })";

    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);

    try
    {
        service->importNamespace(nsId, kImportDocWithInvalidDecoder, "", /*force=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Failed to import namespace"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Invalid resource name"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("decoder/my:decoder/0"));
    }
}

TEST_F(CrudServiceImportNsFromDocTest, InvalidIntegrationNameThrowsBeforeCreate)
{
    static constexpr const char* kImportDocWithInvalidIntegration = R"({
      "policy": {
        "enabled": true,
        "root_decoder": "decoder/wazuh-core-message/0",
        "integrations": [],
        "filters": [],
        "enrichments": [],
        "index_unclassified_events": false,
        "index_discarded_events": false
      },
      "resources": {
        "integrations": [
          {
            "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
            "metadata": {"title": "bad@integration"},
            "enabled": true,
            "category": "security",
            "default_parent": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
            "decoders": [],
            "kvdbs": []
          }
        ]
      }
    })";

    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);

    try
    {
        service->importNamespace(nsId, kImportDocWithInvalidIntegration, "", /*force=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Failed to import namespace"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Invalid resource name"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("bad@integration"));
    }
}

TEST_F(CrudServiceImportNsFromDocTest, InvalidOutputNameThrowsBeforeCreate)
{
    static constexpr const char* kImportDocWithInvalidOutput = R"({
      "policy": {
        "enabled": true,
        "root_decoder": "decoder/wazuh-core-message/0",
        "integrations": [],
        "filters": [],
        "enrichments": [],
        "index_unclassified_events": false,
        "index_discarded_events": false
      },
      "resources": {
        "outputs": [
          {
            "name": "output/bad output/0",
            "id": "b1111111-1111-4111-a111-111111111111",
            "enabled": true,
            "metadata": {"title": "Indexer Output"}
          }
        ]
      }
    })";

    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);

    try
    {
        service->importNamespace(nsId, kImportDocWithInvalidOutput, "", /*force=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Failed to import namespace"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Invalid resource name"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("output/bad output/0"));
    }
}

// Policy is upserted after resources

TEST_F(CrudServiceImportNsFromDocTest, PolicyImportedAfterResources)
{
    ON_CALL(*nsPtr, getPolicy()).WillByDefault(Return(makeReturnPolicy()));

    ::testing::InSequence seq;
    EXPECT_CALL(*nsPtr, createResource("test_kvdb", ResourceType::KVDB, _)).Times(1);
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1);

    EXPECT_NO_THROW(service->importNamespace(nsId, kImportDocWithKVDB, "", /*force=*/true));
}

// originSpace argument is applied to the policy

TEST_F(CrudServiceImportNsFromDocTest, SetsOriginSpace_WhenProvided)
{
    ON_CALL(*nsPtr, getPolicy()).WillByDefault(Return(makeReturnPolicy()));

    EXPECT_CALL(*nsPtr,
                upsertPolicy(Truly(
                    [](const cm::store::dataType::Policy& p)
                    {
                        std::string out;
                        return p.toJson().getString(out, "/origin_space") == json::RetGet::Success;
                    })))
        .Times(1);

    EXPECT_NO_THROW(service->importNamespace(nsId, kMinimalImportDoc, "my_space", /*force=*/true));
}

// Empty originSpace leaves policy origin untouched

TEST_F(CrudServiceImportNsFromDocTest, EmptyOriginSpace_DoesNotOverride)
{
    ON_CALL(*nsPtr, getPolicy()).WillByDefault(Return(makeReturnPolicy()));

    // Just verify it does not throw
    EXPECT_NO_THROW(service->importNamespace(nsId, kMinimalImportDoc, "", /*force=*/true));
}

// Absent resource arrays are silently skipped

TEST_F(CrudServiceImportNsFromDocTest, SkipsAbsentResourceArrays)
{
    ON_CALL(*nsPtr, getPolicy()).WillByDefault(Return(makeReturnPolicy()));

    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);

    EXPECT_NO_THROW(service->importNamespace(nsId, kMinimalImportDoc, "", /*force=*/true));
}

// force=true → validator is never called

TEST_F(CrudServiceImportNsFromDocTest, ForceTrue_SkipsValidation)
{
    ON_CALL(*nsPtr, getPolicy()).WillByDefault(Return(makeReturnPolicy()));

    EXPECT_CALL(*validator, validateAsset(_, _)).Times(0);
    EXPECT_CALL(*validator, softIntegrationValidate(_, _)).Times(0);
    EXPECT_CALL(*validator, softPolicyValidate(_, _)).Times(0);

    EXPECT_NO_THROW(service->importNamespace(nsId, kImportDocWithDecoder, "", /*force=*/true));
}

// force=false → asset validator is called for decoders

TEST_F(CrudServiceImportNsFromDocTest, ForceFalse_ValidatesDecoder)
{
    ON_CALL(*nsPtr, getPolicy()).WillByDefault(Return(makeReturnPolicy()));

    EXPECT_CALL(*validator, validateAsset(_, _)).Times(1).WillOnce(Return(base::noError()));
    EXPECT_CALL(*validator, softPolicyValidate(_, _)).Times(1).WillOnce(Return(base::noError()));

    EXPECT_NO_THROW(service->importNamespace(nsId, kImportDocWithDecoder, "", /*force=*/false));
}

// force=false → integration validator is called

TEST_F(CrudServiceImportNsFromDocTest, ForceFalse_ValidatesIntegration)
{
    ON_CALL(*nsPtr, getPolicy()).WillByDefault(Return(makeReturnPolicy()));

    EXPECT_CALL(*validator, softIntegrationValidate(_, _)).Times(1).WillOnce(Return(base::noError()));
    EXPECT_CALL(*validator, softPolicyValidate(_, _)).Times(1).WillOnce(Return(base::noError()));

    EXPECT_NO_THROW(service->importNamespace(nsId, kImportDocWithIntegration, "", /*force=*/false));
}

// force=false → policy validator is called

TEST_F(CrudServiceImportNsFromDocTest, ForceFalse_ValidatesPolicy)
{
    ON_CALL(*nsPtr, getPolicy()).WillByDefault(Return(makeReturnPolicy()));

    EXPECT_CALL(*validator, softPolicyValidate(_, _)).Times(1).WillOnce(Return(base::noError()));

    EXPECT_NO_THROW(service->importNamespace(nsId, kMinimalImportDoc, "", /*force=*/false));
}

// force=false + validation failure → throws, no createResource

TEST_F(CrudServiceImportNsFromDocTest, ForceFalse_ValidationFailure_Throws)
{
    EXPECT_CALL(*validator, validateAsset(_, _)).Times(1).WillOnce(Return(base::Error {"schema violation"}));

    EXPECT_CALL(*nsPtr, createResource(_, _, _)).Times(0);

    try
    {
        service->importNamespace(nsId, kImportDocWithDecoder, "", /*force=*/false);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Failed to import namespace"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("schema violation"));
    }
}

// Rollback: deleteNamespace called when import fails post-create

TEST_F(CrudServiceImportNsFromDocTest, RollbackOnFailureAfterNamespaceCreate)
{
    // Make upsertPolicy throw to trigger the rollback path.
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1).WillOnce(Throw(std::runtime_error {"policy store failure"}));

    EXPECT_CALL(*store, createNamespace(_)).Times(1).WillOnce(Return(nsPtr));

    EXPECT_CALL(*store, deleteNamespace(_)).Times(1);

    try
    {
        service->importNamespace(nsId, kMinimalImportDoc, "", /*force=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Failed to import namespace"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("policy store failure"));
    }
}

// Rollback delete also fails: original error is still surfaced

TEST_F(CrudServiceImportNsFromDocTest, RollbackDeleteFails_OriginalErrorSurfaced)
{
    EXPECT_CALL(*nsPtr, upsertPolicy(_)).Times(1).WillOnce(Throw(std::runtime_error {"original error"}));
    EXPECT_CALL(*store, createNamespace(_)).Times(1).WillOnce(Return(nsPtr));

    // Rollback delete also throws — the original error must still propagate.
    EXPECT_CALL(*store, deleteNamespace(_)).Times(1).WillOnce(Throw(std::runtime_error {"delete also failed"}));

    try
    {
        service->importNamespace(nsId, kMinimalImportDoc, "", /*force=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Failed to import namespace"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("original error"));
    }
}

// =========================================================================
//   Error wrapping for read / delete operations
// =========================================================================

class CrudServiceErrorWrappingTest : public CrudServiceBase
{
protected:
    const NamespaceId nsId {"dev"};
    std::shared_ptr<NiceMock<MockICMstoreNS>> nsPtr;
    std::shared_ptr<cm::store::ICMStoreNSReader> nsReader;

    void SetUp() override
    {
        CrudServiceBase::SetUp();
        nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();
        nsReader = std::static_pointer_cast<cm::store::ICMStoreNSReader>(nsPtr);
        ON_CALL(*store, getNS(_)).WillByDefault(Return(nsPtr));
        ON_CALL(*store, getNSReader(_)).WillByDefault(Return(nsReader));
        ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(testing::ReturnRef(nsId));
    }
};

// deletePolicy wraps store errors

TEST_F(CrudServiceErrorWrappingTest, DeletePolicy_StoreErrorIsWrapped)
{
    EXPECT_CALL(*nsPtr, deletePolicy()).WillOnce(Throw(std::runtime_error {"low-level error"}));

    try
    {
        service->deletePolicy(nsId);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Failed to delete policy"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("low-level error"));
    }
}

// getResourceByUUID wraps store errors

TEST_F(CrudServiceErrorWrappingTest, GetResourceByUUID_StoreErrorIsWrapped)
{
    const std::string uuid {"3f086ce2-32a4-42b0-be7e-40dcfb9c6160"};

    EXPECT_CALL(*nsPtr, resolveNameFromUUID(uuid)).WillOnce(Throw(std::runtime_error {"resolve failure"}));

    try
    {
        service->getResourceByUUID(nsId, uuid);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Failed to get resource with UUID"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("resolve failure"));
    }
}

// deleteResourceByUUID wraps store errors

TEST_F(CrudServiceErrorWrappingTest, DeleteResourceByUUID_StoreErrorIsWrapped)
{
    const std::string uuid {"some-uuid"};

    EXPECT_CALL(*nsPtr, deleteResourceByUUID(uuid)).WillOnce(Throw(std::runtime_error {"delete failure"}));

    try
    {
        service->deleteResourceByUUID(nsId, uuid);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Failed to delete resource with UUID"));
        EXPECT_THAT(std::string {e.what()}, HasSubstr("delete failure"));
    }
}

// getResourceByUUID rejects unsupported ResourceType from resolver

TEST_F(CrudServiceErrorWrappingTest, GetResourceByUUID_UnsupportedType_Throws)
{
    const std::string uuid {"3f086ce2-32a4-42b0-be7e-40dcfb9c6160"};

    EXPECT_CALL(*nsPtr, resolveNameFromUUID(uuid))
        .WillOnce(Return(std::make_tuple(std::string {"some/name/0"}, ResourceType::UNDEFINED)));

    try
    {
        service->getResourceByUUID(nsId, uuid);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("Unsupported resource type"));
    }
}

// getResourceByUUID returns Integration JSON

TEST_F(CrudServiceErrorWrappingTest, GetResourceByUUID_ReturnsIntegrationJson)
{
    const std::string uuid {"5c1df6b6-1458-4b2e-9001-96f67a8b12c8"};

    ON_CALL(*nsPtr, resolveNameFromUUID(uuid))
        .WillByDefault(Return(std::make_tuple(std::string {"windows"}, ResourceType::INTEGRATION)));

    json::Json integJson {kIntegrationJson};
    auto integ = cm::store::dataType::Integration::fromJson(integJson, true);
    EXPECT_CALL(*nsPtr, getIntegrationByUUID(uuid)).WillOnce(Return(integ));

    const auto result = service->getResourceByUUID(nsId, uuid);

    EXPECT_TRUE(result.isObject());
    EXPECT_EQ(getStringOrEmpty(result, "/id"), uuid);
}

// getResourceByUUID returns KVDB JSON

TEST_F(CrudServiceErrorWrappingTest, GetResourceByUUID_ReturnsKVDBJson)
{
    const std::string uuid {"82e215c4-988a-4f64-8d15-b98b2fc03a4f"};

    ON_CALL(*nsPtr, resolveNameFromUUID(uuid))
        .WillByDefault(Return(std::make_tuple(std::string {"test_kvdb"}, ResourceType::KVDB)));

    json::Json kvdbJson {kKVDBJson};
    auto kvdb = cm::store::dataType::KVDB::fromJson(kvdbJson, true);
    EXPECT_CALL(*nsPtr, getKVDBByUUID(uuid)).WillOnce(Return(kvdb));

    const auto result = service->getResourceByUUID(nsId, uuid);

    EXPECT_TRUE(result.isObject());
    EXPECT_EQ(getStringOrEmpty(result, "/id"), uuid);
}

// getResourceByUUID returns asset JSON (decoder / filter / output)

TEST_F(CrudServiceErrorWrappingTest, GetResourceByUUID_ReturnsAssetJson_Decoder)
{
    const std::string uuid {"3f086ce2-32a4-42b0-be7e-40dcfb9c6160"};

    ON_CALL(*nsPtr, resolveNameFromUUID(uuid))
        .WillByDefault(Return(std::make_tuple(std::string {"decoder/syslog/0"}, ResourceType::DECODER)));

    json::Json assetJson {kDecoderJson};
    EXPECT_CALL(*nsPtr, getAssetByUUID(uuid)).WillOnce(Return(assetJson));

    const auto result = service->getResourceByUUID(nsId, uuid);

    EXPECT_TRUE(result.isObject());
    EXPECT_EQ(getStringOrEmpty(result, "/name"), "decoder/syslog/0");
}

// =========================================================================
//   Small helper failure paths (surfaced through public API)
// =========================================================================

class CrudServiceHelperFailureTest : public CrudServiceBase
{
protected:
    const NamespaceId nsId {"dev"};
    std::shared_ptr<NiceMock<MockICMstoreNS>> nsPtr;

    void SetUp() override
    {
        CrudServiceBase::SetUp();
        nsPtr = std::make_shared<NiceMock<MockICMstoreNS>>();
        ON_CALL(*store, getNS(_)).WillByDefault(Return(nsPtr));
        ON_CALL(*nsPtr, getNamespaceId()).WillByDefault(testing::ReturnRef(nsId));
        ON_CALL(*validator, softIntegrationValidate(_, _)).WillByDefault(Return(base::noError()));
        ON_CALL(*validator, validateAsset(_, _)).WillByDefault(Return(base::noError()));
    }
};

//  upsertResource rejects an asset JSON without /name

TEST_F(CrudServiceHelperFailureTest, UpsertDecoder_MissingName_Throws)
{
    constexpr const char* kNoName = R"({
      "id": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "enabled": true,
      "metadata": {"module": "syslog"}
    })";

    try
    {
        service->upsertResource(nsId, ResourceType::DECODER, makeJsonPayload(kNoName));
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("name"));
    }
}

//  upsertResource rejects an asset JSON with an empty /name

TEST_F(CrudServiceHelperFailureTest, UpsertDecoder_EmptyName_Throws)
{
    constexpr const char* kEmptyName = R"({
      "name": "",
      "id": "3f086ce2-32a4-42b0-be7e-40dcfb9c6160",
      "enabled": true,
      "metadata": {"module": "syslog"}
    })";

    try
    {
        service->upsertResource(nsId, ResourceType::DECODER, makeJsonPayload(kEmptyName));
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("name"));
    }
}

//  importNamespace (vector) rejects a resource with no /id

TEST_F(CrudServiceHelperFailureTest, ImportVector_KVDB_MissingId_Throws)
{
    constexpr const char* kKVDBNoId = R"({
      "metadata": {"title": "test_kvdb"},
      "content": {"0x0": "value"},
      "enabled": true
    })";

    std::vector<json::Json> kvdbs = {makeJsonPayload(kKVDBNoId)};

    ON_CALL(*store, existsNamespace(_)).WillByDefault(Return(false));
    ON_CALL(*store, createNamespace(_)).WillByDefault(Return(nsPtr));

    try
    {
        service->importNamespace(nsId, kvdbs, {}, {}, {}, makeJsonPayload(kPolicyJson), /*softValidation=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("id"));
    }
}

//  importNamespace (vector) rejects a resource with an empty /id

TEST_F(CrudServiceHelperFailureTest, ImportVector_KVDB_EmptyId_Throws)
{
    constexpr const char* kKVDBEmptyId = R"({
      "id": "",
      "metadata": {"title": "test_kvdb"},
      "content": {"0x0": "value"},
      "enabled": true
    })";

    std::vector<json::Json> kvdbs = {makeJsonPayload(kKVDBEmptyId)};

    ON_CALL(*store, existsNamespace(_)).WillByDefault(Return(false));
    ON_CALL(*store, createNamespace(_)).WillByDefault(Return(nsPtr));

    try
    {
        service->importNamespace(nsId, kvdbs, {}, {}, {}, makeJsonPayload(kPolicyJson), /*softValidation=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("id"));
    }
}

//  importNamespace (vector) rejects a resource with an invalid UUID

TEST_F(CrudServiceHelperFailureTest, ImportVector_KVDB_InvalidUUID_Throws)
{
    constexpr const char* kKVDBBadUUID = R"({
      "id": "not-a-uuid",
      "metadata": {"title": "test_kvdb"},
      "content": {"0x0": "value"},
      "enabled": true
    })";

    std::vector<json::Json> kvdbs = {makeJsonPayload(kKVDBBadUUID)};

    ON_CALL(*store, existsNamespace(_)).WillByDefault(Return(false));
    ON_CALL(*store, createNamespace(_)).WillByDefault(Return(nsPtr));

    try
    {
        service->importNamespace(nsId, kvdbs, {}, {}, {}, makeJsonPayload(kPolicyJson), /*softValidation=*/true);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_THAT(std::string {e.what()}, HasSubstr("UUID"));
    }
}

} // namespace cm::crud::test
