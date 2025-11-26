#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <base/json.hpp>
#include <base/name.hpp>
#include <ctistore/icmreader.hpp>

// Include the mock
#include <ctistore/mockcm.hpp>

// Include the class under test
#include "storecti.hpp"

using namespace cm::store;
using namespace testing;

namespace
{

// Helper function to create a valid integration JSON document (CTI Store format)
json::Json createIntegrationJson(const std::string& uuid, const std::string& title,
                                 const std::string& category = "ossec",
                                 bool enable_decoders = true)
{
    json::Json doc;
    doc.setString(uuid, "/name");  // UUID is stored in /name field in CTI Store
    doc.setString("integration", "/type");

    json::Json payload;
    payload.setString("integration", "/type");

    json::Json document;
    document.setString(title, "/title");  // Only title in document section
    document.setArray("/decoders");
    document.setArray("/kvdbs");

    // Category and enable_decoders fields
    document.setString(category, "/category");
    document.setBool(enable_decoders, "/enable_decoders");

    payload.set("/document", document);
    doc.set("/payload", payload);

    return doc;
}

// Helper function to create a valid policy JSON document
json::Json createPolicyJson(const std::string& uuid, const std::string& title)
{
    json::Json doc;
    doc.setString(uuid, "/name");
    doc.setString("policy", "/type");

    json::Json payload;
    payload.setString("policy", "/type");
    payload.setString(title, "/title");

    json::Json document;
    document.setString(uuid, "/id");
    document.setString(title, "/title");
    document.setString("decoder/default/0", "/default_parent");
    document.setString("decoder/root/0", "/root_decoder");
    document.setArray("/integrations");
    // Add at least one integration (required by Policy validation)
    document.appendString("test-integration-uuid", "/integrations");

    payload.set("/document", document);
    doc.set("/payload", payload);

    return doc;
}

// Helper function to create a valid KVDB JSON document
json::Json createKVDBJson(const std::string& uuid, const std::string& title)
{
    json::Json doc;
    doc.setString(uuid, "/name");
    doc.setString("kvdb", "/type");

    json::Json content;
    content.setString("value1", "/key1");
    content.setString("value2", "/key2");

    doc.set("/content", content);

    return doc;
}

// Helper function to create a valid asset (decoder) JSON document
json::Json createAssetJson(const std::string& uuid, const std::string& name)
{
    json::Json doc;
    doc.setString(uuid, "/name");
    doc.setString("decoder", "/type");

    json::Json payload;
    payload.setString("decoder", "/type");

    json::Json document;
    document.setString(name, "/name");

    payload.set("/document", document);
    doc.set("/payload", payload);

    return doc;
}

} // anonymous namespace

/**
 * @brief Test fixture for CMStoreCTI unit tests
 */
class CMStoreCTITest : public ::testing::Test
{
protected:
    std::shared_ptr<cti::store::MockCMReader> mockReader;
    std::unique_ptr<CMStoreCTI> storeCTI;
    NamespaceId testNamespaceId{"test_namespace"};

    void SetUp() override
    {
        mockReader = std::make_shared<cti::store::MockCMReader>();
        storeCTI = std::make_unique<CMStoreCTI>(mockReader, testNamespaceId);
    }

    void TearDown() override
    {
        storeCTI.reset();
        mockReader.reset();
    }
};

/*****************************************************************************
 * Constructor and Basic Tests
 *****************************************************************************/

TEST_F(CMStoreCTITest, Constructor_ValidReader_Success)
{
    EXPECT_NO_THROW({
        CMStoreCTI store(mockReader, NamespaceId("valid_namespace"));
    });
}

TEST_F(CMStoreCTITest, Constructor_NullReader_Accepted)
{
    // Null reader is accepted at construction time (weak_ptr behavior)
    EXPECT_NO_THROW({
        CMStoreCTI store(nullptr, NamespaceId("null_namespace"));
    });
}

TEST_F(CMStoreCTITest, GetNamespaceId_ReturnsCorrectId)
{
    const NamespaceId& nsId = storeCTI->getNamespaceId();
    EXPECT_EQ(nsId.toStr(), "test_namespace");
}

/*****************************************************************************
 * Read-Only Exception Tests (Write Methods)
 *****************************************************************************/

TEST_F(CMStoreCTITest, CreateResource_ThrowsReadOnlyException)
{
    EXPECT_THROW(
        storeCTI->createResource("test", ResourceType::DECODER, "content"),
        std::runtime_error);

    try {
        storeCTI->createResource("test", ResourceType::DECODER, "content");
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        EXPECT_THAT(e.what(), HasSubstr("Read-Only"));
        EXPECT_THAT(e.what(), HasSubstr("creation"));
    }
}

TEST_F(CMStoreCTITest, UpdateResourceByName_ThrowsReadOnlyException)
{
    EXPECT_THROW(
        storeCTI->updateResourceByName("test", ResourceType::DECODER, "content"),
        std::runtime_error);

    try {
        storeCTI->updateResourceByName("test", ResourceType::DECODER, "content");
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        EXPECT_THAT(e.what(), HasSubstr("Read-Only"));
        EXPECT_THAT(e.what(), HasSubstr("update"));
    }
}

TEST_F(CMStoreCTITest, UpdateResourceByUUID_ThrowsReadOnlyException)
{
    EXPECT_THROW(
        storeCTI->updateResourceByUUID("uuid-123", "content"),
        std::runtime_error);

    try {
        storeCTI->updateResourceByUUID("uuid-123", "content");
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        EXPECT_THAT(e.what(), HasSubstr("Read-Only"));
        EXPECT_THAT(e.what(), HasSubstr("update"));
    }
}

TEST_F(CMStoreCTITest, DeleteResourceByName_ThrowsReadOnlyException)
{
    EXPECT_THROW(
        storeCTI->deleteResourceByName("test", ResourceType::DECODER),
        std::runtime_error);

    try {
        storeCTI->deleteResourceByName("test", ResourceType::DECODER);
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        EXPECT_THAT(e.what(), HasSubstr("Read-Only"));
        EXPECT_THAT(e.what(), HasSubstr("deletion"));
    }
}

TEST_F(CMStoreCTITest, DeleteResourceByUUID_ThrowsReadOnlyException)
{
    EXPECT_THROW(
        storeCTI->deleteResourceByUUID("uuid-123"),
        std::runtime_error);

    try {
        storeCTI->deleteResourceByUUID("uuid-123");
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        EXPECT_THAT(e.what(), HasSubstr("Read-Only"));
        EXPECT_THAT(e.what(), HasSubstr("deletion"));
    }
}

TEST_F(CMStoreCTITest, UpsertPolicy_ThrowsReadOnlyException)
{
    json::Json policyJson;
    policyJson.setObject();
    policyJson.setString("test-uuid", "/id");
    policyJson.setString("test-policy", "/name");
    policyJson.setArray("/integrations");
    policyJson.appendString("test-integration-uuid", "/integrations");

    dataType::Policy policy = dataType::Policy::fromJson(policyJson);
    EXPECT_THROW(
        storeCTI->upsertPolicy(policy),
        std::runtime_error);

    try {
        storeCTI->upsertPolicy(policy);
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        EXPECT_THAT(e.what(), HasSubstr("Read-Only"));
        EXPECT_THAT(e.what(), HasSubstr("upsert"));
    }
}

TEST_F(CMStoreCTITest, DeletePolicy_ThrowsReadOnlyException)
{
    EXPECT_THROW(
        storeCTI->deletePolicy(),
        std::runtime_error);

    try {
        storeCTI->deletePolicy();
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        EXPECT_THAT(e.what(), HasSubstr("Read-Only"));
        EXPECT_THAT(e.what(), HasSubstr("deletion"));
    }
}

/*****************************************************************************
 * Policy Read Tests
 *****************************************************************************/

TEST_F(CMStoreCTITest, GetPolicy_Success_ReturnsPolicy)
{
    std::vector<base::Name> policyList = {base::Name("policy1")};
    json::Json policyDoc = createPolicyJson("uuid-policy-1", "TestPolicy");

    EXPECT_CALL(*mockReader, getPolicyList())
        .WillOnce(Return(policyList));
    EXPECT_CALL(*mockReader, getPolicy(base::Name("policy1")))
        .WillOnce(Return(policyDoc));

    dataType::Policy policy = storeCTI->getPolicy();

    // Current stub returns empty policy
    EXPECT_FALSE(policy.getIntegrationsUUIDs().empty());
}

TEST_F(CMStoreCTITest, GetPolicy_EmptyPolicyList_ThrowsException)
{
    EXPECT_CALL(*mockReader, getPolicyList())
        .WillOnce(Return(std::vector<base::Name>{}));

    EXPECT_THROW(storeCTI->getPolicy(), std::runtime_error);
}

/*****************************************************************************
 * Integration Read Tests
 *****************************************************************************/

TEST_F(CMStoreCTITest, GetIntegrationByName_Success_ReturnsIntegration)
{
    json::Json integrationDoc = createIntegrationJson("uuid-int-1", "windows", "test-category", true);

    EXPECT_CALL(*mockReader, getAsset(base::Name("windows")))
        .WillOnce(Return(integrationDoc));

    dataType::Integration integration = storeCTI->getIntegrationByName("windows");

    EXPECT_EQ(integration.getUUID(), "uuid-int-1");
    EXPECT_EQ(integration.getName(), "windows");
    EXPECT_EQ(integration.getCategory(), "test-category");
    EXPECT_TRUE(integration.isEnabled());
}

TEST_F(CMStoreCTITest, GetIntegrationByName_NotFound_ThrowsException)
{
    EXPECT_CALL(*mockReader, getAsset(base::Name("nonexistent")))
        .WillOnce(Throw(std::runtime_error("Asset not found")));

    EXPECT_THROW(storeCTI->getIntegrationByName("nonexistent"), std::runtime_error);
}

TEST_F(CMStoreCTITest, GetIntegrationByUUID_Success_ReturnsIntegration)
{
    json::Json integrationDoc = createIntegrationJson("uuid-int-2", "linux", "linux-category", true);

    EXPECT_CALL(*mockReader, resolveNameFromUUID("uuid-int-2"))
        .WillOnce(Return("linux"));
    EXPECT_CALL(*mockReader, getAsset(base::Name("linux")))
        .WillOnce(Return(integrationDoc));

    dataType::Integration integration = storeCTI->getIntegrationByUUID("uuid-int-2");

    EXPECT_EQ(integration.getUUID(), "uuid-int-2");
    EXPECT_EQ(integration.getName(), "linux");
    EXPECT_EQ(integration.getCategory(), "linux-category");
    EXPECT_TRUE(integration.isEnabled());
}

TEST_F(CMStoreCTITest, GetIntegrationByUUID_NotFound_ThrowsException)
{
    EXPECT_CALL(*mockReader, resolveNameFromUUID("nonexistent-uuid"))
        .WillOnce(Throw(std::runtime_error("UUID not found")));

    EXPECT_THROW(storeCTI->getIntegrationByUUID("nonexistent-uuid"), std::runtime_error);
}

TEST_F(CMStoreCTITest, GetIntegrationByName_MissingUUID_ThrowsException)
{
    // Document without UUID in /name field
    json::Json malformedDoc;
    malformedDoc.setObject();
    malformedDoc.setObject("/payload");
    malformedDoc.setObject("/payload/document");
    malformedDoc.setString("windows", "/payload/document/title");

    EXPECT_CALL(*mockReader, getAsset(base::Name("windows")))
        .WillOnce(Return(malformedDoc));

    EXPECT_THROW(storeCTI->getIntegrationByName("windows"), std::runtime_error);
}

TEST_F(CMStoreCTITest, GetIntegrationByName_MissingDocument_ThrowsException)
{
    // Document without /payload/document section
    json::Json malformedDoc;
    malformedDoc.setObject();
    malformedDoc.setString("uuid-int-1", "/name");
    malformedDoc.setObject("/payload");

    EXPECT_CALL(*mockReader, getAsset(base::Name("windows")))
        .WillOnce(Return(malformedDoc));

    EXPECT_THROW(storeCTI->getIntegrationByName("windows"), std::runtime_error);
}

TEST_F(CMStoreCTITest, GetIntegrationByName_EnableDecodersFalse)
{
    // Create integration document with enable_decoders = false
    json::Json integrationDoc = createIntegrationJson("uuid-disabled", "disabled", "disabled-category", false);

    EXPECT_CALL(*mockReader, getAsset(base::Name("disabled")))
        .WillOnce(Return(integrationDoc));

    dataType::Integration integration = storeCTI->getIntegrationByName("disabled");

    EXPECT_EQ(integration.getCategory(), "disabled-category");
    EXPECT_FALSE(integration.isEnabled());
}

/*****************************************************************************
 * KVDB Read Tests
 *****************************************************************************/

TEST_F(CMStoreCTITest, GetKVDBByName_Success_ReturnsKVDB)
{
    json::Json kvdbContent;
    kvdbContent.setString("value1", "/key1");
    kvdbContent.setString("value2", "/key2");

    EXPECT_CALL(*mockReader, kvdbDump("test_kvdb"))
        .WillOnce(Return(kvdbContent));
    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("test_kvdb"), "kvdb"))
        .WillOnce(Return("uuid-kvdb-1"));

    dataType::KVDB kvdb = storeCTI->getKVDBByName("test_kvdb");

// KVDB content
    auto kvdbJson = kvdb.toJson();
    EXPECT_EQ(kvdbJson.getString("/title").value_or(""), "test_kvdb");
    EXPECT_EQ(kvdbJson.getString("/id").value_or(""), "uuid-kvdb-1");
    EXPECT_EQ(kvdbJson.getJson("/content").value_or(json::Json()).getString("/key1").value_or(""), "value1");
}

TEST_F(CMStoreCTITest, GetKVDBByName_NotFound_ThrowsException)
{
// KVDB not found
    EXPECT_CALL(*mockReader, kvdbDump("nonexistent"))
        .WillOnce(Throw(std::runtime_error("KVDB not found")));

    EXPECT_THROW(storeCTI->getKVDBByName("nonexistent"), std::runtime_error);
}

TEST_F(CMStoreCTITest, GetKVDBByUUID_Success_ReturnsKVDB)
{
    json::Json kvdbContent;
    kvdbContent.setString("value1", "/key1");
    kvdbContent.setString("value2", "/key2");

    EXPECT_CALL(*mockReader, resolveNameFromUUID("uuid-kvdb-2"))
        .WillOnce(Return("another_kvdb"));
    EXPECT_CALL(*mockReader, kvdbDump("another_kvdb"))
        .WillOnce(Return(kvdbContent));

    dataType::KVDB kvdb = storeCTI->getKVDBByUUID("uuid-kvdb-2");

    EXPECT_EQ(kvdb.getUUID(), "uuid-kvdb-2");
}

TEST_F(CMStoreCTITest, GetKVDBByName_EmptyContent_ReturnsValidKVDB)
{
    // KVDB with empty content (valid case)
    json::Json emptyContent;
    emptyContent.setObject();

    EXPECT_CALL(*mockReader, kvdbDump("empty_kvdb"))
        .WillOnce(Return(emptyContent));
    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("empty_kvdb"), "kvdb"))
        .WillOnce(Return("uuid-empty-kvdb"));

    dataType::KVDB kvdb = storeCTI->getKVDBByName("empty_kvdb");
    EXPECT_EQ(kvdb.getUUID(), "uuid-empty-kvdb");
}

TEST_F(CMStoreCTITest, GetKVDBByName_UUIDResolutionFails_ThrowsException)
{
    // kvdbDump succeeds but UUID resolution fails (orphaned KVDB)
    json::Json kvdbContent;
    kvdbContent.setString("value", "/key");

    EXPECT_CALL(*mockReader, kvdbDump("orphan_kvdb"))
        .WillOnce(Return(kvdbContent));
    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("orphan_kvdb"), "kvdb"))
        .WillOnce(Throw(std::runtime_error("UUID not found in index")));

    EXPECT_THROW(storeCTI->getKVDBByName("orphan_kvdb"), std::runtime_error);
}

/*****************************************************************************
 * Asset Read Tests
 *****************************************************************************/

TEST_F(CMStoreCTITest, GetAssetByName_Success_ReturnsAsset)
{
    json::Json assetDoc = createAssetJson("uuid-decoder-1", "decoder/test/0");

    EXPECT_CALL(*mockReader, getAsset(base::Name("decoder/test/0")))
        .WillOnce(Return(assetDoc));

    json::Json asset = storeCTI->getAssetByName(base::Name("decoder/test/0"));

    EXPECT_FALSE(asset.str().empty());
}

TEST_F(CMStoreCTITest, GetAssetByName_NotFound_ThrowsException)
{
// asset not found
    EXPECT_CALL(*mockReader, getAsset(base::Name("nonexistent")))
        .WillOnce(Throw(std::runtime_error("Asset not found")));

    EXPECT_THROW(storeCTI->getAssetByName(base::Name("nonexistent")), std::runtime_error);
}

TEST_F(CMStoreCTITest, GetAssetByUUID_Success_ReturnsAsset)
{
    json::Json assetDoc = createAssetJson("uuid-decoder-2", "decoder/windows/0");

    EXPECT_CALL(*mockReader, resolveNameFromUUID("uuid-decoder-2"))
        .WillOnce(Return("decoder/windows/0"));
    EXPECT_CALL(*mockReader, getAsset(base::Name("decoder/windows/0")))
        .WillOnce(Return(assetDoc));

    json::Json asset = storeCTI->getAssetByUUID("uuid-decoder-2");
}

/*****************************************************************************
 * Asset Existence Tests
 *****************************************************************************/

TEST_F(CMStoreCTITest, AssetExistsByName_Exists_ReturnsTrue)
{
    EXPECT_CALL(*mockReader, assetExists(base::Name("decoder/test/0")))
        .WillOnce(Return(true));

    bool exists = storeCTI->assetExistsByName(base::Name("decoder/test/0"));

    EXPECT_TRUE(exists);
}

TEST_F(CMStoreCTITest, AssetExistsByName_NotExists_ReturnsFalse)
{
    EXPECT_CALL(*mockReader, assetExists(base::Name("nonexistent")))
        .WillOnce(Return(false));

    bool exists = storeCTI->assetExistsByName(base::Name("nonexistent"));

    EXPECT_FALSE(exists);
}

TEST_F(CMStoreCTITest, AssetExistsByUUID_Exists_ReturnsTrue)
{
    EXPECT_CALL(*mockReader, resolveNameFromUUID("uuid-123"))
        .WillOnce(Return("decoder/test/0"));

    bool exists = storeCTI->assetExistsByUUID("uuid-123");

    EXPECT_TRUE(exists);
}

TEST_F(CMStoreCTITest, AssetExistsByUUID_NotExists_ReturnsFalse)
{
// UUID not found
    EXPECT_CALL(*mockReader, resolveNameFromUUID("nonexistent-uuid"))
        .WillOnce(Throw(std::runtime_error("UUID not found")));

    bool exists = storeCTI->assetExistsByUUID("nonexistent-uuid");

    EXPECT_FALSE(exists);
}

/*****************************************************************************
 * Collection Tests
 *****************************************************************************/

TEST_F(CMStoreCTITest, GetCollection_Decoders_ReturnsUUIDNameTuples)
{
    std::vector<base::Name> assetList = {
        base::Name("decoder/test/0"),
        base::Name("decoder/windows/0")
    };

    EXPECT_CALL(*mockReader, getAssetList(cti::store::AssetType::DECODER))
        .WillOnce(Return(assetList));
    EXPECT_CALL(*mockReader, resolveUUIDFromName(testing::_, "decoder"))
        .WillRepeatedly(testing::Return("uuid-test"));

    auto collection = storeCTI->getCollection(ResourceType::DECODER);

    EXPECT_EQ(collection.size(), 2);
    for (const auto& [uuid, name] : collection) {
        EXPECT_FALSE(uuid.empty());
        EXPECT_FALSE(name.empty());
    }
}

TEST_F(CMStoreCTITest, GetCollection_EmptyResult_ReturnsEmptyVector)
{
    EXPECT_CALL(*mockReader, getAssetList(cti::store::AssetType::DECODER))
        .WillOnce(Return(std::vector<base::Name>{}));

    auto collection = storeCTI->getCollection(ResourceType::DECODER);

    EXPECT_TRUE(collection.empty());
}

TEST_F(CMStoreCTITest, GetCollection_Integrations_ReturnsUUIDNameTuples)
{
    std::vector<base::Name> integrationList = {
        base::Name("windows"),
        base::Name("linux"),
        base::Name("apache")
    };

    EXPECT_CALL(*mockReader, getAssetList(cti::store::AssetType::INTEGRATION))
        .WillOnce(Return(integrationList));
    EXPECT_CALL(*mockReader, resolveUUIDFromName(testing::_, "integration"))
        .WillRepeatedly(testing::Return("uuid-test"));

    auto collection = storeCTI->getCollection(ResourceType::INTEGRATION);

    EXPECT_EQ(collection.size(), 3);
    for (const auto& [uuid, name] : collection) {
        EXPECT_FALSE(uuid.empty());
        EXPECT_FALSE(name.empty());
    }
}

TEST_F(CMStoreCTITest, GetCollection_KVDB_ReturnsUUIDNameTuples)
{
    std::vector<std::string> kvdbList = {
        "geo_locations",
        "error_codes",
        "status_mappings"
    };

    EXPECT_CALL(*mockReader, listKVDB())
        .WillOnce(Return(kvdbList));
    EXPECT_CALL(*mockReader, resolveUUIDFromName(testing::_, "kvdb"))
        .WillRepeatedly(testing::Return("uuid-test"));

    auto collection = storeCTI->getCollection(ResourceType::KVDB);

    EXPECT_EQ(collection.size(), 3);
    for (const auto& [uuid, name] : collection) {
        EXPECT_FALSE(uuid.empty());
        EXPECT_FALSE(name.empty());
    }
}

TEST_F(CMStoreCTITest, GetCollection_PartialFailure_SkipsFailedEntries)
{
    std::vector<base::Name> decoderList = {
        base::Name("decoder/valid/0"),
        base::Name("decoder/invalid/0"),
        base::Name("decoder/another_valid/0")
    };

    EXPECT_CALL(*mockReader, getAssetList(cti::store::AssetType::DECODER))
        .WillOnce(Return(decoderList));
    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("decoder/valid/0"), "decoder"))
        .WillOnce(Return("uuid-valid"));
    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("decoder/invalid/0"), "decoder"))
        .WillOnce(Throw(std::runtime_error("UUID not found")));
    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("decoder/another_valid/0"), "decoder"))
        .WillOnce(Return("uuid-another-valid"));

    auto collection = storeCTI->getCollection(ResourceType::DECODER);

    EXPECT_EQ(collection.size(), 2);
}

/*****************************************************************************
 * UUID/Name Resolution Tests
 *****************************************************************************/

TEST_F(CMStoreCTITest, ResolveNameFromUUID_Success_ReturnsNameAndType)
{
    EXPECT_CALL(*mockReader, resolveNameAndTypeFromUUID("uuid-123"))
        .WillOnce(Return(std::make_pair("windows", cti::store::AssetType::INTEGRATION)));

    auto [name, type] = storeCTI->resolveNameFromUUID("uuid-123");

    EXPECT_EQ(name, "windows");
    EXPECT_EQ(type, ResourceType::INTEGRATION);
}

TEST_F(CMStoreCTITest, ResolveNameFromUUID_NotFound_ThrowsException)
{
// UUID not found
    EXPECT_CALL(*mockReader, resolveNameAndTypeFromUUID("nonexistent"))
        .WillOnce(Throw(std::runtime_error("UUID not found")));

    EXPECT_THROW(storeCTI->resolveNameFromUUID("nonexistent"), std::runtime_error);
}

TEST_F(CMStoreCTITest, ResolveUUIDFromName_Success_ReturnsUUID)
{
    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("decoder/test/0"), "decoder"))
        .WillOnce(Return("uuid-456"));

    std::string uuid = storeCTI->resolveUUIDFromName("decoder/test/0", ResourceType::DECODER);

    EXPECT_EQ(uuid, "uuid-456");
}

TEST_F(CMStoreCTITest, ResolveUUIDFromName_NotFound_ThrowsException)
{
// asset not found
    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("nonexistent"), "decoder"))
        .WillOnce(Throw(std::runtime_error("Asset not found")));

    EXPECT_THROW(storeCTI->resolveUUIDFromName("nonexistent", ResourceType::DECODER), std::runtime_error);
}

/*****************************************************************************
 * Edge Case Tests
 *****************************************************************************/

TEST_F(CMStoreCTITest, ExpiredWeakPtr_GetPolicy_ThrowsException)
{
    // Create store with a reader that will be destroyed
    auto tempReader = std::make_shared<cti::store::MockCMReader>();
    CMStoreCTI storeWithExpiredReader(tempReader, NamespaceId("temp"));

    // Destroy the reader
    tempReader.reset();

    EXPECT_THROW(storeWithExpiredReader.getPolicy(), std::runtime_error);
}

TEST_F(CMStoreCTITest, ExpiredWeakPtr_GetIntegrationByName_ThrowsException)
{
    // Create store with a reader that will be destroyed
    auto tempReader = std::make_shared<cti::store::MockCMReader>();
    CMStoreCTI storeWithExpiredReader(tempReader, NamespaceId("temp"));

    // Destroy the reader
    tempReader.reset();

    EXPECT_THROW(storeWithExpiredReader.getIntegrationByName("test"), std::runtime_error);
}

TEST_F(CMStoreCTITest, ExpiredWeakPtr_AssetExistsByName_ReturnsFalse)
{
    // Create store with a reader that will be destroyed
    auto tempReader = std::make_shared<cti::store::MockCMReader>();
    CMStoreCTI storeWithExpiredReader(tempReader, NamespaceId("temp"));

    // Destroy the reader
    tempReader.reset();

    // Existence checks should return false (not throw) when reader is expired
    bool exists = storeWithExpiredReader.assetExistsByName(base::Name("test"));
    EXPECT_FALSE(exists);
}

TEST_F(CMStoreCTITest, MalformedDocument_MissingPayload_ThrowsException)
{
// document without /payload
    json::Json malformedDoc;
    malformedDoc.setString("uuid-123", "/name");
    malformedDoc.setString("integration", "/type");
    // Missing /payload section

    EXPECT_CALL(*mockReader, getAsset(base::Name("malformed")))
        .WillOnce(Return(malformedDoc));

    EXPECT_THROW(storeCTI->getIntegrationByName("malformed"), std::runtime_error);
}

TEST_F(CMStoreCTITest, MalformedDocument_MissingUUID_HandledGracefully)
{
// document without /name (UUID) field
    json::Json docWithoutUUID;
    docWithoutUUID.setString("integration", "/type");

    json::Json payload;
    json::Json document;
    document.setString("test", "/title");
    payload.set("/document", document);
    docWithoutUUID.set("/payload", payload);
    // Missing /name field (UUID)

    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("no-uuid"), "integration"))
        .WillOnce(Throw(std::runtime_error("UUID not found")));

    EXPECT_THROW(storeCTI->resolveUUIDFromName("no-uuid", ResourceType::INTEGRATION), std::runtime_error);
}

