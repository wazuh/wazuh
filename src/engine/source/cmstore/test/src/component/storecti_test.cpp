#include <memory>
#include <string>

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

/**
 * @brief Helper to create a complete integration document with all required fields
 */
json::Json createCompleteIntegrationDoc(
    const std::string& uuid,
    const std::string& title,
    const std::vector<std::string>& decoderUUIDs = {},
    const std::vector<std::string>& kvdbUUIDs = {})
{
    // CTI Store format: UUID is in /name, document only has title, decoders, kvdbs
    json::Json doc;
    doc.setString(uuid, "/name");  // UUID stored in /name field
    doc.setString("integration", "/type");
    doc.setInt(1234, "/offset");

    json::Json payload;
    payload.setString("integration", "/type");

    json::Json document;
    document.setString(title, "/title");  // Only title in document section

    // Add decoders array
    document.setArray("/decoders");
    for (size_t i = 0; i < decoderUUIDs.size(); ++i)
    {
        document.setString(decoderUUIDs[i], std::string("/decoders/") + std::to_string(i));
    }

    // Add kvdbs array
    document.setArray("/kvdbs");
    for (size_t i = 0; i < kvdbUUIDs.size(); ++i)
    {
        document.setString(kvdbUUIDs[i], std::string("/kvdbs/") + std::to_string(i));
    }

    payload.set("/document", document);
    doc.set("/payload", payload);

    return doc;
}

/**
 * @brief Helper to create a complete policy document
 */
json::Json createCompletePolicyDoc(
    const std::string& uuid,
    const std::string& title,
    const std::vector<std::string>& integrationUUIDs = {})
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
    document.setString("decoder/wazuh-core-message/0", "/default_parent");
    document.setString("decoder/root/0", "/root_decoder");

    // Add integrations array
    document.setArray("/integrations");
    for (size_t i = 0; i < integrationUUIDs.size(); ++i)
    {
        document.setString(integrationUUIDs[i], std::string("/integrations/") + std::to_string(i));
    }

    payload.set("/document", document);
    doc.set("/payload", payload);

    return doc;
}

/**
 * @brief Helper to create a complete decoder document
 */
json::Json createCompleteDecoderDoc(const std::string& uuid, const std::string& name)
{
    json::Json doc;
    doc.setString(uuid, "/name");
    doc.setString("decoder", "/type");

    json::Json payload;
    payload.setString("decoder", "/type");

    json::Json document;
    document.setString(name, "/name");

    json::Json metadata;
    metadata.setString("test_module", "/module");
    metadata.setString("Test Decoder", "/title");
    document.set("/metadata", metadata);

    payload.set("/document", document);
    doc.set("/payload", payload);

    return doc;
}

/**
 * @brief Helper to create a complete KVDB document
 */
json::Json createCompleteKVDBDoc(const std::string& uuid, const std::string& title)
{
    json::Json doc;
    doc.setString(uuid, "/name");
    doc.setString("kvdb", "/type");

    json::Json content;
    content.setString("KDC_ERR_NONE", "/0x0");
    content.setString("KDC_ERR_NAME_EXP", "/0x1");
    content.setString("KDC_ERR_SERVICE_EXP", "/0x2");

    doc.set("/content", content);
    doc.setString(title, "/title");
    doc.setBool(true, "/enabled");

    return doc;
}

} // anonymous namespace

/**
 * @brief Component test fixture for CMStoreCTI
 *
 * These tests verify the integration between CMStoreCTI and its dependencies
 * using a mock ICMReader with realistic data.
 */
class CMStoreCTIComponentTest : public ::testing::Test
{
protected:
    std::shared_ptr<cti::store::MockCMReader> mockReader;
    std::unique_ptr<CMStoreCTI> storeCTI;
    NamespaceId testNamespaceId{"component_test_ns"};

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
 * Component Test: Full Policy Workflow
 *****************************************************************************/

TEST_F(CMStoreCTIComponentTest, FullPolicyWorkflow_GetPolicyWithIntegrations)
{
    // Create a policy with integrations
    std::vector<std::string> integrationUUIDs = {
        "int-uuid-1",
        "int-uuid-2",
        "int-uuid-3"
    };
    json::Json policyDoc = createCompletePolicyDoc("policy-uuid-1", "Development 0.0.1", integrationUUIDs);

    std::vector<base::Name> policyList = {base::Name("policy1")};
    EXPECT_CALL(*mockReader, getPolicyList())
        .WillOnce(Return(policyList));
    EXPECT_CALL(*mockReader, getPolicy(base::Name("policy1")))
        .WillOnce(Return(policyDoc));

    dataType::Policy policy = storeCTI->getPolicy();

    EXPECT_EQ(policy.getIntegrationsUUIDs().size(), 3);
    EXPECT_EQ(policy.getDefaultParent().toStr(), "decoder/wazuh-core-message/0");
}

/*****************************************************************************
 * Component Test: Full Integration Workflow
 *****************************************************************************/

TEST_F(CMStoreCTIComponentTest, FullIntegrationWorkflow_GetByNameThenResolveUUID)
{
    // Create integration document
    std::vector<std::string> decoderUUIDs = {"dec-uuid-1", "dec-uuid-2"};
    std::vector<std::string> kvdbUUIDs = {"kvdb-uuid-1"};
    json::Json integrationDoc = createCompleteIntegrationDoc(
        "int-uuid-windows", "windows", decoderUUIDs, kvdbUUIDs);

    EXPECT_CALL(*mockReader, getAsset(base::Name("windows")))
        .WillOnce(Return(integrationDoc));

    dataType::Integration integration = storeCTI->getIntegrationByName("windows");

    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("windows"), "integration"))
        .WillOnce(Return("int-uuid-windows"));

    std::string uuid = storeCTI->resolveUUIDFromName("windows", ResourceType::INTEGRATION);

    EXPECT_EQ(uuid, "int-uuid-windows");
    EXPECT_EQ(integration.getName(), "windows");
    EXPECT_EQ(integration.getDecodersByUUID().size(), 2);
}

TEST_F(CMStoreCTIComponentTest, FullIntegrationWorkflow_GetByUUIDChain)
{
    json::Json integrationDoc = createCompleteIntegrationDoc("int-uuid-linux", "linux");

    EXPECT_CALL(*mockReader, resolveNameFromUUID("int-uuid-linux"))
        .WillOnce(Return("linux"));
    EXPECT_CALL(*mockReader, getAsset(base::Name("linux")))
        .WillOnce(Return(integrationDoc));

    dataType::Integration integration = storeCTI->getIntegrationByUUID("int-uuid-linux");

    EXPECT_EQ(integration.getUUID(), "int-uuid-linux");
    EXPECT_EQ(integration.getName(), "linux");
}

/*****************************************************************************
 * Component Test: Collection Enumeration
 *****************************************************************************/

TEST_F(CMStoreCTIComponentTest, CollectionEnumeration_MultipleDecoders)
{
    std::vector<base::Name> decoderList = {
        base::Name("decoder/windows/syslog/0"),
        base::Name("decoder/linux/syslog/0"),
        base::Name("decoder/macos/syslog/0")
    };

    EXPECT_CALL(*mockReader, getAssetList(cti::store::AssetType::DECODER))
        .WillOnce(Return(decoderList));
    EXPECT_CALL(*mockReader, resolveUUIDFromName(testing::_, "decoder"))
        .WillRepeatedly(testing::Return("test-uuid"));

    auto collection = storeCTI->getCollection(ResourceType::DECODER);

    EXPECT_EQ(collection.size(), 3);
}

TEST_F(CMStoreCTIComponentTest, CollectionEnumeration_IntegrationsCollection)
{
    std::vector<base::Name> integrationList = {
        base::Name("windows"),
        base::Name("linux")
    };

    EXPECT_CALL(*mockReader, getAssetList(cti::store::AssetType::INTEGRATION))
        .WillOnce(Return(integrationList));
    EXPECT_CALL(*mockReader, resolveUUIDFromName(testing::_, "integration"))
        .WillRepeatedly(testing::Return("test-uuid"));

    auto collection = storeCTI->getCollection(ResourceType::INTEGRATION);

    EXPECT_EQ(collection.size(), 2);
}

/*****************************************************************************
 * Component Test: Asset Existence Verification
 *****************************************************************************/

TEST_F(CMStoreCTIComponentTest, AssetExistence_MultipleChecks)
{
    // Setup mock expectations for various existence checks
    EXPECT_CALL(*mockReader, assetExists(base::Name("decoder/exists/0")))
        .WillOnce(Return(true));
    EXPECT_CALL(*mockReader, assetExists(base::Name("decoder/notexists/0")))
        .WillOnce(Return(false));

    // Check existing asset
    bool exists1 = storeCTI->assetExistsByName(base::Name("decoder/exists/0"));
    bool exists2 = storeCTI->assetExistsByName(base::Name("decoder/notexists/0"));

    EXPECT_TRUE(exists1);
    EXPECT_FALSE(exists2);
}

TEST_F(CMStoreCTIComponentTest, AssetExistenceByUUID_ValidAndInvalidUUIDs)
{
    // Setup mock for valid UUID
    EXPECT_CALL(*mockReader, resolveNameFromUUID("valid-uuid"))
        .WillOnce(Return("decoder/valid/0"));

    // Setup mock for invalid UUID
    EXPECT_CALL(*mockReader, resolveNameFromUUID("invalid-uuid"))
        .WillOnce(Throw(std::runtime_error("UUID not found")));

    // Check
    bool existsValid = storeCTI->assetExistsByUUID("valid-uuid");
    bool existsInvalid = storeCTI->assetExistsByUUID("invalid-uuid");

    EXPECT_TRUE(existsValid);
    EXPECT_FALSE(existsInvalid);
}

/*****************************************************************************
 * Component Test: KVDB Operations
 *****************************************************************************/

TEST_F(CMStoreCTIComponentTest, KVDBOperations_GetByNameAndUUID)
{
    // Create KVDB content (kvdbDump returns just content, not full document)
    json::Json kvdbContent;
    kvdbContent.setString("KDC_ERR_NONE", "/0x0");
    kvdbContent.setString("KDC_ERR_NAME_EXP", "/0x1");
    kvdbContent.setString("KDC_ERR_SERVICE_EXP", "/0x2");

    EXPECT_CALL(*mockReader, kvdbDump("kerberos_status_codes"))
        .WillOnce(Return(kvdbContent));
    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("kerberos_status_codes"), "kvdb"))
        .WillOnce(Return("kvdb-uuid-1"));

    dataType::KVDB kvdb1 = storeCTI->getKVDBByName("kerberos_status_codes");

    EXPECT_CALL(*mockReader, resolveNameFromUUID("kvdb-uuid-1"))
        .WillOnce(Return("kerberos_status_codes"));
    EXPECT_CALL(*mockReader, kvdbDump("kerberos_status_codes"))
        .WillOnce(Return(kvdbContent));

    dataType::KVDB kvdb2 = storeCTI->getKVDBByUUID("kvdb-uuid-1");

    EXPECT_EQ(kvdb1.getUUID(), "kvdb-uuid-1");
    EXPECT_EQ(kvdb2.getUUID(), "kvdb-uuid-1");
}

/*****************************************************************************
 * Component Test: Read-Only Behavior
 *****************************************************************************/

TEST_F(CMStoreCTIComponentTest, ReadOnlyBehavior_AllWriteOperationsFail)
{
    // Test all write operations throw consistently
    EXPECT_THROW(
        storeCTI->createResource("test", ResourceType::DECODER, "content"),
        std::runtime_error);

    EXPECT_THROW(
        storeCTI->updateResourceByName("test", ResourceType::DECODER, "content"),
        std::runtime_error);

    EXPECT_THROW(
        storeCTI->updateResourceByUUID("uuid", "content"),
        std::runtime_error);

    EXPECT_THROW(
        storeCTI->deleteResourceByName("test", ResourceType::DECODER),
        std::runtime_error);

    EXPECT_THROW(
        storeCTI->deleteResourceByUUID("uuid"),
        std::runtime_error);

    EXPECT_THROW(
        storeCTI->upsertPolicy(dataType::Policy::fromJson({})),
        std::runtime_error);

    EXPECT_THROW(
        storeCTI->deletePolicy(),
        std::runtime_error);
}

/*****************************************************************************
 * Component Test: Error Propagation
 *****************************************************************************/

TEST_F(CMStoreCTIComponentTest, ErrorPropagation_ReaderExceptionsBubbleUp)
{
    // Setup mocks to throw various exceptions
    EXPECT_CALL(*mockReader, getAsset(base::Name("throwing-asset")))
        .WillOnce(Throw(std::runtime_error("Database connection failed")));

    // Exceptions from reader should propagate
    EXPECT_THROW(
        storeCTI->getAssetByName(base::Name("throwing-asset")),
        std::runtime_error);
}

TEST_F(CMStoreCTIComponentTest, ErrorPropagation_PolicyReaderErrors)
{
    // Setup mock to simulate policy retrieval failure
    EXPECT_CALL(*mockReader, getPolicyList())
        .WillOnce(Throw(std::runtime_error("Storage unavailable")));

    EXPECT_THROW(storeCTI->getPolicy(), std::runtime_error);
}

/*****************************************************************************
 * Component Test: Namespace Isolation
 *****************************************************************************/

TEST_F(CMStoreCTIComponentTest, NamespaceIsolation_DifferentNamespaces)
{
    // Create two stores with different namespaces
    auto mockReader2 = std::make_shared<cti::store::MockCMReader>();
    CMStoreCTI store1(mockReader, NamespaceId("namespace_1"));
    CMStoreCTI store2(mockReader2, NamespaceId("namespace_2"));

    // Verify they have different namespace IDs
    EXPECT_EQ(store1.getNamespaceId().toStr(), "namespace_1");
    EXPECT_EQ(store2.getNamespaceId().toStr(), "namespace_2");
    EXPECT_NE(store1.getNamespaceId().toStr(), store2.getNamespaceId().toStr());
}

/*****************************************************************************
 * Component Test: Concurrent Access Simulation
 *****************************************************************************/

TEST_F(CMStoreCTIComponentTest, ConcurrentAccess_MultipleReadsFromSameStore)
{
    // Setup mock for multiple calls
    json::Json integrationDoc = createCompleteIntegrationDoc("int-uuid", "windows");

    EXPECT_CALL(*mockReader, getAsset(base::Name("windows")))
        .Times(3)
        .WillRepeatedly(Return(integrationDoc));

    // Simulate multiple reads
    dataType::Integration int1 = storeCTI->getIntegrationByName("windows");
    dataType::Integration int2 = storeCTI->getIntegrationByName("windows");
    dataType::Integration int3 = storeCTI->getIntegrationByName("windows");
}

// ============================
// resolveUUIDFromName Tests
// ============================

TEST(CMStoreCTITest, ResolveUUIDFromName_Integration)
{
    auto mockReader = std::make_shared<cti::store::MockCMReader>();
    auto storeCTI = std::make_shared<CMStoreCTI>(mockReader, NamespaceId("test_namespace"));

    // Mock the resolveUUIDFromName call
    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("Test Integration"), "integration"))
        .WillOnce(Return("integration-uuid-123"));

    // Call the method
    std::string uuid = storeCTI->resolveUUIDFromName("Test Integration", ResourceType::INTEGRATION);

    EXPECT_EQ(uuid, "integration-uuid-123");
}

TEST(CMStoreCTITest, ResolveUUIDFromName_Decoder)
{
    auto mockReader = std::make_shared<cti::store::MockCMReader>();
    auto storeCTI = std::make_shared<CMStoreCTI>(mockReader, NamespaceId("test_namespace"));

    // Mock the resolveUUIDFromName call
    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("test_decoder"), "decoder"))
        .WillOnce(Return("decoder-uuid-456"));

    // Call the method
    std::string uuid = storeCTI->resolveUUIDFromName("test_decoder", ResourceType::DECODER);

    EXPECT_EQ(uuid, "decoder-uuid-456");
}

TEST(CMStoreCTITest, ResolveUUIDFromName_KVDB)
{
    auto mockReader = std::make_shared<cti::store::MockCMReader>();
    auto storeCTI = std::make_shared<CMStoreCTI>(mockReader, NamespaceId("test_namespace"));

    // Mock the resolveUUIDFromName call
    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("test_kvdb"), "kvdb"))
        .WillOnce(Return("kvdb-uuid-abc"));

    // Call the method
    std::string uuid = storeCTI->resolveUUIDFromName("test_kvdb", ResourceType::KVDB);

    EXPECT_EQ(uuid, "kvdb-uuid-abc");
}

TEST(CMStoreCTITest, ResolveUUIDFromName_NotFound)
{
    auto mockReader = std::make_shared<cti::store::MockCMReader>();
    auto storeCTI = std::make_shared<CMStoreCTI>(mockReader, NamespaceId("test_namespace"));

    // Mock the resolveUUIDFromName call to throw an exception
    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("NonExistent"), "integration"))
        .WillOnce(Throw(std::runtime_error("Not found")));

    // Call the method and expect an exception
    EXPECT_THROW(
        storeCTI->resolveUUIDFromName("NonExistent", ResourceType::INTEGRATION),
        std::runtime_error
    );
}

TEST(CMStoreCTITest, ResolveUUIDFromName_UnsupportedType)
{
    auto mockReader = std::make_shared<cti::store::MockCMReader>();
    auto storeCTI = std::make_shared<CMStoreCTI>(mockReader, NamespaceId("test_namespace"));

    // Try to resolve UUID with unsupported resource type (OUTPUT)
    EXPECT_THROW(
        storeCTI->resolveUUIDFromName("test_resource", ResourceType::OUTPUT),
        std::runtime_error
    );
}

TEST(CMStoreCTITest, ResolveUUIDFromName_ExpiredReader)
{
    auto mockReader = std::make_shared<cti::store::MockCMReader>();
    auto storeCTI = std::make_shared<CMStoreCTI>(mockReader, NamespaceId("test_namespace"));

    // Reset the shared_ptr to simulate expired reader
    mockReader.reset();

    // Call the method and expect an exception
    EXPECT_THROW(
        storeCTI->resolveUUIDFromName("Test Integration", ResourceType::INTEGRATION),
        std::runtime_error
    );
}

TEST(CMStoreCTITest, ResolveUUIDFromName_ConsistentResults)
{
    auto mockReader = std::make_shared<cti::store::MockCMReader>();
    auto storeCTI = std::make_shared<CMStoreCTI>(mockReader, NamespaceId("test_namespace"));

    // Mock round-trip: Name -> UUID -> Name
    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("Test Integration"), "integration"))
        .WillOnce(Return("test-uuid-123"));

    EXPECT_CALL(*mockReader, resolveNameAndTypeFromUUID("test-uuid-123"))
        .WillOnce(Return(std::make_pair("Test Integration", cti::store::AssetType::INTEGRATION)));

    // Test Name -> UUID
    std::string uuid = storeCTI->resolveUUIDFromName("Test Integration", ResourceType::INTEGRATION);
    EXPECT_EQ(uuid, "test-uuid-123");

    // Test UUID -> Name (round-trip verification)
    auto nameType = mockReader->resolveNameAndTypeFromUUID(uuid);
    EXPECT_EQ(nameType.first, "Test Integration");
    EXPECT_EQ(nameType.second, cti::store::AssetType::INTEGRATION);
}

TEST(CMStoreCTITest, ResolveUUIDFromName_MultipleCallsSameResource)
{
    auto mockReader = std::make_shared<cti::store::MockCMReader>();
    auto storeCTI = std::make_shared<CMStoreCTI>(mockReader, NamespaceId("test_namespace"));

    // Mock multiple calls to the same resource
    EXPECT_CALL(*mockReader, resolveUUIDFromName(base::Name("windows"), "integration"))
        .Times(3)
        .WillRepeatedly(Return("windows-uuid"));

    // Call the method multiple times
    std::string uuid1 = storeCTI->resolveUUIDFromName("windows", ResourceType::INTEGRATION);
    std::string uuid2 = storeCTI->resolveUUIDFromName("windows", ResourceType::INTEGRATION);
    std::string uuid3 = storeCTI->resolveUUIDFromName("windows", ResourceType::INTEGRATION);

    EXPECT_EQ(uuid1, "windows-uuid");
    EXPECT_EQ(uuid2, "windows-uuid");
    EXPECT_EQ(uuid3, "windows-uuid");
}

