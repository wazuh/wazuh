#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include <ctistore/ctistoragedb.hpp>
#include <base/json.hpp>

using namespace cti::store;

namespace
{
    const std::filesystem::path CTI_TEST_PATH = std::filesystem::temp_directory_path() / "cti_test";

    std::filesystem::path uniquePath(const std::filesystem::path& basePath)
    {
        auto pid = getpid();
        auto tid = std::this_thread::get_id();
        std::stringstream ss;
        ss << pid << "_" << tid << "/"; // Unique path per thread and process
        return basePath / ss.str();
    }
}

class CTIStorageDBTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Create unique test database path to avoid conflicts between parallel tests
        m_testDbPath = uniquePath(CTI_TEST_PATH);

        if (std::filesystem::exists(m_testDbPath))
        {
            std::filesystem::remove_all(m_testDbPath);
        }

        // Create the test directory
        std::filesystem::create_directories(m_testDbPath.parent_path());

        m_storage = std::make_unique<CTIStorageDB>(m_testDbPath.string(), false);
    }

    void TearDown() override
    {
        m_storage.reset();

        // Try to clean up test database, but don't fail test if cleanup fails
        try {
            if (std::filesystem::exists(m_testDbPath))
            {
                std::filesystem::remove_all(m_testDbPath);
            }
        } catch (const std::filesystem::filesystem_error& e) {
            // Log error but don't fail the test
            std::cerr << "Warning: Failed to clean up test database: " << e.what() << std::endl;
        }
    }

    json::Json createSamplePolicy(const std::string& name = "policy_1", int version = 1)
    {
        json::Json policy;
        policy.setObject();
        policy.setString(name, "/name");
        policy.setInt(1, "/offset");
        policy.setInt(version, "/version");
        policy.setString("2025-09-19T14:35:57.830144Z", "/inserted_at");

        json::Json payload;
        payload.setObject();
        payload.setString("policy", "/type");

        json::Json document;
        document.setObject();
        document.setString("Wazuh 5.0", "/title");
        document.setBool(true, "/enabled");

        json::Json metadata;
        metadata.setObject();
        metadata.setString(name, "/id");
        metadata.setString("Wazuh Inc.", "/author");
        metadata.setString("2025-09-19T14:24:44Z", "/date");
        metadata.setString("Policy description", "/description");
        metadata.setString("", "/documentation");

        json::Json references;
        references.setArray();
        references.appendString("https://wazuh.com");
        metadata.set("/references", references);

        document.set("/metadata", metadata);
        payload.set("/document", document);

        json::Json integrations;
        integrations.setArray();
        integrations.appendString("integration_1");
        integrations.appendString("integration_2");
        payload.set("/integrations", integrations);

        policy.set("/payload", payload);
        return policy;
    }

    json::Json createSampleIntegration(const std::string& id, const std::string& name)
    {
        json::Json integration;
        integration.setObject();
        integration.setString(id, "/name");
        integration.setInt(2, "/offset");
        integration.setInt(1, "/version");
        integration.setString("2025-09-19T14:35:57.990963Z", "/inserted_at");

        json::Json payload;
        payload.setObject();
        payload.setString("integration", "/type");

        json::Json document;
        document.setObject();
        document.setString("Wazuh Inc.", "/author");
        document.setString("2025-09-19T14:30:24Z", "/date");
        document.setString("Integration description", "/description");
        document.setBool(true, "/enabled");
        document.setString(id, "/id");
        document.setString(name, "/title");

        json::Json decoders;
        decoders.setArray();
        decoders.appendString("decoder_1");
        decoders.appendString("decoder_2");
        document.set("/decoders", decoders);

        json::Json kvdbs;
        kvdbs.setArray();
        kvdbs.appendString("kvdb_1");
        kvdbs.appendString("kvdb_2");
        document.set("/kvdbs", kvdbs);

        json::Json references;
        references.setArray();
        references.appendString("https://wazuh.com");
        document.set("/references", references);

        payload.set("/document", document);
        integration.set("/payload", payload);

        return integration;
    }

    json::Json createSampleDecoder(const std::string& id, const std::string& name, const std::string& integrationId = "")
    {
        json::Json decoder;
        decoder.setObject();
        decoder.setString(id, "/name");
        decoder.setInt(4, "/offset");
        decoder.setInt(1, "/version");
        decoder.setString("2025-09-19T14:35:58.120075Z", "/inserted_at");

        json::Json payload;
        payload.setObject();
        payload.setString("decoder", "/type");
        if (!integrationId.empty())
        {
            payload.setString(integrationId, "/integration_id");
        }

        json::Json document;
        document.setObject();
        document.setString("condition_string", "/check");
        document.setString("2025-09-19T14:31:07Z", "/date");
        document.setBool(true, "/enabled");
        document.setString(id, "/id");
        document.setString(name, "/name");

        json::Json definitions;
        definitions.setObject();
        document.set("/definitions", definitions);

        json::Json metadata;
        metadata.setObject();
        document.set("/metadata", metadata);

        json::Json normalize;
        normalize.setArray();
        document.set("/normalize", normalize);

        json::Json parse;
        parse.setObject();
        document.set("/parse", parse);

        payload.set("/document", document);
        decoder.set("/payload", payload);

        return decoder;
    }

    json::Json createSampleKVDB(const std::string& id, const std::string& name, const std::string& integrationId = "")
    {
        json::Json kvdb;
        kvdb.setObject();
        kvdb.setString(id, "/name");
        kvdb.setInt(8, "/offset");
        kvdb.setInt(1, "/version");
        kvdb.setString("2025-09-19T14:35:58.372599Z", "/inserted_at");

        json::Json payload;
        payload.setObject();
        payload.setString("kvdb", "/type");
        if (!integrationId.empty())
        {
            payload.setString(integrationId, "/integration_id");
        }

        json::Json document;
        document.setObject();
        document.setString("Wazuh Inc.", "/author");
        document.setString("2025-09-19T14:24:44Z", "/date");
        document.setBool(true, "/enabled");
        document.setString(id, "/id");
        document.setString(name, "/title");

        json::Json content;
        content.setObject();
        content.setString("value1", "/key1");
        content.setString("value2", "/key2");
        content.setInt(123, "/key3");
        document.set("/content", content);

        json::Json references;
        references.setArray();
        references.appendString("https://wazuh.com");
        document.set("/references", references);

        payload.set("/document", document);
        kvdb.set("/payload", payload);

        return kvdb;
    }

    std::filesystem::path m_testDbPath;
    std::unique_ptr<CTIStorageDB> m_storage;
};

// Basic functionality tests
TEST_F(CTIStorageDBTest, InitializeDatabase)
{
    ASSERT_TRUE(m_storage->isOpen());
}

TEST_F(CTIStorageDBTest, StorePolicyDocument)
{
    auto policy = createSamplePolicy();

    EXPECT_NO_THROW(m_storage->storePolicy(policy));
}

TEST_F(CTIStorageDBTest, StoreIntegrationDocument)
{
    auto integration = createSampleIntegration("test_integration_id", "Test Integration");

    EXPECT_NO_THROW(m_storage->storeIntegration(integration));
}

TEST_F(CTIStorageDBTest, StoreDecoderDocument)
{
    auto decoder = createSampleDecoder("test_decoder_id", "Test Decoder");

    EXPECT_NO_THROW(m_storage->storeDecoder(decoder));
}

TEST_F(CTIStorageDBTest, StoreKVDBDocument)
{
    auto kvdb = createSampleKVDB("test_kvdb_id", "Test KVDB");

    EXPECT_NO_THROW(m_storage->storeKVDB(kvdb));
}

// Asset retrieval tests
TEST_F(CTIStorageDBTest, GetAssetById)
{
    auto integration = createSampleIntegration("test_integration_id", "Test Integration");
    m_storage->storeIntegration(integration);

    auto retrieved = m_storage->getAsset(base::Name("test_integration_id"), "integration");

    EXPECT_EQ(retrieved.getString("/name").value_or(""), "test_integration_id");

    auto payload = retrieved.getJson("/payload");
    ASSERT_TRUE(payload.has_value());
    auto document = payload.value().getJson("/document");
    ASSERT_TRUE(document.has_value());
    EXPECT_EQ(document->getString("/title").value_or(""), "Test Integration");
}

TEST_F(CTIStorageDBTest, GetAssetByName)
{
    auto integration = createSampleIntegration("test_integration_id", "Test Integration");
    m_storage->storeIntegration(integration);

    auto retrieved = m_storage->getAsset(base::Name("Test Integration"), "integration");

    EXPECT_EQ(retrieved.getString("/name").value_or(""), "test_integration_id");
}

TEST_F(CTIStorageDBTest, AssetExistsById)
{
    auto integration = createSampleIntegration("test_integration_id", "Test Integration");
    m_storage->storeIntegration(integration);

    EXPECT_TRUE(m_storage->assetExists(base::Name("test_integration_id"), "integration"));
    EXPECT_FALSE(m_storage->assetExists(base::Name("non_existent_id"), "integration"));
}

TEST_F(CTIStorageDBTest, AssetExistsByName)
{
    auto integration = createSampleIntegration("test_integration_id", "Test Integration");
    m_storage->storeIntegration(integration);

    EXPECT_TRUE(m_storage->assetExists(base::Name("Test Integration"), "integration"));
    EXPECT_FALSE(m_storage->assetExists(base::Name("Non Existent Integration"), "integration"));
}

TEST_F(CTIStorageDBTest, GetAssetList)
{
    auto integration1 = createSampleIntegration("integration_1", "Integration One");
    auto integration2 = createSampleIntegration("integration_2", "Integration Two");
    auto decoder1 = createSampleDecoder("decoder_1", "Decoder One");

    m_storage->storeIntegration(integration1);
    m_storage->storeIntegration(integration2);
    m_storage->storeDecoder(decoder1);

    auto integrations = m_storage->getAssetList("integration");
    EXPECT_EQ(integrations.size(), 2);

    std::vector<std::string> names;
    for (const auto& name : integrations)
    {
        names.push_back(name.fullName());
    }

    EXPECT_THAT(names, ::testing::UnorderedElementsAre("Integration One", "Integration Two"));

    auto decoders = m_storage->getAssetList("decoder");
    EXPECT_EQ(decoders.size(), 1);
    EXPECT_EQ(decoders[0].fullName(), "Decoder One");
}

// KVDB-specific tests
TEST_F(CTIStorageDBTest, GetKVDBList)
{
    auto kvdb1 = createSampleKVDB("kvdb_1", "KVDB One");
    auto kvdb2 = createSampleKVDB("kvdb_2", "KVDB Two");

    m_storage->storeKVDB(kvdb1);
    m_storage->storeKVDB(kvdb2);

    auto kvdbs = m_storage->getKVDBList();
    EXPECT_EQ(kvdbs.size(), 2);
    EXPECT_THAT(kvdbs, ::testing::UnorderedElementsAre("KVDB One", "KVDB Two"));
}

TEST_F(CTIStorageDBTest, KVDBExists)
{
    auto kvdb = createSampleKVDB("test_kvdb_id", "Test KVDB");
    m_storage->storeKVDB(kvdb);

    EXPECT_TRUE(m_storage->kvdbExists("test_kvdb_id"));
    EXPECT_TRUE(m_storage->kvdbExists("Test KVDB"));
    EXPECT_FALSE(m_storage->kvdbExists("non_existent_kvdb"));
}

TEST_F(CTIStorageDBTest, KVDBDump)
{
    auto kvdb = createSampleKVDB("test_kvdb_id", "Test KVDB");
    m_storage->storeKVDB(kvdb);

    auto kvdbDoc = m_storage->kvdbDump("test_kvdb_id");

    // kvdbDump now returns the full document, not just content
    auto payload = kvdbDoc.getJson("/payload");
    ASSERT_TRUE(payload.has_value());
    auto document = payload.value().getJson("/document");
    ASSERT_TRUE(document.has_value());
    auto content = document.value().getJson("/content");
    ASSERT_TRUE(content.has_value());

    EXPECT_EQ(content->getString("/key1").value_or(""), "value1");
    EXPECT_EQ(content->getString("/key2").value_or(""), "value2");
    EXPECT_EQ(content->getInt("/key3").value_or(0), 123);
}

TEST_F(CTIStorageDBTest, GetKVDBListByIntegration)
{
    auto integration = createSampleIntegration("test_integration", "Test Integration");
    auto kvdb1 = createSampleKVDB("kvdb_1", "KVDB One", "test_integration");
    auto kvdb2 = createSampleKVDB("kvdb_2", "KVDB Two", "test_integration");
    auto kvdb3 = createSampleKVDB("kvdb_3", "KVDB Three", "other_integration");

    m_storage->storeIntegration(integration);
    m_storage->storeKVDB(kvdb1);
    m_storage->storeKVDB(kvdb2);
    m_storage->storeKVDB(kvdb3);

    auto kvdbs = m_storage->getKVDBList(base::Name("Test Integration"));
    EXPECT_EQ(kvdbs.size(), 2);
    EXPECT_THAT(kvdbs, ::testing::UnorderedElementsAre("kvdb_1", "kvdb_2"));
}

// Policy tests
TEST_F(CTIStorageDBTest, GetPolicyIntegrationList)
{
    // Store integrations first so they can be resolved by title
    auto integration1 = createSampleIntegration("integration_1", "Integration One");
    auto integration2 = createSampleIntegration("integration_2", "Integration Two");
    m_storage->storeIntegration(integration1);
    m_storage->storeIntegration(integration2);

    auto policy = createSamplePolicy();
    m_storage->storePolicy(policy);

    auto integrations = m_storage->getPolicyIntegrationList();
    EXPECT_EQ(integrations.size(), 2);

    std::vector<std::string> names;
    for (const auto& name : integrations)
    {
        names.push_back(name.fullName());
    }

    // Now expects titles instead of IDs
    EXPECT_THAT(names, ::testing::UnorderedElementsAre("Integration One", "Integration Two"));
}

TEST_F(CTIStorageDBTest, GetPolicyDefaultParent)
{
    auto defaultParent = m_storage->getPolicyDefaultParent();
    EXPECT_EQ(defaultParent.fullName(), "wazuh");
}

// Error handling tests
TEST_F(CTIStorageDBTest, GetNonExistentAsset)
{
    EXPECT_THROW(m_storage->getAsset(base::Name("non_existent"), "integration"), std::runtime_error);
}

TEST_F(CTIStorageDBTest, GetAssetInvalidType)
{
    EXPECT_THROW(m_storage->getAsset(base::Name("any"), "invalid_type"), std::invalid_argument);
}

TEST_F(CTIStorageDBTest, StoreInvalidDocument)
{
    json::Json invalidDoc;
    invalidDoc.setObject();

    EXPECT_THROW(m_storage->storeIntegration(invalidDoc), std::invalid_argument);
}

TEST_F(CTIStorageDBTest, KVDBDumpNonExistent)
{
    EXPECT_THROW(m_storage->kvdbDump("non_existent"), std::runtime_error);
}

// Batch operations test
TEST_F(CTIStorageDBTest, StoreBatchDocuments)
{
    auto integration = createSampleIntegration("integration_1", "Integration One");
    auto decoder1 = createSampleDecoder("decoder_1", "Decoder One", "integration_1");
    auto decoder2 = createSampleDecoder("decoder_2", "Decoder Two", "integration_1");
    auto kvdb1 = createSampleKVDB("kvdb_1", "KVDB One", "integration_1");
    auto kvdb2 = createSampleKVDB("kvdb_2", "KVDB Two", "integration_1");

    EXPECT_NO_THROW(m_storage->storeIntegration(integration));
    EXPECT_NO_THROW(m_storage->storeDecoder(decoder1));
    EXPECT_NO_THROW(m_storage->storeDecoder(decoder2));
    EXPECT_NO_THROW(m_storage->storeKVDB(kvdb1));
    EXPECT_NO_THROW(m_storage->storeKVDB(kvdb2));

    auto integrations = m_storage->getAssetList("integration");
    EXPECT_EQ(integrations.size(), 1);

    auto decoders = m_storage->getAssetList("decoder");
    EXPECT_EQ(decoders.size(), 2);

    auto kvdbs = m_storage->getKVDBList();
    EXPECT_EQ(kvdbs.size(), 2);
}

// Additional utility methods tests
TEST_F(CTIStorageDBTest, ClearAllDocuments)
{
    auto integration = createSampleIntegration("integration_1", "Integration One");
    auto decoder = createSampleDecoder("decoder_1", "Decoder One");
    auto kvdb = createSampleKVDB("kvdb_1", "KVDB One");
    auto policy = createSamplePolicy();

    m_storage->storeIntegration(integration);
    m_storage->storeDecoder(decoder);
    m_storage->storeKVDB(kvdb);
    m_storage->storePolicy(policy);

    EXPECT_EQ(m_storage->getStorageStats(CTIStorageDB::ColumnFamily::INTEGRATION), 1);
    EXPECT_EQ(m_storage->getStorageStats(CTIStorageDB::ColumnFamily::DECODER), 1);
    EXPECT_EQ(m_storage->getStorageStats(CTIStorageDB::ColumnFamily::KVDB), 1);
    EXPECT_EQ(m_storage->getStorageStats(CTIStorageDB::ColumnFamily::POLICY), 1);

    m_storage->clearAll();

    EXPECT_EQ(m_storage->getStorageStats(CTIStorageDB::ColumnFamily::INTEGRATION), 0);
    EXPECT_EQ(m_storage->getStorageStats(CTIStorageDB::ColumnFamily::DECODER), 0);
    EXPECT_EQ(m_storage->getStorageStats(CTIStorageDB::ColumnFamily::KVDB), 0);
    EXPECT_EQ(m_storage->getStorageStats(CTIStorageDB::ColumnFamily::POLICY), 0);
    EXPECT_EQ(m_storage->getStorageStats(CTIStorageDB::ColumnFamily::METADATA), 0);
}

TEST_F(CTIStorageDBTest, GetStorageStats)
{
    EXPECT_EQ(m_storage->getStorageStats(CTIStorageDB::ColumnFamily::INTEGRATION), 0);

    auto integration1 = createSampleIntegration("integration_1", "Integration One");
    auto integration2 = createSampleIntegration("integration_2", "Integration Two");

    m_storage->storeIntegration(integration1);
    EXPECT_EQ(m_storage->getStorageStats(CTIStorageDB::ColumnFamily::INTEGRATION), 1);

    m_storage->storeIntegration(integration2);
    EXPECT_EQ(m_storage->getStorageStats(CTIStorageDB::ColumnFamily::INTEGRATION), 2);
}

// Document validation tests
TEST_F(CTIStorageDBTest, ValidateDocumentFormat)
{
    json::Json invalidDoc;
    invalidDoc.setObject();

    EXPECT_THROW(m_storage->storeIntegration(invalidDoc), std::invalid_argument);

    json::Json docWithoutName;
    docWithoutName.setObject();
    json::Json payload;
    payload.setObject();
    payload.setString("integration", "/type");
    docWithoutName.set("/payload", payload);

    EXPECT_THROW(m_storage->storeIntegration(docWithoutName), std::invalid_argument);

    json::Json docWithoutPayload;
    docWithoutPayload.setObject();
    docWithoutPayload.setString("test", "/name");

    EXPECT_THROW(m_storage->storeIntegration(docWithoutPayload), std::invalid_argument);
}

// Concurrent access simulation test
TEST_F(CTIStorageDBTest, ConcurrentReadWrite)
{
    auto integration = createSampleIntegration("test_integration", "Test Integration");
    m_storage->storeIntegration(integration);

    EXPECT_TRUE(m_storage->assetExists(base::Name("test_integration"), "integration"));

    auto retrieved = m_storage->getAsset(base::Name("test_integration"), "integration");
    EXPECT_EQ(retrieved.getString("/name").value_or(""), "test_integration");

    auto integration2 = createSampleIntegration("test_integration_2", "Test Integration 2");
    m_storage->storeIntegration(integration2);

    EXPECT_TRUE(m_storage->assetExists(base::Name("test_integration"), "integration"));
    EXPECT_TRUE(m_storage->assetExists(base::Name("test_integration_2"), "integration"));

    auto integrations = m_storage->getAssetList("integration");
    EXPECT_EQ(integrations.size(), 2);
}

// Metadata interface tests - Name-to-ID resolution
TEST_F(CTIStorageDBTest, MetadataNameToIdResolution)
{
    // Store an integration with both ID and title
    auto integration = createSampleIntegration("int_001", "My Integration");
    m_storage->storeIntegration(integration);

    // Should be able to retrieve by ID
    auto byId = m_storage->getAsset(base::Name("int_001"), "integration");
    EXPECT_EQ(byId.getString("/name").value_or(""), "int_001");

    // Should be able to retrieve by title (uses metadata name-to-id mapping)
    auto byTitle = m_storage->getAsset(base::Name("My Integration"), "integration");
    EXPECT_EQ(byTitle.getString("/name").value_or(""), "int_001");

    // Both should return the same document
    EXPECT_EQ(byId.str(), byTitle.str());

    // Check existence using both ID and title
    EXPECT_TRUE(m_storage->assetExists(base::Name("int_001"), "integration"));
    EXPECT_TRUE(m_storage->assetExists(base::Name("My Integration"), "integration"));
}

TEST_F(CTIStorageDBTest, MetadataNameToIdResolutionMultipleAssets)
{
    // Store multiple integrations
    auto int1 = createSampleIntegration("int_001", "Integration Alpha");
    auto int2 = createSampleIntegration("int_002", "Integration Beta");
    auto int3 = createSampleIntegration("int_003", "Integration Gamma");

    m_storage->storeIntegration(int1);
    m_storage->storeIntegration(int2);
    m_storage->storeIntegration(int3);

    // Verify each can be retrieved by both ID and title
    EXPECT_TRUE(m_storage->assetExists(base::Name("int_001"), "integration"));
    EXPECT_TRUE(m_storage->assetExists(base::Name("Integration Alpha"), "integration"));

    EXPECT_TRUE(m_storage->assetExists(base::Name("int_002"), "integration"));
    EXPECT_TRUE(m_storage->assetExists(base::Name("Integration Beta"), "integration"));

    EXPECT_TRUE(m_storage->assetExists(base::Name("int_003"), "integration"));
    EXPECT_TRUE(m_storage->assetExists(base::Name("Integration Gamma"), "integration"));

    // Non-existent names should not be found
    EXPECT_FALSE(m_storage->assetExists(base::Name("int_004"), "integration"));
    EXPECT_FALSE(m_storage->assetExists(base::Name("Non Existent"), "integration"));
}

// Metadata interface tests - Relationship indexes
TEST_F(CTIStorageDBTest, MetadataRelationshipIndexes)
{
    // Create integration with decoders and kvdbs in document
    auto integration = createSampleIntegration("test_int", "Test Integration");
    m_storage->storeIntegration(integration);

    // The metadata should store the relationship indexes
    // Query KVDBs by integration name
    auto kvdbs = m_storage->getKVDBList(base::Name("Test Integration"));

    // Should return the kvdbs defined in the integration document
    EXPECT_EQ(kvdbs.size(), 2);
    EXPECT_THAT(kvdbs, ::testing::UnorderedElementsAre("kvdb_1", "kvdb_2"));
}

TEST_F(CTIStorageDBTest, MetadataRelationshipIndexesUpdate)
{
    // Create integration with initial relationships
    auto integration = createSampleIntegration("test_int", "Test Integration");
    m_storage->storeIntegration(integration);

    auto kvdbs = m_storage->getKVDBList(base::Name("Test Integration"));
    EXPECT_EQ(kvdbs.size(), 2);

    // Update integration with different relationships
    json::Json updatedIntegration = integration;
    json::Json newKvdbs;
    newKvdbs.setArray();
    newKvdbs.appendString("kvdb_3");
    newKvdbs.appendString("kvdb_4");
    newKvdbs.appendString("kvdb_5");

    updatedIntegration.set("/payload/document/kvdbs", newKvdbs);
    m_storage->storeIntegration(updatedIntegration);

    // Metadata relationship indexes should be updated
    auto updatedKvdbList = m_storage->getKVDBList(base::Name("Test Integration"));
    EXPECT_EQ(updatedKvdbList.size(), 3);
    EXPECT_THAT(updatedKvdbList, ::testing::UnorderedElementsAre("kvdb_3", "kvdb_4", "kvdb_5"));
}

TEST_F(CTIStorageDBTest, MetadataRelationshipIndexesNonExistent)
{
    // Query relationships for non-existent integration
    auto kvdbs = m_storage->getKVDBList(base::Name("Non Existent Integration"));

    // Should return empty list
    EXPECT_EQ(kvdbs.size(), 0);
}

TEST_F(CTIStorageDBTest, MetadataClearAll)
{
    // Store data that creates metadata entries
    auto integration = createSampleIntegration("test_int", "Test Integration");
    auto decoder = createSampleDecoder("test_dec", "Test Decoder");

    m_storage->storeIntegration(integration);
    m_storage->storeDecoder(decoder);

    // Verify metadata is working (name resolution)
    EXPECT_TRUE(m_storage->assetExists(base::Name("Test Integration"), "integration"));
    EXPECT_TRUE(m_storage->assetExists(base::Name("Test Decoder"), "decoder"));

    // Clear all should also clear metadata
    m_storage->clearAll();

    // Metadata should be cleared (no name resolution)
    EXPECT_FALSE(m_storage->assetExists(base::Name("Test Integration"), "integration"));
    EXPECT_FALSE(m_storage->assetExists(base::Name("Test Decoder"), "decoder"));

    // Verify metadata column family is empty
    EXPECT_EQ(m_storage->getStorageStats(CTIStorageDB::ColumnFamily::METADATA), 0);
}

// Controlled shutdown test
TEST_F(CTIStorageDBTest, ControlledShutdown)
{
    auto integration = createSampleIntegration("test_integration", "Test Integration");
    auto decoder = createSampleDecoder("test_decoder", "Test Decoder");
    auto kvdb = createSampleKVDB("test_kvdb", "Test KVDB");

    m_storage->storeIntegration(integration);
    m_storage->storeDecoder(decoder);
    m_storage->storeKVDB(kvdb);

    EXPECT_TRUE(m_storage->isOpen());

    // Perform controlled shutdown
    EXPECT_NO_THROW(m_storage->shutdown());

    // After shutdown, database should not be open
    EXPECT_FALSE(m_storage->isOpen());

    // Multiple shutdown calls should be safe
    EXPECT_NO_THROW(m_storage->shutdown());
}

TEST_F(CTIStorageDBTest, ShutdownPersistsData)
{
    auto integration = createSampleIntegration("test_integration", "Test Integration");
    auto kvdb = createSampleKVDB("test_kvdb", "Test KVDB");

    m_storage->storeIntegration(integration);
    m_storage->storeKVDB(kvdb);

    // Perform controlled shutdown
    m_storage->shutdown();
    EXPECT_FALSE(m_storage->isOpen());

    // Reopen the database
    std::string dbPath = m_testDbPath.string();
    m_storage = std::make_unique<CTIStorageDB>(dbPath, false);

    // Verify data was persisted
    EXPECT_TRUE(m_storage->assetExists(base::Name("test_integration"), "integration"));
    EXPECT_TRUE(m_storage->kvdbExists("test_kvdb"));

    auto retrievedIntegration = m_storage->getAsset(base::Name("test_integration"), "integration");
    EXPECT_EQ(retrievedIntegration.getString("/name").value_or(""), "test_integration");
}

// Data integrity test
TEST_F(CTIStorageDBTest, DataIntegrityAfterReopen)
{
    auto integration = createSampleIntegration("test_integration", "Test Integration");
    auto kvdb = createSampleKVDB("test_kvdb", "Test KVDB");

    m_storage->storeIntegration(integration);
    m_storage->storeKVDB(kvdb);

    EXPECT_TRUE(m_storage->assetExists(base::Name("test_integration"), "integration"));
    EXPECT_TRUE(m_storage->kvdbExists("test_kvdb"));

    std::string dbPath = m_testDbPath.string();
    m_storage.reset();

    m_storage = std::make_unique<CTIStorageDB>(dbPath, false);

    EXPECT_TRUE(m_storage->assetExists(base::Name("test_integration"), "integration"));
    EXPECT_TRUE(m_storage->kvdbExists("test_kvdb"));

    auto retrievedIntegration = m_storage->getAsset(base::Name("test_integration"), "integration");
    EXPECT_EQ(retrievedIntegration.getString("/name").value_or(""), "test_integration");

    auto retrievedKvdb = m_storage->kvdbDump("test_kvdb");
    auto retrievedPayload = retrievedKvdb.getJson("/payload");
    ASSERT_TRUE(retrievedPayload.has_value());
    auto retrievedDocument = retrievedPayload.value().getJson("/document");
    ASSERT_TRUE(retrievedDocument.has_value());
    auto retrievedContent = retrievedDocument.value().getJson("/content");
    ASSERT_TRUE(retrievedContent.has_value());
    EXPECT_EQ(retrievedContent->getString("/key1").value_or(""), "value1");
}

// Thread Safety and Concurrency Tests
// These tests verify that our explicit synchronization (shared_mutex) works correctly
// for the single-writer, multiple-reader pattern with both read and write operations.
TEST_F(CTIStorageDBTest, ConcurrentReadWriteOperations)
{
    // This test verifies that writes are exclusive and readers can run concurrently
    const int numReaderThreads = 10;
    const int numWriterThreads = 1; // Single writer as per design
    const int readsPerThread = 50;
    const int writesPerThread = 20;

    std::atomic<int> totalReads{0};
    std::atomic<int> totalWrites{0};
    std::atomic<int> successfulReads{0};
    std::atomic<int> successfulWrites{0};
    std::mutex errorMutex;
    std::vector<std::string> errors;

    // Barrier to synchronize thread start
    std::atomic<bool> startFlag{false};

    // Writer thread - stores new integrations
    auto writerWorker = [&](int threadId) {
        // Wait for start signal
        while (!startFlag.load()) {
            std::this_thread::sleep_for(std::chrono::microseconds(1));
        }

        for (int i = 0; i < writesPerThread; ++i) {
            try {
                totalWrites++;
                std::string id = "writer_" + std::to_string(threadId) + "_integration_" + std::to_string(i);
                std::string title = "Writer " + std::to_string(threadId) + " Integration " + std::to_string(i);

                auto integration = createSampleIntegration(id, title);
                m_storage->storeIntegration(integration);

                successfulWrites++;

                // Small delay to let readers have a chance
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
            catch (const std::exception& e) {
                std::lock_guard<std::mutex> lock(errorMutex);
                errors.push_back("Writer " + std::to_string(threadId) + ": " + e.what());
            }
        }
    };

    // Reader threads - read existing and newly written data
    auto readerWorker = [&](int threadId) {
        // Wait for start signal
        while (!startFlag.load()) {
            std::this_thread::sleep_for(std::chrono::microseconds(1));
        }

        for (int i = 0; i < readsPerThread; ++i) {
            try {
                totalReads++;

                // Try to read from existing data and potentially new data
                auto assetList = m_storage->getAssetList("integration");

                // If there are assets, try to read one
                if (!assetList.empty()) {
                    int index = (threadId * readsPerThread + i) % assetList.size();
                    auto asset = m_storage->getAsset(assetList[index], "integration");
                    EXPECT_FALSE(asset.str().empty());
                }

                successfulReads++;

                // Very small delay to increase concurrency likelihood
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
            catch (const std::exception& e) {
                std::lock_guard<std::mutex> lock(errorMutex);
                errors.push_back("Reader " + std::to_string(threadId) + ": " + e.what());
            }
        }
    };

    // Store some initial data
    for (int i = 0; i < 10; ++i) {
        auto integration = createSampleIntegration("initial_integration_" + std::to_string(i), "Initial Integration " + std::to_string(i));
        m_storage->storeIntegration(integration);
    }

    std::vector<std::thread> threads;

    // Start writer thread
    for (int t = 0; t < numWriterThreads; ++t) {
        threads.emplace_back(writerWorker, t);
    }

    // Start reader threads
    for (int t = 0; t < numReaderThreads; ++t) {
        threads.emplace_back(readerWorker, t);
    }

    // Signal all threads to start
    startFlag.store(true);

    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }

    // Verify results
    EXPECT_TRUE(errors.empty()) << "Mixed read/write errors occurred:\n" <<
        [&errors]() {
            std::string allErrors;
            for (const auto& error : errors) {
                allErrors += error + "\n";
            }
            return allErrors;
        }();

    EXPECT_EQ(successfulWrites.load(), numWriterThreads * writesPerThread)
        << "Expected all writes to succeed";

    EXPECT_EQ(successfulReads.load(), numReaderThreads * readsPerThread)
        << "Expected all reads to succeed";

    // Verify final state - should have initial + written assets
    auto finalList = m_storage->getAssetList("integration");
    EXPECT_EQ(finalList.size(), 10 + numWriterThreads * writesPerThread);
}

TEST_F(CTIStorageDBTest, ConcurrentQueriesDifferentTypes)
{
    // Setup: Store multiple assets of different types
    const int numAssets = 50;

    // Store integrations
    for (int i = 0; i < numAssets; ++i)
    {
        auto integration = createSampleIntegration(
            "integration_" + std::to_string(i),
            "Integration " + std::to_string(i)
        );
        m_storage->storeIntegration(integration);
    }

    // Store decoders
    for (int i = 0; i < numAssets; ++i)
    {
        auto decoder = createSampleDecoder(
            "decoder_" + std::to_string(i),
            "Decoder " + std::to_string(i)
        );
        m_storage->storeDecoder(decoder);
    }

    // Store KVDBs
    for (int i = 0; i < numAssets; ++i)
    {
        auto kvdb = createSampleKVDB(
            "kvdb_" + std::to_string(i),
            "KVDB " + std::to_string(i)
        );
        m_storage->storeKVDB(kvdb);
    }

    // Test concurrent queries on different asset types from multiple threads
    const int numThreads = 10;
    const int queriesPerThread = 20;
    std::vector<std::thread> threads;
    std::atomic<int> successfulQueries{0};
    std::atomic<int> totalQueries{0};
    std::mutex errorMutex;
    std::vector<std::string> errors;

    auto queryWorker = [&](int threadId, const std::string& assetType) {
        for (int i = 0; i < queriesPerThread; ++i)
        {
            try
            {
                totalQueries++;
                int assetIndex = (threadId * queriesPerThread + i) % numAssets;
                std::string assetName;

                if (assetType == "integration")
                {
                    assetName = "Integration " + std::to_string(assetIndex);
                    auto asset = m_storage->getAsset(base::Name(assetName), assetType);
                    EXPECT_FALSE(asset.str().empty());
                }
                else if (assetType == "decoder")
                {
                    assetName = "Decoder " + std::to_string(assetIndex);
                    auto asset = m_storage->getAsset(base::Name(assetName), assetType);
                    EXPECT_FALSE(asset.str().empty());
                }
                else if (assetType == "kvdb")
                {
                    std::string kvdbName = "KVDB " + std::to_string(assetIndex);
                    bool exists = m_storage->kvdbExists(kvdbName);
                    EXPECT_TRUE(exists);
                    if (exists) {
                        auto dump = m_storage->kvdbDump(kvdbName);
                        EXPECT_TRUE(dump.isObject());
                    }
                }

                // Also test list operations
                if (i % 5 == 0) {
                    auto assetList = m_storage->getAssetList(assetType == "kvdb" ? "decoder" : assetType);
                    EXPECT_FALSE(assetList.empty());
                }

                successfulQueries++;
            }
            catch (const std::exception& e)
            {
                std::lock_guard<std::mutex> lock(errorMutex);
                errors.push_back("Thread " + std::to_string(threadId) + " (" + assetType + "): " + e.what());
            }
        }
    };

    // Launch threads querying different asset types concurrently
    for (int t = 0; t < numThreads; ++t)
    {
        if (t % 3 == 0) {
            threads.emplace_back(queryWorker, t, "integration");
        } else if (t % 3 == 1) {
            threads.emplace_back(queryWorker, t, "decoder");
        } else {
            threads.emplace_back(queryWorker, t, "kvdb");
        }
    }

    // Wait for all threads to complete
    for (auto& thread : threads)
    {
        thread.join();
    }

    // Verify results
    EXPECT_TRUE(errors.empty()) << "Concurrent query errors occurred:\n" <<
        [&errors]() {
            std::string allErrors;
            for (const auto& error : errors) {
                allErrors += error + "\n";
            }
            return allErrors;
        }();

    EXPECT_EQ(successfulQueries.load(), totalQueries.load())
        << "Expected all queries to succeed, but " << (totalQueries - successfulQueries)
        << " out of " << totalQueries << " failed";
}

TEST_F(CTIStorageDBTest, ConcurrentQueriesSameType)
{
    // Setup: Store many assets of the same type
    const int numIntegrations = 100;

    for (int i = 0; i < numIntegrations; ++i)
    {
        auto integration = createSampleIntegration(
            "concurrent_integration_" + std::to_string(i),
            "Concurrent Integration " + std::to_string(i)
        );
        m_storage->storeIntegration(integration);
    }

    // Test concurrent queries on the same asset type from multiple threads
    const int numThreads = 20;
    const int queriesPerThread = 15;
    std::vector<std::thread> threads;
    std::atomic<int> successfulQueries{0};
    std::atomic<int> successfulExists{0};
    std::atomic<int> successfulLists{0};
    std::mutex errorMutex;
    std::vector<std::string> errors;

    auto concurrentWorker = [&](int threadId) {
        for (int i = 0; i < queriesPerThread; ++i)
        {
            try
            {
                int assetIndex = (threadId * queriesPerThread + i) % numIntegrations;
                std::string assetName = "Concurrent Integration " + std::to_string(assetIndex);
                std::string assetId = "concurrent_integration_" + std::to_string(assetIndex);

                // Test getAsset by name
                auto asset = m_storage->getAsset(base::Name(assetName), "integration");
                EXPECT_FALSE(asset.str().empty());
                EXPECT_EQ(asset.getString("/name").value_or(""), assetId);
                successfulQueries++;

                // Test assetExists
                bool exists = m_storage->assetExists(base::Name(assetName), "integration");
                EXPECT_TRUE(exists);
                if (exists) successfulExists++;

                // Test getAssetList periodically
                if (i % 5 == 0) {
                    auto assetList = m_storage->getAssetList("integration");
                    EXPECT_GE(assetList.size(), numIntegrations);
                    successfulLists++;
                }
            }
            catch (const std::exception& e)
            {
                std::lock_guard<std::mutex> lock(errorMutex);
                errors.push_back("Thread " + std::to_string(threadId) + ": " + e.what());
            }
        }
    };

    // Launch multiple threads querying the same asset type
    for (int t = 0; t < numThreads; ++t)
    {
        threads.emplace_back(concurrentWorker, t);
    }

    // Wait for all threads to complete
    for (auto& thread : threads)
    {
        thread.join();
    }

    // Verify no errors occurred
    EXPECT_TRUE(errors.empty()) << "Concurrent query errors occurred:\n" <<
        [&errors]() {
            std::string allErrors;
            for (const auto& error : errors) {
                allErrors += error + "\n";
            }
            return allErrors;
        }();

    // Verify all operations succeeded
    int expectedQueries = numThreads * queriesPerThread;
    int expectedExists = numThreads * queriesPerThread;
    int expectedLists = numThreads * (queriesPerThread / 5); // Every 5th query

    EXPECT_EQ(successfulQueries.load(), expectedQueries)
        << "Expected " << expectedQueries << " successful getAsset calls, got " << successfulQueries;

    EXPECT_EQ(successfulExists.load(), expectedExists)
        << "Expected " << expectedExists << " successful assetExists calls, got " << successfulExists;

    EXPECT_EQ(successfulLists.load(), expectedLists)
        << "Expected " << expectedLists << " successful getAssetList calls, got " << successfulLists;
}

TEST_F(CTIStorageDBTest, ConcurrentMixedOperations)
{
    // Setup: Store some initial data
    const int initialAssets = 30;

    for (int i = 0; i < initialAssets; ++i)
    {
        auto integration = createSampleIntegration(
            "mixed_integration_" + std::to_string(i),
            "Mixed Integration " + std::to_string(i)
        );
        m_storage->storeIntegration(integration);

        auto decoder = createSampleDecoder(
            "mixed_decoder_" + std::to_string(i),
            "Mixed Decoder " + std::to_string(i),
            "mixed_integration_" + std::to_string(i)
        );
        m_storage->storeDecoder(decoder);
    }

    // Test mixed read operations (no writes to ensure thread safety focus is on reads)
    const int numThreads = 15;
    std::vector<std::thread> threads;
    std::atomic<int> totalOperations{0};
    std::atomic<int> successfulOperations{0};
    std::mutex errorMutex;
    std::vector<std::string> errors;

    auto mixedOperationsWorker = [&](int threadId) {
        const int operationsPerThread = 30;

        for (int i = 0; i < operationsPerThread; ++i)
        {
            try
            {
                totalOperations++;
                int operation = i % 6; // 6 different types of operations
                int assetIndex = (threadId * operationsPerThread + i) % initialAssets;

                switch (operation)
                {
                    case 0: // Get integration by name
                    {
                        std::string name = "Mixed Integration " + std::to_string(assetIndex);
                        auto asset = m_storage->getAsset(base::Name(name), "integration");
                        EXPECT_FALSE(asset.str().empty());
                        break;
                    }
                    case 1: // Get decoder by name
                    {
                        std::string name = "Mixed Decoder " + std::to_string(assetIndex);
                        auto asset = m_storage->getAsset(base::Name(name), "decoder");
                        EXPECT_FALSE(asset.str().empty());
                        break;
                    }
                    case 2: // Check integration exists
                    {
                        std::string name = "Mixed Integration " + std::to_string(assetIndex);
                        bool exists = m_storage->assetExists(base::Name(name), "integration");
                        EXPECT_TRUE(exists);
                        break;
                    }
                    case 3: // Check decoder exists
                    {
                        std::string name = "Mixed Decoder " + std::to_string(assetIndex);
                        bool exists = m_storage->assetExists(base::Name(name), "decoder");
                        EXPECT_TRUE(exists);
                        break;
                    }
                    case 4: // List integrations
                    {
                        auto list = m_storage->getAssetList("integration");
                        EXPECT_GE(list.size(), initialAssets);
                        break;
                    }
                    case 5: // List decoders
                    {
                        auto list = m_storage->getAssetList("decoder");
                        EXPECT_GE(list.size(), initialAssets);
                        break;
                    }
                }

                successfulOperations++;
            }
            catch (const std::exception& e)
            {
                std::lock_guard<std::mutex> lock(errorMutex);
                errors.push_back("Thread " + std::to_string(threadId) + " op " + std::to_string(i) + ": " + e.what());
            }
        }
    };

    // Launch threads with mixed operations
    for (int t = 0; t < numThreads; ++t)
    {
        threads.emplace_back(mixedOperationsWorker, t);
    }

    // Wait for all threads to complete
    for (auto& thread : threads)
    {
        thread.join();
    }

    // Verify results
    EXPECT_TRUE(errors.empty()) << "Mixed concurrent operation errors occurred:\n" <<
        [&errors]() {
            std::string allErrors;
            for (const auto& error : errors) {
                allErrors += error + "\n";
            }
            return allErrors;
        }();

    EXPECT_EQ(successfulOperations.load(), totalOperations.load())
        << "Expected all " << totalOperations << " mixed operations to succeed, but "
        << (totalOperations - successfulOperations) << " failed";
}

TEST_F(CTIStorageDBTest, ThreadSafetyBasicVerification)
{
    // Simple test: verify that basic read/write operations work without crashes
    // in a multithreaded environment (this should work with our current implementation)

    const int numWriters = 1;
    const int numReaders = 5;
    const int writesPerWriter = 5;
    const int readsPerReader = 10;

    std::vector<std::thread> threads;
    std::atomic<int> successfulWrites{0};
    std::atomic<int> successfulReads{0};
    std::mutex errorMutex;
    std::vector<std::string> errors;

    // Writer worker
    auto writer = [&]() {
        try {
            for (int i = 0; i < writesPerWriter; ++i) {
                std::string id = "basic_integration_" + std::to_string(i);
                std::string title = "Basic Integration " + std::to_string(i);
                auto integration = createSampleIntegration(id, title);

                m_storage->storeIntegration(integration);
                successfulWrites++;

                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(errorMutex);
            errors.push_back("Writer error: " + std::string(e.what()));
        }
    };

    // Reader worker
    auto reader = [&](int threadId) {
        try {
            for (int i = 0; i < readsPerReader; ++i) {
                auto assetList = m_storage->getAssetList("integration");

                // Try to read an asset if any exist
                if (!assetList.empty()) {
                    int index = i % assetList.size();
                    auto asset = m_storage->getAsset(assetList[index], "integration");
                    EXPECT_FALSE(asset.str().empty());
                }

                successfulReads++;
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        }
        catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(errorMutex);
            errors.push_back("Reader " + std::to_string(threadId) + " error: " + e.what());
        }
    };

    // Store some initial data
    for (int i = 0; i < 3; ++i) {
        auto integration = createSampleIntegration("initial_" + std::to_string(i), "Initial " + std::to_string(i));
        m_storage->storeIntegration(integration);
    }

    // Launch threads
    for (int i = 0; i < numWriters; ++i) {
        threads.emplace_back(writer);
    }

    for (int i = 0; i < numReaders; ++i) {
        threads.emplace_back(reader, i);
    }

    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }

    // Basic verification
    EXPECT_TRUE(errors.empty()) << "Errors occurred during basic threading test:\n" <<
        [&errors]() {
            std::string allErrors;
            for (const auto& error : errors) {
                allErrors += error + "\n";
            }
            return allErrors;
        }();

    EXPECT_EQ(successfulWrites.load(), numWriters * writesPerWriter);
    EXPECT_EQ(successfulReads.load(), numReaders * readsPerReader);

    // Should have initial + written assets
    auto finalList = m_storage->getAssetList("integration");
    EXPECT_EQ(finalList.size(), 3 + numWriters * writesPerWriter);
}
