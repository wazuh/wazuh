#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <filesystem>
#include <string>
#include <memory>

#include <ctistore/ctistoragedb.hpp>
#include <base/json.hpp>

using namespace cti::store;

class CTIStorageDBTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Create unique test database path using test name to avoid conflicts
        const ::testing::TestInfo* const test_info = ::testing::UnitTest::GetInstance()->current_test_info();
        std::string test_name = std::string(test_info->test_suite_name()) + "_" + std::string(test_info->name());
        m_testDbPath = std::filesystem::temp_directory_path() / ("cti_storage_test_db_" + test_name);

        if (std::filesystem::exists(m_testDbPath))
        {
            std::filesystem::remove_all(m_testDbPath);
        }

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
        payload.setString("Wazuh 5.0", "/title");
        payload.setString("policy", "/type");

        json::Json integrations;
        integrations.setArray();
        integrations.appendString("integration_1");
        integrations.appendString("integration_2");
        payload.set("/integrations", integrations);

        policy.set("/payload", payload);
        return policy;
    }

    json::Json createSampleIntegration(const std::string& id, const std::string& title)
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
        document.setString(title, "/title");

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

    json::Json createSampleDecoder(const std::string& id, const std::string& title, const std::string& integrationId = "")
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
        document.setString(title, "/title");

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

    json::Json createSampleKVDB(const std::string& id, const std::string& title, const std::string& integrationId = "")
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
        document.setString(title, "/title");

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

    auto content = m_storage->kvdbDump("test_kvdb_id");

    EXPECT_EQ(content.getString("/key1").value_or(""), "value1");
    EXPECT_EQ(content.getString("/key2").value_or(""), "value2");
    EXPECT_EQ(content.getInt("/key3").value_or(0), 123);
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
    auto policy = createSamplePolicy();
    m_storage->storePolicy(policy);

    auto integrations = m_storage->getPolicyIntegrationList();
    EXPECT_EQ(integrations.size(), 2);

    std::vector<std::string> names;
    for (const auto& name : integrations)
    {
        names.push_back(name.fullName());
    }

    EXPECT_THAT(names, ::testing::UnorderedElementsAre("integration_1", "integration_2"));
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

    auto retrievedContent = m_storage->kvdbDump("test_kvdb");
    EXPECT_EQ(retrievedContent.getString("/key1").value_or(""), "value1");
}
