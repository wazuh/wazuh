#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <unistd.h>

#include <gtest/gtest.h>

#include <cmstore/cmstore.hpp>
#include <cmstore/types.hpp>

#include "storens.hpp"

// ======================================================================
//  Helpers
// ======================================================================

namespace
{

class TempDir
{
public:
    TempDir()
        : m_path(
              std::filesystem::temp_directory_path()
              / std::filesystem::path("cmstore_test_" + std::to_string(::getpid()) + "_" + std::to_string(std::rand())))
    {
        std::filesystem::create_directories(m_path);
    }

    ~TempDir() { std::filesystem::remove_all(m_path); }

    const std::filesystem::path& path() const { return m_path; }

private:
    std::filesystem::path m_path;
};

void writeFile(const std::filesystem::path& path, std::string_view content)
{
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path);
    out << content;
}

void writeOutputFile(const std::filesystem::path& path, std::string_view name)
{
    std::ofstream out(path);
    out << "name: " << name << "\n";
    out << "metadata:\n";
    out << "  title: test output\n";
    out << "enabled: true\n";
    out << "outputs:\n";
    out << "  - file: alerts\n";
}

} // namespace

// ======================================================================
//  NamespaceId
// ======================================================================

TEST(NamespaceIdTest, ValidNames)
{
    EXPECT_NO_THROW(cm::store::NamespaceId("test"));
    EXPECT_NO_THROW(cm::store::NamespaceId("namespace_1"));
    EXPECT_NO_THROW(cm::store::NamespaceId("ABC123"));
    EXPECT_NO_THROW(cm::store::NamespaceId("a"));
}

TEST(NamespaceIdTest, InvalidNamesThrow)
{
    EXPECT_THROW(cm::store::NamespaceId(""), std::runtime_error);
    EXPECT_THROW(cm::store::NamespaceId("has space"), std::runtime_error);
    EXPECT_THROW(cm::store::NamespaceId("illegal-dash"), std::runtime_error);
    EXPECT_THROW(cm::store::NamespaceId("dot.name"), std::runtime_error);
    EXPECT_THROW(cm::store::NamespaceId("path/traversal"), std::runtime_error);
}

TEST(NamespaceIdTest, EqualityAndInequality)
{
    cm::store::NamespaceId a("alpha");
    cm::store::NamespaceId b("alpha");
    cm::store::NamespaceId c("beta");

    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

TEST(NamespaceIdTest, ToStrReturnsOriginal)
{
    cm::store::NamespaceId ns("my_ns");
    EXPECT_EQ(ns.toStr(), "my_ns");
}

TEST(NamespaceIdTest, HashWorks)
{
    std::hash<cm::store::NamespaceId> hasher;
    cm::store::NamespaceId a("test");
    cm::store::NamespaceId b("test");
    EXPECT_EQ(hasher(a), hasher(b));
}

// ======================================================================
//  ResourceType conversions
// ======================================================================

TEST(ResourceTypeTest, RoundTripConversion)
{
    using cm::store::ResourceType;
    using cm::store::resourceTypeFromString;
    using cm::store::resourceTypeToString;

    EXPECT_EQ(resourceTypeFromString("decoder"), ResourceType::DECODER);
    EXPECT_EQ(resourceTypeFromString("output"), ResourceType::OUTPUT);
    EXPECT_EQ(resourceTypeFromString("filter"), ResourceType::FILTER);
    EXPECT_EQ(resourceTypeFromString("integration"), ResourceType::INTEGRATION);
    EXPECT_EQ(resourceTypeFromString("kvdb"), ResourceType::KVDB);
    EXPECT_EQ(resourceTypeFromString("unknown"), ResourceType::UNDEFINED);
    EXPECT_EQ(resourceTypeFromString(""), ResourceType::UNDEFINED);

    EXPECT_EQ(resourceTypeToString(ResourceType::DECODER), "decoder");
    EXPECT_EQ(resourceTypeToString(ResourceType::OUTPUT), "output");
    EXPECT_EQ(resourceTypeToString(ResourceType::FILTER), "filter");
    EXPECT_EQ(resourceTypeToString(ResourceType::INTEGRATION), "integration");
    EXPECT_EQ(resourceTypeToString(ResourceType::KVDB), "kvdb");
    EXPECT_EQ(resourceTypeToString(ResourceType::UNDEFINED), "undefined");
}

TEST(ResourceTypeTest, GetResourceTypeFromAssetName)
{
    using cm::store::getResourceTypeFromAssetName;
    using cm::store::ResourceType;

    EXPECT_EQ(getResourceTypeFromAssetName(base::Name("decoder/test/0")), ResourceType::DECODER);
    EXPECT_EQ(getResourceTypeFromAssetName(base::Name("output/test/0")), ResourceType::OUTPUT);
    EXPECT_EQ(getResourceTypeFromAssetName(base::Name("filter/test/0")), ResourceType::FILTER);
    EXPECT_EQ(getResourceTypeFromAssetName(base::Name("integration/test/0")), ResourceType::INTEGRATION);
    EXPECT_EQ(getResourceTypeFromAssetName(base::Name("kvdb/test/0")), ResourceType::UNDEFINED);
    EXPECT_EQ(getResourceTypeFromAssetName(base::Name("single")), ResourceType::UNDEFINED);
}

// ======================================================================
//  Categories
// ======================================================================

TEST(CategoriesTest, ExistingCategoriesFound)
{
    EXPECT_TRUE(cm::store::categories::exists("security"));
    EXPECT_TRUE(cm::store::categories::exists("network-activity"));
    EXPECT_TRUE(cm::store::categories::exists("unclassified"));
}

TEST(CategoriesTest, UnknownCategoryNotFound)
{
    EXPECT_FALSE(cm::store::categories::exists("nonexistent"));
    EXPECT_FALSE(cm::store::categories::exists(""));
}

TEST(CategoriesTest, GetAvailableCategoriesNonEmpty)
{
    const auto& cats = cm::store::categories::getAvailableCategories();
    EXPECT_EQ(cats.size(), 8U);
}

// ======================================================================
//  CMStoreNS (with real filesystem)
// ======================================================================

class CMStoreNSTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_storageDir = std::make_unique<TempDir>();
        m_outputsDir = std::make_unique<TempDir>();
        std::filesystem::create_directories(m_outputsDir->path() / "default");

        // Write initial empty cache
        writeFile(m_storageDir->path() / "cache_ns.json", "[]");
    }

    std::unique_ptr<cm::store::CMStoreNS> makeStore()
    {
        return std::make_unique<cm::store::CMStoreNS>(
            cm::store::NamespaceId("test"), m_storageDir->path(), m_outputsDir->path());
    }

    const std::filesystem::path& storagePath() const { return m_storageDir->path(); }
    const std::filesystem::path& outputsPath() const { return m_outputsDir->path(); }

    std::unique_ptr<TempDir> m_storageDir;
    std::unique_ptr<TempDir> m_outputsDir;
};

TEST_F(CMStoreNSTest, ConstructionSucceeds)
{
    EXPECT_NO_THROW(makeStore());
}

TEST_F(CMStoreNSTest, GetNamespaceId)
{
    auto store = makeStore();
    EXPECT_EQ(store->getNamespaceId().toStr(), "test");
}

TEST_F(CMStoreNSTest, EmptyCollections)
{
    auto store = makeStore();
    EXPECT_TRUE(store->getCollection(cm::store::ResourceType::DECODER).empty());
    EXPECT_TRUE(store->getCollection(cm::store::ResourceType::KVDB).empty());
}

TEST_F(CMStoreNSTest, CreateAndGetDecoder)
{
    auto store = makeStore();

    std::string yml = R"(name: decoder/test/0
enabled: true
parents:
  - decoder/root/0
)";

    auto uuid = store->createResource("decoder/test/0", cm::store::ResourceType::DECODER, yml);
    EXPECT_FALSE(uuid.empty());

    // Verify it exists
    EXPECT_TRUE(store->assetExistsByName(base::Name("decoder/test/0")));
    EXPECT_TRUE(store->assetExistsByUUID(uuid));

    // Get by name
    auto asset = store->getAssetByName(base::Name("decoder/test/0"));
    std::string nameStr;
    EXPECT_EQ(asset.getString(nameStr, "/name"), json::RetGet::Success);
    EXPECT_EQ(nameStr, "decoder/test/0");

    // Get by UUID
    auto asset2 = store->getAssetByUUID(uuid);
    EXPECT_EQ(asset2.getString(nameStr, "/name"), json::RetGet::Success);
    EXPECT_EQ(nameStr, "decoder/test/0");
}

TEST_F(CMStoreNSTest, CreateDuplicateNameThrows)
{
    auto store = makeStore();

    std::string yml = R"(name: decoder/test/0
enabled: true
)";

    store->createResource("decoder/test/0", cm::store::ResourceType::DECODER, yml);
    EXPECT_THROW(store->createResource("decoder/test/0", cm::store::ResourceType::DECODER, yml), std::runtime_error);
}

TEST_F(CMStoreNSTest, ResolveUUIDFromName)
{
    auto store = makeStore();

    std::string yml = R"(name: filter/myfilter/0
enabled: true
type: pre-filter
)";

    auto uuid = store->createResource("filter/myfilter/0", cm::store::ResourceType::FILTER, yml);
    auto resolved = store->resolveUUIDFromName("filter/myfilter/0", cm::store::ResourceType::FILTER);
    EXPECT_EQ(uuid, resolved);
}

TEST_F(CMStoreNSTest, ResolveNameFromUUID)
{
    auto store = makeStore();

    std::string yml = R"(name: output/myout/0
enabled: true
outputs:
  - file: alerts
)";

    auto uuid = store->createResource("output/myout/0", cm::store::ResourceType::OUTPUT, yml);
    auto [name, type] = store->resolveNameFromUUID(uuid);
    EXPECT_EQ(name, "output/myout/0");
    EXPECT_EQ(type, cm::store::ResourceType::OUTPUT);
}

TEST_F(CMStoreNSTest, DeleteResourceByName)
{
    auto store = makeStore();

    std::string yml = R"(name: decoder/del/0
enabled: true
)";

    auto uuid = store->createResource("decoder/del/0", cm::store::ResourceType::DECODER, yml);
    EXPECT_TRUE(store->assetExistsByUUID(uuid));

    store->deleteResourceByName("decoder/del/0", cm::store::ResourceType::DECODER);
    EXPECT_FALSE(store->assetExistsByUUID(uuid));
}

TEST_F(CMStoreNSTest, DeleteResourceByUUID)
{
    auto store = makeStore();

    std::string yml = R"(name: filter/del/0
enabled: true
type: pre-filter
)";

    auto uuid = store->createResource("filter/del/0", cm::store::ResourceType::FILTER, yml);
    store->deleteResourceByUUID(uuid);
    EXPECT_FALSE(store->assetExistsByUUID(uuid));
}

TEST_F(CMStoreNSTest, DeleteNonexistentResourceThrows)
{
    auto store = makeStore();
    EXPECT_THROW(store->deleteResourceByName("no/such/0", cm::store::ResourceType::DECODER), std::runtime_error);
    EXPECT_THROW(store->deleteResourceByUUID("00000000-0000-4000-a000-000000000000"), std::runtime_error);
}

TEST_F(CMStoreNSTest, GetCollectionReturnsCreatedResources)
{
    auto store = makeStore();

    std::string dec1 = "name: decoder/a/0\nenabled: true\n";
    std::string dec2 = "name: decoder/b/0\nenabled: true\n";
    std::string flt1 = "name: filter/c/0\nenabled: true\ntype: pre-filter\n";

    store->createResource("decoder/a/0", cm::store::ResourceType::DECODER, dec1);
    store->createResource("decoder/b/0", cm::store::ResourceType::DECODER, dec2);
    store->createResource("filter/c/0", cm::store::ResourceType::FILTER, flt1);

    auto decoders = store->getCollection(cm::store::ResourceType::DECODER);
    EXPECT_EQ(decoders.size(), 2U);

    auto filters = store->getCollection(cm::store::ResourceType::FILTER);
    EXPECT_EQ(filters.size(), 1U);
}

TEST_F(CMStoreNSTest, AssetExistsByNameReturnsFalseForMissing)
{
    auto store = makeStore();
    EXPECT_FALSE(store->assetExistsByName(base::Name("decoder/missing/0")));
}

TEST_F(CMStoreNSTest, AssetExistsByUUIDReturnsFalseForMissing)
{
    auto store = makeStore();
    EXPECT_FALSE(store->assetExistsByUUID("00000000-0000-4000-a000-000000000000"));
}

TEST_F(CMStoreNSTest, CreateResourceWithExistingIDPreservesIt)
{
    auto store = makeStore();

    std::string existingUUID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
    std::string yml = "name: decoder/withid/0\nenabled: true\nid: " + existingUUID + "\n";

    auto uuid = store->createResource("decoder/withid/0", cm::store::ResourceType::DECODER, yml);
    EXPECT_EQ(uuid, existingUUID);
}

// ======================== Policy ========================

TEST_F(CMStoreNSTest, UpsertAndGetPolicy)
{
    auto store = makeStore();

    cm::store::dataType::Policy policy("Test Policy",
                                       true,
                                       "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                                       {},
                                       {},
                                       {"file", "ip"},
                                       {},
                                       "UNDEFINED",
                                       "",
                                       false,
                                       false,
                                       true);

    EXPECT_NO_THROW(store->upsertPolicy(policy));

    auto retrieved = store->getPolicy();
    EXPECT_EQ(retrieved.getTitle(), "Test Policy");
    EXPECT_TRUE(retrieved.isEnabled());
    EXPECT_EQ(retrieved.getRootDecoderUUID(), "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
}

TEST_F(CMStoreNSTest, DeletePolicy)
{
    auto store = makeStore();

    cm::store::dataType::Policy policy("ToDelete",
                                       true,
                                       "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
                                       {},
                                       {},
                                       {"file"},
                                       {},
                                       "UNDEFINED",
                                       "",
                                       false,
                                       false,
                                       true);

    store->upsertPolicy(policy);
    EXPECT_NO_THROW(store->deletePolicy());
    EXPECT_THROW(store->getPolicy(), std::runtime_error);
}

TEST_F(CMStoreNSTest, GetPolicyWhenNoneExistsThrows)
{
    auto store = makeStore();
    EXPECT_THROW(store->getPolicy(), std::runtime_error);
}

// ======================== Outputs for Space ========================

TEST_F(CMStoreNSTest, GetOutputsForSpaceFallsBackToDefaultDirectory)
{
    writeOutputFile(outputsPath() / "default" / "default-output.yml", "output/default/0");

    auto store = makeStore();
    const auto outputs = store->getOutputsForSpace("nonexistent_space");

    ASSERT_EQ(outputs.size(), 1U);
    std::string nameStr;
    ASSERT_EQ(outputs[0].getString(nameStr, "/name"), json::RetGet::Success);
    EXPECT_EQ(nameStr, "output/default/0");
}

TEST_F(CMStoreNSTest, GetOutputsForSpaceUsesSpaceDirectoryWhenPresent)
{
    std::filesystem::create_directories(outputsPath() / "standard");
    writeOutputFile(outputsPath() / "default" / "default-output.yml", "output/default/0");
    writeOutputFile(outputsPath() / "standard" / "space-output.yml", "output/standard/0");

    auto store = makeStore();
    const auto outputs = store->getOutputsForSpace("standard");

    ASSERT_EQ(outputs.size(), 1U);
    std::string nameStr;
    ASSERT_EQ(outputs[0].getString(nameStr, "/name"), json::RetGet::Success);
    EXPECT_EQ(nameStr, "output/standard/0");
}

TEST_F(CMStoreNSTest, GetOutputsForSpaceEmptyKeyFallsBackToDefault)
{
    writeOutputFile(outputsPath() / "default" / "out.yml", "output/def/0");

    auto store = makeStore();
    const auto outputs = store->getOutputsForSpace("");
    ASSERT_EQ(outputs.size(), 1U);
}

// ======================== Integration CRUD ========================

TEST_F(CMStoreNSTest, CreateAndGetIntegration)
{
    auto store = makeStore();

    std::string ymlContent = R"(id: "f47ac10b-58cc-4372-a567-0e02b2c3d479"
metadata:
  title: test_integration
enabled: true
category: security
decoders: []
kvdbs: []
)";

    auto uuid = store->createResource("test_integration", cm::store::ResourceType::INTEGRATION, ymlContent);
    EXPECT_FALSE(uuid.empty());

    auto integration = store->getIntegrationByName("test_integration");
    EXPECT_EQ(integration.getName(), "test_integration");
    EXPECT_EQ(integration.getCategory(), "security");
    EXPECT_TRUE(integration.isEnabled());

    auto integrationByUUID = store->getIntegrationByUUID(uuid);
    EXPECT_EQ(integrationByUUID.getName(), "test_integration");
}

TEST_F(CMStoreNSTest, GetIntegrationByNameNotFoundThrows)
{
    auto store = makeStore();
    EXPECT_THROW(store->getIntegrationByName("missing"), std::runtime_error);
}

TEST_F(CMStoreNSTest, GetIntegrationByUUIDNotFoundThrows)
{
    auto store = makeStore();
    EXPECT_THROW(store->getIntegrationByUUID("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"), std::runtime_error);
}

// ======================== KVDB CRUD ========================

TEST_F(CMStoreNSTest, CreateAndGetKVDB)
{
    auto store = makeStore();

    std::string ymlContent = R"(id: "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e"
metadata:
  title: test_kvdb
enabled: true
content:
  key1: value1
  key2: value2
)";

    auto uuid = store->createResource("test_kvdb", cm::store::ResourceType::KVDB, ymlContent);
    EXPECT_FALSE(uuid.empty());

    auto kvdb = store->getKVDBByName("test_kvdb");
    EXPECT_EQ(kvdb.getName(), "test_kvdb");
    EXPECT_TRUE(kvdb.isEnabled());

    auto kvdbByUUID = store->getKVDBByUUID(uuid);
    EXPECT_EQ(kvdbByUUID.getName(), "test_kvdb");
}

TEST_F(CMStoreNSTest, GetKVDBByNameNotFoundThrows)
{
    auto store = makeStore();
    EXPECT_THROW(store->getKVDBByName("missing"), std::runtime_error);
}

TEST_F(CMStoreNSTest, GetKVDBByUUIDNotFoundThrows)
{
    auto store = makeStore();
    EXPECT_THROW(store->getKVDBByUUID("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"), std::runtime_error);
}

// ======================== Cache persistence ========================

TEST_F(CMStoreNSTest, CacheSurvivesReinstantiation)
{
    std::string uuid;
    {
        auto store = makeStore();
        std::string yml = "name: decoder/persist/0\nenabled: true\n";
        uuid = store->createResource("decoder/persist/0", cm::store::ResourceType::DECODER, yml);
    }
    // Re-create store from same path — should reload cache from disk
    auto store2 = makeStore();
    EXPECT_TRUE(store2->assetExistsByUUID(uuid));
    EXPECT_TRUE(store2->assetExistsByName(base::Name("decoder/persist/0")));
}

// ======================== CMStore (top-level) ========================

class CMStoreTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_baseDir = std::make_unique<TempDir>();
        m_outputsDir = std::make_unique<TempDir>();
        std::filesystem::create_directories(m_outputsDir->path() / "default");
    }

    std::unique_ptr<cm::store::CMStore> makeStore()
    {
        return std::make_unique<cm::store::CMStore>(m_baseDir->path().string(), m_outputsDir->path().string());
    }

    std::unique_ptr<TempDir> m_baseDir;
    std::unique_ptr<TempDir> m_outputsDir;
};

TEST_F(CMStoreTest, ConstructionOnValidPathSucceeds)
{
    EXPECT_NO_THROW(makeStore());
}

TEST_F(CMStoreTest, ConstructionOnInvalidPathThrows)
{
    EXPECT_THROW(cm::store::CMStore("/nonexistent/path", m_outputsDir->path().string()), std::runtime_error);
}

TEST_F(CMStoreTest, ConstructionOnRelativePathThrows)
{
    EXPECT_THROW(cm::store::CMStore("relative/path", m_outputsDir->path().string()), std::runtime_error);
}

TEST_F(CMStoreTest, CreateAndListNamespaces)
{
    auto store = makeStore();
    EXPECT_TRUE(store->getNamespaces().empty());

    store->createNamespace(cm::store::NamespaceId("ns1"));
    store->createNamespace(cm::store::NamespaceId("ns2"));

    auto ns = store->getNamespaces();
    EXPECT_EQ(ns.size(), 2U);
}

TEST_F(CMStoreTest, ExistsNamespace)
{
    auto store = makeStore();

    EXPECT_FALSE(store->existsNamespace(cm::store::NamespaceId("ns1")));
    store->createNamespace(cm::store::NamespaceId("ns1"));
    EXPECT_TRUE(store->existsNamespace(cm::store::NamespaceId("ns1")));
}

TEST_F(CMStoreTest, CreateDuplicateNamespaceThrows)
{
    auto store = makeStore();
    store->createNamespace(cm::store::NamespaceId("dup"));
    EXPECT_THROW(store->createNamespace(cm::store::NamespaceId("dup")), std::runtime_error);
}

TEST_F(CMStoreTest, CreateForbiddenNamespaceThrows)
{
    auto store = makeStore();
    EXPECT_THROW(store->createNamespace(cm::store::NamespaceId("output")), std::runtime_error);
    EXPECT_THROW(store->createNamespace(cm::store::NamespaceId("system")), std::runtime_error);
    EXPECT_THROW(store->createNamespace(cm::store::NamespaceId("default")), std::runtime_error);
}

TEST_F(CMStoreTest, DeleteNamespace)
{
    auto store = makeStore();
    store->createNamespace(cm::store::NamespaceId("todelete"));
    EXPECT_TRUE(store->existsNamespace(cm::store::NamespaceId("todelete")));

    store->deleteNamespace(cm::store::NamespaceId("todelete"));
    EXPECT_FALSE(store->existsNamespace(cm::store::NamespaceId("todelete")));
}

TEST_F(CMStoreTest, DeleteNonexistentNamespaceThrows)
{
    auto store = makeStore();
    EXPECT_THROW(store->deleteNamespace(cm::store::NamespaceId("nonexistent")), std::runtime_error);
}

TEST_F(CMStoreTest, RenameNamespace)
{
    auto store = makeStore();
    store->createNamespace(cm::store::NamespaceId("oldname"));

    store->renameNamespace(cm::store::NamespaceId("oldname"), cm::store::NamespaceId("newname"));

    EXPECT_FALSE(store->existsNamespace(cm::store::NamespaceId("oldname")));
    EXPECT_TRUE(store->existsNamespace(cm::store::NamespaceId("newname")));
}

TEST_F(CMStoreTest, RenameToExistingNamespaceThrows)
{
    auto store = makeStore();
    store->createNamespace(cm::store::NamespaceId("a"));
    store->createNamespace(cm::store::NamespaceId("b"));

    EXPECT_THROW(store->renameNamespace(cm::store::NamespaceId("a"), cm::store::NamespaceId("b")), std::runtime_error);
}

TEST_F(CMStoreTest, RenameNonexistentNamespaceThrows)
{
    auto store = makeStore();
    EXPECT_THROW(store->renameNamespace(cm::store::NamespaceId("nope"), cm::store::NamespaceId("dest")),
                 std::runtime_error);
}

TEST_F(CMStoreTest, RenameToForbiddenNameThrows)
{
    auto store = makeStore();
    store->createNamespace(cm::store::NamespaceId("myns"));
    EXPECT_THROW(store->renameNamespace(cm::store::NamespaceId("myns"), cm::store::NamespaceId("system")),
                 std::runtime_error);
}

TEST_F(CMStoreTest, GetNSReader)
{
    auto store = makeStore();
    store->createNamespace(cm::store::NamespaceId("reader_ns"));

    auto reader = store->getNSReader(cm::store::NamespaceId("reader_ns"));
    ASSERT_NE(reader, nullptr);
    EXPECT_EQ(reader->getNamespaceId().toStr(), "reader_ns");
}

TEST_F(CMStoreTest, GetNSReaderNonexistentThrows)
{
    auto store = makeStore();
    EXPECT_THROW(store->getNSReader(cm::store::NamespaceId("missing")), std::runtime_error);
}

TEST_F(CMStoreTest, GetNS)
{
    auto store = makeStore();
    store->createNamespace(cm::store::NamespaceId("writable"));

    auto ns = store->getNS(cm::store::NamespaceId("writable"));
    ASSERT_NE(ns, nullptr);
    EXPECT_EQ(ns->getNamespaceId().toStr(), "writable");
}

TEST_F(CMStoreTest, GetNSNonexistentThrows)
{
    auto store = makeStore();
    EXPECT_THROW(store->getNS(cm::store::NamespaceId("missing")), std::runtime_error);
}

TEST_F(CMStoreTest, LoadExistingNamespacesFromDisk)
{
    // Create a namespace directory on disk first
    auto nsPath = m_baseDir->path() / "preexisting";
    std::filesystem::create_directories(nsPath);
    writeFile(nsPath / "cache_ns.json", "[]");

    auto store = makeStore();
    EXPECT_TRUE(store->existsNamespace(cm::store::NamespaceId("preexisting")));
}

TEST_F(CMStoreTest, ForbiddenNamespacesOnDiskAreSkipped)
{
    // Create forbidden-named dirs on disk
    for (const auto& name : {"output", "system", "default"})
    {
        auto nsPath = m_baseDir->path() / name;
        std::filesystem::create_directories(nsPath);
        writeFile(nsPath / "cache_ns.json", "[]");
    }

    auto store = makeStore();
    EXPECT_FALSE(store->existsNamespace(cm::store::NamespaceId("output")));
    EXPECT_FALSE(store->existsNamespace(cm::store::NamespaceId("system")));
    EXPECT_FALSE(store->existsNamespace(cm::store::NamespaceId("default")));
}

// ======================== Data type tests ========================

TEST(IntegrationTest, FromJsonValid)
{
    json::Json j;
    j.setString("f47ac10b-58cc-4372-a567-0e02b2c3d479", "/id");
    j.setString("my_integration", "/metadata/title");
    j.setBool(true, "/enabled");
    j.setString("security", "/category");
    j.setArray("/decoders");
    j.setArray("/kvdbs");

    EXPECT_NO_THROW(cm::store::dataType::Integration::fromJson(j, true));
}

TEST(IntegrationTest, FromJsonMissingNameThrows)
{
    json::Json j;
    j.setString("f47ac10b-58cc-4372-a567-0e02b2c3d479", "/id");
    j.setBool(true, "/enabled");
    j.setString("security", "/category");
    j.setArray("/decoders");
    j.setArray("/kvdbs");

    EXPECT_THROW(cm::store::dataType::Integration::fromJson(j, true), std::runtime_error);
}

TEST(IntegrationTest, FromJsonInvalidCategoryThrows)
{
    json::Json j;
    j.setString("f47ac10b-58cc-4372-a567-0e02b2c3d479", "/id");
    j.setString("my_integration", "/metadata/title");
    j.setBool(true, "/enabled");
    j.setString("invalid_category", "/category");
    j.setArray("/decoders");
    j.setArray("/kvdbs");

    EXPECT_THROW(cm::store::dataType::Integration::fromJson(j, true), std::runtime_error);
}

TEST(IntegrationTest, ToJsonRoundTrip)
{
    json::Json j;
    j.setString("f47ac10b-58cc-4372-a567-0e02b2c3d479", "/id");
    j.setString("round_trip", "/metadata/title");
    j.setBool(false, "/enabled");
    j.setString("other", "/category");
    j.setArray("/decoders");
    j.setArray("/kvdbs");

    auto integration = cm::store::dataType::Integration::fromJson(j, true);
    auto serialized = integration.toJson();

    std::string name;
    EXPECT_EQ(serialized.getString(name, "/metadata/title"), json::RetGet::Success);
    EXPECT_EQ(name, "round_trip");
}

TEST(KVDBTest, FromJsonValid)
{
    json::Json j;
    j.setString("b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e", "/id");
    j.setString("test_kvdb", "/metadata/title");
    j.setBool(true, "/enabled");
    json::Json content;
    content.setString("val1", "/key1");
    j.set("/content", content);

    EXPECT_NO_THROW(cm::store::dataType::KVDB::fromJson(j, true));
}

TEST(KVDBTest, FromJsonMissingContentThrows)
{
    json::Json j;
    j.setString("b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e", "/id");
    j.setString("test_kvdb", "/metadata/title");
    j.setBool(true, "/enabled");

    EXPECT_THROW(cm::store::dataType::KVDB::fromJson(j, true), std::runtime_error);
}

TEST(KVDBTest, ToJsonRoundTrip)
{
    json::Json j;
    j.setString("b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e", "/id");
    j.setString("kvdb_rt", "/metadata/title");
    j.setBool(true, "/enabled");
    json::Json content;
    content.setString("v", "/k");
    j.set("/content", content);

    auto kvdb = cm::store::dataType::KVDB::fromJson(j, true);
    auto serialized = kvdb.toJson();

    std::string name;
    EXPECT_EQ(serialized.getString(name, "/metadata/title"), json::RetGet::Success);
    EXPECT_EQ(name, "kvdb_rt");
}

TEST(PolicyTest, FromJsonValid)
{
    json::Json j;
    j.setString("Test Policy", "/metadata/title");
    j.setBool(true, "/enabled");
    j.setString("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", "/root_decoder");
    j.setArray("/integrations");
    j.setArray("/filters");
    j.setArray("/enrichments");
    j.setString("myspace", "/origin_space");
    j.setBool(false, "/index_unclassified_events");
    j.setBool(false, "/index_discarded_events");
    j.setBool(true, "/cleanup_decoder_variables");

    EXPECT_NO_THROW(cm::store::dataType::Policy::fromJson(j));
}

TEST(PolicyTest, FromJsonMissingEnabledThrows)
{
    json::Json j;
    j.setString("Policy", "/metadata/title");
    j.setString("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", "/root_decoder");
    j.setArray("/integrations");
    j.setArray("/filters");
    j.setArray("/enrichments");
    j.setBool(false, "/index_unclassified_events");
    j.setBool(false, "/index_discarded_events");

    EXPECT_THROW(cm::store::dataType::Policy::fromJson(j), std::runtime_error);
}

TEST(PolicyTest, ToJsonRoundTrip)
{
    json::Json j;
    j.setString("Round Trip", "/metadata/title");
    j.setBool(true, "/enabled");
    j.setString("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", "/root_decoder");
    j.setArray("/integrations");
    j.setArray("/filters");
    j.setArray("/enrichments");
    j.setString("space1", "/origin_space");
    j.setBool(true, "/index_unclassified_events");
    j.setBool(false, "/index_discarded_events");
    j.setBool(true, "/cleanup_decoder_variables");

    auto policy = cm::store::dataType::Policy::fromJson(j);
    auto serialized = policy.toJson();

    std::string title;
    EXPECT_EQ(serialized.getString(title, "/metadata/title"), json::RetGet::Success);
    EXPECT_EQ(title, "Round Trip");
    EXPECT_TRUE(policy.shouldIndexUnclassifiedEvents());
    EXPECT_FALSE(policy.shouldIndexDiscardedEvents());
    EXPECT_TRUE(policy.shouldCleanupDecoderVariables());
}
