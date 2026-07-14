#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <unistd.h>

#include <base/logging.hpp>
#include <base/name.hpp>
#include <base/utils/generator.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cmstore/cmstore.hpp>
#include <cmstore/types.hpp>

#include "fileutils.hpp"
#include "storens.hpp"

namespace
{

class CMStoreNSJsonTest : public ::testing::Test
{
protected:
    std::filesystem::path m_root;
    std::filesystem::path m_outputs;

    void SetUp() override
    {
        logging::testInit();
        const auto suffix = base::utils::generators::generateUUIDv4();
        m_root = std::filesystem::temp_directory_path() / ("cmstore-test-" + suffix);
        m_outputs = m_root / "default_outputs";

        std::filesystem::create_directories(m_root);
        std::filesystem::create_directories(m_outputs);
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(m_root, ec);
    }
};

} // namespace

TEST_F(CMStoreNSJsonTest, CreateResourcePersistsJsonAndGetterReadsItBack)
{
    cm::store::CMStoreNS store {cm::store::NamespaceId("test"), m_root, m_outputs};

    json::Json payload;
    payload.setObject();
    payload.setString("decoder/syslog/0", "/name");
    payload.setString("3f086ce2-32a4-42b0-be7e-40dcfb9c6160", "/id");
    payload.setObject("/metadata");
    payload.setString("syslog", "/metadata/module");

    const auto uuid = store.createResource("decoder/syslog/0", cm::store::ResourceType::DECODER, payload);

    EXPECT_EQ(uuid, "3f086ce2-32a4-42b0-be7e-40dcfb9c6160");

    const auto resourcePath = m_root / "decoders" / "decoder_syslog_0.json";
    std::ifstream persistedFile(resourcePath);
    ASSERT_TRUE(persistedFile.is_open());
    const std::string persisted((std::istreambuf_iterator<char>(persistedFile)), std::istreambuf_iterator<char>());
    EXPECT_THAT(persisted, ::testing::HasSubstr("\"name\":\"decoder/syslog/0\""));
    EXPECT_THAT(persisted, ::testing::HasSubstr("\"id\":\"3f086ce2-32a4-42b0-be7e-40dcfb9c6160\""));

    const auto asset = store.getAssetByName(base::Name {"decoder/syslog/0"});
    std::string name;
    EXPECT_EQ(asset.getString(name, "/name"), json::RetGet::Success);
    EXPECT_EQ(name, "decoder/syslog/0");
    std::string id;
    EXPECT_EQ(asset.getString(id, "/id"), json::RetGet::Success);
    EXPECT_EQ(id, "3f086ce2-32a4-42b0-be7e-40dcfb9c6160");
}

TEST_F(CMStoreNSJsonTest, JsonResourcesOnDiskAreLoadedDuringStoreInitialization)
{
    std::filesystem::create_directories(m_root / "decoders");

    const auto jsonPath = m_root / "decoders" / "decoder_syslog_0.json";
    std::ofstream jsonFile(jsonPath);
    ASSERT_TRUE(jsonFile.is_open());
    jsonFile
        << R"({"name":"decoder/syslog/0","id":"3f086ce2-32a4-42b0-be7e-40dcfb9c6160","metadata":{"module":"syslog"}})";
    jsonFile.close();

    cm::store::CMStoreNS store {cm::store::NamespaceId("test"), m_root, m_outputs};

    const auto asset = store.getAssetByName(base::Name {"decoder/syslog/0"});
    std::string name;
    EXPECT_EQ(asset.getString(name, "/name"), json::RetGet::Success);
    EXPECT_EQ(name, "decoder/syslog/0");
    std::string id;
    EXPECT_EQ(asset.getString(id, "/id"), json::RetGet::Success);
    EXPECT_EQ(id, "3f086ce2-32a4-42b0-be7e-40dcfb9c6160");
}

TEST_F(CMStoreNSJsonTest, DefaultOutputsYamlAreConvertedToJson)
{
    std::filesystem::create_directories(m_outputs / "default");

    std::ofstream outputFile(m_outputs / "default" / "stdout.yml");
    ASSERT_TRUE(outputFile.is_open());
    outputFile << "name: output/stdout\n";
    outputFile << "enabled: true\n";
    outputFile << "batch: 5\n";
    outputFile.close();

    cm::store::CMStoreNS store {cm::store::NamespaceId("test"), m_root, m_outputs};

    const auto outputs = store.getOutputsForSpace("");
    ASSERT_EQ(outputs.size(), 1u);
    std::string name;
    EXPECT_EQ(outputs[0].getString(name, "/name"), json::RetGet::Success);
    EXPECT_EQ(name, "output/stdout");
    ASSERT_TRUE(outputs[0].getBool("/enabled").has_value());
    EXPECT_TRUE(outputs[0].getBool("/enabled").value());
    ASSERT_TRUE(outputs[0].getInt("/batch").has_value());
    EXPECT_EQ(outputs[0].getInt("/batch").value(), 5);
}

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

json::Json makeResourceJson(std::string_view name, std::string_view uuid = "", bool enabled = true)
{
    json::Json resource;
    resource.setObject();
    resource.setString(name, "/name");
    resource.setBool(enabled, "/enabled");
    if (!uuid.empty())
    {
        resource.setString(uuid, "/id");
    }
    return resource;
}

json::Json makeDecoderJson(std::string_view name, std::string_view uuid = "", bool enabled = true)
{
    auto decoder = makeResourceJson(name, uuid, enabled);
    decoder.setArray("/parents");
    decoder.appendString("decoder/root/0", "/parents");
    return decoder;
}

json::Json makeFilterJson(std::string_view name, std::string_view uuid = "", bool enabled = true)
{
    auto filter = makeResourceJson(name, uuid, enabled);
    filter.setString("pre-filter", "/type");
    return filter;
}

json::Json makeOutputJson(std::string_view name, std::string_view uuid = "", bool enabled = true)
{
    auto output = makeResourceJson(name, uuid, enabled);
    json::Json fileOutput;
    fileOutput.setObject();
    fileOutput.setString("alerts", "/file");
    output.setArray("/outputs");
    output.appendJson(fileOutput, "/outputs");
    return output;
}

json::Json makeIntegrationJson(std::string_view name,
                               std::string_view uuid,
                               std::string_view category = "security",
                               bool enabled = true)
{
    json::Json integration;
    integration.setObject();
    integration.setString(uuid, "/id");
    integration.setString(name, "/metadata/title");
    integration.setBool(enabled, "/enabled");
    integration.setString(category, "/category");
    integration.setArray("/decoders");
    integration.setArray("/kvdbs");
    return integration;
}

json::Json makeKVDBJson(std::string_view name, std::string_view uuid, bool enabled = true)
{
    json::Json kvdb;
    kvdb.setObject();
    kvdb.setString(uuid, "/id");
    kvdb.setString(name, "/metadata/title");
    kvdb.setBool(enabled, "/enabled");
    kvdb.setString("value1", "/content/key1");
    kvdb.setString("value2", "/content/key2");
    return kvdb;
}

std::string validUUID()
{
    return base::utils::generators::generateUUIDv4();
}

json::Json makeValidIntegrationJson(bool includeId = true)
{
    json::Json j;
    if (includeId)
    {
        j.setString(validUUID(), "/id");
    }
    j.setString("my_integration", "/metadata/title");
    j.setBool(true, "/enabled");
    j.setString("security", "/category");
    j.setArray("/decoders");
    j.setArray("/kvdbs");
    return j;
}

json::Json makeValidPolicyJson()
{
    json::Json j;
    j.setString("Test Policy", "/metadata/title");
    j.setBool(true, "/enabled");
    j.setString(validUUID(), "/root_decoder");
    j.setArray("/integrations");
    j.setArray("/filters");
    j.setArray("/enrichments");
    j.setBool(false, "/index_unclassified_events");
    j.setBool(false, "/index_discarded_events");
    return j;
}

json::Json makeMinimalResourceJson()
{
    json::Json j;
    j.setObject();
    j.setString(base::utils::generators::generateUUIDv4(), "/id");
    return j;
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

TEST(IntegrationTest, ConstructorValidData)
{
    EXPECT_NO_THROW(cm::store::dataType::Integration(validUUID(), "name", true, "security", std::nullopt, {}, {}));
}

TEST(IntegrationTest, ConstructorEmptyUUIDRequiredThrows)
{
    EXPECT_THROW(cm::store::dataType::Integration("", "name", true, "security", std::nullopt, {}, {}, true),
                 std::runtime_error);
}

TEST(IntegrationTest, ConstructorEmptyUUIDNotRequired)
{
    EXPECT_NO_THROW(cm::store::dataType::Integration("", "name", true, "security", std::nullopt, {}, {}, false));
}

TEST(IntegrationTest, ConstructorInvalidUUIDThrows)
{
    EXPECT_THROW(cm::store::dataType::Integration("not-a-uuid", "name", true, "security", std::nullopt, {}, {}),
                 std::runtime_error);
}

TEST(IntegrationTest, ConstructorEmptyNameThrows)
{
    EXPECT_THROW(cm::store::dataType::Integration(validUUID(), "", true, "security", std::nullopt, {}, {}),
                 std::runtime_error);
}

TEST(IntegrationTest, ConstructorEmptyCategoryThrows)
{
    EXPECT_THROW(cm::store::dataType::Integration(validUUID(), "name", true, "", std::nullopt, {}, {}),
                 std::runtime_error);
}

TEST(IntegrationTest, ConstructorInvalidCategoryThrows)
{
    EXPECT_THROW(cm::store::dataType::Integration(validUUID(), "name", true, "invalid_category", std::nullopt, {}, {}),
                 std::runtime_error);
}

TEST(IntegrationTest, ConstructorInvalidDefaultParentThrows)
{
    EXPECT_THROW(
        cm::store::dataType::Integration(validUUID(), "name", true, "security", std::string("not-a-uuid"), {}, {}),
        std::runtime_error);
}

TEST(IntegrationTest, ConstructorDuplicateDecoderUUIDsThrows)
{
    const std::string uuid = validUUID();
    EXPECT_THROW(
        cm::store::dataType::Integration(validUUID(), "name", true, "security", std::nullopt, {}, {uuid, uuid}),
        std::runtime_error);
}

TEST(IntegrationTest, ConstructorDuplicateKVDBUUIDsThrows)
{
    const std::string uuid = validUUID();
    EXPECT_THROW(
        cm::store::dataType::Integration(validUUID(), "name", true, "security", std::nullopt, {uuid, uuid}, {}),
        std::runtime_error);
}

TEST(IntegrationTest, FromJsonWithDecodersAndKVDBs)
{
    auto j = makeValidIntegrationJson();
    j.appendString(validUUID(), "/decoders");
    j.appendString(validUUID(), "/kvdbs");

    auto integration = cm::store::dataType::Integration::fromJson(j, true);
    EXPECT_EQ(integration.getDecodersByUUID().size(), 1U);
    EXPECT_EQ(integration.getKVDBsByUUID().size(), 1U);
}

TEST(IntegrationTest, FromJsonWithDefaultParent)
{
    auto j = makeValidIntegrationJson();
    const std::string parent = validUUID();
    j.setString(parent, "/default_parent");

    auto integration = cm::store::dataType::Integration::fromJson(j, true);
    ASSERT_TRUE(integration.hasDefaultParent());
    EXPECT_EQ(*integration.getDefaultParent(), parent);
}

TEST(IntegrationTest, FromJsonMissingIdRequiredThrows)
{
    auto j = makeValidIntegrationJson(false);
    EXPECT_THROW(cm::store::dataType::Integration::fromJson(j, true), std::runtime_error);
}

TEST(IntegrationTest, FromJsonInvalidIdRequiredThrows)
{
    auto j = makeValidIntegrationJson(false);
    j.setString("not-a-valid-uuid", "/id");
    EXPECT_THROW(cm::store::dataType::Integration::fromJson(j, true), std::runtime_error);
}

TEST(IntegrationTest, FromJsonMissingIdNotRequired)
{
    auto j = makeValidIntegrationJson(false);
    EXPECT_NO_THROW(cm::store::dataType::Integration::fromJson(j, false));
}

TEST(IntegrationTest, FromJsonMissingNameThrows)
{
    auto j = makeValidIntegrationJson();
    j.erase("/metadata/title");
    EXPECT_THROW(cm::store::dataType::Integration::fromJson(j, true), std::runtime_error);
}

TEST(IntegrationTest, FromJsonInvalidNameTypeThrows)
{
    auto j = makeValidIntegrationJson();
    j.setBool(true, "/metadata/title");
    EXPECT_THROW(cm::store::dataType::Integration::fromJson(j, true), std::runtime_error);
}

TEST(IntegrationTest, FromJsonMissingEnabledThrows)
{
    auto j = makeValidIntegrationJson();
    j.erase("/enabled");
    EXPECT_THROW(cm::store::dataType::Integration::fromJson(j, true), std::runtime_error);
}

TEST(IntegrationTest, FromJsonInvalidEnabledTypeThrows)
{
    auto j = makeValidIntegrationJson();
    j.setString("true", "/enabled");
    EXPECT_THROW(cm::store::dataType::Integration::fromJson(j, true), std::runtime_error);
}

TEST(IntegrationTest, FromJsonMissingCategoryThrows)
{
    auto j = makeValidIntegrationJson();
    j.erase("/category");
    EXPECT_THROW(cm::store::dataType::Integration::fromJson(j, true), std::runtime_error);
}

TEST(IntegrationTest, FromJsonInvalidCategoryTypeThrows)
{
    auto j = makeValidIntegrationJson();
    j.setBool(true, "/category");
    EXPECT_THROW(cm::store::dataType::Integration::fromJson(j, true), std::runtime_error);
}

TEST(IntegrationTest, FromJsonDecoderEntryNotStringThrows)
{
    auto j = makeValidIntegrationJson();
    j.appendJson(json::Json("42"), "/decoders");
    EXPECT_THROW(cm::store::dataType::Integration::fromJson(j, true), std::runtime_error);
}

TEST(IntegrationTest, FromJsonKVDBEntryNotStringThrows)
{
    auto j = makeValidIntegrationJson();
    j.appendJson(json::Json("42"), "/kvdbs");
    EXPECT_THROW(cm::store::dataType::Integration::fromJson(j, true), std::runtime_error);
}

TEST(IntegrationTest, FromJsonEmptyDefaultParentThrows)
{
    auto j = makeValidIntegrationJson();
    j.setString("", "/default_parent");
    EXPECT_THROW(cm::store::dataType::Integration::fromJson(j, true), std::runtime_error);
}

TEST(IntegrationTest, FromJsonInvalidDefaultParentThrows)
{
    auto j = makeValidIntegrationJson();
    j.setString("not-a-valid-uuid", "/default_parent");
    EXPECT_THROW(cm::store::dataType::Integration::fromJson(j, true), std::runtime_error);
}

TEST(IntegrationTest, ToJsonWithDecodersKVDBsAndDefaultParent)
{
    const std::string decoderUUID = validUUID();
    const std::string kvdbUUID = validUUID();
    const std::string parentUUID = validUUID();

    cm::store::dataType::Integration integration(
        validUUID(), "name", true, "security", parentUUID, {kvdbUUID}, {decoderUUID});
    json::Json serialized = integration.toJson();

    std::string val;
    EXPECT_EQ(serialized.getString(val, "/default_parent"), json::RetGet::Success);
    EXPECT_EQ(val, parentUUID);

    EXPECT_EQ(serialized.getString(val, "/decoders/0"), json::RetGet::Success);
    EXPECT_EQ(val, decoderUUID);

    EXPECT_EQ(serialized.getString(val, "/kvdbs/0"), json::RetGet::Success);
    EXPECT_EQ(val, kvdbUUID);
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
        logging::testInit();
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

    auto uuid =
        store->createResource("decoder/test/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/test/0"));
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

    store->createResource("decoder/test/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/test/0"));
    EXPECT_THROW(
        store->createResource("decoder/test/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/test/0")),
        std::runtime_error);
}

TEST_F(CMStoreNSTest, ResolveUUIDFromName)
{
    auto store = makeStore();

    auto uuid = store->createResource(
        "filter/myfilter/0", cm::store::ResourceType::FILTER, makeFilterJson("filter/myfilter/0"));
    auto resolved = store->resolveUUIDFromName("filter/myfilter/0", cm::store::ResourceType::FILTER);
    EXPECT_EQ(uuid, resolved);
}

TEST_F(CMStoreNSTest, ResolveNameFromUUID)
{
    auto store = makeStore();

    auto uuid =
        store->createResource("output/myout/0", cm::store::ResourceType::OUTPUT, makeOutputJson("output/myout/0"));
    auto [name, type] = store->resolveNameFromUUID(uuid);
    EXPECT_EQ(name, "output/myout/0");
    EXPECT_EQ(type, cm::store::ResourceType::OUTPUT);
}

TEST_F(CMStoreNSTest, DeleteResourceByName)
{
    auto store = makeStore();

    auto uuid =
        store->createResource("decoder/del/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/del/0"));
    EXPECT_TRUE(store->assetExistsByUUID(uuid));

    store->deleteResourceByName("decoder/del/0", cm::store::ResourceType::DECODER);
    EXPECT_FALSE(store->assetExistsByUUID(uuid));
}

TEST_F(CMStoreNSTest, DeleteResourceByUUID)
{
    auto store = makeStore();

    auto uuid = store->createResource("filter/del/0", cm::store::ResourceType::FILTER, makeFilterJson("filter/del/0"));
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

    store->createResource("decoder/a/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/a/0"));
    store->createResource("decoder/b/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/b/0"));
    store->createResource("filter/c/0", cm::store::ResourceType::FILTER, makeFilterJson("filter/c/0"));

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
    auto uuid = store->createResource(
        "decoder/withid/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/withid/0", existingUUID));
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

    auto uuid = store->createResource("test_integration",
                                      cm::store::ResourceType::INTEGRATION,
                                      makeIntegrationJson("test_integration", "f47ac10b-58cc-4372-a567-0e02b2c3d479"));
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

    auto uuid = store->createResource(
        "test_kvdb", cm::store::ResourceType::KVDB, makeKVDBJson("test_kvdb", "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e"));
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
        uuid = store->createResource(
            "decoder/persist/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/persist/0"));
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
        logging::testInit();
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

TEST(KVDBTest, ConstructorValidData)
{
    json::Json content;
    content.setString("v", "/k");
    EXPECT_NO_THROW(cm::store::dataType::KVDB(validUUID(), "name", std::move(content), true));
}

TEST(KVDBTest, ConstructorEmptyUUIDRequiredThrows)
{
    json::Json content;
    content.setString("v", "/k");
    EXPECT_THROW(cm::store::dataType::KVDB("", "name", std::move(content), true, true), std::runtime_error);
}

TEST(KVDBTest, ConstructorEmptyUUIDNotRequired)
{
    json::Json content;
    content.setString("v", "/k");
    EXPECT_NO_THROW(cm::store::dataType::KVDB("", "name", std::move(content), true, false));
}

TEST(KVDBTest, ConstructorInvalidUUIDThrows)
{
    json::Json content;
    content.setString("v", "/k");
    EXPECT_THROW(cm::store::dataType::KVDB("not-a-uuid", "name", std::move(content), true, true), std::runtime_error);
}

TEST(KVDBTest, ConstructorEmptyNameThrows)
{
    json::Json content;
    content.setString("v", "/k");
    EXPECT_THROW(cm::store::dataType::KVDB(validUUID(), "", std::move(content), true), std::runtime_error);
}

TEST(KVDBTest, ConstructorContentNotObjectThrows)
{
    json::Json notObject("42");
    EXPECT_THROW(cm::store::dataType::KVDB(validUUID(), "name", std::move(notObject), true), std::runtime_error);
}

TEST(KVDBTest, FromJsonMissingIdRequiredThrows)
{
    json::Json j;
    j.setString("test_kvdb", "/metadata/title");
    j.setBool(true, "/enabled");
    json::Json content;
    content.setString("v", "/k");
    j.set("/content", content);

    EXPECT_THROW(cm::store::dataType::KVDB::fromJson(j, true), std::runtime_error);
}

TEST(KVDBTest, FromJsonInvalidIdRequiredThrows)
{
    json::Json j;
    j.setString("not-a-uuid", "/id");
    j.setString("test_kvdb", "/metadata/title");
    j.setBool(true, "/enabled");
    json::Json content;
    content.setString("v", "/k");
    j.set("/content", content);

    EXPECT_THROW(cm::store::dataType::KVDB::fromJson(j, true), std::runtime_error);
}

TEST(KVDBTest, FromJsonMissingTitleThrows)
{
    json::Json j;
    j.setString(validUUID(), "/id");
    j.setBool(true, "/enabled");
    json::Json content;
    content.setString("v", "/k");
    j.set("/content", content);

    EXPECT_THROW(cm::store::dataType::KVDB::fromJson(j, true), std::runtime_error);
}

TEST(KVDBTest, FromJsonInvalidTitleTypeThrows)
{
    json::Json j;
    j.setString(validUUID(), "/id");
    j.setBool(true, "/metadata/title");
    j.setBool(true, "/enabled");
    json::Json content;
    content.setString("v", "/k");
    j.set("/content", content);

    EXPECT_THROW(cm::store::dataType::KVDB::fromJson(j, true), std::runtime_error);
}

TEST(KVDBTest, FromJsonContentNotObjectThrows)
{
    json::Json j;
    j.setString(validUUID(), "/id");
    j.setString("test_kvdb", "/metadata/title");
    j.setBool(true, "/enabled");
    j.setString("not-an-object", "/content");

    EXPECT_THROW(cm::store::dataType::KVDB::fromJson(j, true), std::runtime_error);
}

TEST(KVDBTest, FromJsonMissingEnabledThrows)
{
    json::Json j;
    j.setString(validUUID(), "/id");
    j.setString("test_kvdb", "/metadata/title");
    json::Json content;
    content.setString("v", "/k");
    j.set("/content", content);

    EXPECT_THROW(cm::store::dataType::KVDB::fromJson(j, true), std::runtime_error);
}

TEST(KVDBTest, FromJsonEnabledNotBoolThrows)
{
    json::Json j;
    j.setString(validUUID(), "/id");
    j.setString("test_kvdb", "/metadata/title");
    j.setString("yes", "/enabled");
    json::Json content;
    content.setString("v", "/k");
    j.set("/content", content);

    EXPECT_THROW(cm::store::dataType::KVDB::fromJson(j, true), std::runtime_error);
}

TEST(KVDBTest, ToJsonPreservesAllFields)
{
    const std::string uuid = validUUID();
    json::Json content;
    content.setString("V1", "/k1");
    content.setString("V2", "/k2");

    cm::store::dataType::KVDB kvdb(uuid, "kvdb_full", std::move(content), false);
    auto serialized = kvdb.toJson();

    std::string idOut;
    EXPECT_EQ(serialized.getString(idOut, "/id"), json::RetGet::Success);
    EXPECT_EQ(idOut, uuid);

    std::string titleOut;
    EXPECT_EQ(serialized.getString(titleOut, "/metadata/title"), json::RetGet::Success);
    EXPECT_EQ(titleOut, "kvdb_full");

    EXPECT_EQ(serialized.getBool("/enabled"), std::optional<bool>(false));

    std::string v1, v2;
    EXPECT_EQ(serialized.getString(v1, "/content/k1"), json::RetGet::Success);
    EXPECT_EQ(v1, "V1");
    EXPECT_EQ(serialized.getString(v2, "/content/k2"), json::RetGet::Success);
    EXPECT_EQ(v2, "V2");
}

TEST(PolicyTest, ConstructorValidData)
{
    EXPECT_NO_THROW(cm::store::dataType::Policy("title",
                                                true,
                                                validUUID(),
                                                {validUUID(), validUUID()},
                                                {validUUID()},
                                                {"file"},
                                                {validUUID()},
                                                "my_space",
                                                "hash123",
                                                true,
                                                false,
                                                true));
}

TEST(PolicyTest, ConstructorInvalidOriginSpaceThrows)
{
    EXPECT_THROW(cm::store::dataType::Policy(
                     "title", true, validUUID(), {}, {}, {}, {}, "invalid space!", "", false, false, true),
                 std::runtime_error);
}

TEST(PolicyTest, ConstructorDuplicateIntegrationsThrows)
{
    const std::string uuid = validUUID();
    EXPECT_THROW(cm::store::dataType::Policy(
                     "title", true, validUUID(), {uuid, uuid}, {}, {}, {}, "UNDEFINED", "", false, false, true),
                 std::runtime_error);
}

TEST(PolicyTest, ConstructorDuplicateFiltersThrows)
{
    const std::string uuid = validUUID();
    EXPECT_THROW(cm::store::dataType::Policy(
                     "title", true, validUUID(), {}, {uuid, uuid}, {}, {}, "UNDEFINED", "", false, false, true),
                 std::runtime_error);
}

TEST(PolicyTest, ConstructorDuplicateOutputsThrows)
{
    const std::string uuid = validUUID();
    EXPECT_THROW(cm::store::dataType::Policy(
                     "title", true, validUUID(), {}, {}, {}, {uuid, uuid}, "UNDEFINED", "", false, false, true),
                 std::runtime_error);
}

TEST(PolicyTest, FromJsonWithAllCollections)
{
    auto j = makeValidPolicyJson();
    j.appendString(validUUID(), "/integrations");
    j.appendString(validUUID(), "/integrations");
    j.appendString(validUUID(), "/filters");
    j.appendString("file", "/enrichments");
    j.appendString("ip", "/enrichments");
    j.setArray("/outputs");
    j.appendString(validUUID(), "/outputs");
    j.setString("space1", "/origin_space");
    j.setString("hashvalue", "/hash");
    j.setBool(true, "/cleanup_decoder_variables");

    auto policy = cm::store::dataType::Policy::fromJson(j);
    EXPECT_EQ(policy.getIntegrationsUUIDs().size(), 2);
    EXPECT_EQ(policy.getFiltersUUIDs().size(), 1);
    EXPECT_EQ(policy.getEnrichments().size(), 2);
    EXPECT_EQ(policy.getOutputsUUIDs().size(), 1);
    EXPECT_EQ(policy.getOriginSpace(), "space1");
    EXPECT_EQ(policy.getHash(), "hashvalue");
}

TEST(PolicyTest, FromJsonMissingOriginSpaceUsesDefault)
{
    auto j = makeValidPolicyJson();
    auto policy = cm::store::dataType::Policy::fromJson(j);
    EXPECT_EQ(policy.getOriginSpace(), "UNDEFINED");
}

TEST(PolicyTest, FromJsonMissingHashEmpty)
{
    auto j = makeValidPolicyJson();
    auto policy = cm::store::dataType::Policy::fromJson(j);
    EXPECT_TRUE(policy.getHash().empty());
}

TEST(PolicyTest, FromJsonMissingCleanupUsesDefault)
{
    auto j = makeValidPolicyJson();
    auto policy = cm::store::dataType::Policy::fromJson(j);
    EXPECT_TRUE(policy.shouldCleanupDecoderVariables());
}

TEST(PolicyTest, FromJsonNonObjectThrows)
{
    json::Json j("[]");
    EXPECT_THROW(cm::store::dataType::Policy::fromJson(j), std::runtime_error);
}

TEST(PolicyTest, FromJsonMissingRootDecoderThrows)
{
    auto j = makeValidPolicyJson();
    j.erase("/root_decoder");
    EXPECT_THROW(cm::store::dataType::Policy::fromJson(j), std::runtime_error);
}

TEST(PolicyTest, FromJsonRootDecoderNullUUIDIsEmpty)
{
    auto j = makeValidPolicyJson();
    j.setNull("/root_decoder");

    auto p = cm::store::dataType::Policy::fromJson(j);
    EXPECT_TRUE(p.getRootDecoderUUID().empty());
}

 TEST(PolicyTest, FromJsonRootDecoderWrongTypeThrows)
 {
     auto j = makeValidPolicyJson();
     j.setInt(42, "/root_decoder");
     EXPECT_THROW(cm::store::dataType::Policy::fromJson(j), std::runtime_error);
 }

TEST(PolicyTest, FromJsonMissingIntegrationsThrows)
{
    auto j = makeValidPolicyJson();
    j.erase("/integrations");
    EXPECT_THROW(cm::store::dataType::Policy::fromJson(j), std::runtime_error);
}

TEST(PolicyTest, FromJsonIntegrationEntryNotStringThrows)
{
    auto j = makeValidPolicyJson();
    json::Json number("42");
    j.appendJson(number, "/integrations");
    EXPECT_THROW(cm::store::dataType::Policy::fromJson(j), std::runtime_error);
}

TEST(PolicyTest, FromJsonMissingFiltersThrows)
{
    auto j = makeValidPolicyJson();
    j.erase("/filters");
    EXPECT_THROW(cm::store::dataType::Policy::fromJson(j), std::runtime_error);
}

TEST(PolicyTest, FromJsonFilterEntryNotStringThrows)
{
    auto j = makeValidPolicyJson();
    json::Json number("7");
    j.appendJson(number, "/filters");
    EXPECT_THROW(cm::store::dataType::Policy::fromJson(j), std::runtime_error);
}

TEST(PolicyTest, FromJsonMissingEnrichmentsThrows)
{
    auto j = makeValidPolicyJson();
    j.erase("/enrichments");
    EXPECT_THROW(cm::store::dataType::Policy::fromJson(j), std::runtime_error);
}

TEST(PolicyTest, FromJsonEnrichmentEntryNotStringThrows)
{
    auto j = makeValidPolicyJson();
    json::Json number("123");
    j.appendJson(number, "/enrichments");
    EXPECT_THROW(cm::store::dataType::Policy::fromJson(j), std::runtime_error);
}

TEST(PolicyTest, FromJsonOutputEntryNotStringThrows)
{
    auto j = makeValidPolicyJson();
    j.setArray("/outputs");
    json::Json number("99");
    j.appendJson(number, "/outputs");
    EXPECT_THROW(cm::store::dataType::Policy::fromJson(j), std::runtime_error);
}

TEST(PolicyTest, FromJsonMissingEnabledThrows)
{
    auto j = makeValidPolicyJson();
    j.erase("/enabled");
    EXPECT_THROW(cm::store::dataType::Policy::fromJson(j), std::runtime_error);
}

TEST(PolicyTest, FromJsonIndexUnclassifiedMissingThrows)
{
    auto j = makeValidPolicyJson();
    j.erase("/index_unclassified_events");
    EXPECT_THROW(cm::store::dataType::Policy::fromJson(j), std::runtime_error);
}

TEST(PolicyTest, FromJsonIndexUnclassifiedNotBooleanThrows)
{
    auto j = makeValidPolicyJson();
    j.setString("false", "/index_unclassified_events");
    EXPECT_THROW(cm::store::dataType::Policy::fromJson(j), std::runtime_error);
}

TEST(PolicyTest, FromJsonIndexDiscardedMissingThrows)
{
    auto j = makeValidPolicyJson();
    j.erase("/index_discarded_events");
    EXPECT_THROW(cm::store::dataType::Policy::fromJson(j), std::runtime_error);
}

TEST(PolicyTest, FromJsonIndexDiscardedNotBooleanThrows)
{
    auto j = makeValidPolicyJson();
    j.setString("false", "/index_discarded_events");
    EXPECT_THROW(cm::store::dataType::Policy::fromJson(j), std::runtime_error);
}

TEST(PolicyTest, ToJsonNonEmptyCollections)
{
    const std::string root = validUUID();
    const std::string intA = validUUID();
    const std::string intB = validUUID();
    const std::string filterA = validUUID();
    const std::string outputA = validUUID();

    cm::store::dataType::Policy policy("Title",
                                       true,
                                       root,
                                       {intA, intB},
                                       {filterA},
                                       {"file", "ip"},
                                       {outputA},
                                       "my_space",
                                       "hash123",
                                       true,
                                       true,
                                       false);

    auto j = policy.toJson();

    std::string title;
    EXPECT_EQ(j.getString(title, "/metadata/title"), json::RetGet::Success);
    EXPECT_EQ(title, "Title");
    EXPECT_EQ(j.getBool("/enabled"), std::optional<bool>(true));
    EXPECT_EQ(j.getBool("/index_unclassified_events"), std::optional<bool>(true));
    EXPECT_EQ(j.getBool("/index_discarded_events"), std::optional<bool>(true));
    EXPECT_EQ(j.getBool("/cleanup_decoder_variables"), std::optional<bool>(false));

    std::string rootOut;
    EXPECT_EQ(j.getString(rootOut, "/root_decoder"), json::RetGet::Success);
    EXPECT_EQ(rootOut, root);

    std::string originSpace;
    EXPECT_EQ(j.getString(originSpace, "/origin_space"), json::RetGet::Success);
    EXPECT_EQ(originSpace, "my_space");

    std::string hash;
    EXPECT_EQ(j.getString(hash, "/hash"), json::RetGet::Success);
    EXPECT_EQ(hash, "hash123");

    EXPECT_TRUE(j.isArray("/integrations"));
    EXPECT_EQ(j.size("/integrations"), 2);
    EXPECT_TRUE(j.isArray("/filters"));
    EXPECT_EQ(j.size("/filters"), 1);
    EXPECT_TRUE(j.isArray("/enrichments"));
    EXPECT_EQ(j.size("/enrichments"), 2);
    EXPECT_TRUE(j.isArray("/outputs"));
    EXPECT_EQ(j.size("/outputs"), 1);
}

TEST(FileUtilsTest, IsValidFileNameAcceptsValid)
{
    EXPECT_TRUE(fileutils::isValidFileName("decoder_syslog_0.json"));
    EXPECT_TRUE(fileutils::isValidFileName("a"));
    EXPECT_TRUE(fileutils::isValidFileName("file-name.with.dots.txt"));
}

TEST(FileUtilsTest, IsValidFileNameRejectsEmpty)
{
    EXPECT_FALSE(fileutils::isValidFileName(""));
}

TEST(FileUtilsTest, IsValidFileNameRejectsInvalidChars)
{
    EXPECT_FALSE(fileutils::isValidFileName("bad:name"));
    EXPECT_FALSE(fileutils::isValidFileName("bad*name"));
    EXPECT_FALSE(fileutils::isValidFileName("bad?name"));
    EXPECT_FALSE(fileutils::isValidFileName("bad\"name"));
    EXPECT_FALSE(fileutils::isValidFileName("bad<name"));
    EXPECT_FALSE(fileutils::isValidFileName("bad>name"));
    EXPECT_FALSE(fileutils::isValidFileName("bad|name"));
}

TEST(FileUtilsTest, IsValidFileNameRejectsDots)
{
    EXPECT_FALSE(fileutils::isValidFileName("."));
    EXPECT_FALSE(fileutils::isValidFileName(".."));
}

TEST(FileUtilsTest, IsValidFileNameRejectsPathSeparators)
{
    EXPECT_FALSE(fileutils::isValidFileName("dir/file"));
    EXPECT_FALSE(fileutils::isValidFileName("dir\\file"));
    EXPECT_FALSE(fileutils::isValidFileName("/abs"));
}

TEST(FileUtilsTest, IsValidFileNameRejectsControlChars)
{
    EXPECT_FALSE(fileutils::isValidFileName(std::string("bad\x01name")));
    EXPECT_FALSE(fileutils::isValidFileName(std::string("bad\nname")));
    EXPECT_FALSE(fileutils::isValidFileName(std::string("bad\x7fname")));
}

TEST(FileUtilsTest, IsValidFileNameRejectsTooLong)
{
    EXPECT_TRUE(fileutils::isValidFileName(std::string(255, 'a')));
    EXPECT_FALSE(fileutils::isValidFileName(std::string(256, 'a')));
}

TEST(FileUtilsTest, ReadJsonFileValid)
{
    TempDir dir;
    const auto path = dir.path() / "data.json";
    writeFile(path, R"({"key":"value","num":42})");

    auto j = fileutils::readJsonFile(path);
    std::string value;
    EXPECT_EQ(j.getString(value, "/key"), json::RetGet::Success);
    EXPECT_EQ(value, "value");
}

TEST(FileUtilsTest, ReadJsonFileMissingThrows)
{
    TempDir dir;
    const auto path = dir.path() / "missing.json";
    EXPECT_THROW(fileutils::readJsonFile(path), std::runtime_error);
}

TEST(FileUtilsTest, ReadJsonFileInvalidThrows)
{
    TempDir dir;
    const auto path = dir.path() / "invalid.json";
    writeFile(path, "{not valid json");
    EXPECT_THROW(fileutils::readJsonFile(path), std::runtime_error);
}

TEST(FileUtilsTest, UpsertFileExistingDir)
{
    TempDir dir;
    const auto path = dir.path() / "file.txt";
    auto err = fileutils::upsertFile(path, "hello");
    EXPECT_FALSE(err.has_value());
    EXPECT_TRUE(std::filesystem::exists(path));
    EXPECT_EQ(fileutils::readFileAsString(path), "hello");
}

TEST(FileUtilsTest, UpsertFileCreatesParentDirs)
{
    TempDir dir;
    const auto path = dir.path() / "nested" / "deep" / "file.txt";
    auto err = fileutils::upsertFile(path, "content");
    EXPECT_FALSE(err.has_value());
    EXPECT_TRUE(std::filesystem::exists(path));
    EXPECT_EQ(fileutils::readFileAsString(path), "content");
}

TEST(FileUtilsTest, DeleteFileExisting)
{
    TempDir dir;
    const auto path = dir.path() / "file.txt";
    writeFile(path, "x");
    ASSERT_TRUE(std::filesystem::exists(path));

    auto err = fileutils::deleteFile(path);
    EXPECT_FALSE(err.has_value());
    EXPECT_FALSE(std::filesystem::exists(path));
}

TEST(FileUtilsTest, DeleteFileNonEmptyDirectoryReturnsError)
{
    TempDir dir;
    const auto subdir = dir.path() / "subdir";
    std::filesystem::create_directories(subdir);
    writeFile(subdir / "file.txt", "x");

    auto err = fileutils::deleteFile(subdir);
    EXPECT_TRUE(err.has_value());
}

TEST(FileUtilsTest, SetFilePermissionsOnMissingPathReturnsError)
{
    TempDir dir;
    auto err = fileutils::setFilePermissions(dir.path() / "missing.txt");
    EXPECT_TRUE(err.has_value());
}

TEST(FileUtilsTest, SetDirectoryPermissionsOnMissingPathReturnsError)
{
    TempDir dir;
    auto err = fileutils::setDirectoryPermissions(dir.path() / "missing_dir");
    EXPECT_TRUE(err.has_value());
}

TEST(FileUtilsTest, UpsertFileFailsWhenTargetIsExistingDirectory)
{
    TempDir dir;
    const auto target = dir.path() / "blocked.txt";
    std::filesystem::create_directories(target);

    auto err = fileutils::upsertFile(target, "data");
    ASSERT_TRUE(err.has_value());
    EXPECT_NE(err->find("Failed to open file for writing"), std::string::npos);
}

TEST(FileUtilsTest, UpsertFileFailsWhenParentPathIsRegularFile)
{
    TempDir dir;
    const auto blocker = dir.path() / "blocker";
    writeFile(blocker, "x");

    const auto target = blocker / "sub" / "child.txt";
    auto err = fileutils::upsertFile(target, "data");
    ASSERT_TRUE(err.has_value());
    EXPECT_NE(err->find("Failed to create parent directories"), std::string::npos);
}

TEST(FileUtilsTest, ReadYMLFileAsJsonMissingThrows)
{
    TempDir dir;
    EXPECT_THROW(fileutils::readYMLFileAsJson(dir.path() / "missing.yml"), std::runtime_error);
}

TEST(FileUtilsTest, ReadYMLFileAsJsonInvalidYAMLThrows)
{
    TempDir dir;
    const auto path = dir.path() / "bad.yml";
    writeFile(path, "key: value\n  bad: : indent\n: : :");
    EXPECT_THROW(fileutils::readYMLFileAsJson(path), std::runtime_error);
}

TEST(FileUtilsTest, ReadFileAsStringMissingThrows)
{
    TempDir dir;
    EXPECT_THROW(fileutils::readFileAsString(dir.path() / "missing.txt"), std::runtime_error);
}

TEST_F(CMStoreNSTest, RebuildCacheLoadsOutputsDirectory)
{
    std::filesystem::remove(storagePath() / "cache_ns.json");
    std::filesystem::create_directories(storagePath() / "outputs");
    writeFile(storagePath() / "outputs" / "output_x_0.json", makeMinimalResourceJson().str());

    auto store = makeStore();
    EXPECT_EQ(store->getCollection(cm::store::ResourceType::OUTPUT).size(), 1u);
}

TEST_F(CMStoreNSTest, RebuildCacheLoadsFiltersDirectory)
{
    std::filesystem::remove(storagePath() / "cache_ns.json");
    std::filesystem::create_directories(storagePath() / "filters");
    writeFile(storagePath() / "filters" / "filter_x_0.json", makeMinimalResourceJson().str());

    auto store = makeStore();
    EXPECT_EQ(store->getCollection(cm::store::ResourceType::FILTER).size(), 1u);
}

TEST_F(CMStoreNSTest, RebuildCacheLoadsIntegrationsDirectory)
{
    std::filesystem::remove(storagePath() / "cache_ns.json");
    std::filesystem::create_directories(storagePath() / "integrations");
    writeFile(storagePath() / "integrations" / "my_integration.json", makeMinimalResourceJson().str());

    auto store = makeStore();
    EXPECT_EQ(store->getCollection(cm::store::ResourceType::INTEGRATION).size(), 1u);
}

TEST_F(CMStoreNSTest, RebuildCacheLoadsKVDBsDirectory)
{
    std::filesystem::remove(storagePath() / "cache_ns.json");
    std::filesystem::create_directories(storagePath() / "kvdbs");
    writeFile(storagePath() / "kvdbs" / "my_kvdb.json", makeMinimalResourceJson().str());

    auto store = makeStore();
    EXPECT_EQ(store->getCollection(cm::store::ResourceType::KVDB).size(), 1u);
}

TEST_F(CMStoreNSTest, RebuildCacheSkipsNonRegularFileInsideResourceDir)
{
    std::filesystem::remove(storagePath() / "cache_ns.json");
    std::filesystem::create_directories(storagePath() / "decoders" / "subdir");
    writeFile(storagePath() / "decoders" / "decoder_ok_0.json", makeMinimalResourceJson().str());

    auto store = makeStore();
    EXPECT_EQ(store->getCollection(cm::store::ResourceType::DECODER).size(), 1u);
}

TEST_F(CMStoreNSTest, RebuildCacheSkipsFileWithInvalidExtension)
{
    std::filesystem::remove(storagePath() / "cache_ns.json");
    std::filesystem::create_directories(storagePath() / "decoders");
    writeFile(storagePath() / "decoders" / "foo.txt", makeMinimalResourceJson().str());
    writeFile(storagePath() / "decoders" / "decoder_ok_0.json", makeMinimalResourceJson().str());

    auto store = makeStore();
    EXPECT_EQ(store->getCollection(cm::store::ResourceType::DECODER).size(), 1u);
}

TEST_F(CMStoreNSTest, RebuildCacheSkipsFileWithInvalidJSON)
{
    std::filesystem::remove(storagePath() / "cache_ns.json");
    std::filesystem::create_directories(storagePath() / "decoders");
    writeFile(storagePath() / "decoders" / "decoder_bad_0.json", "{not json");
    writeFile(storagePath() / "decoders" / "decoder_ok_0.json", makeMinimalResourceJson().str());

    auto store = makeStore();
    EXPECT_EQ(store->getCollection(cm::store::ResourceType::DECODER).size(), 1u);
}

TEST_F(CMStoreNSTest, RebuildCacheSkipsFileWithExistingInvalidUUID)
{
    std::filesystem::remove(storagePath() / "cache_ns.json");
    std::filesystem::create_directories(storagePath() / "decoders");
    writeFile(storagePath() / "decoders" / "decoder_bad_0.json", R"({"id":"not-a-uuid"})");
    writeFile(storagePath() / "decoders" / "decoder_ok_0.json", makeMinimalResourceJson().str());

    auto store = makeStore();
    EXPECT_EQ(store->getCollection(cm::store::ResourceType::DECODER).size(), 1u);
}

TEST_F(CMStoreNSTest, CreateResourceWithNonObjectContentThrows)
{
    auto store = makeStore();
    json::Json arrayJson("[]");
    EXPECT_THROW(store->createResource("decoder/x/0", cm::store::ResourceType::DECODER, arrayJson), std::runtime_error);
}

TEST_F(CMStoreNSTest, CreateResourceWithInvalidNameThrows)
{
    auto store = makeStore();
    auto j = makeDecoderJson("decoder/with*star/0");
    EXPECT_THROW(store->createResource("decoder/with*star/0", cm::store::ResourceType::DECODER, j), std::runtime_error);
}

TEST_F(CMStoreNSTest, CreateResourceWithUndefinedTypeThrows)
{
    auto store = makeStore();
    json::Json j;
    j.setObject();
    EXPECT_THROW(store->createResource("validname", cm::store::ResourceType::UNDEFINED, j), std::runtime_error);
}

TEST_F(CMStoreNSTest, AssetExistsByNameThrowsWhenTypeUndefined)
{
    auto store = makeStore();
    EXPECT_THROW(store->assetExistsByName(base::Name("kvdb/x/0")), std::runtime_error);
}

TEST_F(CMStoreNSTest, AssetExistsByUUIDReturnsTrueForKVDB)
{
    auto store = makeStore();
    auto uuid = store->createResource("my_kvdb", cm::store::ResourceType::KVDB, makeKVDBJson("my_kvdb", validUUID()));
    EXPECT_TRUE(store->assetExistsByUUID(uuid));
}

TEST_F(CMStoreNSTest, CreateResourceFailsWhenFilePathBlockedByDirectory)
{
    auto store = makeStore();
    const auto path = storagePath() / "decoders" / "decoder_blocked_0.json";
    std::filesystem::create_directories(path);

    EXPECT_THROW(store->createResource(
                     "decoder/blocked/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/blocked/0")),
                 std::runtime_error);
}

TEST_F(CMStoreNSTest, UpdateResourceByNameFailsWhenWriteFails)
{
    auto store = makeStore();
    const auto uuid =
        store->createResource("decoder/upd/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/upd/0"));

    const auto path = storagePath() / "decoders" / "decoder_upd_0.json";
    std::filesystem::remove(path);
    std::filesystem::create_directories(path);

    auto j = makeDecoderJson("decoder/upd/0", uuid);
    EXPECT_THROW(store->updateResourceByName("decoder/upd/0", cm::store::ResourceType::DECODER, j), std::runtime_error);
}

TEST_F(CMStoreNSTest, UpdateResourceByUUIDFailsWhenWriteFails)
{
    auto store = makeStore();
    const auto uuid =
        store->createResource("decoder/upd2/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/upd2/0"));

    const auto path = storagePath() / "decoders" / "decoder_upd2_0.json";
    std::filesystem::remove(path);
    std::filesystem::create_directories(path);

    auto j = makeDecoderJson("decoder/upd2/0", uuid);
    EXPECT_THROW(store->updateResourceByUUID(uuid, j), std::runtime_error);
}

TEST_F(CMStoreNSTest, DeleteResourceByNameFailsWhenPathIsNonEmptyDir)
{
    auto store = makeStore();
    store->createResource("decoder/del/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/del/0"));

    const auto path = storagePath() / "decoders" / "decoder_del_0.json";
    std::filesystem::remove(path);
    std::filesystem::create_directories(path / "blocker");

    EXPECT_THROW(store->deleteResourceByName("decoder/del/0", cm::store::ResourceType::DECODER), std::runtime_error);
}

TEST_F(CMStoreNSTest, DeleteResourceByUUIDFailsWhenPathIsNonEmptyDir)
{
    auto store = makeStore();
    auto uuid =
        store->createResource("decoder/del2/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/del2/0"));

    const auto path = storagePath() / "decoders" / "decoder_del2_0.json";
    std::filesystem::remove(path);
    std::filesystem::create_directories(path / "blocker");

    EXPECT_THROW(store->deleteResourceByUUID(uuid), std::runtime_error);
}

TEST_F(CMStoreNSTest, UpdateResourceByNameMissingIdThrows)
{
    auto store = makeStore();
    store->createResource("decoder/upd3/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/upd3/0"));

    auto j = makeDecoderJson("decoder/upd3/0");
    EXPECT_THROW(store->updateResourceByName("decoder/upd3/0", cm::store::ResourceType::DECODER, j),
                 std::runtime_error);
}

TEST_F(CMStoreNSTest, UpdateResourceByUUIDMissingIdThrows)
{
    auto store = makeStore();
    auto uuid =
        store->createResource("decoder/upd4/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/upd4/0"));

    auto j = makeDecoderJson("decoder/upd4/0");
    EXPECT_THROW(store->updateResourceByUUID(uuid, j), std::runtime_error);
}

TEST_F(CMStoreNSTest, UpsertPolicyFailsWhenFilePathBlockedByDirectory)
{
    auto store = makeStore();
    std::filesystem::create_directories(storagePath() / "policy.json");

    EXPECT_THROW(store->upsertPolicy(cm::store::dataType::Policy {
                     "title", true, validUUID(), {}, {}, {}, {}, "UNDEFINED", "", false, false, true}),
                 std::runtime_error);
}

TEST_F(CMStoreNSTest, DeletePolicyFailsWhenPathIsNonEmptyDir)
{
    auto store = makeStore();
    std::filesystem::create_directories(storagePath() / "policy.json" / "blocker");

    EXPECT_THROW(store->deletePolicy(), std::runtime_error);
}

TEST_F(CMStoreNSTest, GetIntegrationByUUIDThrowsWhenTypeIsDecoder)
{
    auto store = makeStore();
    auto uuid =
        store->createResource("decoder/wrong/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/wrong/0"));

    EXPECT_THROW(store->getIntegrationByUUID(uuid), std::runtime_error);
}

TEST_F(CMStoreNSTest, GetKVDBByUUIDThrowsWhenTypeIsDecoder)
{
    auto store = makeStore();
    auto uuid = store->createResource(
        "decoder/wrong2/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/wrong2/0"));

    EXPECT_THROW(store->getKVDBByUUID(uuid), std::runtime_error);
}

TEST_F(CMStoreNSTest, GetOutputsSkipsSubdirectory)
{
    std::filesystem::create_directories(outputsPath() / "default" / "subdir");
    auto store = makeStore();
    auto outputs = store->getOutputsForSpace("");
    EXPECT_EQ(outputs.size(), 0u);
}

TEST_F(CMStoreNSTest, GetOutputsSkipsNonYamlFile)
{
    writeFile(outputsPath() / "default" / "ignore.txt", "data");
    auto store = makeStore();
    auto outputs = store->getOutputsForSpace("");
    EXPECT_EQ(outputs.size(), 0u);
}

TEST_F(CMStoreNSTest, GetOutputsThrowsOnInvalidYAML)
{
    writeFile(outputsPath() / "default" / "bad.yml", "key: value\n  bad: : indent\n: : :");
    auto store = makeStore();
    EXPECT_THROW(store->getOutputsForSpace(""), std::runtime_error);
}

TEST_F(CMStoreNSTest, ConstructionMissingStoragePathThrows)
{
    const auto missingPath = storagePath() / "missing_storage";
    EXPECT_THROW(cm::store::CMStoreNS(cm::store::NamespaceId("test"), missingPath, outputsPath()), std::runtime_error);
}

TEST_F(CMStoreNSTest, ConstructionStoragePathIsFileThrows)
{
    const auto filePath = storagePath() / "not_a_dir";
    writeFile(filePath, "x");
    EXPECT_THROW(cm::store::CMStoreNS(cm::store::NamespaceId("test"), filePath, outputsPath()), std::runtime_error);
}

TEST_F(CMStoreNSTest, ConstructionWrapsInitializationFailure)
{
    std::filesystem::remove(storagePath() / "cache_ns.json");
    std::filesystem::create_directories(storagePath() / "cache_ns.json");

    EXPECT_THROW(cm::store::CMStoreNS(cm::store::NamespaceId("test"), storagePath(), outputsPath()),
                 std::runtime_error);
}

TEST_F(CMStoreNSTest, TemplateGetResourceByNameWorksForSupportedTypes)
{
    auto store = makeStore();

    store->createResource(
        "decoder/template/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/template/0"));
    store->createResource("templ_integration",
                          cm::store::ResourceType::INTEGRATION,
                          makeIntegrationJson("templ_integration", validUUID()));
    store->createResource("templ_kvdb", cm::store::ResourceType::KVDB, makeKVDBJson("templ_kvdb", validUUID()));

    const auto& reader = static_cast<const cm::store::ICMStoreNSReader&>(*store);

    auto asset = reader.getResourceByName<json::Json>("decoder/template/0");
    auto integration = reader.getResourceByName<cm::store::dataType::Integration>("templ_integration");
    auto kvdb = reader.getResourceByName<cm::store::dataType::KVDB>("templ_kvdb");

    std::string nameStr;
    EXPECT_EQ(asset.getString(nameStr, "/name"), json::RetGet::Success);
    EXPECT_EQ(nameStr, "decoder/template/0");
    EXPECT_EQ(integration.getName(), "templ_integration");
    EXPECT_EQ(kvdb.getName(), "templ_kvdb");
}

TEST_F(CMStoreNSTest, TemplateGetResourceByUUIDWorksForSupportedTypes)
{
    auto store = makeStore();

    const auto assetUUID = store->createResource(
        "decoder/templateuuid/0", cm::store::ResourceType::DECODER, makeDecoderJson("decoder/templateuuid/0"));
    const auto integrationUUID = store->createResource("templ_uuid_integration",
                                                       cm::store::ResourceType::INTEGRATION,
                                                       makeIntegrationJson("templ_uuid_integration", validUUID()));
    const auto kvdbUUID = store->createResource(
        "templ_uuid_kvdb", cm::store::ResourceType::KVDB, makeKVDBJson("templ_uuid_kvdb", validUUID()));

    const auto& reader = static_cast<const cm::store::ICMStoreNSReader&>(*store);

    auto asset = reader.getResourceByUUID<json::Json>(assetUUID);
    auto integration = reader.getResourceByUUID<cm::store::dataType::Integration>(integrationUUID);
    auto kvdb = reader.getResourceByUUID<cm::store::dataType::KVDB>(kvdbUUID);

    std::string nameStr;
    EXPECT_EQ(asset.getString(nameStr, "/name"), json::RetGet::Success);
    EXPECT_EQ(nameStr, "decoder/templateuuid/0");
    EXPECT_EQ(integration.getName(), "templ_uuid_integration");
    EXPECT_EQ(kvdb.getName(), "templ_uuid_kvdb");
}

TEST_F(CMStoreTest, ConstructionOnMissingOutputsPathThrows)
{
    EXPECT_THROW(cm::store::CMStore(m_baseDir->path().string(), "/nonexistent/outputs"), std::runtime_error);
}

TEST_F(CMStoreTest, ConstructionOnOutputsPathThatIsFileThrows)
{
    const auto outputsFile = m_baseDir->path() / "outputs-file";
    writeFile(outputsFile, "x");
    EXPECT_THROW(cm::store::CMStore(m_baseDir->path().string(), outputsFile.string()), std::runtime_error);
}

TEST_F(CMStoreTest, ConstructionOnRelativeOutputsPathThrows)
{
    EXPECT_THROW(cm::store::CMStore(m_baseDir->path().string(), "relative/outputs"), std::runtime_error);
}

TEST_F(CMStoreTest, LoadNamespacesIgnoresRegularFilesOnDisk)
{
    writeFile(m_baseDir->path() / "not_a_namespace.txt", "x");

    auto store = makeStore();
    EXPECT_TRUE(store->getNamespaces().empty());
}

TEST_F(CMStoreTest, CreateNamespaceWhenDirectoryAlreadyExistsOnDiskThrows)
{
    auto store = makeStore();
    std::filesystem::create_directories(m_baseDir->path() / "existing");
    EXPECT_THROW(store->createNamespace(cm::store::NamespaceId("existing")), std::runtime_error);
}

TEST_F(CMStoreTest, RenameNamespaceMissingOnDiskThrows)
{
    auto store = makeStore();
    store->createNamespace(cm::store::NamespaceId("ghost"));

    std::filesystem::remove_all(m_baseDir->path() / "ghost");

    EXPECT_THROW(store->renameNamespace(cm::store::NamespaceId("ghost"), cm::store::NamespaceId("renamed")),
                 std::runtime_error);
}

TEST_F(CMStoreTest, RenameNamespaceDestinationAlreadyExistsOnDiskThrows)
{
    auto store = makeStore();
    store->createNamespace(cm::store::NamespaceId("from_ns"));
    std::filesystem::create_directories(m_baseDir->path() / "to_ns");

    EXPECT_THROW(store->renameNamespace(cm::store::NamespaceId("from_ns"), cm::store::NamespaceId("to_ns")),
                 std::runtime_error);
}
