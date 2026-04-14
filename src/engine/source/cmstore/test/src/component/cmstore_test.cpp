#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <unistd.h>
#include <unordered_set>
#include <vector>

#include <gtest/gtest.h>

#include <cmstore/cmstore.hpp>

// ======================================================================
//  Helpers
// ======================================================================

namespace
{

/// RAII temporary directory, auto-cleaned on destruction.
class TempDir
{
public:
    TempDir(std::string_view prefix = "cmstore_ctest")
        : m_path(std::filesystem::temp_directory_path()
                 / std::filesystem::path(std::string(prefix) + "_" + std::to_string(::getpid()) + "_"
                                         + std::to_string(counter_++)))
    {
        std::filesystem::create_directories(m_path);
    }

    ~TempDir() { std::filesystem::remove_all(m_path); }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    const std::filesystem::path& path() const { return m_path; }

private:
    std::filesystem::path m_path;
    static inline int counter_ = 0;
};

void writeFile(const std::filesystem::path& path, std::string_view content)
{
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path);
    out << content;
}

void writeOutputYml(const std::filesystem::path& dir, std::string_view filename, std::string_view assetName)
{
    std::filesystem::create_directories(dir);
    std::ofstream out(dir / std::string(filename));
    out << "name: " << assetName << "\n"
        << "metadata:\n"
        << "  title: component test output\n"
        << "enabled: true\n"
        << "outputs:\n"
        << "  - file: alerts\n";
}

/// Minimal valid decoder YML (needs name and enabled at minimum).
std::string makeDecoderYml(std::string_view name, std::string_view uuid = "")
{
    std::string yml;
    yml += "name: " + std::string(name) + "\n";
    yml += "enabled: true\n";
    yml += "parents:\n  - decoder/root/0\n";
    if (!uuid.empty())
    {
        yml += "id: " + std::string(uuid) + "\n";
    }
    return yml;
}

std::string makeFilterYml(std::string_view name, std::string_view uuid = "")
{
    std::string yml;
    yml += "name: " + std::string(name) + "\n";
    yml += "enabled: true\n";
    yml += "type: pre-filter\n";
    if (!uuid.empty())
    {
        yml += "id: " + std::string(uuid) + "\n";
    }
    return yml;
}

std::string makeIntegrationYml(std::string_view name, std::string_view uuid, std::string_view category = "security")
{
    std::string yml;
    yml += "id: \"" + std::string(uuid) + "\"\n";
    yml += "metadata:\n  title: " + std::string(name) + "\n";
    yml += "enabled: true\n";
    yml += "category: " + std::string(category) + "\n";
    yml += "decoders: []\n";
    yml += "kvdbs: []\n";
    return yml;
}

std::string makeKVDBYml(std::string_view name, std::string_view uuid)
{
    std::string yml;
    yml += "id: \"" + std::string(uuid) + "\"\n";
    yml += "metadata:\n  title: " + std::string(name) + "\n";
    yml += "enabled: true\n";
    yml += "content:\n  key1: value1\n  key2: value2\n";
    return yml;
}

cm::store::dataType::Policy makePolicy(std::string_view title = "Test Policy",
                                       std::string_view rootDecoder = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")
{
    return cm::store::dataType::Policy(title,
                                       true,
                                       rootDecoder,
                                       {},             // integrations
                                       {},             // filters
                                       {"file", "ip"}, // enrichments
                                       {},             // outputs
                                       "UNDEFINED",
                                       "",
                                       false,
                                       false,
                                       true);
}

} // namespace

// ======================================================================
//  Fixture
// ======================================================================

class CMStoreComponentTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_baseDir = std::make_unique<TempDir>("cmstore_base");
        m_outputsDir = std::make_unique<TempDir>("cmstore_outputs");
        std::filesystem::create_directories(m_outputsDir->path() / "default");
    }

    std::unique_ptr<cm::store::CMStore> createStore()
    {
        return std::make_unique<cm::store::CMStore>(m_baseDir->path().string(), m_outputsDir->path().string());
    }

    const std::filesystem::path& basePath() const { return m_baseDir->path(); }
    const std::filesystem::path& outputsPath() const { return m_outputsDir->path(); }

    std::unique_ptr<TempDir> m_baseDir;
    std::unique_ptr<TempDir> m_outputsDir;
};

// ======================================================================
//  Full lifecycle: namespace → resource CRUD → verify on disk
// ======================================================================

TEST_F(CMStoreComponentTest, FullDecoderLifecycle)
{
    auto store = createStore();

    // Create namespace
    auto ns = store->createNamespace(cm::store::NamespaceId("lifecycle"));
    ASSERT_NE(ns, nullptr);

    // Create decoder
    auto uuid =
        ns->createResource("decoder/http/0", cm::store::ResourceType::DECODER, makeDecoderYml("decoder/http/0"));
    EXPECT_FALSE(uuid.empty());

    // Read back by name
    auto asset = ns->getAssetByName(base::Name("decoder/http/0"));
    std::string nameStr;
    EXPECT_EQ(asset.getString(nameStr, "/name"), json::RetGet::Success);
    EXPECT_EQ(nameStr, "decoder/http/0");

    // Read back by UUID
    auto asset2 = ns->getAssetByUUID(uuid);
    std::string nameStr2;
    EXPECT_EQ(asset2.getString(nameStr2, "/name"), json::RetGet::Success);
    EXPECT_EQ(nameStr2, "decoder/http/0");

    // Verify file exists on disk
    auto filePath = basePath() / "lifecycle" / "decoders" / "decoder_http_0.yml";
    EXPECT_TRUE(std::filesystem::exists(filePath));

    // Update (must keep same UUID)
    std::string updatedYml = "name: decoder/http/0\nenabled: false\nid: " + uuid + "\n";
    EXPECT_NO_THROW(ns->updateResourceByName("decoder/http/0", cm::store::ResourceType::DECODER, updatedYml));

    // Verify update
    auto updated = ns->getAssetByUUID(uuid);
    auto enabledOpt = updated.getBool("/enabled");
    ASSERT_TRUE(enabledOpt.has_value());
    EXPECT_FALSE(enabledOpt.value());

    // Delete by name
    ns->deleteResourceByName("decoder/http/0", cm::store::ResourceType::DECODER);
    EXPECT_FALSE(ns->assetExistsByUUID(uuid));
    EXPECT_FALSE(std::filesystem::exists(filePath));
}

TEST_F(CMStoreComponentTest, FullFilterLifecycle)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("filterlife"));

    auto uuid = ns->createResource("filter/allow/0", cm::store::ResourceType::FILTER, makeFilterYml("filter/allow/0"));
    EXPECT_FALSE(uuid.empty());

    EXPECT_TRUE(ns->assetExistsByName(base::Name("filter/allow/0")));

    // Delete by UUID
    ns->deleteResourceByUUID(uuid);
    EXPECT_FALSE(ns->assetExistsByName(base::Name("filter/allow/0")));
}

// ======================================================================
//  Integration lifecycle
// ======================================================================

TEST_F(CMStoreComponentTest, IntegrationCreateAndRetrieve)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("integ"));

    const std::string intUUID = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    auto uuid =
        ns->createResource("windows", cm::store::ResourceType::INTEGRATION, makeIntegrationYml("windows", intUUID));
    EXPECT_EQ(uuid, intUUID);

    auto integration = ns->getIntegrationByName("windows");
    EXPECT_EQ(integration.getName(), "windows");
    EXPECT_EQ(integration.getCategory(), "security");
    EXPECT_TRUE(integration.isEnabled());

    auto integByUUID = ns->getIntegrationByUUID(intUUID);
    EXPECT_EQ(integByUUID.getName(), "windows");
}

// ======================================================================
//  KVDB lifecycle
// ======================================================================

TEST_F(CMStoreComponentTest, KVDBCreateAndRetrieve)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("kvdbns"));

    const std::string kvdbUUID = "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e";
    auto uuid = ns->createResource("test_kvdb", cm::store::ResourceType::KVDB, makeKVDBYml("test_kvdb", kvdbUUID));
    EXPECT_EQ(uuid, kvdbUUID);

    auto kvdb = ns->getKVDBByName("test_kvdb");
    EXPECT_EQ(kvdb.getName(), "test_kvdb");
    EXPECT_TRUE(kvdb.isEnabled());

    std::string val;
    EXPECT_EQ(kvdb.getData().getString(val, "/key1"), json::RetGet::Success);
    EXPECT_EQ(val, "value1");

    auto kvdbByUUID = ns->getKVDBByUUID(kvdbUUID);
    EXPECT_EQ(kvdbByUUID.getName(), "test_kvdb");
}

// ======================================================================
//  Policy lifecycle
// ======================================================================

TEST_F(CMStoreComponentTest, PolicyUpsertGetDelete)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("polns"));

    // No policy initially
    EXPECT_THROW(ns->getPolicy(), std::runtime_error);

    // Upsert
    auto policy = makePolicy("MyPolicy");
    EXPECT_NO_THROW(ns->upsertPolicy(policy));

    // Get
    auto retrieved = ns->getPolicy();
    EXPECT_EQ(retrieved.getTitle(), "MyPolicy");
    EXPECT_TRUE(retrieved.isEnabled());
    EXPECT_EQ(retrieved.getRootDecoderUUID(), "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");

    // Overwrite
    auto policy2 = makePolicy("UpdatedPolicy");
    EXPECT_NO_THROW(ns->upsertPolicy(policy2));
    auto retrieved2 = ns->getPolicy();
    EXPECT_EQ(retrieved2.getTitle(), "UpdatedPolicy");

    // Delete
    EXPECT_NO_THROW(ns->deletePolicy());
    EXPECT_THROW(ns->getPolicy(), std::runtime_error);
}

// ======================================================================
//  Persistence: data survives store re-creation
// ======================================================================

TEST_F(CMStoreComponentTest, DataPersistsAcrossStoreInstances)
{
    std::string uuid;
    {
        auto store = createStore();
        auto ns = store->createNamespace(cm::store::NamespaceId("persist"));
        uuid = ns->createResource(
            "decoder/survive/0", cm::store::ResourceType::DECODER, makeDecoderYml("decoder/survive/0"));

        ns->upsertPolicy(makePolicy());
    }
    // Store destroyed, re-create from same paths
    {
        auto store2 = createStore();
        EXPECT_TRUE(store2->existsNamespace(cm::store::NamespaceId("persist")));

        auto ns2 = store2->getNS(cm::store::NamespaceId("persist"));
        EXPECT_TRUE(ns2->assetExistsByUUID(uuid));
        EXPECT_TRUE(ns2->assetExistsByName(base::Name("decoder/survive/0")));

        auto policy = ns2->getPolicy();
        EXPECT_EQ(policy.getTitle(), "Test Policy");
    }
}

// ======================================================================
//  Multiple namespaces with independent resources
// ======================================================================

TEST_F(CMStoreComponentTest, MultipleNamespacesAreIsolated)
{
    auto store = createStore();

    auto nsA = store->createNamespace(cm::store::NamespaceId("nsA"));
    auto nsB = store->createNamespace(cm::store::NamespaceId("nsB"));

    auto uuidA = nsA->createResource(
        "decoder/shared_name/0", cm::store::ResourceType::DECODER, makeDecoderYml("decoder/shared_name/0"));
    auto uuidB = nsB->createResource(
        "decoder/shared_name/0", cm::store::ResourceType::DECODER, makeDecoderYml("decoder/shared_name/0"));

    // Different UUIDs for same resource name in different namespaces
    EXPECT_NE(uuidA, uuidB);

    // Each namespace only sees its own
    EXPECT_TRUE(nsA->assetExistsByUUID(uuidA));
    EXPECT_FALSE(nsA->assetExistsByUUID(uuidB));
    EXPECT_TRUE(nsB->assetExistsByUUID(uuidB));
    EXPECT_FALSE(nsB->assetExistsByUUID(uuidA));
}

// ======================================================================
//  Rename namespace preserves resources
// ======================================================================

TEST_F(CMStoreComponentTest, RenameNamespacePreservesResources)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("before"));

    auto uuid =
        ns->createResource("decoder/keep/0", cm::store::ResourceType::DECODER, makeDecoderYml("decoder/keep/0"));

    // Release the shared_ptr so rename can proceed
    ns.reset();

    store->renameNamespace(cm::store::NamespaceId("before"), cm::store::NamespaceId("after"));

    EXPECT_FALSE(store->existsNamespace(cm::store::NamespaceId("before")));
    EXPECT_TRUE(store->existsNamespace(cm::store::NamespaceId("after")));

    auto nsAfter = store->getNS(cm::store::NamespaceId("after"));
    EXPECT_TRUE(nsAfter->assetExistsByUUID(uuid));
    EXPECT_TRUE(nsAfter->assetExistsByName(base::Name("decoder/keep/0")));
}

// ======================================================================
//  Delete namespace removes everything from disk
// ======================================================================

TEST_F(CMStoreComponentTest, DeleteNamespaceRemovesDiskContents)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("ephemeral"));

    ns->createResource("decoder/tmp/0", cm::store::ResourceType::DECODER, makeDecoderYml("decoder/tmp/0"));

    auto nsPath = basePath() / "ephemeral";
    EXPECT_TRUE(std::filesystem::exists(nsPath));

    ns.reset(); // release ref
    store->deleteNamespace(cm::store::NamespaceId("ephemeral"));

    EXPECT_FALSE(std::filesystem::exists(nsPath));
    EXPECT_FALSE(store->existsNamespace(cm::store::NamespaceId("ephemeral")));
}

// ======================================================================
//  getCollection returns correct entries across types
// ======================================================================

TEST_F(CMStoreComponentTest, GetCollectionMultipleTypes)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("coll"));

    ns->createResource("decoder/a/0", cm::store::ResourceType::DECODER, makeDecoderYml("decoder/a/0"));
    ns->createResource("decoder/b/0", cm::store::ResourceType::DECODER, makeDecoderYml("decoder/b/0"));
    ns->createResource("filter/c/0", cm::store::ResourceType::FILTER, makeFilterYml("filter/c/0"));

    const std::string intUUID = "11111111-2222-4333-a444-555555555555";
    ns->createResource("myint", cm::store::ResourceType::INTEGRATION, makeIntegrationYml("myint", intUUID));

    auto decoders = ns->getCollection(cm::store::ResourceType::DECODER);
    EXPECT_EQ(decoders.size(), 2U);

    auto filters = ns->getCollection(cm::store::ResourceType::FILTER);
    EXPECT_EQ(filters.size(), 1U);

    auto integrations = ns->getCollection(cm::store::ResourceType::INTEGRATION);
    EXPECT_EQ(integrations.size(), 1U);

    auto kvdbs = ns->getCollection(cm::store::ResourceType::KVDB);
    EXPECT_TRUE(kvdbs.empty());
}

// ======================================================================
//  UUID / name resolution end-to-end
// ======================================================================

TEST_F(CMStoreComponentTest, ResolveUUIDNameRoundTrip)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("resolve"));

    auto uuid = ns->createResource("decoder/rt/0", cm::store::ResourceType::DECODER, makeDecoderYml("decoder/rt/0"));

    auto resolvedUUID = ns->resolveUUIDFromName("decoder/rt/0", cm::store::ResourceType::DECODER);
    EXPECT_EQ(resolvedUUID, uuid);

    auto [name, type] = ns->resolveNameFromUUID(uuid);
    EXPECT_EQ(name, "decoder/rt/0");
    EXPECT_EQ(type, cm::store::ResourceType::DECODER);
}

// ======================================================================
//  Outputs for space resolution
// ======================================================================

TEST_F(CMStoreComponentTest, OutputsForSpaceFallbackAndOverride)
{
    writeOutputYml(outputsPath() / "default", "default_out.yml", "output/default/0");
    writeOutputYml(outputsPath() / "custom_space", "custom_out.yml", "output/custom/0");

    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("outns"));

    // Nonexistent space → fallback to default
    {
        const auto outputs = ns->getOutputsForSpace("nonexistent");
        ASSERT_EQ(outputs.size(), 1U);
        std::string n;
        EXPECT_EQ(outputs[0].getString(n, "/name"), json::RetGet::Success);
        EXPECT_EQ(n, "output/default/0");
    }

    // Existing space → uses space directory
    {
        const auto outputs = ns->getOutputsForSpace("custom_space");
        ASSERT_EQ(outputs.size(), 1U);
        std::string n;
        EXPECT_EQ(outputs[0].getString(n, "/name"), json::RetGet::Success);
        EXPECT_EQ(n, "output/custom/0");
    }

    // Empty key → fallback to default
    {
        const auto outputs = ns->getOutputsForSpace("");
        ASSERT_EQ(outputs.size(), 1U);
    }
}

// ======================================================================
//  Update by UUID
// ======================================================================

TEST_F(CMStoreComponentTest, UpdateResourceByUUID)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("updns"));

    auto uuid = ns->createResource("decoder/upd/0", cm::store::ResourceType::DECODER, makeDecoderYml("decoder/upd/0"));

    std::string updateYml = "name: decoder/upd/0\nenabled: false\nid: " + uuid + "\n";
    EXPECT_NO_THROW(ns->updateResourceByUUID(uuid, updateYml));

    auto asset = ns->getAssetByUUID(uuid);
    auto enabledOpt = asset.getBool("/enabled");
    ASSERT_TRUE(enabledOpt.has_value());
    EXPECT_FALSE(enabledOpt.value());
}

// ======================================================================
//  Error cases
// ======================================================================

TEST_F(CMStoreComponentTest, UpdateWithMismatchedUUIDAThrows)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("mismatch"));

    auto uuid = ns->createResource("decoder/m/0", cm::store::ResourceType::DECODER, makeDecoderYml("decoder/m/0"));

    // Update with a different UUID in content
    std::string badYml = "name: decoder/m/0\nenabled: true\nid: 00000000-0000-4000-a000-000000000000\n";
    EXPECT_THROW(ns->updateResourceByName("decoder/m/0", cm::store::ResourceType::DECODER, badYml), std::runtime_error);
    EXPECT_THROW(ns->updateResourceByUUID(uuid, badYml), std::runtime_error);
}

TEST_F(CMStoreComponentTest, CreateDuplicateResourceThrows)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("dup"));

    ns->createResource("decoder/dup/0", cm::store::ResourceType::DECODER, makeDecoderYml("decoder/dup/0"));

    EXPECT_THROW(ns->createResource("decoder/dup/0", cm::store::ResourceType::DECODER, makeDecoderYml("decoder/dup/0")),
                 std::runtime_error);
}

TEST_F(CMStoreComponentTest, DeleteNonexistentResourceThrows)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("delerr"));

    EXPECT_THROW(ns->deleteResourceByName("decoder/nope/0", cm::store::ResourceType::DECODER), std::runtime_error);
    EXPECT_THROW(ns->deleteResourceByUUID("00000000-0000-4000-a000-000000000000"), std::runtime_error);
}

TEST_F(CMStoreComponentTest, GetNonexistentThrows)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("geterr"));

    EXPECT_THROW(ns->getAssetByName(base::Name("decoder/nope/0")), std::runtime_error);
    EXPECT_THROW(ns->getAssetByUUID("00000000-0000-4000-a000-000000000000"), std::runtime_error);
    EXPECT_THROW(ns->getIntegrationByName("missing"), std::runtime_error);
    EXPECT_THROW(ns->getKVDBByName("missing"), std::runtime_error);
}

TEST_F(CMStoreComponentTest, ForbiddenNamespaceOperations)
{
    auto store = createStore();

    EXPECT_THROW(store->createNamespace(cm::store::NamespaceId("system")), std::runtime_error);
    EXPECT_THROW(store->createNamespace(cm::store::NamespaceId("output")), std::runtime_error);
    EXPECT_THROW(store->createNamespace(cm::store::NamespaceId("default")), std::runtime_error);
}

TEST_F(CMStoreComponentTest, DeleteWithActiveReferencesThrows)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("refns"));

    // ns still holds a shared_ptr → use_count > 1
    EXPECT_THROW(store->deleteNamespace(cm::store::NamespaceId("refns")), std::runtime_error);

    // After releasing, deletion succeeds
    ns.reset();
    EXPECT_NO_THROW(store->deleteNamespace(cm::store::NamespaceId("refns")));
}

TEST_F(CMStoreComponentTest, RenameWithActiveReferencesThrows)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("renref"));

    EXPECT_THROW(store->renameNamespace(cm::store::NamespaceId("renref"), cm::store::NamespaceId("renamed")),
                 std::runtime_error);

    ns.reset();
    EXPECT_NO_THROW(store->renameNamespace(cm::store::NamespaceId("renref"), cm::store::NamespaceId("renamed")));
}

// ======================================================================
//  getNSReader provides read-only access
// ======================================================================

TEST_F(CMStoreComponentTest, NSReaderCanReadResources)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("readonly"));

    auto uuid = ns->createResource("decoder/rd/0", cm::store::ResourceType::DECODER, makeDecoderYml("decoder/rd/0"));
    ns.reset();

    auto reader = store->getNSReader(cm::store::NamespaceId("readonly"));
    ASSERT_NE(reader, nullptr);

    EXPECT_TRUE(reader->assetExistsByUUID(uuid));
    EXPECT_TRUE(reader->assetExistsByName(base::Name("decoder/rd/0")));
    EXPECT_EQ(reader->getNamespaceId().toStr(), "readonly");

    auto asset = reader->getAssetByUUID(uuid);
    std::string n;
    EXPECT_EQ(asset.getString(n, "/name"), json::RetGet::Success);
    EXPECT_EQ(n, "decoder/rd/0");
}

// ======================================================================
//  Preexisting namespaces loaded on construction
// ======================================================================

TEST_F(CMStoreComponentTest, PreexistingNamespacesLoadedOnConstruction)
{
    // Manually create namespace dirs before constructing CMStore
    writeFile(basePath() / "pre1" / "cache_ns.json", "[]");
    writeFile(basePath() / "pre2" / "cache_ns.json", "[]");

    auto store = createStore();
    EXPECT_TRUE(store->existsNamespace(cm::store::NamespaceId("pre1")));
    EXPECT_TRUE(store->existsNamespace(cm::store::NamespaceId("pre2")));

    auto ns = store->getNamespaces();
    EXPECT_EQ(ns.size(), 2U);
}

// ======================================================================
//  Large collection: many resources in one namespace
// ======================================================================

TEST_F(CMStoreComponentTest, ManyResourcesInSingleNamespace)
{
    auto store = createStore();
    auto ns = store->createNamespace(cm::store::NamespaceId("bulk"));

    constexpr int N = 50;
    std::vector<std::string> uuids;
    uuids.reserve(N);

    for (int i = 0; i < N; ++i)
    {
        auto name = "decoder/bulk_" + std::to_string(i) + "/0";
        auto uuid = ns->createResource(name, cm::store::ResourceType::DECODER, makeDecoderYml(name));
        uuids.push_back(uuid);
    }

    // Verify all exist
    auto collection = ns->getCollection(cm::store::ResourceType::DECODER);
    EXPECT_EQ(collection.size(), static_cast<size_t>(N));

    // Verify all UUIDs are unique
    std::unordered_set<std::string> uuidSet(uuids.begin(), uuids.end());
    EXPECT_EQ(uuidSet.size(), static_cast<size_t>(N));

    // Delete half and verify
    for (int i = 0; i < N / 2; ++i)
    {
        ns->deleteResourceByUUID(uuids[i]);
    }
    auto remaining = ns->getCollection(cm::store::ResourceType::DECODER);
    EXPECT_EQ(remaining.size(), static_cast<size_t>(N - N / 2));
}

// ======================================================================
//  Cache rebuild: corrupt cache → store rebuilds from files
// ======================================================================

TEST_F(CMStoreComponentTest, CacheRebuildFromCorruptFile)
{
    // Create a namespace with a resource
    std::string uuid;
    {
        auto store = createStore();
        auto ns = store->createNamespace(cm::store::NamespaceId("rebuild"));
        uuid = ns->createResource("decoder/rb/0", cm::store::ResourceType::DECODER, makeDecoderYml("decoder/rb/0"));
    }

    // Corrupt the cache file
    auto cachePath = basePath() / "rebuild" / "cache_ns.json";
    ASSERT_TRUE(std::filesystem::exists(cachePath));
    writeFile(cachePath, "NOT VALID JSON {{{");

    // Re-create store — should rebuild cache from .yml files on disk
    auto store2 = createStore();
    auto ns2 = store2->getNS(cm::store::NamespaceId("rebuild"));

    EXPECT_TRUE(ns2->assetExistsByUUID(uuid));
    EXPECT_TRUE(ns2->assetExistsByName(base::Name("decoder/rb/0")));
}
