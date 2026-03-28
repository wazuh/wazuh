#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <unistd.h>

#include <base/name.hpp>
#include <base/utils/generator.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cmstore/cmstore.hpp>

#include "storens.hpp"

namespace
{

class CMStoreNSTest : public ::testing::Test
{
protected:
    std::filesystem::path m_root;
    std::filesystem::path m_outputs;

    void SetUp() override
    {
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

TEST_F(CMStoreNSTest, CreateResourcePersistsJsonAndGetterReadsItBack)
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

    const auto resourcePath = m_root / "decoders" / "decoder_syslog_0.yml";
    std::ifstream persistedFile(resourcePath);
    ASSERT_TRUE(persistedFile.is_open());
    const std::string persisted((std::istreambuf_iterator<char>(persistedFile)), std::istreambuf_iterator<char>());
    EXPECT_THAT(persisted, ::testing::HasSubstr("\"name\":\"decoder/syslog/0\""));
    EXPECT_THAT(persisted, ::testing::HasSubstr("\"id\":\"3f086ce2-32a4-42b0-be7e-40dcfb9c6160\""));

    const auto asset = store.getAssetByName(base::Name {"decoder/syslog/0"});
    EXPECT_EQ(asset.getString("/name").value_or(""), "decoder/syslog/0");
    EXPECT_EQ(asset.getString("/id").value_or(""), "3f086ce2-32a4-42b0-be7e-40dcfb9c6160");
}

TEST_F(CMStoreNSTest, JsonResourcesOnDiskAreLoadedDuringStoreInitialization)
{
    std::filesystem::create_directories(m_root / "decoders");

    const auto jsonPath = m_root / "decoders" / "decoder_syslog_0.yml";
    std::ofstream jsonFile(jsonPath);
    ASSERT_TRUE(jsonFile.is_open());
    jsonFile << R"({"name":"decoder/syslog/0","id":"3f086ce2-32a4-42b0-be7e-40dcfb9c6160","metadata":{"module":"syslog"}})";
    jsonFile.close();

    cm::store::CMStoreNS store {cm::store::NamespaceId("test"), m_root, m_outputs};

    const auto asset = store.getAssetByName(base::Name {"decoder/syslog/0"});
    EXPECT_EQ(asset.getString("/name").value_or(""), "decoder/syslog/0");
    EXPECT_EQ(asset.getString("/id").value_or(""), "3f086ce2-32a4-42b0-be7e-40dcfb9c6160");
}

TEST_F(CMStoreNSTest, DefaultOutputsYamlAreConvertedToJson)
{
    std::ofstream outputFile(m_outputs / "stdout.yml");
    ASSERT_TRUE(outputFile.is_open());
    outputFile << "name: output/stdout\n";
    outputFile << "enabled: true\n";
    outputFile << "batch: 5\n";
    outputFile.close();

    cm::store::CMStoreNS store {cm::store::NamespaceId("test"), m_root, m_outputs};

    const auto outputs = store.getDefaultOutputs();
    ASSERT_EQ(outputs.size(), 1u);
    EXPECT_EQ(outputs[0].getString("/name").value_or(""), "output/stdout");
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
        : m_path(std::filesystem::temp_directory_path()
                 / std::filesystem::path("cmstore_outputs_test_" + std::to_string(::getpid()) + "_"
                                         + std::to_string(std::rand())))
    {
        std::filesystem::create_directories(m_path);
    }

    ~TempDir() { std::filesystem::remove_all(m_path); }

    const std::filesystem::path& path() const { return m_path; }

private:
    std::filesystem::path m_path;
};

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

TEST(ContentManagerTest, GetOutputsForSpaceFallsBackToDefaultDirectory)
{
    TempDir storageDir;
    TempDir outputsDir;

    std::filesystem::create_directories(outputsDir.path() / "default");
    writeOutputFile(outputsDir.path() / "default" / "default-output.yml", "output/default/0");

    cm::store::CMStoreNS store(cm::store::NamespaceId("test"), storageDir.path(), outputsDir.path());

    const auto outputs = store.getOutputsForSpace("standard");

    ASSERT_EQ(outputs.size(), 1U);
    ASSERT_TRUE(outputs[0].getString("/name").has_value());
    EXPECT_EQ(outputs[0].getString("/name").value(), "output/default/0");
}

TEST(ContentManagerTest, GetOutputsForSpaceUsesSpaceDirectoryWhenPresent)
{
    TempDir storageDir;
    TempDir outputsDir;

    std::filesystem::create_directories(outputsDir.path() / "default");
    std::filesystem::create_directories(outputsDir.path() / "standard");
    writeOutputFile(outputsDir.path() / "default" / "default-output.yml", "output/default/0");
    writeOutputFile(outputsDir.path() / "standard" / "space-output.yml", "output/standard/0");

    cm::store::CMStoreNS store(cm::store::NamespaceId("test"), storageDir.path(), outputsDir.path());

    const auto outputs = store.getOutputsForSpace("standard");

    ASSERT_EQ(outputs.size(), 1U);
    ASSERT_TRUE(outputs[0].getString("/name").has_value());
    EXPECT_EQ(outputs[0].getString("/name").value(), "output/standard/0");
}
