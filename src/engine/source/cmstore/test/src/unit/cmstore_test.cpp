#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <unistd.h>

#include <gtest/gtest.h>

#include <cmstore/cmstore.hpp>

#include "storens.hpp"

TEST(ContentManagerTest, init)
{
    cm::store::CMStoreNS store (cm::store::NamespaceId("test"), std::filesystem::temp_directory_path(), std::filesystem::temp_directory_path());
    GTEST_SKIP() << "Not implemented yet.";
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
