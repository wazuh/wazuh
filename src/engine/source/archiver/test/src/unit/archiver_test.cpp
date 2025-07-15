#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

#include <archiver/archiver.hpp>
#include <base/logging.hpp>

static const std::filesystem::path TEST_PATH = "/tmp/archiver_test";
static const std::filesystem::path TEST_FILE_PATH = TEST_PATH / "__test_archives__";

std::filesystem::path uniquePath()
{
    auto pid = getpid();
    auto tid = std::this_thread::get_id();
    std::stringstream ss;
    ss << pid << "_" << tid; // Unique path per thread and process
    return TEST_PATH / ss.str();
}

class ArchiverTest : public ::testing::Test
{
protected:
    std::filesystem::path m_path;
    std::filesystem::path m_filePath;

    void SetUp() override
    {
        logging::testInit();
        m_path = uniquePath();
        m_filePath = m_path / "__test_file__";
        std::filesystem::create_directories(m_path);
    }

    void TearDown() override { std::filesystem::remove_all(m_path); }
};

TEST_F(ArchiverTest, Init)
{
    // Test default constructor
    archiver::Archiver archiver(m_filePath.string());

    EXPECT_TRUE(std::filesystem::exists(m_filePath));
    EXPECT_FALSE(archiver.isActive());
}

TEST_F(ArchiverTest, InitActive)
{
    // Test constructor with active state
    archiver::Archiver archiver(m_filePath.string(), true);

    EXPECT_TRUE(std::filesystem::exists(m_filePath));
    EXPECT_TRUE(archiver.isActive());
}

TEST_F(ArchiverTest, InitParentNotExists)
{
    // Test constructor with non-existing parent directory
    EXPECT_THROW(archiver::Archiver archiver(m_path.string() + "/not_existing/archives.json"), std::runtime_error);
}

TEST_F(ArchiverTest, Activate)
{
    // Test activation
    archiver::Archiver archiver(m_filePath.string());

    EXPECT_FALSE(archiver.isActive());
    archiver.activate();

    EXPECT_TRUE(archiver.isActive());
}

TEST_F(ArchiverTest, Deactivate)
{
    // Test deactivation
    archiver::Archiver archiver(m_filePath.string(), true);

    EXPECT_TRUE(archiver.isActive());
    archiver.deactivate();

    EXPECT_FALSE(archiver.isActive());
}

TEST_F(ArchiverTest, Archive)
{
    // Test archiving data
    archiver::Archiver archiver(m_filePath.string(), true);

    std::string data = "Test data";
    base::OptError error = archiver.archive(data);

    EXPECT_FALSE(error);
    EXPECT_TRUE(std::filesystem::exists(m_filePath));
    EXPECT_TRUE(std::filesystem::is_regular_file(m_filePath));

    std::ifstream file(m_filePath);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    EXPECT_EQ(content, data + '\n');
}

TEST_F(ArchiverTest, ArchiveNotActive)
{
    // Test archiving data when not active
    archiver::Archiver archiver(m_filePath.string());

    std::string data = "Test data";
    base::OptError error = archiver.archive(data);

    EXPECT_FALSE(error);
    EXPECT_TRUE(std::filesystem::exists(m_filePath));
    EXPECT_TRUE(std::filesystem::is_regular_file(m_filePath));

    std::ifstream file(m_filePath);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    EXPECT_EQ(content, "");
}
