#include <gtest/gtest.h>

#include <filesystem_wrapper.hpp>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace
{
    void writeFile(const std::filesystem::path& path, std::size_t bytes)
    {
        std::ofstream out {path, std::ios::binary | std::ios::trunc};
        out << std::string(bytes, 'x');
    }
} // namespace

class FileSystemWrapperTest : public ::testing::Test
{
    protected:
        std::filesystem::path m_root;
        file_system::FileSystemWrapper m_fs;

        void SetUp() override
        {
            // std::filesystem rather than mkdtemp: the suite is also built for the Windows
            // agent, where mkdtemp does not exist and /tmp is not a path.
            const auto base {std::filesystem::temp_directory_path()};
            std::error_code ec;

            for (int attempt = 0; attempt < 100; ++attempt)
            {
                const auto unique
                {
                    std::chrono::steady_clock::now().time_since_epoch().count() + attempt
                };
                const auto candidate {base / ("fswraptest_" + std::to_string(unique))};

                if (std::filesystem::create_directory(candidate, ec) && !ec)
                {
                    m_root = candidate;
                    return;
                }
            }

            FAIL() << "could not create a unique temporary directory under " << base;
        }

        void TearDown() override
        {
            std::error_code ec;
            std::filesystem::remove_all(m_root, ec);
        }
};

TEST_F(FileSystemWrapperTest, FileSizeReturnsRealSize)
{
    const auto filePath = m_root / "a.txt";
    writeFile(filePath, 123);

    EXPECT_EQ(m_fs.file_size(filePath), 123u);
}

TEST_F(FileSystemWrapperTest, FileSizeMissingFileReturnsZero)
{
    EXPECT_EQ(m_fs.file_size(m_root / "does_not_exist"), 0u);
}

TEST_F(FileSystemWrapperTest, FileSizeOnDirectoryReturnsZero)
{
    EXPECT_EQ(m_fs.file_size(m_root), 0u);
}

TEST_F(FileSystemWrapperTest, DirectorySizeMissingDirectoryReturnsZero)
{
    EXPECT_EQ(m_fs.directory_size(m_root / "does_not_exist", 1000, std::chrono::milliseconds(1000)), 0u);
}

TEST_F(FileSystemWrapperTest, DirectorySizeOnFileReturnsZero)
{
    const auto filePath = m_root / "a.txt";
    writeFile(filePath, 10);

    EXPECT_EQ(m_fs.directory_size(filePath, 1000, std::chrono::milliseconds(1000)), 0u);
}

TEST_F(FileSystemWrapperTest, DirectorySizeSumsNestedFiles)
{
    std::filesystem::create_directories(m_root / "sub" / "deeper");
    writeFile(m_root / "one.bin", 10);
    writeFile(m_root / "sub" / "two.bin", 20);
    writeFile(m_root / "sub" / "deeper" / "three.bin", 30);

    EXPECT_EQ(m_fs.directory_size(m_root, 1000, std::chrono::milliseconds(1000)), 60u);
}

TEST_F(FileSystemWrapperTest, DirectorySizeEntryCapReturnsZero)
{
    writeFile(m_root / "one.bin", 10);
    writeFile(m_root / "two.bin", 20);
    writeFile(m_root / "three.bin", 30);

    // Only one entry allowed, but the directory holds three: the cap must be hit before
    // any of them is summed.
    EXPECT_EQ(m_fs.directory_size(m_root, 1, std::chrono::milliseconds(1000)), 0u);
}

TEST_F(FileSystemWrapperTest, DirectorySizeDeadlineReturnsZero)
{
    writeFile(m_root / "one.bin", 10);

    // A negative deadline is already exceeded before the first entry is inspected,
    // regardless of how fast the walk runs.
    EXPECT_EQ(m_fs.directory_size(m_root, 1000, std::chrono::milliseconds(-1)), 0u);
}

TEST_F(FileSystemWrapperTest, DirectorySizeNeverReturnsPartialSum)
{
    writeFile(m_root / "one.bin", 10);
    writeFile(m_root / "two.bin", 20);
    writeFile(m_root / "three.bin", 30);

    // The cap is hit on the second entry: a partial-sum implementation would report 10
    // (the first file alone). The contract requires 0 instead.
    const auto result = m_fs.directory_size(m_root, 1, std::chrono::milliseconds(1000));
    EXPECT_EQ(result, 0u);
    EXPECT_NE(result, 10u);
}

TEST_F(FileSystemWrapperTest, DirectorySizeCountsSymlinkedFileOnce)
{
    const auto realFile = m_root / "real.bin";
    writeFile(realFile, 42);

    std::error_code ec;
    std::filesystem::create_symlink(realFile, m_root / "alias.bin", ec);

    if (ec)
    {
        GTEST_SKIP() << "symbolic links are not permitted here: " << ec.message();
    }

    // The real file and its alias both resolve to the same 42 bytes. Following the alias
    // as if it were a regular file would double the total to 84.
    EXPECT_EQ(m_fs.directory_size(m_root, 1000, std::chrono::milliseconds(1000)), 42u);
}

TEST_F(FileSystemWrapperTest, DirectorySizeDoesNotFollowSymlinkedDirectory)
{
    std::filesystem::create_directories(m_root / "real_dir");
    writeFile(m_root / "real_dir" / "inside.bin", 55);

    std::error_code ec;
    std::filesystem::create_directory_symlink(m_root / "real_dir", m_root / "alias_dir", ec);

    if (ec)
    {
        GTEST_SKIP() << "symbolic links are not permitted here: " << ec.message();
    }

    // Following alias_dir would recurse into real_dir a second time and double the total.
    EXPECT_EQ(m_fs.directory_size(m_root, 1000, std::chrono::milliseconds(1000)), 55u);
}
