#include <gtest/gtest.h>

#include <filesystem_wrapper.hpp>

#include <chrono>
#include <fstream>
#include <filesystem>

namespace
{
    class FileSystemWrapperTest : public ::testing::Test
    {
        protected:
            void SetUp() override
            {
                m_root = std::filesystem::temp_directory_path() / "fs_wrapper_test_XXXXXX";
                std::filesystem::remove_all(m_root);
                std::filesystem::create_directories(m_root);
            }

            void TearDown() override
            {
                std::filesystem::remove_all(m_root);
            }

            static void writeFile(const std::filesystem::path& path, std::size_t bytes)
            {
                std::filesystem::create_directories(path.parent_path());
                std::ofstream file { path, std::ios::binary };
                std::string content(bytes, 'x');
                file << content;
            }

            std::filesystem::path m_root;
            file_system::FileSystemWrapper m_fs;
    };

    TEST_F(FileSystemWrapperTest, FileSizeReturnsRealSize)
    {
        const auto filePath { m_root / "file.txt" };
        writeFile(filePath, 1234);
        EXPECT_EQ(m_fs.file_size(filePath), 1234u);
    }

    TEST_F(FileSystemWrapperTest, FileSizeReturnsZeroOnMissingFile)
    {
        EXPECT_EQ(m_fs.file_size(m_root / "missing.txt"), 0u);
    }

    TEST_F(FileSystemWrapperTest, FileSizeReturnsZeroOnDirectory)
    {
        EXPECT_EQ(m_fs.file_size(m_root), 0u);
    }

    TEST_F(FileSystemWrapperTest, DirectorySizeSumsNestedFiles)
    {
        writeFile(m_root / "a.txt", 100);
        writeFile(m_root / "sub" / "b.txt", 250);
        writeFile(m_root / "sub" / "deeper" / "c.txt", 7);

        EXPECT_EQ(m_fs.directory_size(m_root, 1000, std::chrono::milliseconds { 5000 }), 357u);
    }

    TEST_F(FileSystemWrapperTest, DirectorySizeCountsSymlinkedFilesOnlyOnce)
    {
        // A macOS bundle keeps framework binaries behind symlinks, so following them would
        // add the same bytes twice. Only the real file may be counted.
        writeFile(m_root / "Versions" / "A" / "binary", 300);
        std::error_code ec;
        std::filesystem::create_symlink(m_root / "Versions" / "A" / "binary", m_root / "binary", ec);
        ASSERT_FALSE(ec);

        EXPECT_EQ(m_fs.directory_size(m_root, 1000, std::chrono::milliseconds { 5000 }), 300u);
    }

    TEST_F(FileSystemWrapperTest, DirectorySizeDoesNotFollowSymlinkedDirectories)
    {
        writeFile(m_root / "real" / "file", 120);
        std::error_code ec;
        std::filesystem::create_directory_symlink(m_root / "real", m_root / "alias", ec);
        ASSERT_FALSE(ec);

        EXPECT_EQ(m_fs.directory_size(m_root, 1000, std::chrono::milliseconds { 5000 }), 120u);
    }

    TEST_F(FileSystemWrapperTest, DirectorySizeReturnsZeroWhenNotADirectory)
    {
        const auto filePath { m_root / "file.txt" };
        writeFile(filePath, 42);
        EXPECT_EQ(m_fs.directory_size(filePath, 1000, std::chrono::milliseconds { 5000 }), 0u);
    }

    TEST_F(FileSystemWrapperTest, DirectorySizeReturnsZeroWhenMissing)
    {
        EXPECT_EQ(m_fs.directory_size(m_root / "missing", 1000, std::chrono::milliseconds { 5000 }), 0u);
    }

    TEST_F(FileSystemWrapperTest, DirectorySizeReturnsZeroOnEntryCapHit)
    {
        writeFile(m_root / "a.txt", 100);
        writeFile(m_root / "b.txt", 100);
        // A single visited entry already exceeds a cap of zero.
        EXPECT_EQ(m_fs.directory_size(m_root, 0, std::chrono::milliseconds { 5000 }), 0u);
    }

    TEST_F(FileSystemWrapperTest, DirectorySizeReturnsZeroOnDeadlineHit)
    {
        writeFile(m_root / "a.txt", 100);
        // A deadline of 0ms is exceeded as soon as the clock is read.
        EXPECT_EQ(m_fs.directory_size(m_root, 1000, std::chrono::milliseconds { 0 }), 0u);
    }

    TEST_F(FileSystemWrapperTest, DirectorySizeNeverReturnsPartialSum)
    {
        // With a cap that permits exactly the directory entry itself but not
        // the file inside it, the walk must report 0, not a partial total.
        writeFile(m_root / "sub" / "a.txt", 500);
        EXPECT_EQ(m_fs.directory_size(m_root, 1, std::chrono::milliseconds { 5000 }), 0u);
    }
}
