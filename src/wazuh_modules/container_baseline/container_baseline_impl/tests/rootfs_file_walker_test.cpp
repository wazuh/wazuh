#include "rootfs_file_walker.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

using wazuh::container_baseline::IsOverlayWhiteout;
using wazuh::container_baseline::WalkContainerPath;

TEST(IsOverlayWhiteout, CharDeviceZeroZeroIsWhiteout)
{
    EXPECT_TRUE(IsOverlayWhiteout(S_IFCHR | 0644, makedev(0, 0)));
}

TEST(IsOverlayWhiteout, CharDeviceNonZeroIsNotWhiteout)
{
    EXPECT_FALSE(IsOverlayWhiteout(S_IFCHR | 0644, makedev(1, 3))); // e.g. /dev/null
}

TEST(IsOverlayWhiteout, RegularFileIsNeverAWhiteout)
{
    EXPECT_FALSE(IsOverlayWhiteout(S_IFREG | 0644, makedev(0, 0)));
}

class RootfsFileWalkerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        char tmpl[] = "/tmp/cbaseline_walker_test_XXXXXX";
        dir_ = ::mkdtemp(tmpl);
        ASSERT_FALSE(dir_.empty());
    }

    void TearDown() override
    {
        std::string cmd = "rm -rf '" + dir_ + "'";
        ASSERT_EQ(std::system(cmd.c_str()), 0);
    }

    void WriteFile(const std::string& relative, const std::string& content)
    {
        std::ofstream f(dir_ + "/" + relative);
        f << content;
    }

    std::string dir_;
};

// This test walks the real host filesystem via a plain path rather than a
// /proc/<pid>/root prefix — WalkContainerPath's kernel-namespace-translation
// behavior is exactly "read whatever the given host path resolves to", so
// exercising it against a self-constructed directory tree (instead of a real
// container) validates the walk/hash/recursion logic without needing a live
// container in the test environment.
TEST_F(RootfsFileWalkerTest, WalksFlatDirectoryAndHashesRegularFiles)
{
    WriteFile("a.txt", "hello");
    WriteFile("b.txt", "world");

    const auto result = WalkContainerPath(::getpid(), dir_, -1, 0, 0);
    ASSERT_FALSE(result.root_missing);
    EXPECT_FALSE(result.truncated);
    EXPECT_EQ(result.rows.size(), 2u);

    for (const auto& row : result.rows) {
        EXPECT_FALSE(row.hash_sha256.empty());
        EXPECT_FALSE(row.is_symlink);
    }
}

TEST_F(RootfsFileWalkerTest, RecursionLevelZeroDoesNotDescendIntoSubdirs)
{
    WriteFile("top.txt", "x");
    ASSERT_EQ(::mkdir((dir_ + "/sub").c_str(), 0755), 0);
    WriteFile("sub/nested.txt", "y");

    const auto result = WalkContainerPath(::getpid(), dir_, /*recursion_level=*/0, 0, 0);
    ASSERT_FALSE(result.root_missing);
    ASSERT_EQ(result.rows.size(), 1u);
    EXPECT_EQ(result.rows[0].path, dir_ + "/top.txt");
}

TEST_F(RootfsFileWalkerTest, UnlimitedRecursionDescendsAllLevels)
{
    WriteFile("top.txt", "x");
    ASSERT_EQ(::mkdir((dir_ + "/sub").c_str(), 0755), 0);
    WriteFile("sub/nested.txt", "y");

    const auto result = WalkContainerPath(::getpid(), dir_, /*recursion_level=*/-1, 0, 0);
    ASSERT_FALSE(result.root_missing);
    EXPECT_EQ(result.rows.size(), 2u);
}

TEST_F(RootfsFileWalkerTest, MaxFilesCapTruncates)
{
    WriteFile("a.txt", "1");
    WriteFile("b.txt", "2");
    WriteFile("c.txt", "3");

    const auto result = WalkContainerPath(::getpid(), dir_, -1, /*max_files=*/2, 0);
    EXPECT_TRUE(result.truncated);
    EXPECT_LE(result.rows.size(), 2u);
}

TEST_F(RootfsFileWalkerTest, MissingPathIsReportedNotCrashed)
{
    const auto result = WalkContainerPath(::getpid(), dir_ + "/does-not-exist", -1, 0, 0);
    EXPECT_TRUE(result.root_missing);
    EXPECT_TRUE(result.rows.empty());
}

TEST_F(RootfsFileWalkerTest, SymlinkIsRecordedWithoutHashing)
{
    WriteFile("target.txt", "content");
    ASSERT_EQ(::symlink((dir_ + "/target.txt").c_str(), (dir_ + "/link.txt").c_str()), 0);

    const auto result = WalkContainerPath(::getpid(), dir_, -1, 0, 0);
    ASSERT_FALSE(result.root_missing);

    bool found_symlink = false;
    for (const auto& row : result.rows) {
        if (row.path == dir_ + "/link.txt") {
            found_symlink = true;
            EXPECT_TRUE(row.is_symlink);
            EXPECT_TRUE(row.hash_sha256.empty());
        }
    }
    EXPECT_TRUE(found_symlink);
}
