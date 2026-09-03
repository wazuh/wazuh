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
using wazuh::container_baseline::IsPathWithinMount;
using wazuh::container_baseline::WalkContainerPath;

TEST(IsPathWithinMount, MatchesTheDestinationItself)
{
    EXPECT_TRUE(IsPathWithinMount("/data", "/data"));
}

TEST(IsPathWithinMount, MatchesPathsBelowTheDestination)
{
    EXPECT_TRUE(IsPathWithinMount("/data/sub", "/data"));
    EXPECT_TRUE(IsPathWithinMount("/data/sub/deep.txt", "/data"));
}

TEST(IsPathWithinMount, DoesNotMatchASiblingSharingAPrefix)
{
    // The whole point of the guard: "/variable" must not count as inside
    // "/var", or the walk would follow a mount it was never allowed into.
    EXPECT_FALSE(IsPathWithinMount("/variable", "/var"));
    EXPECT_FALSE(IsPathWithinMount("/datastore/x", "/data"));
}

TEST(IsPathWithinMount, HandlesTrailingSlashDestination)
{
    EXPECT_TRUE(IsPathWithinMount("/data/sub", "/data/"));
    EXPECT_FALSE(IsPathWithinMount("/datastore", "/data/"));
}

TEST(IsPathWithinMount, EmptyDestinationNeverMatches)
{
    EXPECT_FALSE(IsPathWithinMount("/anything", ""));
}

TEST(IsPathWithinMount, ShorterPathIsNotInside)
{
    EXPECT_FALSE(IsPathWithinMount("/da", "/data"));
}

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

TEST_F(RootfsFileWalkerTest, FileOverTheSizeLimitIsReportedButNotHashed)
{
    WriteFile("small.txt", "tiny");
    WriteFile("big.txt", std::string(4096, 'x'));

    // max_hash_bytes is a "don't hash above this" threshold, NOT a cutoff to
    // hash up to: a digest over a prefix would match no other reader's value
    // and would collide for any two files sharing that prefix.
    const auto result = WalkContainerPath(::getpid(), dir_, -1, 0, /*max_hash_bytes=*/1024);
    ASSERT_FALSE(result.root_missing);
    ASSERT_EQ(result.rows.size(), 2u);

    for (const auto& row : result.rows) {
        if (row.path == dir_ + "/big.txt") {
            EXPECT_EQ(row.size, 4096u);
            EXPECT_TRUE(row.hash_md5.empty());
            EXPECT_TRUE(row.hash_sha1.empty());
            EXPECT_TRUE(row.hash_sha256.empty()) << "a prefix digest was emitted for an over-limit file";
        } else {
            EXPECT_FALSE(row.hash_sha256.empty());
        }
    }
}

TEST_F(RootfsFileWalkerTest, HashSelectionIsHonoured)
{
    WriteFile("a.txt", "abc");

    wazuh::container_baseline::HashSelection only_sha256;
    only_sha256.md5 = false;
    only_sha256.sha1 = false;

    const auto result = WalkContainerPath(::getpid(), dir_, -1, 0, 0, nullptr, only_sha256);
    ASSERT_EQ(result.rows.size(), 1u);

    EXPECT_TRUE(result.rows[0].hash_md5.empty());
    EXPECT_TRUE(result.rows[0].hash_sha1.empty());
    EXPECT_EQ(result.rows[0].hash_sha256,
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_F(RootfsFileWalkerTest, OwnershipIsReportedForEveryRow)
{
    WriteFile("a.txt", "x");

    const auto result = WalkContainerPath(::getpid(), dir_, -1, 0, 0);
    ASSERT_EQ(result.rows.size(), 1u);

    // uid/gid go through the /proc/<pid>/{uid,gid}_map translation, which is
    // the identity map for a process that is not userns-remapped — so on the
    // test host these must equal the real ids rather than being blank or
    // shifted.
    EXPECT_EQ(result.rows[0].uid, std::to_string(::getuid()));
    EXPECT_EQ(result.rows[0].gid, std::to_string(::getgid()));
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
