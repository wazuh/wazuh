#include "internal_path_guard.hpp"

#include <string>
#include <vector>

#include <gtest/gtest.h>

using wazuh::container_baseline::IsSafeInternalPath;
using wazuh::container_baseline::kMaxInternalPathLength;

TEST(InternalPathGuard, AcceptsOrdinaryAbsoluteContainerPaths)
{
    EXPECT_TRUE(IsSafeInternalPath("/"));
    EXPECT_TRUE(IsSafeInternalPath("/etc"));
    EXPECT_TRUE(IsSafeInternalPath("/etc/passwd"));
    EXPECT_TRUE(IsSafeInternalPath("/usr/local/bin/app"));
    EXPECT_TRUE(IsSafeInternalPath("/var/log/nginx/access.log"));

    // A leading dot is a hidden file, not a relative component.
    EXPECT_TRUE(IsSafeInternalPath("/root/.ssh/authorized_keys"));
    EXPECT_TRUE(IsSafeInternalPath("/etc/..hidden"));
    EXPECT_TRUE(IsSafeInternalPath("/etc/x..y"));
    EXPECT_TRUE(IsSafeInternalPath("/etc/..."));
}

TEST(InternalPathGuard, RejectsEveryFormOfParentEscape)
{
    // The path arrives in a kernel event emitted by a process inside the
    // container, so it is chosen by whatever the container is running.
    const std::vector<std::string> escapes = {
        "/..",
        "/../",
        "/../etc/passwd",
        "/etc/..",
        "/etc/../../root/.ssh/id_rsa",
        "/etc/../../../../root/.ssh/id_rsa",
        "/a/b/../../../etc/shadow",
        "/etc/./../root",
    };

    for (const auto& path : escapes)
    {
        EXPECT_FALSE(IsSafeInternalPath(path)) << path;
    }
}

TEST(InternalPathGuard, RejectsCurrentDirectoryComponents)
{
    EXPECT_FALSE(IsSafeInternalPath("/."));
    EXPECT_FALSE(IsSafeInternalPath("/./etc"));
    EXPECT_FALSE(IsSafeInternalPath("/etc/./passwd"));
    EXPECT_FALSE(IsSafeInternalPath("/etc/."));
}

TEST(InternalPathGuard, RejectsNonCanonicalSpellingsOfAValidPath)
{
    // file_entry is keyed by path, so admitting two spellings of one file would
    // store it twice under keys that never converge.
    EXPECT_FALSE(IsSafeInternalPath("/etc//passwd"));
    EXPECT_FALSE(IsSafeInternalPath("//etc/passwd"));
    EXPECT_FALSE(IsSafeInternalPath("/etc/passwd/"));
    EXPECT_FALSE(IsSafeInternalPath("/etc/"));
}

TEST(InternalPathGuard, RejectsRelativeAndEmptyPaths)
{
    EXPECT_FALSE(IsSafeInternalPath(""));
    EXPECT_FALSE(IsSafeInternalPath("etc/passwd"));
    EXPECT_FALSE(IsSafeInternalPath("./etc"));
    EXPECT_FALSE(IsSafeInternalPath("../etc"));
}

TEST(InternalPathGuard, RejectsAnEmbeddedNul)
{
    // std::string carries it happily; the kernel would stop at it, so the path
    // that was checked is not the path that gets opened.
    std::string smuggled("/etc/passwd");
    smuggled.push_back('\0');
    smuggled += "/../../root";

    EXPECT_FALSE(IsSafeInternalPath(smuggled));
    EXPECT_FALSE(IsSafeInternalPath(std::string("/etc\0/passwd", 12)));
}

TEST(InternalPathGuard, RejectsAbsurdlyLongPaths)
{
    EXPECT_TRUE(IsSafeInternalPath("/" + std::string(kMaxInternalPathLength - 1, 'a')));
    EXPECT_FALSE(IsSafeInternalPath("/" + std::string(kMaxInternalPathLength, 'a')));
}
