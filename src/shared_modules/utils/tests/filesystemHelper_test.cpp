/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 23, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "filesystemHelper_test.h"

void FilesystemUtilsTest::SetUp() {};

void FilesystemUtilsTest::TearDown() {};
#ifdef WIN32
TEST_F(FilesystemUtilsTest, FilesystemExistsDir)
{
    EXPECT_TRUE(Utils::existsDir(R"(C:\)"));
}

TEST_F(FilesystemUtilsTest, FilesystemEnumerateDir)
{
    const auto items {Utils::enumerateDir(R"(C:\)")};
    EXPECT_FALSE(items.empty());
}

TEST_F(FilesystemUtilsTest, joinPathsBothEmpty)
{
    EXPECT_EQ(Utils::joinPaths("", ""), "");
}

TEST_F(FilesystemUtilsTest, joinPathsBaseEmpty)
{
    EXPECT_EQ(Utils::joinPaths("", R"(relative\path)"), R"(relative\path)");
}

TEST_F(FilesystemUtilsTest, joinPathsRelativeEmpty)
{
    EXPECT_EQ(Utils::joinPaths(R"(C:\base\path)", ""), R"(C:\base\path)");
}

TEST_F(FilesystemUtilsTest, joinPathsNormalCase)
{
    EXPECT_EQ(Utils::joinPaths(R"(C:\base\path)", R"(relative\path)"), R"(C:\base\path\relative\path)");
}

TEST_F(FilesystemUtilsTest, joinPathsBaseWithTrailingSlash)
{
    EXPECT_EQ(Utils::joinPaths(R"(C:\base\path\)", R"(relative\path)"), R"(C:\base\path\relative\path)");
}

TEST_F(FilesystemUtilsTest, joinPathsRelativeWithLeadingSlash)
{
    EXPECT_EQ(Utils::joinPaths(R"(C:\base\path)", R"(\relative\path)"), R"(C:\base\path\relative\path)");
}

TEST_F(FilesystemUtilsTest, joinPathsBothWithSlash)
{
    EXPECT_EQ(Utils::joinPaths(R"(C:\base\path\)", R"(\relative\path)"), R"(C:\base\path\relative\path)");
}

TEST_F(FilesystemUtilsTest, joinPathsSingleLevel)
{
    EXPECT_EQ(Utils::joinPaths(R"(C:\base)", "file.txt"), R"(C:\base\file.txt)");
}

TEST_F(FilesystemUtilsTest, joinPathsMixedSeparators)
{
    // Forward slashes should be converted to backslashes on Windows
    EXPECT_EQ(Utils::joinPaths(R"(C:\base\path)", "relative/path/file.txt"), R"(C:\base\path\relative\path\file.txt)");
}

TEST_F(FilesystemUtilsTest, joinPathsMultipleTrailingSlashes)
{
    EXPECT_EQ(Utils::joinPaths(R"(C:\base\path\\\)", R"(\\\relative\path)"), R"(C:\base\path\relative\path)");
}

TEST_F(FilesystemUtilsTest, joinPathsBaseOnlySeparators)
{
    EXPECT_EQ(Utils::joinPaths(R"(\\\)", R"(relative\path)"), R"(relative\path)");
}

#else

TEST_F(FilesystemUtilsTest, FilesystemExistsDir)
{
    EXPECT_TRUE(Utils::existsDir(R"(/usr)"));
}

TEST_F(FilesystemUtilsTest, FilesystemExistsRegular)
{
    // Check correct input, for macos and linux.
    EXPECT_TRUE(Utils::existsRegular(R"(/etc/services)"));

    // Check wrong input
    EXPECT_FALSE(Utils::existsRegular(R"(/etc)"));
}

TEST_F(FilesystemUtilsTest, FilesystemEnumerateDir)
{
    const auto items {Utils::enumerateDir(R"(/usr)")};
    EXPECT_FALSE(items.empty());
}

TEST_F(FilesystemUtilsTest, getFileContent)
{
    const auto& inputFile{"/etc/services"};
    const auto content {Utils::getFileContent(inputFile)};
    EXPECT_FALSE(content.empty());
}

TEST_F(FilesystemUtilsTest, getFileBinaryContent)
{
    const auto binContent {Utils::getBinaryContent("/usr/bin/gcc")};
    EXPECT_FALSE(binContent.empty());
}

TEST_F(FilesystemUtilsTest, joinPathsBothEmpty)
{
    EXPECT_EQ(Utils::joinPaths("", ""), "");
}

TEST_F(FilesystemUtilsTest, joinPathsBaseEmpty)
{
    EXPECT_EQ(Utils::joinPaths("", "relative/path"), "relative/path");
}

TEST_F(FilesystemUtilsTest, joinPathsRelativeEmpty)
{
    EXPECT_EQ(Utils::joinPaths("/base/path", ""), "/base/path");
}

TEST_F(FilesystemUtilsTest, joinPathsNormalCase)
{
    EXPECT_EQ(Utils::joinPaths("/base/path", "relative/path"), "/base/path/relative/path");
}

TEST_F(FilesystemUtilsTest, joinPathsBaseWithTrailingSlash)
{
    EXPECT_EQ(Utils::joinPaths("/base/path/", "relative/path"), "/base/path/relative/path");
}

TEST_F(FilesystemUtilsTest, joinPathsRelativeWithLeadingSlash)
{
    EXPECT_EQ(Utils::joinPaths("/base/path", "/relative/path"), "/base/path/relative/path");
}

TEST_F(FilesystemUtilsTest, joinPathsBothWithSlash)
{
    EXPECT_EQ(Utils::joinPaths("/base/path/", "/relative/path"), "/base/path/relative/path");
}

TEST_F(FilesystemUtilsTest, joinPathsSingleLevel)
{
    EXPECT_EQ(Utils::joinPaths("/base", "file.txt"), "/base/file.txt");
}

TEST_F(FilesystemUtilsTest, joinPathsMultipleTrailingSlashes)
{
    EXPECT_EQ(Utils::joinPaths("/base/path///", "///relative/path"), "/base/path/relative/path");
}

TEST_F(FilesystemUtilsTest, joinPathsBaseOnlySeparators)
{
    EXPECT_EQ(Utils::joinPaths("///", "relative/path"), "relative/path");
}

TEST_F(FilesystemUtilsTest, isUnmountedAutomountPointFalseForLocalPaths)
{
    const ScopedTestDirectory base {"wazuh_automount_test"};
    std::filesystem::create_directories(base.path() / "dir");
    std::ofstream {base.path() / "file"} << "data";
    std::filesystem::create_directory_symlink(base.path() / "dir", base.path() / "link");
    std::filesystem::create_symlink(base.path() / "missing", base.path() / "dangling");
    ASSERT_EQ(::mkfifo((base.path() / "fifo").c_str(), 0600), 0);

    EXPECT_FALSE(Utils::isUnmountedAutomountPoint((base.path() / "dir").string()));
    EXPECT_FALSE(Utils::isUnmountedAutomountPoint((base.path() / "file").string()));
    EXPECT_FALSE(Utils::isUnmountedAutomountPoint((base.path() / "link").string()));
    EXPECT_FALSE(Utils::isUnmountedAutomountPoint((base.path() / "dangling").string()));
    // The check must not wait for a writer on a FIFO
    EXPECT_FALSE(Utils::isUnmountedAutomountPoint((base.path() / "fifo").string()));
    EXPECT_FALSE(Utils::isUnmountedAutomountPoint((base.path() / "missing").string()));
    EXPECT_FALSE(Utils::isUnmountedAutomountPoint(""));
}

#ifdef __linux__
// fstatfs() stand-ins reporting a given file system type, so the check runs on any host
static int fileSystemStatusAutofs(int, struct statfs* info)
{
    info->f_type = AUTOFS_SUPER_MAGIC;
    return 0;
}

static int fileSystemStatusNfs(int, struct statfs* info)
{
    info->f_type = NFS_SUPER_MAGIC;
    return 0;
}

static int fileSystemStatusFails(int, struct statfs*)
{
    errno = EBADF;
    return -1;
}

TEST_F(FilesystemUtilsTest, isUnmountedAutomountPointTrueOnlyForAutofs)
{
    const ScopedTestDirectory base {"wazuh_automount_type_test"};

    EXPECT_TRUE(Utils::isUnmountedAutomountPoint(base.path().string(), fileSystemStatusAutofs));
    EXPECT_FALSE(Utils::isUnmountedAutomountPoint(base.path().string(), fileSystemStatusNfs));
    EXPECT_FALSE(Utils::isUnmountedAutomountPoint(base.path().string(), fileSystemStatusFails));
    // A path that cannot be opened is never reported, whatever its file system would be
    EXPECT_FALSE(Utils::isUnmountedAutomountPoint((base.path() / "missing").string(), fileSystemStatusAutofs));
}

// The flags the check opened the path with, as the stand-in below saw them
static int s_openFlags {-1};

static int fileSystemStatusRecordingFlags(int fd, struct statfs* info)
{
    s_openFlags = ::fcntl(fd, F_GETFL);
    info->f_type = AUTOFS_SUPER_MAGIC;
    return 0;
}

TEST_F(FilesystemUtilsTest, isUnmountedAutomountPointOpensThePathOnly)
{
    // The check rests on its open flags: O_PATH does not trigger the automount of the last
    // component, and O_DIRECTORY does
    const ScopedTestDirectory base {"wazuh_automount_flags_test"};
    s_openFlags = -1;

    EXPECT_TRUE(Utils::isUnmountedAutomountPoint(base.path().string(), fileSystemStatusRecordingFlags));
    ASSERT_NE(s_openFlags, -1);
    EXPECT_EQ(s_openFlags & O_PATH, O_PATH);
    EXPECT_EQ(s_openFlags & O_DIRECTORY, 0);
}

TEST_F(FilesystemUtilsTest, automountCheckCacheReusesAnswersForItsTtl)
{
    using Clock = Utils::AutomountCheckCache::Clock;
    Utils::AutomountCheckCache::clear();
    int probes {0};
    bool unmounted {true};
    const auto probe {[&](const std::string&)
    {
        ++probes;
        return unmounted;
    }};
    const auto start {Clock::now()};
    const auto ttl {Utils::AutomountCheckCache::ttl()};

    EXPECT_TRUE(Utils::AutomountCheckCache::check("/cache-test/alice", probe, start));
    EXPECT_EQ(probes, 1);

    // Within the TTL, the cached answer is given without asking again, even if it changed
    unmounted = false;
    EXPECT_TRUE(Utils::AutomountCheckCache::check("/cache-test/alice", probe, start + ttl - std::chrono::seconds {1}));
    EXPECT_EQ(probes, 1);

    // Each path has its own answer
    EXPECT_FALSE(Utils::AutomountCheckCache::check("/cache-test/bob", probe, start));
    EXPECT_EQ(probes, 2);

    // Once the TTL has passed, it asks again
    EXPECT_FALSE(Utils::AutomountCheckCache::check("/cache-test/alice", probe, start + ttl));
    EXPECT_EQ(probes, 3);

    Utils::AutomountCheckCache::clear();
    EXPECT_FALSE(Utils::AutomountCheckCache::check("/cache-test/alice", probe, start + ttl));
    EXPECT_EQ(probes, 4);
}
#endif

TEST_F(FilesystemUtilsTest, expandAbsolutePathWithAutomountCheckKeepsLocalDirectories)
{
    const ScopedTestDirectory base {"wazuh_expand_test"};
    std::filesystem::create_directories(base.path() / "home" / "alice" / ".local" / "lib");
    std::filesystem::create_directories(base.path() / "home" / "bob" / ".local" / "lib");

    std::deque<std::string> output;
    Utils::expandAbsolutePath((base.path() / "home" / "*" / ".local" / "lib").string(), output,
                              [](const std::string & path)
    {
        return Utils::isUnmountedAutomountPoint(path);
    });
    std::sort(output.begin(), output.end());

    const std::deque<std::string> expected {(base.path() / "home" / "alice" / ".local" / "lib").string(),
                                            (base.path() / "home" / "bob" / ".local" / "lib").string()};
    EXPECT_EQ(output, expected);
}

TEST_F(FilesystemUtilsTest, expandAbsolutePathDoesNotDescendIntoSkippedEntries)
{
    const ScopedTestDirectory base {"wazuh_expand_skip_test"};
    std::filesystem::create_directories(base.path() / "home" / "alice" / ".local" / "lib");
    std::filesystem::create_directories(base.path() / "home" / "bob" / ".local" / "lib");
    std::filesystem::create_directories(base.path() / "home" / "carol" / ".local" / "lib");

    std::vector<std::string> asked;
    const auto skipBob = [&](const std::string & path)
    {
        asked.push_back(path);
        return path == (base.path() / "home" / "bob").string();
    };

    std::deque<std::string> output;
    Utils::expandAbsolutePath((base.path() / "home" / "*" / ".local" / "lib").string(), output, skipBob);
    std::sort(output.begin(), output.end());

    const std::deque<std::string> expected {(base.path() / "home" / "alice" / ".local" / "lib").string(),
                                            (base.path() / "home" / "carol" / ".local" / "lib").string()};
    EXPECT_EQ(output, expected);
    // Only the entries matching a wildcard are asked about, and nothing below bob
    std::sort(asked.begin(), asked.end());
    const std::vector<std::string> expectedAsked {(base.path() / "home" / "alice").string(),
                                                  (base.path() / "home" / "bob").string(),
                                                  (base.path() / "home" / "carol").string()};
    EXPECT_EQ(asked, expectedAsked);
}

TEST_F(FilesystemUtilsTest, expandAbsolutePathAsksOnlyAboutTheFirstWildcardLevel)
{
    const ScopedTestDirectory base {"wazuh_expand_levels_test"};
    std::filesystem::create_directories(base.path() / "home" / "alice" / "lib" / "python3.9" / "site-packages");
    std::filesystem::create_directories(base.path() / "home" / "alice" / "lib" / "python3.12" / "site-packages");

    std::vector<std::string> asked;
    std::deque<std::string> output;
    Utils::expandAbsolutePath((base.path() / "home" / "*" / "lib" / "python*" / "*-packages").string(), output,
                              [&](const std::string & path)
    {
        asked.push_back(path);
        return false;
    });

    EXPECT_EQ(output.size(), 2u);
    const std::vector<std::string> expectedAsked {(base.path() / "home" / "alice").string()};
    EXPECT_EQ(asked, expectedAsked);
}

TEST_F(FilesystemUtilsTest, expandAbsolutePathWithoutCheckSkipsNothing)
{
    const ScopedTestDirectory base {"wazuh_expand_plain_test"};
    std::filesystem::create_directories(base.path() / "home" / "alice");
    std::filesystem::create_directories(base.path() / "home" / "bob");

    std::deque<std::string> output;
    Utils::expandAbsolutePath((base.path() / "home" / "*").string(), output);

    EXPECT_EQ(output.size(), 2u);
}

#ifdef __linux__
// How many file systems are mounted on a path, from /proc/self/mounts
static int mountCount(const std::string& mountPoint)
{
    std::ifstream mounts {"/proc/self/mounts"};
    std::string device;
    std::string path;
    std::string rest;
    int count {0};

    while (mounts >> device >> path && std::getline(mounts, rest))
    {
        count += path == mountPoint ? 1 : 0;
    }

    return count;
}

// An autofs mount point with nothing mounted on it yet that this process can open, or an empty
// string if the host has none
static std::string findAutofsTrigger()
{
    std::ifstream mounts {"/proc/self/mounts"};
    std::string device;
    std::string path;
    std::string type;
    std::string rest;

    while (mounts >> device >> path >> type && std::getline(mounts, rest))
    {
        if (type == "autofs" && path.find('\\') == std::string::npos && mountCount(path) == 1 &&
                ::access(path.c_str(), X_OK) == 0)
        {
            return path;
        }
    }

    return "";
}

// Whether the kernel honors O_PATH and reports the file system of an O_PATH descriptor (Linux 3.12
// or later upstream, or a distribution kernel with the same support, such as RHEL 7)
static bool kernelReportsFileSystemOfPathDescriptors()
{
#ifdef O_PATH
    const auto fd {::open("/", O_PATH | O_CLOEXEC)};

    if (fd < 0)
    {
        return false;
    }

    // Reading an O_PATH descriptor fails with EBADF; a kernel that ignores O_PATH opened the
    // directory for reading, and fails with EISDIR instead
    char byte {};
    const auto honorsPathOnly {::read(fd, &byte, 1) < 0 && errno == EBADF};
    struct statfs info {};
    const auto reportsFileSystem {::fstatfs(fd, &info) == 0};

    ::close(fd);

    return honorsPathOnly && reportsFileSystem;
#else
    return false;
#endif
}

TEST_F(FilesystemUtilsTest, isUnmountedAutomountPointTrueForAnAutofsTrigger)
{
    const auto trigger {findAutofsTrigger()};

    if (trigger.empty() || !kernelReportsFileSystemOfPathDescriptors())
    {
        GTEST_SKIP() << "No reachable autofs mount point without a file system mounted on it, or a kernel that cannot report the file system of an O_PATH descriptor";
    }

    // Asked right after the trigger was found, so a false result comes from the check itself (an
    // open that mounts it), not from another process mounting it in between
    ASSERT_TRUE(Utils::isUnmountedAutomountPoint(trigger, ::fstatfs));

    const auto parent {std::filesystem::path(trigger).parent_path()};
    const auto listParent {parent != parent.root_path()};
    std::deque<std::string> skipped;
    std::deque<std::string> all;

    if (listParent)
    {
        Utils::expandAbsolutePath((parent / "*").string(), skipped, [](const std::string & path)
        {
            return Utils::isUnmountedAutomountPoint(path);
        });
        Utils::expandAbsolutePath((parent / "*").string(), all);
    }

    const auto stillUnmounted {Utils::isUnmountedAutomountPoint(trigger, ::fstatfs)};

    // The trigger belongs to the host (e.g. binfmt_misc), so another process can mount it while the
    // parent is listed; the results then say nothing about the check
    if (mountCount(trigger) != 1)
    {
        GTEST_SKIP() << "Another process mounted " << trigger << " during the test";
    }

    if (listParent)
    {
        // The check leaves the trigger out of the expansion, and listing it does not mount it
        EXPECT_EQ(std::find(skipped.begin(), skipped.end(), trigger), skipped.end());
        EXPECT_NE(std::find(all.begin(), all.end(), trigger), all.end());
    }

    EXPECT_TRUE(stillUnmounted);
}
#endif
#endif
