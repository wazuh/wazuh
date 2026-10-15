// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <base/process.hpp>

using namespace base::process;
namespace fs = std::filesystem;

// Exit codes for goDaemon functional test
static constexpr int EXIT_DAEMON_FAILURE = 2;
static constexpr int EXIT_WRITE_FAILURE = 3;

namespace
{
constexpr std::size_t LOOKUP_CAP = 65536; ///< Contract: largest buffer offered to the lookup

/// Initial buffer size the contract mandates: the sysconf hint, or 1024 when it gives none.
std::size_t expectedInitialSize(int sysconfName)
{
    const long hint = sysconf(sysconfName);
    return std::min(hint > 0 ? static_cast<std::size_t>(hint) : std::size_t {1024}, LOOKUP_CAP);
}

/// Runs fn, expects a std::runtime_error and returns its what() ("" if nothing or something else was thrown).
template<typename Fn>
std::string thrownMessage(Fn&& fn)
{
    try
    {
        fn();
    }
    catch (const std::runtime_error& e)
    {
        return e.what();
    }
    catch (...)
    {
        return "<unexpected exception type>";
    }
    return "<no exception>";
}

/// Reads the whole file, byte by byte.
std::string readAll(const fs::path& file)
{
    std::ifstream ifs(file, std::ios::binary);
    return {std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>()};
}

/// Fresh, empty temporary directory for a test; the pid suffix keeps concurrent runs apart.
fs::path freshDir(const std::string& name)
{
    const auto dir = fs::temp_directory_path() / (name + "_" + std::to_string(getpid()));
    fs::remove_all(dir);
    fs::create_directory(dir);
    return dir;
}

/// Lookup fake for both passwd and group: returns `ranges` ERANGEs, then `finalRc`; records every buffer size.
/// errno is deliberately left with misleading values: 0 on ERANGE and ERANGE on success, so an implementation
/// that reads errno instead of the return code fails.
template<typename Entry>
struct FakeLookup
{
    int ranges;          ///< ERANGE answers before the final one (-1: ERANGE forever)
    int finalRc;         ///< Final return code
    bool foundOnSuccess; ///< Final rc==0: set *found = entry (true) or nullptr (false)
    unsigned id;         ///< Id stored in the entry on success
    std::vector<size_t>* sizes;

    int operator()(const char* name, Entry* entry, char* buf, size_t len, Entry** found) const
    {
        sizes->push_back(len);
        EXPECT_STREQ(name, "x");
        std::memset(buf, 0, len); // the buffer really has len bytes (ASAN would catch a lie)
        *found = nullptr;

        if (ranges < 0 || static_cast<int>(sizes->size()) <= ranges)
        {
            errno = 0;
            return ERANGE;
        }
        if (finalRc != 0)
        {
            errno = 0;
            return finalRc;
        }
        errno = ERANGE;
        if (foundOnSuccess)
        {
            setId(entry);
            *found = entry;
        }
        return 0;
    }

    void setId(struct passwd* entry) const { entry->pw_uid = static_cast<uid_t>(id); }
    void setId(struct group* entry) const { entry->gr_gid = static_cast<gid_t>(id); }
};

using FakeUserLookup = FakeLookup<struct passwd>;
using FakeGroupLookup = FakeLookup<struct group>;

/// Every size doubles the previous one; first is base, last is the cap.
void expectDoublingToCap(const std::vector<size_t>& sizes, std::size_t base)
{
    ASSERT_FALSE(sizes.empty());
    EXPECT_EQ(sizes.front(), base);
    for (std::size_t i = 1; i < sizes.size(); ++i)
    {
        EXPECT_EQ(sizes[i], std::min(sizes[i - 1] * 2, LOOKUP_CAP)) << "call " << i;
    }
    EXPECT_EQ(sizes.back(), LOOKUP_CAP);
    // No call after the cap was offered once
    EXPECT_EQ(std::count(sizes.begin(), sizes.end(), LOOKUP_CAP), 1);
}
} // namespace

// Test createPID success scenario
TEST(CreatePIDTest, Success)
{
    // Arrange
    fs::path tmpDir = freshDir("base_process_test_success");
    std::string svcName = "svc";
    int pidValue = 12345;

    // Act
    auto result = createPID(tmpDir.string(), svcName, pidValue);

    // Assert
    ASSERT_FALSE(isError(result));
    fs::path pidFile = tmpDir / (svcName + "-" + std::to_string(pidValue) + ".pid");
    ASSERT_TRUE(fs::exists(pidFile));
    EXPECT_EQ(readAll(pidFile), std::to_string(pidValue) + "\n");

    struct stat st;
    ASSERT_EQ(stat(pidFile.c_str(), &st), 0);
    mode_t mode = st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
    EXPECT_EQ(mode, (S_IRUSR | S_IWUSR | S_IRGRP));

    // Cleanup
    fs::remove_all(tmpDir);
}

// Test createPID failure scenario
TEST(CreatePIDTest, Failure)
{
    std::string invalidPath = "/tmp/nonexistent_dir_abc";
    fs::remove_all(invalidPath);
    auto result = createPID(invalidPath, "svc", 1);
    ASSERT_TRUE(isError(result));
    EXPECT_EQ(base::getError(result).message,
              "could not create PID file /tmp/nonexistent_dir_abc/svc-1.pid: No such file or directory (2)");
}

// The mode given to open() is filtered by the umask; only fchmod yields exactly 0640 under umask 077.
TEST(CreatePIDTest, ModeIs0640UnderUmask077)
{
    const fs::path tmpDir = freshDir("base_process_test_umask");
    const fs::path pidFile = tmpDir / "svc-777.pid";

    const mode_t saved = umask(077);
    const auto result = createPID(tmpDir.string(), "svc", 777);
    umask(saved);

    ASSERT_FALSE(isError(result)) << base::getError(result).message;
    struct stat st;
    ASSERT_EQ(stat(pidFile.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 07777, static_cast<mode_t>(0640));
    EXPECT_EQ(readAll(pidFile), "777\n");

    fs::remove_all(tmpDir);
}

// A stale, longer PID file must be fully replaced, not overwritten in place.
TEST(CreatePIDTest, TruncatesExisting)
{
    const fs::path tmpDir = freshDir("base_process_test_truncate");
    const fs::path pidFile = tmpDir / "svc-42.pid";
    {
        std::ofstream ofs(pidFile, std::ios::binary);
        ofs << "1234567890\nstale content that is much longer than the new one\n";
    }

    const auto result = createPID(tmpDir.string(), "svc", 42);

    ASSERT_FALSE(isError(result)) << base::getError(result).message;
    EXPECT_EQ(readAll(pidFile), "42\n");
    struct stat st;
    ASSERT_EQ(stat(pidFile.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 07777, static_cast<mode_t>(0640));

    fs::remove_all(tmpDir);
}

// Functional test for goDaemon: execution continues in the grandchild, which is in a new session it does not lead
// (double fork after setsid) and has umask 027.
TEST(GoDaemonFunctionalTest, ContinuesInGrandchild)
{
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);
    const pid_t originalSid = getsid(0);
    pid_t pid = fork();
    ASSERT_GE(pid, 0);

    if (pid == 0)
    {
        // Child context for goDaemon
        close(fds[0]);

        try
        {
            goDaemon();
        }
        catch (...)
        {
            _exit(EXIT_DAEMON_FAILURE);
        }
        // In grandchild: 'X' only if detached as daemon(7) describes, 'N' otherwise
        const pid_t sid = getsid(0);
        const mode_t mask = umask(0);
        const char msg = (sid != originalSid && sid != getpid() && mask == 027) ? 'X' : 'N';
        ssize_t w = write(fds[1], &msg, 1);
        if (w != 1)
        {
            _exit(EXIT_WRITE_FAILURE);
        }
        _exit(EXIT_SUCCESS);
    }

    // Parent context: read from pipe
    close(fds[1]);
    char buf = 0;
    ssize_t n = read(fds[0], &buf, 1);
    close(fds[0]);
    EXPECT_EQ(n, 1);
    EXPECT_EQ(buf, 'X');

    int status;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);
}

// In the grandchild, stdin, stdout and stderr are all /dev/null. Before goDaemon they are pointed at a pipe, so the
// check does not depend on how the test runner set them up.
TEST(GoDaemonFunctionalTest, StdioIsDevNull)
{
    struct stat devNull;
    ASSERT_EQ(stat("/dev/null", &devNull), 0);
    ASSERT_TRUE(S_ISCHR(devNull.st_mode));

    int report[2];
    ASSERT_EQ(pipe(report), 0);
    int sentinel[2];
    ASSERT_EQ(pipe(sentinel), 0);

    pid_t pid = fork();
    ASSERT_GE(pid, 0);

    if (pid == 0)
    {
        close(report[0]);
        // Point 0/1/2 at something that is not /dev/null
        for (const int target : {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO})
        {
            if (dup2(sentinel[1], target) < 0)
            {
                _exit(EXIT_WRITE_FAILURE);
            }
        }
        close(sentinel[0]);
        close(sentinel[1]);

        try
        {
            goDaemon();
        }
        catch (...)
        {
            _exit(EXIT_DAEMON_FAILURE);
        }

        // Grandchild: one char per fd, 'Y' = /dev/null, 'N' = something else, 'E' = fstat failed
        char result[3];
        for (int fd = 0; fd < 3; ++fd)
        {
            struct stat st;
            if (fstat(fd, &st) != 0)
            {
                result[fd] = 'E';
            }
            else
            {
                result[fd] = (S_ISCHR(st.st_mode) && st.st_rdev == devNull.st_rdev) ? 'Y' : 'N';
            }
        }
        if (write(report[1], result, sizeof(result)) != static_cast<ssize_t>(sizeof(result)))
        {
            _exit(EXIT_WRITE_FAILURE);
        }
        _exit(EXIT_SUCCESS);
    }

    close(report[1]);
    close(sentinel[0]);
    close(sentinel[1]);

    std::string got;
    char buf[8];
    ssize_t n;
    while ((n = read(report[0], buf, sizeof(buf))) > 0)
    {
        got.append(buf, static_cast<std::size_t>(n));
    }
    close(report[0]);

    int status;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);

    // fd 0, 1, 2 in this order
    EXPECT_EQ(got, "YYY");
}

/*** lookupUid ***/

TEST(LookupUid, CurrentUser)
{
    struct passwd* pwd = getpwuid(getuid());
    ASSERT_NE(pwd, nullptr);
    EXPECT_EQ(lookupUid(pwd->pw_name), getuid());
}

TEST(LookupUid, UnknownRealUser)
{
    EXPECT_EQ(thrownMessage([] { lookupUid("wazuh_test_nonexistent_user"); }),
              "user 'wazuh_test_nonexistent_user' not found");
}

TEST(LookupUid, FoundAfterTwoErange)
{
    std::vector<size_t> sizes;
    const auto base = expectedInitialSize(_SC_GETPW_R_SIZE_MAX);

    const uid_t uid = lookupUid("x", FakeUserLookup {2, 0, true, 4242, &sizes});

    EXPECT_EQ(uid, static_cast<uid_t>(4242));
    EXPECT_EQ(sizes, (std::vector<size_t> {base, std::min(base * 2, LOOKUP_CAP), std::min(base * 4, LOOKUP_CAP)}));
}

TEST(LookupUid, ErangeAlwaysHitsCap)
{
    std::vector<size_t> sizes;

    EXPECT_EQ(thrownMessage([&] { lookupUid("x", FakeUserLookup {-1, 0, true, 0, &sizes}); }),
              "could not look up user 'x': entry larger than 65536 bytes");

    expectDoublingToCap(sizes, expectedInitialSize(_SC_GETPW_R_SIZE_MAX));
}

TEST(LookupUid, OtherErrorCode)
{
    std::vector<size_t> sizes;

    EXPECT_EQ(thrownMessage([&] { lookupUid("x", FakeUserLookup {0, EIO, true, 0, &sizes}); }),
              "could not look up user 'x': Input/output error (5)");
    EXPECT_EQ(sizes.size(), 1u); // no retry on a code other than ERANGE
}

TEST(LookupUid, NotFound)
{
    std::vector<size_t> sizes;

    EXPECT_EQ(thrownMessage([&] { lookupUid("x", FakeUserLookup {0, 0, false, 0, &sizes}); }), "user 'x' not found");
    EXPECT_EQ(sizes.size(), 1u);
}

/*** lookupGid ***/

TEST(LookupGid, CurrentGroup)
{
    struct group* grp = getgrgid(getgid());
    ASSERT_NE(grp, nullptr);
    EXPECT_EQ(lookupGid(grp->gr_name), getgid());
}

TEST(LookupGid, UnknownRealGroup)
{
    EXPECT_EQ(thrownMessage([] { lookupGid("wazuh_test_nonexistent_group"); }),
              "group 'wazuh_test_nonexistent_group' not found");
}

TEST(LookupGid, FoundAfterTwoErange)
{
    std::vector<size_t> sizes;
    const auto base = expectedInitialSize(_SC_GETGR_R_SIZE_MAX);

    const gid_t gid = lookupGid("x", FakeGroupLookup {2, 0, true, 4343, &sizes});

    EXPECT_EQ(gid, static_cast<gid_t>(4343));
    EXPECT_EQ(sizes, (std::vector<size_t> {base, std::min(base * 2, LOOKUP_CAP), std::min(base * 4, LOOKUP_CAP)}));
}

TEST(LookupGid, ErangeAlwaysHitsCap)
{
    std::vector<size_t> sizes;

    EXPECT_EQ(thrownMessage([&] { lookupGid("x", FakeGroupLookup {-1, 0, true, 0, &sizes}); }),
              "could not look up group 'x': entry larger than 65536 bytes");

    expectDoublingToCap(sizes, expectedInitialSize(_SC_GETGR_R_SIZE_MAX));
}

TEST(LookupGid, OtherErrorCode)
{
    std::vector<size_t> sizes;

    EXPECT_EQ(thrownMessage([&] { lookupGid("x", FakeGroupLookup {0, EIO, true, 0, &sizes}); }),
              "could not look up group 'x': Input/output error (5)");
    EXPECT_EQ(sizes.size(), 1u);
}

TEST(LookupGid, NotFound)
{
    std::vector<size_t> sizes;

    EXPECT_EQ(thrownMessage([&] { lookupGid("x", FakeGroupLookup {0, 0, false, 0, &sizes}); }), "group 'x' not found");
    EXPECT_EQ(sizes.size(), 1u);
}

/*** dropToUser / dropToGroup ***/

TEST(DropToUser, SameUidSucceeds)
{
    EXPECT_NO_THROW(dropToUser(getuid()));
}

TEST(DropToUser, ThrowsWhenNotPermitted)
{
    if (getuid() == 0)
    {
        GTEST_SKIP() << "requires a non-root user";
    }
    const uid_t target = getuid() + 1;
    EXPECT_EQ(thrownMessage([&] { dropToUser(target); }),
              "could not set user ID " + std::to_string(target) + ": Operation not permitted (1)");
}

// Functional test: the drop is irreversible, so it runs in a forked child
TEST(DropToUser, DropsPrivilegesInChild)
{
    if (getuid() != 0)
    {
        GTEST_SKIP() << "requires root";
    }

    struct passwd* pwd = getpwuid(65534); // nobody
    if (pwd == nullptr)
    {
        GTEST_SKIP() << "uid 65534 (nobody) not available";
    }
    const uid_t targetUid = pwd->pw_uid;

    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0)
    {
        try
        {
            dropToUser(targetUid);
        }
        catch (...)
        {
            _exit(EXIT_DAEMON_FAILURE);
        }
        _exit((getuid() == targetUid && geteuid() == targetUid) ? EXIT_SUCCESS : EXIT_WRITE_FAILURE);
    }

    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);
}

// Once the user is dropped, neither the group nor the user can go back to root: exact messages, in a child.
TEST(DropToUser, MessagesAfterDropInChild)
{
    if (getuid() != 0)
    {
        GTEST_SKIP() << "requires root";
    }

    int report[2];
    ASSERT_EQ(pipe(report), 0);

    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0)
    {
        close(report[0]);
        std::string out;
        try
        {
            dropToGroup(65534);
            dropToUser(65534);
        }
        catch (const std::exception& e)
        {
            out = std::string("setup: ") + e.what();
        }
        if (out.empty())
        {
            out = thrownMessage([] { dropToGroup(0); }) + "|" + thrownMessage([] { dropToUser(0); });
        }
        (void)!write(report[1], out.data(), out.size());
        _exit(EXIT_SUCCESS);
    }

    close(report[1]);
    std::string got;
    char buf[256];
    ssize_t n;
    while ((n = read(report[0], buf, sizeof(buf))) > 0)
    {
        got.append(buf, static_cast<std::size_t>(n));
    }
    close(report[0]);

    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);
    EXPECT_EQ(got,
              "could not drop supplementary groups: Operation not permitted (1)|"
              "could not set user ID 0: Operation not permitted (1)");
}

// Functional test: as root, dropping to another group leaves real, effective and supplementary groups on it only.
TEST(DropToGroup, DropsToTargetGroupInChild)
{
    if (getuid() != 0)
    {
        GTEST_SKIP() << "requires root";
    }
    const gid_t target = 65534;

    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0)
    {
        try
        {
            dropToGroup(target);
        }
        catch (...)
        {
            _exit(EXIT_DAEMON_FAILURE);
        }
        gid_t groups[64];
        const int count = getgroups(64, groups);
        const bool ok = getgid() == target && getegid() == target && count == 1 && groups[0] == target;
        _exit(ok ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);
}

// setgroups() mutates process-wide state, so it runs in a forked child.
// Root must succeed and keep only gid; unprivileged processes lack CAP_SETGID and must throw.
TEST(DropToGroup, SetGroupInChild)
{
    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0)
    {
        bool threw = false;
        try
        {
            dropToGroup(getgid());
        }
        catch (const std::runtime_error&)
        {
            threw = true;
        }
        bool ok = (getuid() == 0) ? !threw : threw;
        if (ok && getuid() == 0)
        {
            // Only gid remains: no supplementary groups other than gid itself
            gid_t groups[64];
            const int count = getgroups(64, groups);
            ok = count == 1 && groups[0] == getgid();
        }
        _exit(ok ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);
}
