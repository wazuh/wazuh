// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <sstream>
#include <string>
#include <utility>
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

/// ProcessSysCalls with all 13 members set to fakes that succeed and record their arguments, so no real system call
/// runs. A test overrides one member to make it fail. Like FakeLookup, every successful fake leaves errno = ENOSYS, so
/// an implementation that reads errno after the wrong call fails. The fork fake never returns > 0: the real _exit of
/// the parent would end the test runner.
struct RecordingSys
{
    const int fakeFd; ///< Returned by open

    int forks = 0;
    int setsids = 0;
    std::vector<mode_t> umasks;
    std::vector<std::string> opens;
    std::vector<std::pair<int, int>> dup2s; ///< (fd, target)
    std::vector<int> closes;
    std::vector<std::pair<int, mode_t>> fchmods;
    std::string written; ///< Bytes accepted by write
    std::vector<gid_t> setgroups;
    std::vector<gid_t> setgids;
    std::vector<uid_t> setuids;
    std::vector<uid_t> seteuids;
    std::vector<int> sysconfs;

    RecordingSys()
        : RecordingSys(5)
    {
    }

    explicit RecordingSys(int fd)
        : fakeFd(fd)
    {
        m_sys.fork = [this]() -> pid_t
        {
            ++forks;
            errno = ENOSYS;
            return 0;
        };
        m_sys.setsid = [this]() -> pid_t
        {
            ++setsids;
            errno = ENOSYS;
            return 1;
        };
        m_sys.umask = [this](mode_t mask) -> mode_t
        {
            umasks.push_back(mask);
            errno = ENOSYS;
            return 022;
        };
        m_sys.open = [this](const char* path, int, mode_t) -> int
        {
            opens.emplace_back(path);
            errno = ENOSYS;
            return fakeFd;
        };
        m_sys.dup2 = [this](int oldFd, int newFd) -> int
        {
            dup2s.emplace_back(oldFd, newFd);
            errno = ENOSYS;
            return newFd;
        };
        m_sys.close = [this](int closeFd) -> int
        {
            closes.push_back(closeFd);
            errno = ENOSYS;
            return 0;
        };
        m_sys.fchmod = [this](int modeFd, mode_t mode) -> int
        {
            fchmods.emplace_back(modeFd, mode);
            errno = ENOSYS;
            return 0;
        };
        m_sys.write = [this](int, const void* buf, size_t len) -> ssize_t
        {
            written.append(static_cast<const char*>(buf), len);
            errno = ENOSYS;
            return static_cast<ssize_t>(len);
        };
        m_sys.setgroups = [this](size_t count, const gid_t* list) -> int
        {
            setgroups.insert(setgroups.end(), list, list + count);
            errno = ENOSYS;
            return 0;
        };
        m_sys.setgid = [this](gid_t gid) -> int
        {
            setgids.push_back(gid);
            errno = ENOSYS;
            return 0;
        };
        m_sys.setuid = [this](uid_t uid) -> int
        {
            setuids.push_back(uid);
            errno = ENOSYS;
            return 0;
        };
        m_sys.seteuid = [this](uid_t uid) -> int
        {
            seteuids.push_back(uid);
            errno = ENOSYS;
            return 0;
        };
        m_sys.sysconf = [this](int name) -> long
        {
            sysconfs.push_back(name);
            errno = ENOSYS;
            return -1;
        };
    }

    RecordingSys(const RecordingSys&) = delete;
    RecordingSys& operator=(const RecordingSys&) = delete;

    ProcessSysCalls& sys() { return m_sys; }

    /// All 13 members are set: none falls back to the real call.
    bool allSet() const
    {
        return m_sys.fork && m_sys.setsid && m_sys.umask && m_sys.open && m_sys.dup2 && m_sys.close && m_sys.fchmod
               && m_sys.write && m_sys.setgroups && m_sys.setgid && m_sys.setuid && m_sys.seteuid && m_sys.sysconf;
    }

private:
    ProcessSysCalls m_sys;
};

/// Directory of the createPID error cases: never created, open is fake.
constexpr auto FAKE_PID_DIR = "/wazuh_test_fake_pid_dir";
const std::string FAKE_PID_FILE = std::string(FAKE_PID_DIR) + "/svc-1.pid";
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
    const fs::path tmpDir = freshDir("base_process_test_failure");
    const fs::path missing = tmpDir / "missing";

    auto result = createPID(missing.string(), "svc", 1);

    ASSERT_TRUE(isError(result));
    EXPECT_EQ(base::getError(result).message,
              "could not create PID file " + (missing / "svc-1.pid").string() + ": No such file or directory (2)");

    fs::remove_all(tmpDir);
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

// The first buffer is the sysconf hint, 1024 without one, never above the cap.
TEST(LookupUid, InitialSizeFromSysconf)
{
    const std::vector<std::pair<long, std::size_t>> cases {{4096, 4096}, {-1, 1024}, {1048576, LOOKUP_CAP}};
    for (const auto& [hint, expected] : cases)
    {
        RecordingSys rec;
        rec.sys().sysconf = [&rec, hint = hint](int name) -> long
        {
            rec.sysconfs.push_back(name);
            errno = ENOSYS;
            return hint;
        };
        ASSERT_TRUE(rec.allSet());
        std::vector<size_t> sizes;

        EXPECT_EQ(lookupUid("x", FakeUserLookup {0, 0, true, 7, &sizes}, rec.sys()), static_cast<uid_t>(7));

        ASSERT_FALSE(sizes.empty()) << "hint " << hint;
        EXPECT_EQ(sizes.front(), expected) << "hint " << hint;
        EXPECT_EQ(rec.sysconfs, std::vector<int> {_SC_GETPW_R_SIZE_MAX}) << "hint " << hint;
    }
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

/*** Error paths with injected system calls ***/

TEST(RecordingSysTest, RecordingSysFakesEverything)
{
    RecordingSys rec {};

    EXPECT_TRUE(rec.allSet());
    EXPECT_EQ(rec.fakeFd, 5);
    EXPECT_EQ(rec.sys().fork(), 0);
    EXPECT_EQ(rec.sys().open("/dev/null", O_RDWR, 0), 5);
    EXPECT_EQ(rec.sys().write(5, "ab", 2), 2);
    EXPECT_EQ(rec.sys().sysconf(_SC_GETPW_R_SIZE_MAX), -1);
    EXPECT_EQ(errno, ENOSYS);
    EXPECT_EQ(rec.forks, 1);
    EXPECT_EQ(rec.opens, std::vector<std::string> {"/dev/null"});
    EXPECT_EQ(rec.written, "ab");
}

TEST(GoDaemonErrors, FirstForkFails)
{
    RecordingSys rec;
    rec.sys().fork = [&rec]() -> pid_t
    {
        ++rec.forks;
        errno = EAGAIN;
        return -1;
    };
    ASSERT_TRUE(rec.allSet());

    EXPECT_EQ(thrownMessage([&] { goDaemon(rec.sys()); }),
              "fork failed (first): Resource temporarily unavailable (11)");
    EXPECT_EQ(rec.forks, 1);
    EXPECT_EQ(rec.setsids, 0);
}

TEST(GoDaemonErrors, SecondForkFails)
{
    RecordingSys rec;
    rec.sys().fork = [&rec]() -> pid_t
    {
        if (++rec.forks == 1)
        {
            errno = ENOSYS;
            return 0;
        }
        errno = EAGAIN;
        return -1;
    };
    ASSERT_TRUE(rec.allSet());

    EXPECT_EQ(thrownMessage([&] { goDaemon(rec.sys()); }),
              "fork failed (second): Resource temporarily unavailable (11)");
    EXPECT_EQ(rec.forks, 2);
    EXPECT_EQ(rec.setsids, 1);
    EXPECT_TRUE(rec.umasks.empty());
}

TEST(GoDaemonErrors, SetsidFails)
{
    RecordingSys rec;
    rec.sys().setsid = [&rec]() -> pid_t
    {
        ++rec.setsids;
        errno = EPERM;
        return -1;
    };
    ASSERT_TRUE(rec.allSet());

    EXPECT_EQ(thrownMessage([&] { goDaemon(rec.sys()); }), "setsid failed: Operation not permitted (1)");
    EXPECT_EQ(rec.forks, 1);
    EXPECT_EQ(rec.setsids, 1);
}

TEST(GoDaemonErrors, DevNullOpenFails)
{
    RecordingSys rec;
    rec.sys().open = [&rec](const char* path, int, mode_t) -> int
    {
        rec.opens.emplace_back(path);
        errno = ENOENT;
        return -1;
    };
    ASSERT_TRUE(rec.allSet());

    EXPECT_EQ(thrownMessage([&] { goDaemon(rec.sys()); }), "could not open /dev/null: No such file or directory (2)");
    EXPECT_EQ(rec.forks, 2);
    EXPECT_EQ(rec.umasks, std::vector<mode_t> {027});
    EXPECT_EQ(rec.opens, std::vector<std::string> {"/dev/null"});
    EXPECT_TRUE(rec.dup2s.empty());
}

TEST(GoDaemonErrors, Dup2FailsClosesFd)
{
    RecordingSys rec {7};
    rec.sys().dup2 = [&rec](int fd, int target) -> int
    {
        rec.dup2s.emplace_back(fd, target);
        if (target == STDOUT_FILENO)
        {
            errno = EBADF;
            return -1;
        }
        errno = ENOSYS;
        return target;
    };
    ASSERT_TRUE(rec.allSet());

    EXPECT_EQ(thrownMessage([&] { goDaemon(rec.sys()); }),
              "could not redirect fd 1 to /dev/null: Bad file descriptor (9)");
    EXPECT_EQ(rec.dup2s, (std::vector<std::pair<int, int>> {{7, 0}, {7, 1}}));
    EXPECT_EQ(rec.closes, std::vector<int> {7});
}

TEST(GoDaemonErrors, Dup2FailsLowFdNotClosed)
{
    RecordingSys rec {2};
    rec.sys().dup2 = [&rec](int fd, int target) -> int
    {
        rec.dup2s.emplace_back(fd, target);
        errno = EBADF;
        return -1;
    };
    ASSERT_TRUE(rec.allSet());

    EXPECT_EQ(thrownMessage([&] { goDaemon(rec.sys()); }),
              "could not redirect fd 0 to /dev/null: Bad file descriptor (9)");
    EXPECT_EQ(rec.dup2s, (std::vector<std::pair<int, int>> {{2, 0}}));
    EXPECT_TRUE(rec.closes.empty());
}

TEST(CreatePIDErrors, FchmodFails)
{
    RecordingSys rec {5};
    rec.sys().fchmod = [&rec](int fd, mode_t mode) -> int
    {
        rec.fchmods.emplace_back(fd, mode);
        errno = EPERM;
        return -1;
    };
    ASSERT_TRUE(rec.allSet());

    const auto result = createPID(FAKE_PID_DIR, "svc", 1, rec.sys());

    ASSERT_TRUE(isError(result));
    EXPECT_EQ(base::getError(result).message,
              "could not set mode 0640 on PID file " + FAKE_PID_FILE + ": Operation not permitted (1)");
    EXPECT_EQ(rec.opens, std::vector<std::string> {FAKE_PID_FILE});
    EXPECT_EQ(rec.fchmods, (std::vector<std::pair<int, mode_t>> {{5, 0640}}));
    EXPECT_TRUE(rec.written.empty());
    EXPECT_EQ(rec.closes, std::vector<int> {5});
}

TEST(CreatePIDErrors, WriteFails)
{
    RecordingSys rec;
    rec.sys().write = [](int, const void*, size_t) -> ssize_t
    {
        errno = EIO;
        return -1;
    };
    ASSERT_TRUE(rec.allSet());

    const auto result = createPID(FAKE_PID_DIR, "svc", 1, rec.sys());

    ASSERT_TRUE(isError(result));
    EXPECT_EQ(base::getError(result).message, "could not write PID file " + FAKE_PID_FILE + ": Input/output error (5)");
    EXPECT_EQ(rec.closes, std::vector<int> {rec.fakeFd});
}

TEST(CreatePIDErrors, ShortWrite)
{
    RecordingSys rec;
    rec.sys().write = [](int, const void*, size_t) -> ssize_t
    {
        errno = ENOSYS;
        return 0;
    };
    ASSERT_TRUE(rec.allSet());

    const auto result = createPID(FAKE_PID_DIR, "svc", 1, rec.sys());

    ASSERT_TRUE(isError(result));
    EXPECT_EQ(base::getError(result).message, "could not write PID file " + FAKE_PID_FILE + ": short write");
    EXPECT_EQ(rec.closes, std::vector<int> {rec.fakeFd});
}

TEST(CreatePIDErrors, CloseFails)
{
    RecordingSys rec;
    rec.sys().close = [&rec](int fd) -> int
    {
        rec.closes.push_back(fd);
        errno = EIO;
        return -1;
    };
    ASSERT_TRUE(rec.allSet());

    const auto result = createPID(FAKE_PID_DIR, "svc", 1, rec.sys());

    ASSERT_TRUE(isError(result));
    EXPECT_EQ(base::getError(result).message, "could not close PID file " + FAKE_PID_FILE + ": Input/output error (5)");
    EXPECT_EQ(rec.written, "1\n");
    EXPECT_EQ(rec.closes, std::vector<int> {rec.fakeFd});
}

TEST(DropErrors, SetgidAfterSetgroups)
{
    RecordingSys rec;
    rec.sys().setgid = [&rec](gid_t gid) -> int
    {
        rec.setgids.push_back(gid);
        errno = EPERM;
        return -1;
    };
    ASSERT_TRUE(rec.allSet());

    EXPECT_EQ(thrownMessage([&] { dropToGroup(4242, rec.sys()); }),
              "could not set group ID 4242: Operation not permitted (1)");
    EXPECT_EQ(rec.setgroups, std::vector<gid_t> {4242});
    EXPECT_EQ(rec.setgids, std::vector<gid_t> {4242});
}

TEST(DropErrors, SeteuidAfterSetuid)
{
    RecordingSys rec;
    rec.sys().seteuid = [&rec](uid_t uid) -> int
    {
        rec.seteuids.push_back(uid);
        errno = EPERM;
        return -1;
    };
    ASSERT_TRUE(rec.allSet());

    EXPECT_EQ(thrownMessage([&] { dropToUser(4242, rec.sys()); }),
              "could not set effective user ID 4242: Operation not permitted (1)");
    EXPECT_EQ(rec.setuids, std::vector<uid_t> {4242});
    EXPECT_EQ(rec.seteuids, std::vector<uid_t> {4242});
}
