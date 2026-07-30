#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

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

// Test createPID success scenario
TEST(CreatePIDTest, Success)
{
    // Arrange
    fs::path tmpDir = fs::temp_directory_path() / "base_process_test_success";
    fs::create_directory(tmpDir);
    std::string svcName = "svc";
    int pidValue = 12345;

    // Act
    auto result = createPID(tmpDir.string(), svcName, pidValue);

    // Assert
    ASSERT_FALSE(isError(result));
    fs::path pidFile = tmpDir / (svcName + "-" + std::to_string(pidValue) + ".pid");
    ASSERT_TRUE(fs::exists(pidFile));

    std::ifstream ifs(pidFile);
    ASSERT_TRUE(ifs.is_open());
    std::string content;
    std::getline(ifs, content);
    EXPECT_EQ(content, std::to_string(pidValue));
    ifs.close();

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
    auto result = createPID(invalidPath, "svc", 1);
    ASSERT_TRUE(isError(result));
}

// Functional test for goDaemon: grandchild should continue execution
TEST(GoDaemonFunctionalTest, ContinuesInGrandchild)
{
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);
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
            exit(EXIT_DAEMON_FAILURE);
        }
        // In grandchild: signal success
        const char msg = 'X';
        ssize_t w = write(fds[1], &msg, 1);
        if (w != 1)
        {
            exit(EXIT_WRITE_FAILURE);
        }
        exit(EXIT_SUCCESS);
    }

    // Parent context: read from pipe
    close(fds[1]);
    char buf = 0;
    ssize_t n = read(fds[0], &buf, 1);
    EXPECT_EQ(n, 1);
    EXPECT_EQ(buf, 'X');

    int status;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);
}

TEST(PrivSepGetUserTest, ResolvesCurrentUser)
{
    struct passwd* pwd = getpwuid(getuid());
    ASSERT_NE(pwd, nullptr);
    EXPECT_EQ(privSepGetUser(pwd->pw_name), getuid());
}

TEST(PrivSepGetUserTest, ThrowsOnUnknownUser)
{
    EXPECT_THROW(privSepGetUser("wazuh_test_nonexistent_user"), std::runtime_error);
}

TEST(PrivSepGetGroupTest, ResolvesCurrentGroup)
{
    struct group* grp = getgrgid(getgid());
    ASSERT_NE(grp, nullptr);
    EXPECT_EQ(privSepGetGroup(grp->gr_name), getgid());
}

TEST(PrivSepGetGroupTest, ThrowsOnUnknownGroup)
{
    EXPECT_THROW(privSepGetGroup("wazuh_test_nonexistent_group"), std::runtime_error);
}

TEST(PrivSepSetUserTest, SameUidSucceeds)
{
    EXPECT_NO_THROW(privSepSetUser(getuid()));
}

TEST(PrivSepSetUserTest, ThrowsWhenNotPermitted)
{
    if (getuid() == 0)
    {
        GTEST_SKIP() << "requires a non-root user";
    }
    EXPECT_THROW(privSepSetUser(getuid() + 1), std::runtime_error);
}

// Functional test: the drop is irreversible, so it runs in a forked child
TEST(PrivSepSetUserTest, DropsPrivilegesInChild)
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
            privSepSetUser(targetUid);
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

// setgroups() mutates process-wide state, so it runs in a forked child.
// Root must succeed; unprivileged processes lack CAP_SETGID and must throw.
TEST(PrivSepSetGroupTest, SetGroupInChild)
{
    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0)
    {
        bool threw = false;
        try
        {
            privSepSetGroup(getgid());
        }
        catch (const std::runtime_error&)
        {
            threw = true;
        }
        const bool ok = (getuid() == 0) ? !threw : threw;
        _exit(ok ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    int status = 0;
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);
}
