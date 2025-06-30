#ifndef _BASE_PROCESS_HPP
#define _BASE_PROCESS_HPP

#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fmt/format.h>

#include <base/error.hpp>

namespace base::process
{
constexpr auto MAXSTR = 65536;
constexpr auto OS_SUCCESS = 0;  /* Success                  */
constexpr auto OS_INVALID = -1; /* Invalid entry            */
constexpr auto SETGID_ERROR = "Unable to switch to group '{}' due to [({})-({})].";
constexpr auto SETUID_ERROR = "Unable to switch to user '{}' due to [({})-({})].";
constexpr auto USER_ERROR = "Invalid user '{}' or group '{}'";
constexpr uid_t INVALID_UID = static_cast<uid_t>(OS_INVALID);
constexpr gid_t INVALID_GID = static_cast<gid_t>(OS_INVALID);

/**
 * @brief Transforms the current process into a daemon (double fork + detach).
 */
void goDaemon()
{
    pid_t pid = fork();
    if (pid < 0)
    {
        throw std::runtime_error {fmt::format("FORK_ERROR (1st): {} ({})", std::strerror(errno), errno)};
    }
    if (pid > 0)
    {
        exit(EXIT_SUCCESS); // Parent exits
    }

    if (setsid() < 0)
    {
        throw std::runtime_error {fmt::format("SETSID_ERROR: {} ({})", std::strerror(errno), errno)};
    }

    pid = fork();
    if (pid < 0)
    {
        throw std::runtime_error {fmt::format("FORK_ERROR (2nd): {} ({})", std::strerror(errno), errno)};
    }
    if (pid > 0)
    {
        exit(EXIT_SUCCESS); // First child exits
    }

    // Optional: set file mode creation mask
    umask(027);

    // Redirect stdin, stdout, stderr to /dev/null
    int fd = open("/dev/null", O_RDWR);
    if (fd < 0)
    {
        throw std::runtime_error {
            fmt::format("REDIRECT_ERROR: Could not open /dev/null - {} ({})", std::strerror(errno), errno)};
    }

    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
}

/**
 * @brief Creates a PID file for the specified service name.
 *
 * @param path Directory where the PID file will be written.
 * @param name Service name (used in filename).
 * @param pid Process ID to write.
 * @return std::nullopt if successful, otherwise a base::Error describing the issue.
 */
OptError createPID(const std::string& path, const std::string& name, int pid)
{
    const auto file = std::filesystem::path(path) / fmt::format("{}-{}.pid", name, pid);

    std::ofstream ofs(file, std::ios::trunc);
    if (!ofs)
    {
        return Error {fmt::format("FILE_ERROR: {} - {} ({})", file.string(), std::strerror(errno), errno)};
    }

    ofs << pid << '\n';
    ofs.close();

    if (chmod(file.c_str(), 0640) != 0)
    {
        return Error {fmt::format("CHMOD_ERROR: {} - {} ({})", file.string(), std::strerror(errno), errno)};
    }

    return std::nullopt;
}

struct passwd* getpwnam(const char* name, struct passwd* pwd, char* buf, size_t buflen)
{
    struct passwd* result = NULL;
    int retval = getpwnam_r(name, pwd, buf, buflen, &result);

    if (result == NULL)
    {
        errno = retval;
    }

    return result;
}

struct group* getgrnam(const char* name, struct group* grp, char* buf, int buflen)
{
    struct group* result = NULL;
    int retval = getgrnam_r(name, grp, buf, buflen, &result);

    if (result == NULL)
    {
        errno = retval;
    }

    return result;
}

/**
 * @brief Find a UID by user name
 * @param name Name of the user.
 * @return UID of the user, if found.
 * @retval -1 user not found.
 */
uid_t privSepGetUser(const std::string& username)
{
    long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize <= 0)
        bufsize = 1024;

    std::vector<char> buffer(static_cast<size_t>(bufsize));
    struct passwd pwd_storage {};
    struct passwd* result = nullptr;

    while (true)
    {
        result = getpwnam(username.c_str(), &pwd_storage, buffer.data(), buffer.size());
        if (result)
        {
            return result->pw_uid;
        }
        if (errno == ERANGE)
        {
            // Expand buffer and retry
            if (buffer.size() >= MAXSTR)
            {
                break;
            }
            buffer.resize(std::min(buffer.size() * 2, static_cast<size_t>(MAXSTR)));
            errno = 0;
        }
        else if (errno == 0)
        {
            // Not found
            return INVALID_UID;
        }
        else
        {
            // Other error
            throw std::system_error(errno, std::generic_category(), "Error looking up user '" + username + "'");
        }
    }

    throw std::runtime_error("Exceeded maximum buffer size looking up user '" + username + "'");
}

/**
 * @brief Lookup a group’s GID by group name.
 *        Automatically grows the buffer on ERANGE.
 * @param groupname  The name of the group to look up.
 * @return GID if found.
 * @throws std::system_error on underlying errors.
 * @retval INVALID_GID if group not found.
 */
gid_t privSepGetGroup(const std::string& groupname)
{
    long bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (bufsize <= 0)
        bufsize = 1024;

    std::vector<char> buffer(static_cast<size_t>(bufsize));
    struct group grp_storage {};
    struct group* result = nullptr;

    while (true)
    {
        result = getgrnam(groupname.c_str(), &grp_storage, buffer.data(), buffer.size());
        if (result)
        {
            return result->gr_gid;
        }
        if (errno == ERANGE)
        {
            if (buffer.size() >= MAXSTR)
            {
                break;
            }
            buffer.resize(std::min(buffer.size() * 2, static_cast<size_t>(MAXSTR)));
            errno = 0;
        }
        else if (errno == 0)
        {
            return INVALID_GID;
        }
        else
        {
            throw std::system_error(errno, std::generic_category(), "Error looking up group '" + groupname + "'");
        }
    }

    throw std::runtime_error("Exceeded maximum buffer size looking up group '" + groupname + "'");
}

int privSepSetUser(uid_t uid)
{
    if (setuid(uid) < 0)
    {
        return (OS_INVALID);
    }

    return (OS_SUCCESS);
}

int privSepSetGroup(gid_t gid)
{
    if (setgroups(1, &gid) == -1)
    {
        return (OS_INVALID);
    }

    if (setgid(gid) < 0)
    {
        return (OS_INVALID);
    }

    return (OS_SUCCESS);
}

} // namespace base::process

#endif // _BASE_PROCESS_HPP
