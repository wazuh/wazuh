#ifndef _BASE_PROCESS_HPP
#define _BASE_PROCESS_HPP

#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <grp.h>
#include <limits.h>
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

/**
 * @brief Thread-safe wrapper for retrieving user account information by username.
 *
 * This function provides a simplified interface to getpwnam_r() by handling the
 * result parameter internally and setting errno appropriately on failure.
 *
 * @param name The username to look up in the password database
 * @param pwd Pointer to a passwd structure to store the result
 * @param buf Buffer to store string fields of the passwd structure
 * @param buflen Size of the buffer in bytes
 *
 * @return Pointer to the passwd structure on success, NULL on failure.
 *         On failure, errno is set to indicate the error condition.
 *
 * @note The caller must provide a sufficiently large buffer to store all
 *       string fields. If the buffer is too small, the function will fail
 *       and errno will be set to ERANGE.
 *
 * @warning This function modifies errno on failure. Check errno to determine
 *          the specific error condition when NULL is returned.
 */
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

/**
 * @brief Thread-safe wrapper for retrieving group information by name.
 *
 * This function provides a simplified interface to getgrnam_r() by handling
 * the result pointer internally and setting errno appropriately on failure.
 *
 * @param name The name of the group to look up
 * @param grp Pointer to a group structure to store the result
 * @param buf Buffer to store string data referenced by the group structure
 * @param buflen Size of the buffer in bytes
 *
 * @return Pointer to the group structure on success, NULL on failure.
 *         On failure, errno is set to indicate the error.
 *
 * @note This function is thread-safe and reentrant.
 * @note The caller must provide a sufficiently large buffer to hold all
 *       string data associated with the group entry.
 */
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

/**
 * @brief Sets the user ID for privilege separation.
 *
 * This function changes the effective user ID of the calling process to the
 * specified user ID. This is typically used for privilege separation to drop
 * elevated privileges and run with reduced permissions for security purposes.
 *
 * @param uid The user ID to set for the current process
 * @return OS_SUCCESS if the user ID was successfully set, OS_INVALID if the
 *         setuid() system call failed
 */
int privSepSetUser(uid_t uid)
{
    if (setuid(uid) < 0)
    {
        return (OS_INVALID);
    }

    return (OS_SUCCESS);
}

/**
 * @brief Sets the group ID and supplementary groups for privilege separation.
 *
 * This function performs privilege separation by setting the process group ID
 * and clearing supplementary groups, leaving only the specified group.
 *
 * @param gid The group ID to set for the current process
 *
 * @return OS_SUCCESS on successful group ID change, OS_INVALID on failure
 *
 * @note This function first clears all supplementary groups by calling setgroups()
 *       with a single group, then sets the effective group ID using setgid().
 * @note This operation typically requires appropriate privileges (e.g., running as root).
 * @warning Calling this function will drop supplementary group memberships.
 */
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

/**
 * @brief Gets the Wazuh installation home directory path.
 *
 * This function determines the Wazuh home directory by reading the current
 * executable's path from /proc/self/exe and deriving the installation root.
 * It assumes the executable is located in the "bin" subdirectory of the
 * Wazuh installation (e.g., /var/ossec/bin/executable).
 *
 * @return std::string The path to the Wazuh home directory (e.g., "/var/ossec").
 *                     Returns an empty string if the executable path cannot be determined.
 *
 */
std::string getWazuhHome()
{
    char path[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (count != -1)
    {
        path[count] = '\0';
        std::string exePath(path);

        // Executable folder -> /var/ossec/bin
        std::string dir = exePath.substr(0, exePath.find_last_of('/'));

        // Remove the "/bin" suffix if it exists -> /var/ossec
        const std::string binSuffix = "/bin";
        if (dir.size() >= binSuffix.size()
            && dir.compare(dir.size() - binSuffix.size(), binSuffix.size(), binSuffix) == 0)
        {
            dir = dir.substr(0, dir.size() - binSuffix.size());
        }

        return dir;
    }

    return {};
}

/**
 * @brief Sets the name of the current thread.
 *
 * This function assigns a name to the calling thread,
 * On Linux, the thread name is limited to 15 characters; if the provided name is longer, it will be truncated.
 * If the input name is empty, the function does nothing.
 *
 * @param name The desired name for the thread.
 */
void setThreadName(const std::string& name)
{
    if (name.empty())
    {
        return; // No name to set
    }

    // Limit thread name to 15 characters (Linux limit)
    std::string threadName = name.substr(0, 15);
    pthread_setname_np(pthread_self(), threadName.c_str());
}

} // namespace base::process

#endif // _BASE_PROCESS_HPP
