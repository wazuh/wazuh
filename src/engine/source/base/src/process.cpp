#include <algorithm>
#include <cerrno>
#include <cstring>
#include <optional>
#include <pthread.h>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <climits>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fmt/format.h>

#include <base/error.hpp>
#include <base/process.hpp>

constexpr auto MAX_RBUFFER_SIZE = 65536;

namespace base::process
{

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
            if (buffer.size() >= MAX_RBUFFER_SIZE)
            {
                break;
            }
            buffer.resize(std::min(buffer.size() * 2, static_cast<size_t>(MAX_RBUFFER_SIZE)));
            errno = 0;
        }
        else if (errno == 0)
        {
            throw std::runtime_error("Error changing to group '" + groupname + "': group not found");
        }
        else
        {
            throw std::runtime_error(fmt::format("Error looking up group '{}': {} ({})",
                                             groupname,
                                             std::strerror(errno),
                                             errno));
        }
    }

    throw std::runtime_error("Exceeded maximum buffer size looking up group '" + groupname + "'");
}


void privSepSetGroup(gid_t gid)
{
    if (setgroups(1, &gid) == -1)
    {
        throw std::runtime_error(fmt::format("Error clearing supplementary groups: {} ({})", strerror(errno), errno));
    }

    if (setgid(gid) < 0)
    {
        throw std::runtime_error(fmt::format("Error changing to group ID {}: {} ({})", gid, strerror(errno), errno));
    }
}

std::filesystem::path getWazuhHome()
{
    return std::filesystem::path("/var/ossec");
}

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

bool isStandaloneModeEnable()
{
    static const bool enabled = []()
    {
        const char* env = std::getenv(ENV_ENGINE_STANDALONE);
        if (!env)
            return false;

        std::string val(env);
        std::transform(
            val.begin(), val.end(), val.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        return val == "true";
    }();

    return enabled;
}

} // namespace base::process
