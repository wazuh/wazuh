#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
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
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <fmt/format.h>

#include <base/error.hpp>
#include <base/managerLogSink.hpp>
#include <base/process.hpp>

namespace base::process
{

namespace
{
constexpr std::size_t LOOKUP_BUFFER_CAP = 65536;    ///< Largest buffer offered to getpwnam_r/getgrnam_r
constexpr std::size_t LOOKUP_BUFFER_DEFAULT = 1024; ///< Used when sysconf gives no hint

/// "<strerror> (<code>)" for an errno-style code.
std::string describeError(int code)
{
    return fmt::format("{} ({})", std::strerror(code), code);
}

/// Initial buffer size for a reentrant lookup: the sysconf hint, or the default; never above the cap.
std::size_t initialLookupSize(int sysconfName)
{
    const long hint = sysconf(sysconfName);
    const auto size = hint > 0 ? static_cast<std::size_t>(hint) : LOOKUP_BUFFER_DEFAULT;
    return std::min(size, LOOKUP_BUFFER_CAP);
}

/**
 * @brief Runs a getpwnam_r/getgrnam_r-style lookup, doubling the buffer on ERANGE up to the cap.
 *
 * Only the return code of the lookup decides; errno is never read. Returns idOf(entry) while the buffer that
 * backs the entry's strings is still alive.
 */
template<typename Entry, typename Lookup, typename IdOf>
auto lookupId(const char* kind, const std::string& name, int sysconfName, const Lookup& lookup, IdOf idOf)
{
    std::vector<char> buffer(initialLookupSize(sysconfName));

    while (true)
    {
        Entry entry {};
        Entry* found = nullptr;
        const int rc = lookup(name.c_str(), &entry, buffer.data(), buffer.size(), &found);

        if (rc == 0)
        {
            if (found == nullptr)
            {
                throw std::runtime_error {fmt::format("{} '{}' not found", kind, name)};
            }
            return idOf(*found);
        }

        if (rc != ERANGE)
        {
            throw std::runtime_error {fmt::format("could not look up {} '{}': {}", kind, name, describeError(rc))};
        }

        if (buffer.size() >= LOOKUP_BUFFER_CAP)
        {
            throw std::runtime_error {
                fmt::format("could not look up {} '{}': entry larger than {} bytes", kind, name, LOOKUP_BUFFER_CAP)};
        }
        buffer.resize(std::min(buffer.size() * 2, LOOKUP_BUFFER_CAP));
    }
}

/// fork(); the parent leaves with _exit (no atexit handlers, no static destructors), the child returns.
void detach(const char* stage)
{
    const pid_t pid = fork();
    if (pid < 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("fork failed ({}): {}", stage, describeError(err))};
    }
    if (pid > 0)
    {
        _exit(EXIT_SUCCESS);
    }
}
} // namespace

void goDaemon()
{
    detach("first");

    if (setsid() < 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("setsid failed: {}", describeError(err))};
    }

    detach("second");

    umask(027);

    const int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (fd < 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("could not open /dev/null: {}", describeError(err))};
    }

    for (const int target : {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO})
    {
        if (dup2(fd, target) < 0)
        {
            const int err = errno;
            if (fd > STDERR_FILENO)
            {
                close(fd);
            }
            throw std::runtime_error {
                fmt::format("could not redirect fd {} to /dev/null: {}", target, describeError(err))};
        }
    }

    if (fd > STDERR_FILENO)
    {
        close(fd);
    }
}

OptError createPID(const std::string& path, const std::string& name, int pid)
{
    const auto file = (std::filesystem::path(path) / fmt::format("{}-{}.pid", name, pid)).string();

    const int fd = open(file.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);
    if (fd < 0)
    {
        const int err = errno;
        return Error {fmt::format("could not create PID file {}: {}", file, describeError(err))};
    }

    // The mode given to open() is filtered by the umask; fchmod sets it exactly.
    if (fchmod(fd, 0640) != 0)
    {
        const int err = errno;
        close(fd);
        return Error {fmt::format("could not set mode 0640 on PID file {}: {}", file, describeError(err))};
    }

    const auto content = fmt::format("{}\n", pid);
    std::size_t written = 0;
    while (written < content.size())
    {
        const ssize_t rc = write(fd, content.data() + written, content.size() - written);
        if (rc < 0)
        {
            const int err = errno;
            if (err == EINTR)
            {
                continue;
            }
            close(fd);
            return Error {fmt::format("could not write PID file {}: {}", file, describeError(err))};
        }
        if (rc == 0)
        {
            close(fd);
            return Error {fmt::format("could not write PID file {}: short write", file)};
        }
        written += static_cast<std::size_t>(rc);
    }

    if (close(fd) != 0)
    {
        const int err = errno;
        return Error {fmt::format("could not close PID file {}: {}", file, describeError(err))};
    }

    return std::nullopt;
}

uid_t lookupUid(const std::string& name, const UserLookup& lookup)
{
    return lookupId<struct passwd>(
        "user", name, _SC_GETPW_R_SIZE_MAX, lookup, [](const struct passwd& entry) { return entry.pw_uid; });
}

gid_t lookupGid(const std::string& name, const GroupLookup& lookup)
{
    return lookupId<struct group>(
        "group", name, _SC_GETGR_R_SIZE_MAX, lookup, [](const struct group& entry) { return entry.gr_gid; });
}

void dropToGroup(gid_t gid)
{
    if (setgroups(1, &gid) != 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("could not drop supplementary groups: {}", describeError(err))};
    }

    if (setgid(gid) != 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("could not set group ID {}: {}", gid, describeError(err))};
    }
}

void dropToUser(uid_t uid)
{
    if (setuid(uid) != 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("could not set user ID {}: {}", uid, describeError(err))};
    }

    if (seteuid(uid) != 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("could not set effective user ID {}: {}", uid, describeError(err))};
    }
}

namespace
{
std::atomic<bool> g_managerMode {false};

/// dirname(3) of a path without touching it; "" stays "" (unresolvable executable => no home).
std::string dirName(const std::string& path)
{
    if (path.empty())
    {
        return {};
    }

    auto end = path.find_last_not_of('/');
    if (end == std::string::npos)
    {
        return "/";
    }
    const auto slash = path.rfind('/', end);
    if (slash == std::string::npos)
    {
        return ".";
    }
    end = path.find_last_not_of('/', slash);
    return end == std::string::npos ? std::string("/") : path.substr(0, end + 1);
}

[[noreturn]] void exitHomeNotFound()
{
    const auto line = base::logging::formatPlainLine(base::logging::localTimestamp(),
                                                     "wazuh-manager-analysisd",
                                                     "CRITICAL",
                                                     "(1108): Unable to find Wazuh install directory. Export it to "
                                                     "WAZUH_MANAGER_HOME environment variable.");
    // Best effort: the process exits right after, so a failed write has nowhere to be reported.
    const ssize_t written = ::write(STDERR_FILENO, line.data(), line.size());
    static_cast<void>(written);
    std::exit(EXIT_FAILURE);
}
} // namespace

std::filesystem::path resolveManagerHome(const std::function<const char*(const char*)>& getenv,
                                         const std::string& exePath,
                                         const std::function<bool(const std::string&)>& isDirectory)
{
    // Forced home: returned as is, without any check
    if (const char* forced = getenv("WAZUH_MANAGER_FORCE_HOME"))
    {
        return std::filesystem::path(forced);
    }

    std::string home;
    if (const char* env = getenv("WAZUH_MANAGER_HOME"); env != nullptr && env[0] != '\0')
    {
        home = env;
    }
    else
    {
        // <home>/bin/<executable>: cut the executable's directory at the first "/bin"
        home = dirName(exePath);
        if (const auto pos = home.find("/bin"); pos != std::string::npos)
        {
            home.resize(pos);
        }
    }

    if (!isDirectory(home))
    {
        exitHomeNotFound();
    }
    return std::filesystem::path(home);
}

void setManagerMode()
{
    g_managerMode.store(true);
}

std::filesystem::path getWazuhHome()
{
    if (g_managerMode.load())
    {
        static const std::filesystem::path home = []()
        {
            std::error_code ec;
            const auto exePath = std::filesystem::read_symlink("/proc/self/exe", ec);
            return resolveManagerHome([](const char* name) -> const char* { return std::getenv(name); },
                                      ec ? std::string() : exePath.string(),
                                      [](const std::string& path)
                                      {
                                          std::error_code dirEc;
                                          return !path.empty() && std::filesystem::is_directory(path, dirEc);
                                      });
        }();
        return home;
    }

    // Standalone mode / unit tests: conf::Conf may still use this value to build default paths when the
    // dedicated environment variables are not set.
    return std::filesystem::current_path();
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

std::string getEnvOrDefault(const char* name, const std::string& defaultValue)
{
    const char* val = std::getenv(name);
    return val ? std::string(val) : defaultValue;
}

std::size_t getEnvSizeOrDefault(const char* name, std::size_t defaultValue)
{
    const char* val = std::getenv(name);
    if (val)
    {
        try
        {
            return std::stoull(val);
        }
        catch (...)
        {
            return defaultValue;
        }
    }
    return defaultValue;
}

int getEnvIntOrDefault(const char* name, int defaultValue)
{
    const char* val = std::getenv(name);
    if (val)
    {
        try
        {
            return std::stoi(val);
        }
        catch (...)
        {
            return defaultValue;
        }
    }
    return defaultValue;
}

bool getEnvBoolOrDefault(const char* name, bool defaultValue)
{
    const char* val = std::getenv(name);
    if (val)
    {
        std::string v(val);
        std::transform(
            v.begin(), v.end(), v.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return v == "true" || v == "1" || v == "yes";
    }
    return defaultValue;
}

} // namespace base::process
