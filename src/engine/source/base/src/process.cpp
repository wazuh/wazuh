// SPDX-License-Identifier: AGPL-3.0-or-later
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

/// Copy of sys with every empty member set to the real system call.
ProcessSysCalls withDefaults(ProcessSysCalls sys)
{
    if (!sys.fork)
    {
        sys.fork = []()
        {
            return ::fork();
        };
    }
    if (!sys.fcntl)
    {
        sys.fcntl = [](int fd, int cmd, int arg)
        {
            return ::fcntl(fd, cmd, arg);
        };
    }
    if (!sys.pipe2)
    {
        sys.pipe2 = [](int fds[2], int flags)
        {
            return ::pipe2(fds, flags);
        };
    }
    if (!sys.read)
    {
        sys.read = [](int fd, void* buf, size_t count)
        {
            return ::read(fd, buf, count);
        };
    }
    if (!sys.pthread_sigmask)
    {
        sys.pthread_sigmask = [](int how, const sigset_t* set, sigset_t* old)
        {
            return ::pthread_sigmask(how, set, old);
        };
    }
    if (!sys.sigtimedwait)
    {
        sys.sigtimedwait = [](const sigset_t* set, siginfo_t* info, const struct timespec* timeout)
        {
            return ::sigtimedwait(set, info, timeout);
        };
    }
    if (!sys.setsid)
    {
        sys.setsid = []()
        {
            return ::setsid();
        };
    }
    if (!sys.umask)
    {
        sys.umask = [](mode_t mask)
        {
            return ::umask(mask);
        };
    }
    if (!sys.open)
    {
        sys.open = [](const char* path, int flags, mode_t mode)
        {
            return ::open(path, flags, mode);
        };
    }
    if (!sys.dup2)
    {
        sys.dup2 = [](int oldFd, int newFd)
        {
            return ::dup2(oldFd, newFd);
        };
    }
    if (!sys.close)
    {
        sys.close = [](int fd)
        {
            return ::close(fd);
        };
    }
    if (!sys.fchmod)
    {
        sys.fchmod = [](int fd, mode_t mode)
        {
            return ::fchmod(fd, mode);
        };
    }
    if (!sys.write)
    {
        sys.write = [](int fd, const void* data, size_t size)
        {
            return ::write(fd, data, size);
        };
    }
    if (!sys.setgroups)
    {
        sys.setgroups = [](size_t size, const gid_t* list)
        {
            return ::setgroups(size, list);
        };
    }
    if (!sys.setgid)
    {
        sys.setgid = [](gid_t gid)
        {
            return ::setgid(gid);
        };
    }
    if (!sys.setuid)
    {
        sys.setuid = [](uid_t uid)
        {
            return ::setuid(uid);
        };
    }
    if (!sys.seteuid)
    {
        sys.seteuid = [](uid_t uid)
        {
            return ::seteuid(uid);
        };
    }
    if (!sys.sysconf)
    {
        sys.sysconf = [](int name)
        {
            return ::sysconf(name);
        };
    }
    return sys;
}

/// Initial buffer size for a reentrant lookup: the sysconf hint, or the default; never above the cap.
std::size_t initialLookupSize(int sysconfName, const ProcessSysCalls& s)
{
    const long hint = s.sysconf(sysconfName);
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
auto lookupId(const char* kind,
              const std::string& name,
              int sysconfName,
              const Lookup& lookup,
              IdOf idOf,
              const ProcessSysCalls& s)
{
    std::vector<char> buffer(initialLookupSize(sysconfName, s));

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

/// Status bytes of the startup channel. 'F' is followed by the cause, up to end of file.
constexpr char CHANNEL_READY = 'R';
constexpr char CHANNEL_FAILED = 'F';

/// What the launching process prints when the grandchild died without saying why.
constexpr auto NO_REASON_MSG = "wazuh-engine: the engine failed to start and reported no reason; see the engine log\n";

/**
 * @brief Blocks SIGPIPE for as long as it is alive and drains one pending instance on the way out.
 *
 * write(2) on a pipe whose reader is gone does NOT return EPIPE while SIGPIPE keeps its default disposition: it
 * delivers the signal and kills the process. The engine only sets SIG_IGN well after the first report points, so the
 * guard cannot rely on that. Draining uses a zero timeout and tolerates EAGAIN, because POSIX leaves it unspecified
 * whether a blocked signal whose disposition is ignore stays pending.
 */
class SigPipeGuard
{
public:
    explicit SigPipeGuard(const ProcessSysCalls& sys)
        : m_sys(&sys)
    {
        sigset_t block;
        sigemptyset(&block);
        sigaddset(&block, SIGPIPE);
        m_blocked = m_sys->pthread_sigmask(SIG_BLOCK, &block, &m_previous) == 0;
    }

    /// Drains a SIGPIPE raised by our own write, so it is not delivered once the mask is restored.
    void drain() const
    {
        if (!m_blocked)
        {
            return;
        }
        sigset_t pending;
        sigemptyset(&pending);
        sigaddset(&pending, SIGPIPE);
        const struct timespec immediately {0, 0};
        while (m_sys->sigtimedwait(&pending, nullptr, &immediately) < 0 && errno == EINTR)
        {
        }
    }

    ~SigPipeGuard()
    {
        if (m_blocked)
        {
            m_sys->pthread_sigmask(SIG_SETMASK, &m_previous, nullptr);
        }
    }

    SigPipeGuard(const SigPipeGuard&) = delete;
    SigPipeGuard& operator=(const SigPipeGuard&) = delete;

private:
    const ProcessSysCalls* m_sys;
    sigset_t m_previous {};
    bool m_blocked {false};
};

/**
 * @brief Writes the whole buffer, retrying EINTR and completing short writes.
 *
 * Any other errno aborts without retrying: the reader is gone or the channel is broken, and the caller's job is to
 * carry on to the log, never to spin. EPIPE is one of those cases and is not an error worth reporting.
 */
void writeAll(int fd, const char* data, std::size_t size, const ProcessSysCalls& s)
{
    SigPipeGuard guard(s);
    bool sawEpipe = false;
    std::size_t written = 0;
    while (written < size)
    {
        const ssize_t rc = s.write(fd, data + written, size - written);
        if (rc > 0)
        {
            written += static_cast<std::size_t>(rc);
            continue;
        }
        if (rc == 0)
        {
            // Nothing consumed and no error: retrying forever would burn a core in the daemon with no log and no
            // verdict, leaving the launcher blocked. createPID treats the same condition as a hard error.
            break;
        }
        if (errno == EINTR)
        {
            continue;
        }
        sawEpipe = (errno == EPIPE);
        break;
    }
    if (sawEpipe)
    {
        guard.drain();
    }
}

/// Writes a status byte and its optional text to the channel, as one buffer.
void sendFrame(int fd, char status, std::string_view text, const ProcessSysCalls& s)
{
    std::string frame;
    frame.reserve(1 + text.size());
    frame.push_back(status);
    frame.append(text);
    writeAll(fd, frame.data(), frame.size(), s);
}

/// Best effort write to the launching process's stderr, which is still connected at that point.
///
/// Guarded like the channel writes: if the launcher's stderr is a pipe whose reader has gone
/// (`wazuh-manager-control start 2>&1 | head -1`), a bare write would kill this process with SIGPIPE and the shell
/// would report 141 instead of the status we computed.
void toStderr(std::string_view text)
{
    const ProcessSysCalls real = withDefaults({});
    SigPipeGuard guard(real);
    bool sawEpipe = false;
    std::size_t written = 0;
    while (written < text.size())
    {
        const ssize_t rc = ::write(STDERR_FILENO, text.data() + written, text.size() - written);
        if (rc > 0)
        {
            written += static_cast<std::size_t>(rc);
            continue;
        }
        if (rc < 0 && errno == EINTR)
        {
            continue;
        }
        sawEpipe = (rc < 0 && errno == EPIPE);
        break;
    }
    if (sawEpipe)
    {
        guard.drain();
    }
}

/**
 * @brief Reads the verdict in the launching process and returns the status it must exit with.
 *
 * Every path that is not an explicit READY ends in EXIT_FAILURE, and every path that produces no diagnosis prints the
 * generic line, so the caller is never left with a non-zero status and a silent stderr.
 */
int awaitVerdict(int fd, const ProcessSysCalls& s)
{
    char status = 0;
    ssize_t rc = 0;
    while ((rc = s.read(fd, &status, 1)) < 0 && errno == EINTR)
    {
    }

    if (rc < 0)
    {
        toStderr(fmt::format("wazuh-engine: cannot read the startup channel: {}\n", describeError(errno)));
        return EXIT_FAILURE;
    }
    if (rc == 0)
    {
        toStderr(NO_REASON_MSG); // died before saying anything
        return EXIT_FAILURE;
    }
    if (status == CHANNEL_READY)
    {
        return EXIT_SUCCESS; // do not wait for end of file: the engine outlives us
    }
    if (status != CHANNEL_FAILED)
    {
        toStderr(fmt::format("wazuh-engine: unexpected startup channel byte {:#04x}\n",
                             static_cast<unsigned>(static_cast<unsigned char>(status))));
        return EXIT_FAILURE;
    }

    std::string reason;
    char chunk[512];
    while (true)
    {
        const ssize_t got = s.read(fd, chunk, sizeof(chunk));
        if (got > 0)
        {
            reason.append(chunk, static_cast<std::size_t>(got));
            continue;
        }
        if (got < 0 && errno == EINTR)
        {
            continue;
        }
        break; // end of file, or an error we cannot do anything about
    }

    if (reason.empty())
    {
        toStderr(NO_REASON_MSG); // 'F' arrived but the text did not
    }
    else
    {
        if (reason.back() != '\n')
        {
            reason.push_back('\n');
        }
        toStderr(reason);
    }
    return EXIT_FAILURE;
}

} // namespace

StartupReport::StartupReport(int writeFd, ProcessSysCalls sys)
    : m_fd(writeFd)
    , m_sys(withDefaults(std::move(sys)))
{
    // withDefaults here too, and not only in goDaemon: the documented contract of ProcessSysCalls is that an empty
    // member is the real call, and this constructor is public.
}

StartupReport::StartupReport(StartupReport&& other) noexcept
    : m_fd(other.m_fd)
    , m_sys(std::move(other.m_sys))
{
    other.m_fd = -1;
}

StartupReport& StartupReport::operator=(StartupReport&& other) noexcept
{
    if (this != &other)
    {
        disconnect();
        m_fd = other.m_fd;
        m_sys = std::move(other.m_sys);
        other.m_fd = -1;
    }
    return *this;
}

StartupReport::~StartupReport()
{
    disconnect();
}

void StartupReport::disconnect()
{
    if (m_fd >= 0)
    {
        m_sys.close(m_fd);
        m_fd = -1;
    }
}

void StartupReport::reportReady()
{
    if (m_fd < 0)
    {
        return; // disconnected: foreground mode, or already reported
    }
    sendFrame(m_fd, CHANNEL_READY, {}, m_sys);
    disconnect();
}

void StartupReport::reportFailure(std::string_view reason)
{
    if (m_fd < 0)
    {
        return;
    }
    sendFrame(m_fd, CHANNEL_FAILED, reason, m_sys);
    disconnect();
}

StartupReport goDaemon(const ProcessSysCalls& sys)
{
    const auto s = withDefaults(sys);

    int channel[2] = {-1, -1};
    if (s.pipe2(channel, O_CLOEXEC) < 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("could not create the startup channel: {}", describeError(err))};
    }
    // pipe2 hands out the lowest free descriptors. If the binary was launched with stdin/stdout/stderr closed, an end
    // can land on 0, 1 or 2 and the dup2 of /dev/null below would silently replace it: the grandchild would then write
    // its verdict into /dev/null and a healthy start would be reported as a failure. daemon(7) lists this step.
    const auto lift = [&s](int fd)
    {
        if (fd > STDERR_FILENO)
        {
            return fd;
        }
        const int moved = s.fcntl(fd, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
        if (moved < 0)
        {
            return fd; // best effort: keep the original rather than lose the channel
        }
        s.close(fd);
        return moved;
    };
    const int readEnd = lift(channel[0]);
    const int writeEnd = lift(channel[1]);

    // First fork. Unlike a plain double fork, the original process does not leave with success here: it waits for the
    // verdict and exits with it, which is the whole point of the channel.
    const pid_t first = s.fork();
    if (first < 0)
    {
        const int err = errno;
        s.close(readEnd);
        s.close(writeEnd);
        throw std::runtime_error {fmt::format("fork failed (first): {}", describeError(err))};
    }
    if (first > 0)
    {
        s.close(writeEnd); // or we would never see end of file
        _exit(awaitVerdict(readEnd, s));
    }
    s.close(readEnd); // the children never read

    if (s.setsid() < 0)
    {
        const int err = errno;
        const auto msg = fmt::format("setsid failed: {}", describeError(err));
        sendFrame(writeEnd, CHANNEL_FAILED, msg, s); // still the intermediate child: no grandchild exists yet
        s.close(writeEnd);
        throw std::runtime_error {msg};
    }

    const pid_t second = s.fork();
    if (second < 0)
    {
        const int err = errno;
        const auto msg = fmt::format("fork failed (second): {}", describeError(err));
        sendFrame(writeEnd, CHANNEL_FAILED, msg, s);
        s.close(writeEnd);
        throw std::runtime_error {msg};
    }
    if (second > 0)
    {
        _exit(EXIT_SUCCESS); // its copy of the write end closes here, leaving the grandchild as sole owner
    }

    s.umask(027);

    const int fd = s.open("/dev/null", O_RDWR | O_CLOEXEC, 0);
    if (fd < 0)
    {
        const int err = errno;
        const auto msg = fmt::format("could not open /dev/null: {}", describeError(err));
        sendFrame(writeEnd, CHANNEL_FAILED, msg, s);
        s.close(writeEnd);
        throw std::runtime_error {msg};
    }

    for (const int target : {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO})
    {
        if (s.dup2(fd, target) < 0)
        {
            const int err = errno;
            const auto msg = fmt::format("could not redirect fd {} to /dev/null: {}", target, describeError(err));
            if (fd > STDERR_FILENO)
            {
                s.close(fd);
            }
            sendFrame(writeEnd, CHANNEL_FAILED, msg, s);
            s.close(writeEnd);
            throw std::runtime_error {msg};
        }
    }

    if (fd > STDERR_FILENO)
    {
        s.close(fd);
    }

    return StartupReport {writeEnd, s};
}

OptError createPID(const std::string& path, const std::string& name, int pid, const ProcessSysCalls& sys)
{
    const auto s = withDefaults(sys);
    const auto file = (std::filesystem::path(path) / fmt::format("{}-{}.pid", name, pid)).string();

    const int fd = s.open(file.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);
    if (fd < 0)
    {
        const int err = errno;
        return Error {fmt::format("could not create PID file {}: {}", file, describeError(err))};
    }

    // The mode given to open() is filtered by the umask; fchmod sets it exactly.
    if (s.fchmod(fd, 0640) != 0)
    {
        const int err = errno;
        s.close(fd);
        return Error {fmt::format("could not set mode 0640 on PID file {}: {}", file, describeError(err))};
    }

    const auto content = fmt::format("{}\n", pid);
    std::size_t written = 0;
    while (written < content.size())
    {
        const ssize_t rc = s.write(fd, content.data() + written, content.size() - written);
        if (rc < 0)
        {
            const int err = errno;
            if (err == EINTR)
            {
                continue;
            }
            s.close(fd);
            return Error {fmt::format("could not write PID file {}: {}", file, describeError(err))};
        }
        if (rc == 0)
        {
            s.close(fd);
            return Error {fmt::format("could not write PID file {}: short write", file)};
        }
        written += static_cast<std::size_t>(rc);
    }

    if (s.close(fd) != 0)
    {
        const int err = errno;
        return Error {fmt::format("could not close PID file {}: {}", file, describeError(err))};
    }

    return std::nullopt;
}

uid_t lookupUid(const std::string& name, const UserLookup& lookup, const ProcessSysCalls& sys)
{
    return lookupId<struct passwd>(
        "user",
        name,
        _SC_GETPW_R_SIZE_MAX,
        lookup,
        [](const struct passwd& entry) { return entry.pw_uid; },
        withDefaults(sys));
}

gid_t lookupGid(const std::string& name, const GroupLookup& lookup, const ProcessSysCalls& sys)
{
    return lookupId<struct group>(
        "group",
        name,
        _SC_GETGR_R_SIZE_MAX,
        lookup,
        [](const struct group& entry) { return entry.gr_gid; },
        withDefaults(sys));
}

void dropToGroup(gid_t gid, const ProcessSysCalls& sys)
{
    const auto s = withDefaults(sys);

    if (s.setgroups(1, &gid) != 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("could not drop supplementary groups: {}", describeError(err))};
    }

    if (s.setgid(gid) != 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("could not set group ID {}: {}", gid, describeError(err))};
    }
}

void dropToUser(uid_t uid, const ProcessSysCalls& sys)
{
    const auto s = withDefaults(sys);

    if (s.setuid(uid) != 0)
    {
        const int err = errno;
        throw std::runtime_error {fmt::format("could not set user ID {}: {}", uid, describeError(err))};
    }

    if (s.seteuid(uid) != 0)
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
