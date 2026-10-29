// SPDX-License-Identifier: AGPL-3.0-or-later
#include <base/managerLogSink.hpp>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <mutex>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <base/logging.hpp>
#include <base/process.hpp>

namespace
{

/// The JSON description keeps the first OS_MAXSTR - 1 bytes of the message, like the C logger.
constexpr std::size_t JSON_DESCRIPTION_MAX = 65535;

/// File mode of a newly created log file.
constexpr mode_t LOG_FILE_MODE = 0660;

struct SinkState
{
    std::mutex mutex;
    base::logging::ManagerLogOptions options;
    base::logging::ManagerLogDeps deps;
};

/// Immortal state: allocated once and never released (see the header).
SinkState& sinkState()
{
    static SinkState* const state = new SinkState();
    return *state;
}

std::atomic<bool> g_initialized {false};
std::atomic<int> g_debugLevel {0};

void fillDefaults(base::logging::ManagerLogDeps& deps)
{
    if (!deps.now)
    {
        deps.now = &base::logging::localTimestamp;
    }
    if (!deps.pid)
    {
        deps.pid = []()
        {
            return static_cast<int>(::getpid());
        };
    }
    if (!deps.isRoot)
    {
        deps.isRoot = []()
        {
            return ::getuid() == 0;
        };
    }
    if (!deps.groupId)
    {
        // Same reentrant lookup as the privilege drop (64 KiB cap); any failure means "no group": the file keeps the
        // group of its creator.
        deps.groupId = [](const std::string& name) -> std::optional<gid_t>
        {
            try
            {
                return base::process::lookupGid(name);
            }
            catch (const std::exception&)
            {
                return std::nullopt;
            }
        };
    }
    if (!deps.open)
    {
        deps.open = [](const char* path, int flags, mode_t mode)
        {
            return ::open(path, flags, mode);
        };
    }
    if (!deps.fstat)
    {
        deps.fstat = [](int fd, struct stat* buf)
        {
            return ::fstat(fd, buf);
        };
    }
    if (!deps.fchown)
    {
        deps.fchown = [](int fd, uid_t uid, gid_t gid)
        {
            return ::fchown(fd, uid, gid);
        };
    }
    if (!deps.fchmod)
    {
        deps.fchmod = [](int fd, mode_t mode)
        {
            return ::fchmod(fd, mode);
        };
    }
    if (!deps.write)
    {
        deps.write = [](int fd, const char* data, size_t size)
        {
            return ::write(fd, data, size);
        };
    }
    if (!deps.close)
    {
        deps.close = [](int fd)
        {
            return ::close(fd);
        };
    }
}

/// Plain and JSON level names: Trace/Debug -> debug, Info -> info, Warn -> warning, Err/Critical -> error.
const char* plainLevel(::logging::Level lvl)
{
    switch (lvl)
    {
        case ::logging::Level::Trace:
        case ::logging::Level::Debug: return "DEBUG";
        case ::logging::Level::Warn: return "WARNING";
        case ::logging::Level::Err:
        case ::logging::Level::Critical: return "ERROR";
        default: return "INFO";
    }
}

const char* jsonLevel(::logging::Level lvl)
{
    switch (lvl)
    {
        case ::logging::Level::Trace:
        case ::logging::Level::Debug: return "debug";
        case ::logging::Level::Warn: return "warning";
        case ::logging::Level::Err:
        case ::logging::Level::Critical: return "error";
        default: return "info";
    }
}

/// Source file without its directory.
std::string_view baseName(const char* file)
{
    if (file == nullptr)
    {
        return {};
    }
    const char* slash = std::strrchr(file, '/');
    return slash != nullptr ? std::string_view(slash + 1) : std::string_view(file);
}

std::string_view orEmpty(const char* str)
{
    return str != nullptr ? std::string_view(str) : std::string_view();
}

/// Append a JSON string literal (quotes included) with the escaping rules of cJSON_PrintUnformatted.
void appendJsonString(std::string& out, std::string_view str)
{
    static constexpr char HEX[] = "0123456789abcdef";

    out.push_back('"');
    for (const char c : str)
    {
        const auto byte = static_cast<unsigned char>(c);
        switch (c)
        {
            case '"': out.append("\\\""); break;
            case '\\': out.append("\\\\"); break;
            case '\b': out.append("\\b"); break;
            case '\f': out.append("\\f"); break;
            case '\n': out.append("\\n"); break;
            case '\r': out.append("\\r"); break;
            case '\t': out.append("\\t"); break;
            default:
                if (byte < 0x20)
                {
                    out.append("\\u00");
                    out.push_back(HEX[byte >> 4]);
                    out.push_back(HEX[byte & 0x0F]);
                }
                else
                {
                    out.push_back(c);
                }
                break;
        }
    }
    out.push_back('"');
}

/// Keep @p fd only when it is a lone regular file (the C logger's w_openat_nofollow_vetted rule): O_NOFOLLOW rules
/// out a link at the last component and O_NONBLOCK a FIFO without a reader, but not a FIFO with one, a device or a
/// hard link to another file.
/// @return @p fd, or -1 after closing it.
int vetLogFile(const base::logging::ManagerLogDeps& deps, int fd)
{
    if (fd < 0)
    {
        return fd;
    }
    struct stat st {};
    if (deps.fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1)
    {
        (void)deps.close(fd);
        return -1;
    }
    return fd;
}

/// Open a log file for appending, creating it (0660, group of the manager when root) if it does not exist.
/// logs/ is writable by the service account, which can plant a link, hard link or FIFO at the log's name, and the
/// engine logs as root until it drops privileges: the name is never followed as a link and only a lone regular file is
/// written. O_NONBLOCK makes no difference to a regular file's writes.
/// @return The descriptor, or -1 (the line is dropped for this destination).
int openLogFile(const base::logging::ManagerLogOptions& options,
                const base::logging::ManagerLogDeps& deps,
                const std::string& path)
{
    constexpr int APPEND_FLAGS = O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY;

    int fd = deps.open(path.c_str(), APPEND_FLAGS, 0);
    if (fd >= 0 || errno != ENOENT)
    {
        return vetLogFile(deps, fd);
    }

    fd = vetLogFile(deps, deps.open(path.c_str(), APPEND_FLAGS | O_CREAT | O_EXCL, LOG_FILE_MODE));
    if (fd < 0)
    {
        // Somebody else created it in between: append to theirs
        return errno == EEXIST ? vetLogFile(deps, deps.open(path.c_str(), APPEND_FLAGS, 0)) : -1;
    }

    // Failures of fchmod/fchown keep the file: the line is still written.
    (void)deps.fchmod(fd, LOG_FILE_MODE);
    if (deps.isRoot())
    {
        if (const auto gid = deps.groupId(options.groupName))
        {
            (void)deps.fchown(fd, static_cast<uid_t>(-1), *gid);
        }
    }
    return fd;
}

void writeToFile(const base::logging::ManagerLogOptions& options,
                 const base::logging::ManagerLogDeps& deps,
                 const std::string& path,
                 const std::string& line)
{
    const int fd = openLogFile(options, deps, path);
    if (fd < 0)
    {
        return;
    }
    (void)deps.write(fd, line.data(), line.size()); // A short write drops the line, never retried
    (void)deps.close(fd);
}

} // namespace

namespace base::logging
{

void initManager(const ManagerLogOptions& options, ManagerLogDeps deps)
{
    fillDefaults(deps);

    auto& state = sinkState();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.options = options;
    state.deps = std::move(deps);
    g_initialized.store(true, std::memory_order_release);
}

void setManagerDebugLevel(int level)
{
    g_debugLevel.store(level, std::memory_order_relaxed);
}

int managerDebugLevel()
{
    return g_debugLevel.load(std::memory_order_relaxed);
}

std::string localTimestamp()
{
    const std::time_t now = std::time(nullptr);
    struct tm local {};
    char buffer[32] {};
    if (localtime_r(&now, &local) == nullptr || std::strftime(buffer, sizeof(buffer), "%Y/%m/%d %H:%M:%S", &local) == 0)
    {
        return {};
    }
    return buffer;
}

std::string formatPlainLine(std::string_view now, std::string_view tag, std::string_view level, std::string_view text)
{
    std::string line;
    line.reserve(now.size() + tag.size() + level.size() + text.size() + 6);
    line.append(now).append(" ").append(tag).append(": ").append(level).append(": ").append(text).append("\n");
    return line;
}

void write(
    ::logging::Level lvl, std::string_view tag, const char* file, int line, const char* func, std::string_view text)
{
    if (!g_initialized.load(std::memory_order_acquire))
    {
        return;
    }

    // Logging must not change errno for the caller (open/write/close below set it)
    const int savedErrno = errno;
    struct ErrnoRestore
    {
        int value;
        ~ErrnoRestore() { errno = value; }
    } errnoRestore {savedErrno};

    const int debugLevel = managerDebugLevel();
    if ((lvl == ::logging::Level::Trace && debugLevel < 2) || (lvl == ::logging::Level::Debug && debugLevel < 1))
    {
        return;
    }

    try
    {
        auto& state = sinkState();
        std::lock_guard<std::mutex> lock(state.mutex);
        const auto& options = state.options;
        const auto& deps = state.deps;

        const std::string now = deps.now();
        const bool withDebugInfo = debugLevel >= 1;
        const int pid = withDebugInfo ? deps.pid() : 0;
        const auto fileName = baseName(file);
        const auto funcName = orEmpty(func);

        if (options.logJson)
        {
            std::string json;
            json.reserve(text.size() + 128);
            json.append("{\"timestamp\":");
            appendJsonString(json, now);
            json.append(",\"tag\":");
            appendJsonString(json, tag);
            if (withDebugInfo)
            {
                json.append(",\"pid\":").append(std::to_string(pid));
                json.append(",\"file\":");
                appendJsonString(json, fileName);
                json.append(",\"line\":").append(std::to_string(line));
                json.append(",\"routine\":");
                appendJsonString(json, funcName);
            }
            json.append(",\"level\":");
            appendJsonString(json, jsonLevel(lvl));
            json.append(",\"description\":");
            appendJsonString(json, text.substr(0, JSON_DESCRIPTION_MAX));
            json.append("}\n");

            writeToFile(options, deps, options.jsonPath, json);
        }

        if (options.logPlain || options.writeStderr)
        {
            std::string plain;
            if (withDebugInfo)
            {
                plain.reserve(now.size() + tag.size() + fileName.size() + funcName.size() + text.size() + 64);
                plain.append(now).append(" ").append(tag);
                plain.append("[").append(std::to_string(pid)).append("] ");
                plain.append(fileName).append(":").append(std::to_string(line));
                plain.append(" at ").append(funcName).append("(): ");
                plain.append(plainLevel(lvl)).append(": ").append(text).append("\n");
            }
            else
            {
                plain = formatPlainLine(now, tag, plainLevel(lvl), text);
            }

            if (options.logPlain)
            {
                writeToFile(options, deps, options.plainPath, plain);
            }
            if (options.writeStderr)
            {
                (void)deps.write(STDERR_FILENO, plain.data(), plain.size());
            }
        }
    }
    catch (...)
    {
        // Never throw from a log call (e.g. std::bad_alloc); the line is lost
    }
}

} // namespace base::logging
