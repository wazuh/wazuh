// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _BASE_MANAGER_LOG_SINK_HPP
#define _BASE_MANAGER_LOG_SINK_HPP

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include <sys/types.h>

namespace logging
{
enum class Level; // Defined in base/logging.hpp, which includes this header.
} // namespace logging

/**
 * @brief Log writer of the engine in manager mode (logs/wazuh-manager.log and logs/wazuh-manager.json).
 *
 * Reproduces the observable contract of the manager's C logger: same plain and JSON lines, same order of the
 * destinations (JSON, plain, stderr), same level names and the same debug prefix. Each line is composed in memory and
 * written with a single write() per destination, under one process-wide mutex; files are opened per line with
 * O_APPEND, so a rename/rotation of the file is picked up by the next line.
 *
 * Life cycle: main() calls initManager() in manager mode right after loading etc/wazuh-manager.conf, before the
 * RLIMIT warnings and before goDaemon(). The mutex crosses the fork()s of goDaemon() only because no other thread
 * exists yet. The state (options, dependencies, mutex) is never destroyed, so lines emitted by the exit handlers or by
 * late threads after main() returns never touch a destroyed mutex.
 *
 * Before initManager() (unit tests, and main() before the call) write() is a no-op that neither throws nor touches the
 * file system.
 */
namespace base::logging
{

/**
 * @brief What the sink writes and where. Paths are relative to the current directory (the home after main()'s chdir).
 */
struct ManagerLogOptions
{
    std::string plainPath {"logs/wazuh-manager.log"}; ///< Plain log file
    std::string jsonPath {"logs/wazuh-manager.json"}; ///< JSON log file
    bool logPlain {true};                             ///< Write the plain file
    bool logJson {false};                             ///< Write the JSON file
    bool writeStderr {true};                          ///< Copy every plain line to stderr (fd 2)
    std::string groupName {"wazuh-manager"};          ///< Group of a newly created file when running as root
};

/**
 * @brief Injectable system calls of the sink. An empty member is filled with the real call by initManager().
 */
struct ManagerLogDeps
{
    std::function<std::string()> now; ///< "YYYY/MM/DD HH:MM:SS", local time
    std::function<int()> pid;         ///< getpid(), evaluated per line
    std::function<bool()> isRoot;     ///< getuid() == 0
    std::function<std::optional<gid_t>(const std::string&)>
        groupId; ///< Group of the name; default: base::process::lookupGid (64 KiB cap), std::nullopt when unknown or on
                 ///< error
    std::function<int(const char*, int, mode_t)> open;      ///< ::open
    std::function<int(int, uid_t, gid_t)> fchown;           ///< ::fchown
    std::function<int(int, mode_t)> fchmod;                 ///< ::fchmod
    std::function<ssize_t(int, const char*, size_t)> write; ///< ::write (files and stderr = fd 2)
    std::function<int(int)> close;                          ///< ::close of the descriptors from open
};

/**
 * @brief Activate the sink. Every call replaces the options and dependencies under the sink mutex (idempotent).
 */
void initManager(const ManagerLogOptions& options, ManagerLogDeps deps = {});

/**
 * @brief Set the debug level of manager mode (0: none, 1: debug, 2: debug + trace). Relaxed atomic.
 */
void setManagerDebugLevel(int level);

/**
 * @brief Current debug level of manager mode.
 */
int managerDebugLevel();

/**
 * @brief Write one log line to the active destinations. No-op before initManager(); never throws.
 *
 * Trace lines are written only with debug level >= 2 and Debug lines with >= 1 (lines coming from the shared libraries
 * do not pass through should_log()). The text is written as is (not a printf format).
 *
 * @param lvl Level of the line (Trace/Debug -> DEBUG, Info -> INFO, Warn -> WARNING, Err/Critical -> ERROR).
 * @param tag Tag of the line.
 * @param file Source file (its directory is dropped); may be nullptr.
 * @param line Source line.
 * @param func Source function; may be nullptr.
 * @param text Message.
 */
void write(
    ::logging::Level lvl, std::string_view tag, const char* file, int line, const char* func, std::string_view text);

/**
 * @brief Plain line without debug prefix: "<now> <tag>: <level>: <text>\n".
 */
std::string formatPlainLine(std::string_view now, std::string_view tag, std::string_view level, std::string_view text);

/**
 * @brief Current local time as "YYYY/MM/DD HH:MM:SS" (the default ManagerLogDeps::now).
 */
std::string localTimestamp();

} // namespace base::logging

#endif // _BASE_MANAGER_LOG_SINK_HPP
