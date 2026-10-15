// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _BASE_PROCESS_HPP
#define _BASE_PROCESS_HPP

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <functional>
#include <optional>
#include <pthread.h>
#include <stdexcept>
#include <string>

#include <grp.h>
#include <pwd.h>
#include <sys/types.h>

#include <fmt/format.h>

#include <base/error.hpp>

namespace base::process
{
constexpr auto ENV_ENGINE_STANDALONE = "WAZUH_ENGINE_STANDALONE"; ///< Env var to indicate standalone mode

constexpr auto WAZUH_USER = "wazuh-manager";  ///< User the engine drops to in manager-integrated mode
constexpr auto WAZUH_GROUP = "wazuh-manager"; ///< Group the engine drops to in manager-integrated mode

/**
 * @brief Injectable system calls of the process helpers (tests only). An empty member is the real call.
 *
 * A fake follows the contract of the call it replaces: on failure it returns -1 (fork, setsid, open, dup2, close,
 * fchmod, write, setgroups, setgid, setuid, seteuid) and sets errno, which the helpers read right after the call.
 * write returning 0 is a short write (errno is not read); sysconf returning a value <= 0 means "no size hint" (errno is
 * not read); umask never fails and its result is ignored.
 */
struct ProcessSysCalls
{
    std::function<pid_t()> fork;
    std::function<pid_t()> setsid;
    std::function<mode_t(mode_t)> umask;
    std::function<int(const char*, int, mode_t)> open;
    std::function<int(int, int)> dup2;
    std::function<int(int)> close;
    std::function<int(int, mode_t)> fchmod;
    std::function<ssize_t(int, const void*, size_t)> write;
    std::function<int(size_t, const gid_t*)> setgroups;
    std::function<int(gid_t)> setgid;
    std::function<int(uid_t)> setuid;
    std::function<int(uid_t)> seteuid;
    std::function<long(int)> sysconf; ///< Size hint of the reentrant user/group lookups
};

/**
 * @brief Transforms the current process into a daemon.
 *
 * fork (the parent exits with _exit), setsid, fork again (the first child exits with _exit), umask(027) and
 * stdin, stdout and stderr redirected to /dev/null.
 *
 * The parents always leave with the real _exit (no atexit handlers, no static destructors): it stays outside
 * ProcessSysCalls. With an empty umask member, umask(027) is applied to the calling process.
 *
 * @param sys System calls (the real ones by default).
 * @throws std::runtime_error if any step fails.
 */
void goDaemon(const ProcessSysCalls& sys = {});

/**
 * @brief Creates (or truncates) the PID file <path>/<name>-<pid>.pid with mode 0640 and content "<pid>\n".
 *
 * @param path Directory where the PID file will be written.
 * @param name Service name (used in filename).
 * @param pid Process ID to write.
 * @param sys System calls (the real ones by default).
 * @return std::nullopt if successful, otherwise a base::Error describing the issue.
 */
OptError createPID(const std::string& path, const std::string& name, int pid, const ProcessSysCalls& sys = {});

/**
 * @brief Reentrant user lookup with the getpwnam_r(3) contract (injectable for tests).
 *
 * Returns 0 and sets *found to entry (or to nullptr when the name does not exist), or an errno-style code
 * (ERANGE: buffer too small).
 */
using UserLookup =
    std::function<int(const char* name, struct passwd* entry, char* buf, size_t len, struct passwd** found)>;

/**
 * @brief Reentrant group lookup with the getgrnam_r(3) contract (injectable for tests).
 *
 * Returns 0 and sets *found to entry (or to nullptr when the name does not exist), or an errno-style code
 * (ERANGE: buffer too small).
 */
using GroupLookup =
    std::function<int(const char* name, struct group* entry, char* buf, size_t len, struct group** found)>;

/**
 * @brief Resolves a user name to its UID.
 *
 * The buffer starts at sysconf(_SC_GETPW_R_SIZE_MAX) (1024 when undefined) and doubles on every ERANGE returned
 * by the lookup, up to 65536 bytes. Only the return code is inspected, never errno.
 *
 * @param name User name.
 * @param lookup Lookup function (getpwnam_r in production).
 * @param sys System calls; only sysconf is used (the real one by default).
 * @return uid_t The user ID.
 * @throws std::runtime_error if the user does not exist, the lookup fails or the entry exceeds 65536 bytes.
 */
uid_t lookupUid(const std::string& name, const UserLookup& lookup = ::getpwnam_r, const ProcessSysCalls& sys = {});

/**
 * @brief Resolves a group name to its GID.
 *
 * The buffer starts at sysconf(_SC_GETGR_R_SIZE_MAX) (1024 when undefined) and doubles on every ERANGE returned
 * by the lookup, up to 65536 bytes. Only the return code is inspected, never errno.
 *
 * @param name Group name.
 * @param lookup Lookup function (getgrnam_r in production).
 * @param sys System calls; only sysconf is used (the real one by default).
 * @return gid_t The group ID.
 * @throws std::runtime_error if the group does not exist, the lookup fails or the entry exceeds 65536 bytes.
 */
gid_t lookupGid(const std::string& name, const GroupLookup& lookup = ::getgrnam_r, const ProcessSysCalls& sys = {});

/**
 * @brief Makes gid the only group of the process: setgroups(1, &gid), then setgid(gid).
 *
 * Must run before dropToUser(): once the process is no longer root, the group cannot be changed.
 *
 * @param gid Group ID.
 * @param sys System calls (the real ones by default).
 * @throws std::runtime_error if a system call fails.
 */
void dropToGroup(gid_t gid, const ProcessSysCalls& sys = {});

/**
 * @brief Sets the real and effective user IDs: setuid(uid), then seteuid(uid).
 *
 * Irreversible when leaving root. Call it after dropToGroup().
 *
 * @param uid User ID.
 * @param sys System calls (the real ones by default).
 * @throws std::runtime_error if a system call fails.
 */
void dropToUser(uid_t uid, const ProcessSysCalls& sys = {});

/**
 * @brief Resolves the manager home directory.
 *
 * Steps 2 and 3 follow the home lookup of the C daemons (src/shared/src/file_op.c) on Linux, with /proc/self/exe
 * only and none of its other fallbacks; step 1 is the engine's own override.
 *
 * 1. WAZUH_MANAGER_FORCE_HOME defined (even empty or not a directory): returned as is, never checked.
 * 2. Otherwise WAZUH_MANAGER_HOME, when not empty, as is (not cut at "/bin").
 * 3. Otherwise dirname(exePath) cut at the first "/bin" substring (the whole dirname when there is none),
 *    e.g. /var/wazuh-manager/bin/wazuh-manager-analysisd -> /var/wazuh-manager.
 *
 * When the result of 2 or 3 is not a directory, it writes
 * "<now> wazuh-manager-analysisd: CRITICAL: (1108): Unable to find Wazuh install directory. Export it to
 * WAZUH_MANAGER_HOME environment variable." to stderr and exits with status 1 (no log file is written).
 *
 * @param getenv Environment lookup (std::getenv in production).
 * @param exePath Resolved path of the running executable (/proc/self/exe in production; "" if it cannot be read).
 * @param isDirectory Whether a path is an existing directory.
 * @return std::filesystem::path The home directory.
 */
std::filesystem::path resolveManagerHome(const std::function<const char*(const char*)>& getenv,
                                         const std::string& exePath,
                                         const std::function<bool(const std::string&)>& isDirectory);

/**
 * @brief Enables manager mode for getWazuhHome() (process-wide and irreversible; main() in manager mode).
 */
void setManagerMode();

/**
 * @brief Gets the Wazuh installation home directory path.
 *
 * In manager mode (after setManagerMode()) it resolves the home once with resolveManagerHome() from the real
 * environment and /proc/self/exe, and caches it; an invalid home ends the process (see resolveManagerHome()).
 *
 * Otherwise (standalone mode or unit tests) it returns the current working directory. In standalone mode,
 * runtime paths are expected to come from dedicated environment variables; this fallback can still be used
 * to build defaults when those variables are not set.
 *
 * @return std::filesystem::path The path to the Wazuh home directory.
 *
 */
std::filesystem::path getWazuhHome();

/**
 * @brief Sets the name of the current thread.
 *
 * This function assigns a name to the calling thread,
 * On Linux, the thread name is limited to 15 characters; if the provided name is longer, it will be truncated.
 * If the input name is empty, the function does nothing.
 *
 * @param name The desired name for the thread.
 */
void setThreadName(const std::string& name);

/**
 * @brief Checks whether standalone mode is enabled for the Wazuh engine.
 *
 * @return true  If standalone mode is enabled.
 * @return false Otherwise.
 */
bool isStandaloneModeEnable();

/**
 * @brief Get environment variable as string with default value.
 *
 * @param name Environment variable name
 * @param defaultValue Default value if variable not set
 * @return Value from environment or default
 */
std::string getEnvOrDefault(const char* name, const std::string& defaultValue);

/**
 * @brief Get environment variable as size_t with default value.
 *
 * @param name Environment variable name
 * @param defaultValue Default value if variable not set or invalid
 * @return Value from environment or default
 */
std::size_t getEnvSizeOrDefault(const char* name, std::size_t defaultValue);

/**
 * @brief Get environment variable as int with default value.
 *
 * @param name Environment variable name
 * @param defaultValue Default value if variable not set or invalid
 * @return Value from environment or default
 */
int getEnvIntOrDefault(const char* name, int defaultValue);

/**
 * @brief Get environment variable as bool with default value.
 *
 * Recognizes: "true", "1", "yes" (case-insensitive) as true.
 *
 * @param name Environment variable name
 * @param defaultValue Default value if variable not set
 * @return Value from environment or default
 */
bool getEnvBoolOrDefault(const char* name, bool defaultValue);

} // namespace base::process

#endif // _BASE_PROCESS_HPP
