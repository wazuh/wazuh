#ifndef _BASE_PROCESS_HPP
#define _BASE_PROCESS_HPP

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <optional>
#include <pthread.h>
#include <stdexcept>
#include <string>

#include <fmt/format.h>

#include <base/error.hpp>

namespace base::process
{
constexpr auto ENV_ENGINE_STANDALONE = "WAZUH_ENGINE_STANDALONE"; ///< Env var to indicate standalone mode

constexpr auto WAZUH_USER = "wazuh-manager";  ///< User the engine drops to in manager-integrated mode
constexpr auto WAZUH_GROUP = "wazuh-manager"; ///< Group the engine drops to in manager-integrated mode

/**
 * @brief Transforms the current process into a daemon (double fork + detach).
 */
void goDaemon();

/**
 * @brief Creates a PID file for the specified service name.
 *
 * @param path Directory where the PID file will be written.
 * @param name Service name (used in filename).
 * @param pid Process ID to write.
 * @return std::nullopt if successful, otherwise a base::Error describing the issue.
 */
OptError createPID(const std::string& path, const std::string& name, int pid);

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
struct passwd* getpwnam(const char* name, struct passwd* pwd, char* buf, size_t buflen);

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
struct group* getgrnam(const char* name, struct group* grp, char* buf, int buflen);

/**
 * @brief Lookup a group’s GID by group name.
 *        Automatically grows the buffer on ERANGE.
 * @param groupname  The name of the group to look up.
 * @return GID if found.
 * @throws std::runtime_error if the group is not found or on other errors.
 */
gid_t privSepGetGroup(const std::string& groupname);

/**
 * @brief Sets the group ID and supplementary groups for privilege separation.
 *
 * This function performs privilege separation by setting the process group ID
 * and clearing supplementary groups, leaving only the specified group.
 *
 * @param gid The group ID to set for the current process
 *
 * @throws std::runtime_error if any system call fails, with a descriptive error message.
 * @warning This function modifies the process's group IDs and should be used with caution.
 *          It is typically called in a privileged context before dropping privileges.
 */
void privSepSetGroup(gid_t gid);

/**
 * @brief Lookup a user’s UID by username.
 *        Automatically grows the buffer on ERANGE.
 * @param username  The name of the user to look up.
 * @return UID if found.
 * @throws std::runtime_error if the user is not found or on other errors.
 */
uid_t privSepGetUser(const std::string& username);

/**
 * @brief Sets the user ID of the current process for privilege separation.
 *
 * This function drops user privileges by setting both the real and effective
 * user IDs to the given value. It must be called after privSepSetGroup(),
 * since changing the group is no longer permitted once the process is not
 * running as root.
 *
 * @param uid The user ID to set for the current process
 *
 * @throws std::runtime_error if any system call fails, with a descriptive error message.
 * @warning This operation is irreversible: once the process drops to an
 *          unprivileged user it cannot regain root privileges.
 */
void privSepSetUser(uid_t uid);

/**
 * @brief Gets the Wazuh installation home directory path.
 *
 * It delegates the functionality to w_homedir() when manager is not standalone
 * (libwazuhshared already loaded), the canonical Wazuh function used by
 * every other daemon. It resolves the path via /proc/self/exe
 * (e.g. /var/wazuh-manager/bin/wazuh-engine -> /var/wazuh-manager).
 *
 * It returns the current working directory when the manager is in standalone
 * mode or during unit tests (libwazuhshared not loaded). In standalone mode,
 * runtime paths are expected to come from dedicated environment variables;
 * this fallback can still be used to build defaults when those variables are
 * not set.
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
