#ifndef _BASE_PROCESS_HPP
#define _BASE_PROCESS_HPP

#include <cerrno>
#include <cstring>
#include <optional>
#include <filesystem>
#include <pthread.h>
#include <stdexcept>
#include <string>

#include <fmt/format.h>

#include <base/error.hpp>

namespace base::process
{
const uid_t INVALID_UID = static_cast<uid_t>(-1);
const gid_t INVALID_GID = static_cast<gid_t>(-1);

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
 * @brief Find a UID by user name
 * @param name Name of the user.
 * @return UID of the user, if found.
 * @retval -1 user not found.
 */
uid_t privSepGetUser(const std::string& username);

/**
 * @brief Lookup a group’s GID by group name.
 *        Automatically grows the buffer on ERANGE.
 * @param groupname  The name of the group to look up.
 * @return GID if found.
 * @throws std::system_error on underlying errors.
 * @retval INVALID_GID if group not found.
 */
gid_t privSepGetGroup(const std::string& groupname);

/**
 * @brief Sets the user ID for privilege separation.
 *
 * This function changes the effective user ID of the calling process to the
 * specified user ID. This is typically used for privilege separation to drop
 * elevated privileges and run with reduced permissions for security purposes.
 *
 * @param uid The user ID to set for the current process
 * @return false on success, true on failure
 */
bool privSepSetUser(uid_t uid);

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
 * @note false is returned on success, true on failure.
 * @warning Calling this function will drop supplementary group memberships.
 */
int privSepSetGroup(gid_t gid);

/**
 * @brief Gets the Wazuh installation home directory path.
 *
 * This function determines the Wazuh home directory by reading the current
 * executable's path from /proc/self/exe and deriving the installation root.
 * It assumes the executable is located in the "bin" subdirectory of the
 * Wazuh installation (e.g., /var/ossec/bin/executable).
 *
 * @return std::filesystem::path The path to the Wazuh home directory ("/var/ossec").
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

} // namespace base::process

#endif // _BASE_PROCESS_HPP
