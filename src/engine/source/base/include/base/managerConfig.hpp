#ifndef _BASE_MANAGERCONFIG_HPP
#define _BASE_MANAGERCONFIG_HPP

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

/**
 * @brief Manager configuration (etc/wazuh-manager.conf, strict XML) as seen by the engine in manager mode.
 *
 * Thin process-wide wrapper over shared_modules/manager_config: the effective document (schema
 * defaults applied) is loaded once in main() before any thread starts and only read afterwards.
 * In standalone mode nothing is loaded and every getter answers "no document".
 */
namespace base::managerConfig
{

/// Configuration file, relative to the manager home.
constexpr std::string_view FILE_RELATIVE_PATH = "etc/wazuh-manager.conf";

/**
 * @brief Load <home>/etc/wazuh-manager.conf without checking the files it references (start-up).
 * @throws std::runtime_error "<pointer>: <message>" when the file is missing or invalid.
 */
void load(const std::filesystem::path& home);

/**
 * @brief Validate <home>/etc/wazuh-manager.conf, also checking that the referenced files exist (-t).
 * @return "<pointer>: <message>" of the first problem, or nullopt when the file is valid.
 */
std::optional<std::string> validate(const std::filesystem::path& home);

/// @return true after a successful load().
bool isLoaded();

/// @return Canonical JSON of one top-level section of the effective document; "" without document or section.
std::string sectionJson(std::string_view section);

/// @return cluster.name and cluster.node_name of the effective document; empty strings without document.
std::pair<std::string, std::string> clusterNames();

/**
 * @brief Register the loaded document as the section provider of libwazuhshared.so (w_mconf_hook_set).
 *
 * os_logging_config() and the cluster getters that live inside the shared library then read the same
 * document as the engine. Requires base::libwazuhshared::init(); the cJSON objects handed to the library
 * are created with its own cJSON_Parse, so it frees them with the matching allocator.
 * @throws std::runtime_error if the symbols cannot be resolved.
 */
void registerSharedHook();

/// Forget the loaded document (tests).
void reset();

} // namespace base::managerConfig

#endif // _BASE_MANAGERCONFIG_HPP
