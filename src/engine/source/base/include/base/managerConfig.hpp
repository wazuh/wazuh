#ifndef _BASE_MANAGERCONFIG_HPP
#define _BASE_MANAGERCONFIG_HPP

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

/**
 * @brief Manager configuration (/etc/wazuh-manager/wazuh-manager.conf, strict XML) as seen by the engine in manager
 * mode.
 *
 * Thin process-wide wrapper over shared_modules/manager_config: the effective document (schema
 * defaults applied) is loaded once in main() before any thread starts and only read afterwards.
 * In standalone mode nothing is loaded and every getter answers "no document".
 */
namespace base::managerConfig
{

/**
 * @brief The manager's configuration directory. Fixed and absolute: a custom installation home moves the home
 * only, never the configuration.
 *
 * Defined once per language and kept identical in all of them: here, WAZUH_MANAGER_CONF_DIR in
 * src/shared/include/defs.h, Utils::MANAGER_CONF_DIR in src/shared_modules/utils/managerConfDir.hpp,
 * framework/wazuh/core/common.py (CONF_PATH) and src/init/shared.sh (CONF_DIR). The engine keeps its own
 * copy because it includes neither the C headers nor shared_modules/utils.
 */
constexpr std::string_view MANAGER_CONF_DIR = "/etc/wazuh-manager";

/// Configuration file name, inside MANAGER_CONF_DIR.
constexpr std::string_view FILE_NAME = "wazuh-manager.conf";

/// @return MANAGER_CONF_DIR/FILE_NAME, the file load() and validate() read by default.
std::filesystem::path filePath();

/**
 * @brief Load @p file without checking the files it references (start-up).
 * @param home Manager home: relative paths inside the document resolve against it.
 * @param file Configuration file (default: filePath()); tests pass their own.
 * @throws std::runtime_error "<pointer>: <message>" when the file is missing or invalid.
 */
void load(const std::filesystem::path& home, const std::filesystem::path& file = filePath());

/**
 * @brief Validate @p file, also checking that the referenced files exist (-t).
 * @param home Manager home: relative paths inside the document resolve against it.
 * @param file Configuration file (default: filePath()); tests pass their own.
 * @return "<pointer>: <message>" of the first problem, or nullopt when the file is valid.
 */
std::optional<std::string> validate(const std::filesystem::path& home, const std::filesystem::path& file = filePath());

/// @return true after a successful load().
bool isLoaded();

/// @return Canonical JSON of one top-level section of the effective document; "" without document or section.
std::string sectionJson(std::string_view section);

/// @return cluster.name and cluster.node_name of the effective document; empty strings without document.
std::pair<std::string, std::string> clusterNames();

/// Formats of the manager log (logging.log_format).
struct LogFormat
{
    bool plain; ///< Write logs/wazuh-manager.log
    bool json;  ///< Write logs/wazuh-manager.json
};

/**
 * @brief logging.log_format of the effective document: an array of strings where only "plain" and "json" count.
 * @return The formats found; {plain} when none is valid or there is no document or section.
 */
LogFormat logFormat();

/// Forget the loaded document (tests).
void reset();

} // namespace base::managerConfig

#endif // _BASE_MANAGERCONFIG_HPP
