#ifndef _STREAMLOG_LOGGER_HPP
#define _STREAMLOG_LOGGER_HPP

#include <chrono>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>

/**
 * @file LogManager.hpp
 * @brief Asynchronous, rotating log management module.
 *
 * @defgroup LogManagerModule Log Manager
 * @brief Handles named, rotating log channels with asynchronous writes.
 *
 * This module provides:
 *   - Registration of named log channels with rotation configuration.
 *   - Retrieval of lightweight writer functors for application code.
 *   - Asynchronous, thread-safe writes into date- and size-rotated files via a dedicated I/O thread.
 *   - Runtime reconfiguration and on-demand rotation.
 *   - Hard-link “latest” pointer to the current log file for each channel.
 *
 * ## Concepts
 *
 * - **Channel Registration**
 *   Clients call `registerLog(name, config)` to declare a log stream,
 *
 * - **RotationConfig**
 *   Defines `basePath`, `tag`, `pattern`, optional `maxSize`, `maxAge`, and `bufferSize`.
 *   E.g.
 *   ```cpp
 *   RotationConfig cfg {
 *     "/var/ossec/logs",         // basePath
 *     "alerts",                  // ${tag} -> {basePath}/${tag}/${tag}.json
 *     "${YYYY}/${MMM}/wazuh-${tag}-${DD}.json",
 *     10*1024*1024,              // rotate after 10 MiB
 *     std::chrono::hours(24),    // or rotate daily
 *     1<<20                      // 1 MiB write buffer
 *   };
 *   ```
 *
 * - **Writer Functor**
 *   `auto writer = logManager.getWriter("alerts");`
 *   `writer(jsonString);` enqueues one line (JSON string + ‘\n’) to the log.
 *
 * - **Asynchronous I/O**
 *   A dedicated thread per channel flushes buffered lines on each write.
 *
 * - **Rotation Mechanics**
 *   When any placeholder in `pattern` changes (date, `counter`, or `maxAge`),
 *   a new file is created and the channel’s hard-link `<basePath>/<tag>.json` is updated
 *   to point at it.
 *
 * - **Runtime API**
 *   - `updateConfig(name, newConfig)` modifies rotation parameters on the fly.
 *   - `rotateNow(name)` forces immediate rotation.
 *
 * - **Error Handling**
 *   - On I/O failure, writes are discarded and an emergency error log is emitted.
 *
 * @see RotationConfig
 * @see LogManager
 * @ingroup LogManagerModule
 */
namespace streamlog
{
/**
 * @brief Configuration structure for the streamlog logger.
 *
 * Contains parameters for log file management, including base path, tag, file naming pattern,
 * optional maximum file size, optional maximum file age, and buffer size.
 */
struct RotationConfig
{
    std::filesystem::path basePath; ///< The base directory path where log files will be stored.
    std::string tag;                ///< A string identifier used to tag log entries or files.
    std::string pattern;            ///< The pattern used for naming log files, which can include placeholders.
    std::optional<size_t> maxSize;  ///< Optional maximum size (in bytes) for a log file before rotation.
    std::optional<std::chrono::seconds> maxAge; ///< Optional maximum age (in seconds) for a log file before rotation.
    size_t bufferSize = 1 << 20;                ///<  The size (in events) of the buffer used for logging operations.
};

class LogManager
{
public:
    void registerLog(std::string_view name, const RotationConfig& cfg);
    void updateConfig(std::string_view name, const RotationConfig& cfg);
    void rotateNow(std::string_view name);
    std::function<void(std::string&&)> getWriter(const std::string& name);
    ~LogManager();
};

} // namespace streamlog

#endif // _STREAMLOG_LOGGER_HPP
