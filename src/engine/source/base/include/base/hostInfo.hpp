#ifndef BASE_HOST_INFO_HPP
#define BASE_HOST_INFO_HPP

#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <netdb.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <unordered_map>

#include "json.hpp"
#include "utils/stringUtils.hpp"

namespace base::hostInfo
{

/// JSON pointer for agent id.
constexpr char EVENT_AGENT_ID[] {"/agent/id"};
/// JSON pointer for agent (host) name.
constexpr char EVENT_AGENT_NAME[] {"/agent/name"};

/// JSON pointer for OS name (e.g., "Ubuntu").
constexpr char EVENT_HOST_OS_NAME[] {"/host/os/name"};
/// JSON pointer for OS version (e.g., "20.04.6 LTS").
constexpr char EVENT_HOST_OS_VERSION[] {"/host/os/version"};
/// JSON pointer for OS codename / full name (e.g., "Focal Fossa").
constexpr char EVENT_HOST_OS_FULL[] {"/host/os/full"};
/// JSON pointer for OS platform ID (e.g., "ubuntu").
constexpr char EVENT_HOST_OS_PLATFORM[] {"/host/os/platform"};
/// JSON pointer for kernel descriptor (e.g., "Linux |worker |5.4.0-...|x86_64").
constexpr char EVENT_HOST_OS_KERNEL[] {"/host/os/kernel"};

/// JSON pointer for machine architecture (e.g., "x86_64").
constexpr char EVENT_HOST_ARCHITECTURE[] {"/host/architecture"};
/// JSON pointer for host IPv4 addresses array.
constexpr char EVENT_HOST_IP[] {"/host/ip"};

/**
 * @brief Collects host information and returns it as a JSON document.
 *
 * The resulting JSON follows this shape (fields present when available):
 *
 * @code{.json}
 * {
 *   "agent": {
 *     "id":   "000",
 *     "name": "worker"
 *   },
 *   "host": {
 *     "os": {
 *       "name":     "Ubuntu",
 *       "version":  "22.04.4 LTS",
 *       "full":     "Jammy Jellyfish",
 *       "platform": "ubuntu",
 *       "kernel":   "Linux |worker |5.15.0-113-generic|x86_64"
 *     },
 *     "architecture": "x86_64",
 *     "ip": ["192.168.1.10", "10.0.0.5"]
 *   }
 * }
 * @endcode
 *
 * Notes:
 * - `host.ip` is an array of IPv4 strings (may be empty if no addresses are found).
 * - `host.os.kernel` is a formatted descriptor including OS, hostname, kernel release and arch.
 * - Missing data is simply omitted (no nulls), depending on system call availability.
 *
 * @return json::Json with the fields above set when available.
 * @throws std::runtime_error on unexpected system call failures (e.g., gethostname()).
 */
json::Json toJson();

} // namespace base::hostInfo

#endif // BASE_HOST_INFO_HPP
