#pragma once

#include "container_context.hpp"

#include <sys/types.h>

#include <string>
#include <string_view>
#include <vector>

namespace wazuh::container_baseline {

/// @brief The container image's operating-system identity, read from the
/// container's own os-release(5) file.
///
/// The host row for wazuh-states-inventory-system describes the node; this row
/// describes the *image* distro (debian:12 on an Ubuntu host, etc.), which is
/// what vulnerability detection needs to correlate the container's package rows
/// against the right feed. `kernel` is the host's — containers share it — and
/// is stamped from uname(2) so the row is self-contained for OS+kernel matching.
struct OsBaselineRow
{
    std::string name;      ///< NAME= ("Debian GNU/Linux").
    std::string full;      ///< PRETTY_NAME= ("Debian GNU/Linux 12 (bookworm)").
    std::string version;   ///< VERSION_ID= ("12").
    std::string codename;  ///< VERSION_CODENAME= ("bookworm").
    std::string platform;  ///< ID= ("debian").
    std::string family;    ///< ID_LIKE= first token ("debian" on ubuntu).
    std::string kernel;    ///< Host kernel release (shared with the container).

    std::string        container_id;
    ContainerContextPtr container; ///< null until ApplyIdentity() stamps it.
};

/// @brief Parse one os-release(5) "KEY=value" line. Values may be bare or
/// single/double quoted; double-quoted values un-escape \" \\ \$ \`.
/// Exposed for unit testing.
/// @return false for comments, blank lines, or lines without KEY=.
[[nodiscard]] bool ParseOsReleaseLine(std::string_view line, std::string& key, std::string& value);

/// @brief Read /proc/<pid>/root/etc/os-release (falling back to
/// /usr/lib/os-release, the documented precedence) for a live PID inside the
/// target container. A scratch image has neither file — empty result, not an
/// error, same semantics as the other rootfs scanners.
/// @return 0 or 1 rows.
[[nodiscard]] std::vector<OsBaselineRow> ScanContainerOs(pid_t pid);

} // namespace wazuh::container_baseline
