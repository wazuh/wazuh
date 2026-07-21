#pragma once

#include "container_context.hpp"

#include <sys/types.h>

#include <string>
#include <vector>

namespace wazuh::container_baseline {

/// @brief A systemd service defined inside the container image, mirroring the
/// host wazuh-states-inventory-services row.
///
/// The host reader queries live systemd over D-Bus, so it also has the running
/// active_state. A container is usually single-process with no systemd running,
/// so this is a static read of the unit files on the rootfs: name, description,
/// ExecStart binary, and enablement (from *.wants symlinks). `state` (running vs
/// stopped) is left "unknown" — it needs the container's own systemd D-Bus,
/// which only systemd-init images expose.
struct ServiceBaselineRow
{
    std::string name;        ///< Unit name without the ".service" suffix.
    std::string description; ///< [Unit] Description=.
    std::string state;       ///< "unknown" — live active_state needs the container's systemd over D-Bus.
    std::string enabled;     ///< "enabled" (symlinked under a *.wants dir) / "disabled".
    std::string type;        ///< "systemd".
    std::string executable;  ///< [Service] ExecStart= binary (argv[0], exec prefixes stripped).
    std::string file_path;   ///< Unit file path as seen inside the container.

    std::string        container_id;
    ContainerContextPtr container; ///< null until ApplyIdentity() stamps it.
};

/// @brief Pull Description= and the ExecStart= binary (argv[0], with systemd's
/// -@+!: exec prefixes stripped) out of a unit file's text. First occurrence of
/// each wins. Exposed for unit testing.
void ParseUnitFile(const std::string& contents, std::string& description, std::string& executable);

/// @brief Enumerate .service units from the container rootfs
/// (/proc/<pid>/root/{etc,usr/lib,lib}/systemd/system). Static view: enablement
/// comes from *.wants symlinks, runtime state is "unknown". A single-process
/// image with no systemd tree yields an empty result, not an error.
[[nodiscard]] std::vector<ServiceBaselineRow> ScanContainerServices(pid_t pid);

} // namespace wazuh::container_baseline
