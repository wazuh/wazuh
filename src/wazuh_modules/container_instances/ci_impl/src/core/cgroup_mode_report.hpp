#pragma once

#include "logger.hpp"

#include "cgroup_host_mode.h"

#include <string>

namespace wazuh::container_instances
{

    /// What the module says about the host's cgroup hierarchy at startup.
    ///
    /// Split out from the facade so the one thing that matters here can be
    /// asserted without a cgroup v1 host to run on: that a legacy host is
    /// reported at ERROR, with text that names the consequence. On a v1 host
    /// this module is the component that fails, and until this existed it was
    /// the only one that failed SILENTLY — the eBPF drain at least logs a
    /// diagnosis (#37203 O4).
    struct CgroupModeReport
    {
        LogLevel level;
        std::string message;
    };

    [[nodiscard]] inline CgroupModeReport describeCgroupHostMode(wz_cgroup_mode_t mode)
    {
        const std::string prefix = std::string {"Host cgroup hierarchy: "} + wz_cgroup_mode_name(mode);

        if (wz_cgroup_mode_has_usable_cgroup_id(mode))
        {
            return {LogLevel::info, prefix + "; container attribution is supported"};
        }

        // ERROR rather than warn: on this host the module cannot do the job it
        // was enabled to do, and it will not recover by itself.
        //
        // The sentence about exited containers is not padding. Since the
        // stopped-container work, `listContainers()` hides only records that
        // are unresolved AND running — so a v1 host, where every record is
        // unresolved, publishes exactly the containers that are not running.
        // An operator who checks whether the list is empty finds it is not,
        // and concludes this works. It does not.
        return {LogLevel::error,
                prefix + ". Container discovery resolves cgroup v2 paths only, so no RUNNING container will be "
                         "reported: inventory stays empty and container file integrity monitoring is disabled. "
                         "Exited containers may still be listed, which is not a sign that this is working. "
                         "Container security requires a cgroup v2 (unified) host."};
    }

} // namespace wazuh::container_instances
