#pragma once

#include "cgroup_host_mode.h"
#include "container_record.hpp"
#include "logger.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace wazuh::container_instances
{

    /// Notices when cgroup attribution has stopped working, and says so once.
    ///
    /// Every other failure on this path is loud: a runtime that cannot be
    /// reached throws, an unsupported hierarchy is reported at startup, a
    /// cgroup that vanishes mid-scan is skipped and retried. The failure this
    /// watches for is the only silent one — the runtime answers, the module
    /// reconciles, records are published, and every one of them carries key 0.
    /// Nothing errors, startup still calls the host supported, and container
    /// FIM is simply empty. Nobody reports that; they report "container FIM
    /// does not work" much later, with nothing in the log to go on.
    ///
    /// The known cause is a hybrid host whose runtime does not place containers
    /// in the unified hierarchy (runc below 1.1 with the cgroupfs driver). The
    /// unified line is the one a hybrid host keys on, so every container reads
    /// the same path there, no container id can be extracted from it, and the
    /// resolver returns a scan with no containers in it at all. This class is
    /// deliberately not written against that cause, though: it watches the
    /// SYMPTOM, so any other way of arriving at it is reported too.
    class AttributionHealth
    {
        public:
            /// Test seam. Production passes nothing and probes the real host.
            using CgroupModeProbe = wz_cgroup_mode_t (*)();

            /// Call once per reconcile, with the records about to be published.
            void observe(const std::vector<ContainerRecord>& records,
                         const Logger& logger,
                         CgroupModeProbe probe = &wz_cgroup_mode)
            {
                std::size_t running = 0;
                std::size_t resolved = 0;

                for (const auto& record : records)
                {
                    // A stopped container has no process and therefore no
                    // cgroup, so its zero key is correct and says nothing about
                    // whether attribution works. Counting it would make a host
                    // whose containers are all stopped look broken.
                    if (!isRunning(record.state))
                    {
                        continue;
                    }

                    ++running;

                    if (record.hostKey != 0)
                    {
                        ++resolved;
                    }
                }

                if (running == 0 || resolved != 0)
                {
                    /* Either nothing to attribute, or attribution demonstrably
                     * works. Rearmed rather than merely reset: a host that
                     * recovers and breaks again is worth a second warning, and
                     * the latch below exists to stop repetition, not to make
                     * this a once-per-process message. */
                    m_consecutiveBlind = 0;
                    m_warned = false;
                    return;
                }

                /* Not on the first reconcile. A container the runtime has just
                 * reported running can momentarily have no cgroup the resolver
                 * can see, and warning on that would cry wolf at every startup.
                 * The real fault never clears, so waiting costs nothing: it
                 * delays the message by a few reconciles and no more. */
                if (++m_consecutiveBlind < BLIND_RECONCILES_BEFORE_WARN || m_warned)
                {
                    return;
                }

                m_warned = true;

                /* Probed HERE rather than per reconcile. It is two stat() calls
                 * on a path that otherwise does none, and it is needed only in
                 * the branch that is about to log. */
                const auto mode = probe();

                std::string message = "Container attribution is not working: the runtime reports " +
                                      std::to_string(running) +
                                      " running container(s), and none of them could be matched to a cgroup on this "
                                      "host (cgroup hierarchy: " +
                                      wz_cgroup_mode_name(mode) +
                                      "). Container FIM and container inventory keys stay empty while this lasts.";

                if (mode == WZ_CGROUP_MODE_HYBRID)
                {
                    message +=
                        " On a hybrid host the usual cause is a container runtime that does not place containers in "
                        "the unified cgroup hierarchy (runc below 1.1 with the cgroupfs driver): every container then "
                        "reports the same unified cgroup path and none can be identified. Upgrade runc to 1.1 or "
                        "later, or set the runtime's cgroup driver to systemd.";
                }

                logger(LogLevel::warn, message);
            }

        private:
            /// How many reconciles in a row must find nothing before this logs.
            static constexpr unsigned int BLIND_RECONCILES_BEFORE_WARN = 3;

            unsigned int m_consecutiveBlind {0};

            /// Logged for the current episode. Cleared when attribution works
            /// again, so this is one message per outage rather than one ever.
            bool m_warned {false};
    };

} // namespace wazuh::container_instances
