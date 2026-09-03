#pragma once

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wazuh::container_baseline {

/// @brief A user-namespace id translation table, as read from
/// /proc/<pid>/uid_map or /proc/<pid>/gid_map.
///
/// Why this is needed: the file walker stats the container's files from the
/// HOST, so st_uid/st_gid come back in the host's id space. Under a
/// userns-remapped container those are the remapped values (root inside the
/// container is commonly uid 100000 outside it), while the container's own
/// /etc/passwd — which the user/group scanners read — is in the CONTAINER's id
/// space. Reporting both untranslated puts two different id spaces in the same
/// baseline with nothing to reconcile them: `file.uid = 100000` and
/// `user.id = 0` describing the same principal.
///
/// Each /proc map line is "<inside> <outside> <length>", so translation is a
/// range lookup. A container without a userns has the identity map
/// ("0 0 4294967295") and translation is a no-op.
class IdMap
{
    public:
        /// @brief An identity map — translation is a no-op. Also the result when
        /// the map file cannot be read, so a failure degrades to today's
        /// behaviour rather than to wrong ids.
        IdMap() = default;

        /// @brief Read /proc/<pid>/<map_file> ("uid_map" or "gid_map").
        static IdMap FromProc(pid_t pid, const char* map_file);

        /// @brief Translate a host-side id into the container's id space.
        /// Returns the input unchanged when no range covers it (which is what
        /// the kernel itself reports as overflowuid/nobody).
        [[nodiscard]] uint32_t toContainer(uint32_t host_id) const;

        /// @brief True when this is the identity mapping, i.e. the container is
        /// not userns-remapped and no translation is needed.
        [[nodiscard]] bool isIdentity() const noexcept { return m_ranges.empty(); }

        /// @brief Parse map-file contents. Exposed for unit testing.
        static IdMap Parse(const std::string& contents);

    private:
        struct Range
        {
            uint32_t inside{0};  ///< First id inside the namespace.
            uint32_t outside{0}; ///< Corresponding first id outside it (host side).
            uint32_t length{0};
        };

        /// Empty means "identity map": either genuinely absent, or the single
        /// full-range identity line, which needs no lookup.
        std::vector<Range> m_ranges;
};

} // namespace wazuh::container_baseline
