#pragma once

#include "container_context.hpp"

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace wazuh::container_baseline {

/// @brief One user account read from a container's own /etc/passwd.
///
/// The UID/GID here are the file's *content* — the container's logical view —
/// which, unlike stat() metadata, is immune to user-namespace remapping: the
/// bytes of /etc/passwd are the same no matter which side of the userns reads
/// them. Field names mirror sysinfo's UsersProvider::genUserJson().
///
/// NOTE(reuse): sysinfo already parses passwd streams (PasswdWrapperLinux::
/// fgetpwent_r, data_provider/src/extended_sources/wrappers/unix/linux/
/// passwd_wrapper.hpp) but its call site hardcodes "/etc/passwd"
/// (users_linux.cpp). That parser is reusable here with a minimal change — a
/// path parameter on UsersProvider::collectLocalUsers() — kept standalone for
/// the spike so the module stays free of the sysinfo link; flag for
/// consolidation when the schema lands (#37203-4).
struct UserBaselineRow
{
    std::string name;
    int64_t     uid{0};
    int64_t     gid{0};
    std::string description; ///< GECOS field.
    std::string home;
    std::string shell;

    std::string        container_id;
    ContainerContextPtr container; ///< null until ApplyIdentity() stamps it.
};

/// @brief One group read from a container's own /etc/group. Same userns
/// immunity note as UserBaselineRow.
///
/// NOTE(reuse): unlike passwd, sysinfo's GroupsProvider is *not* reusable for
/// containers — it enumerates via NSS (getgrent/getgrgid_r, groups_linux.cpp),
/// which libc always resolves against the host's own databases and cannot be
/// pointed at another rootfs. A stream parser is the only host-side option.
struct GroupBaselineRow
{
    std::string name;
    int64_t     gid{0};
    std::vector<std::string> members;

    std::string        container_id;
    ContainerContextPtr container; ///< null until ApplyIdentity() stamps it.
};

/// @brief Parse one passwd(5) line ("name:passwd:uid:gid:gecos:home:shell").
/// @return false for comments, blank lines, or lines without the 7 fields /
///         a numeric uid+gid — the row is untouched in that case.
[[nodiscard]] bool ParsePasswdLine(std::string_view line, UserBaselineRow& row);

/// @brief Parse one group(5) line ("name:passwd:gid:member1,member2").
[[nodiscard]] bool ParseGroupLine(std::string_view line, GroupBaselineRow& row);

/// @brief Read /proc/<pid>/root/etc/passwd for a live PID inside the target
/// container. A distroless/scratch image simply has no such file — that is an
/// empty result, not an error (spike edge-case decision).
[[nodiscard]] std::vector<UserBaselineRow> ScanContainerUsers(pid_t pid);

/// @brief Read /proc/<pid>/root/etc/group. Same absent-file semantics.
[[nodiscard]] std::vector<GroupBaselineRow> ScanContainerGroups(pid_t pid);

} // namespace wazuh::container_baseline
