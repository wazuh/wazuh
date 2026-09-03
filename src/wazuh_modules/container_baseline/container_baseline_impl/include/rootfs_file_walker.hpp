#pragma once

#include "container_context.hpp"
#include "hash_helper.hpp"

#include <sys/types.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace wazuh::container_baseline {

/// @brief One file (or symlink) baseline row produced by a rootfs walk.
///
/// Field names/types deliberately mirror `fim_file_data` (src/config/include/
/// syscheck-config.h) so this struct maps 1:1 onto the shape FIM already syncs
/// for host files — the only genuinely new fields are the container-context
/// ones, which mirror the container fields already present on `whodata_evt`.
struct FileBaselineRow : ContainerScoped
{
    std::string path;          ///< Logical in-container path (e.g. "/etc/passwd").
    std::string permissions;   ///< Octal mode string, e.g. "0644".
    std::string uid;           ///< Translated into the CONTAINER's id space (see IdMap).
    std::string gid;           ///< Translated into the CONTAINER's id space (see IdMap).
    std::string owner;         ///< Resolved from the container's own /etc/passwd when available.
    std::string group;         ///< Resolved from the container's own /etc/group when available.
    int64_t     mtime{0};
    uint64_t    size{0};
    uint64_t    inode{0};
    uint64_t    device{0};
    bool        is_symlink{false};
    std::string hash_md5;      ///< Empty for symlinks, unreadable files, and files over the size cap.
    std::string hash_sha1;
    std::string hash_sha256;
};

/// @brief Outcome of a walk, including what NFR3-style truncation happened.
struct WalkResult
{
    std::vector<FileBaselineRow> rows;
    bool                         truncated{false};  ///< true if max_files was hit.
    bool                         root_missing{false}; ///< true if internal_path doesn't exist in the container.
};

/// @brief Recursively walk `internal_path` inside a container's rootfs, via the
/// kernel's own namespace translation (/proc/<pid>/root/<internal_path>), and
/// produce a FileBaselineRow per regular file / symlink found.
///
/// No overlay math, no per-runtime path resolution: the kernel resolves the
/// mount-namespace view for us, which is why this needs a live PID rather than
/// the container id alone (see pid_resolver.hpp).
///
/// Correctness handling:
///   - Non-regular / non-directory / non-symlink special files (sockets, fifos,
///     device nodes) are skipped — they are not meaningful FIM baseline targets
///     and can't be safely hashed.
///   - Symlinks are recorded as metadata-only rows (no hash, not followed) —
///     matches most FIM implementations' treatment of symlinks.
///   - `..`-escaping is impossible by construction: this walks by recursing
///     into directory entries returned by readdir(), never by resolving a
///     caller-supplied path containing "..".
///   - **Mount boundaries are enforced.** Because /proc/<pid>/root exposes the
///     container's whole mount namespace, an unguarded walk follows bind mounts
///     wherever they lead — a pod with `hostPath: /` mounted at /host would
///     otherwise have the entire HOST filesystem walked and hashed, and
///     attributed to that container. Crossing onto a different device is
///     allowed only into a destination the container's own OCI mount list
///     declares, and never into a mount whose source is the host root.
///   - **Ownership is reported in the container's id space**, translated through
///     /proc/<pid>/{uid,gid}_map, so it agrees with the ids the user/group
///     scanners read from the container's /etc/passwd. Owner/group NAMES are
///     resolved from the container's own account files when present.
///
/// @param pid Live PID inside the container (from PidIndex::pidsFor()).
/// @param internal_path Absolute in-container path to start the walk at (e.g. "/etc").
/// @param recursion_level Depth limit: 0 = only entries directly in internal_path,
///                         N = N levels of subdirectories, negative = unlimited
///                         (mirrors syscheck directories' recursion_level convention).
/// @param max_files Hard cap on rows returned before the walk stops early and
///                   reports `truncated = true`. 0 = unlimited (use with care).
/// @param max_hash_bytes Files LARGER than this are not hashed at all and their
///                        hash fields are left empty — the same policy host FIM
///                        applies via syscheck.file_max_size. A partial digest
///                        is never produced. 0 = no limit.
/// @param context The container's runtime context, used for the OCI-mount
///                 allowlist that governs mount-boundary crossing. May be null,
///                 in which case no device-boundary crossing is permitted.
/// @param hashes Which digests to compute for each hashed file.
/// @param rate_limit Invoked once per file BEFORE it is hashed, so the caller
///                    can throttle. FIM supplies check_max_fps(), whose token
///                    bucket is process-global — so a container walk shares one
///                    files-per-second budget with the host walk instead of
///                    competing with it. May block. Empty = no throttling.
WalkResult WalkContainerPath(pid_t              pid,
                              const std::string& internal_path,
                              int                recursion_level,
                              size_t             max_files,
                              size_t             max_hash_bytes,
                              const ContainerContextPtr&   context = nullptr,
                              const HashSelection&         hashes = {},
                              const std::function<void()>& rate_limit = {});

/// @brief True if `st_mode`/`st_rdev` identify an overlayfs whiteout marker
/// (a character device with major=minor=0).
///
/// NOTE: unreachable under the /proc/<pid>/root addressing this module uses —
/// the kernel presents the already-merged overlay view, in which whiteouts do
/// not appear. Retained only because a lower/upper-layer reader (the M1
/// fallback for containers with no live PID) would need it.
///
/// Exposed for unit testing.
bool IsOverlayWhiteout(mode_t mode, dev_t rdev);

/// @brief True when `logical_path` is the mount destination itself or sits
/// below it.
///
/// This is the predicate that decides whether the walk may follow a mount, so
/// it must not treat "/variable" as being inside "/var". Exposed for unit
/// testing.
bool IsPathWithinMount(const std::string& logical_path, const std::string& mount_destination);

} // namespace wazuh::container_baseline
