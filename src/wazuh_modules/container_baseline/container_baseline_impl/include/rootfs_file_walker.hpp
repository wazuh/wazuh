#pragma once

#include "container_context.hpp"

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wazuh::container_baseline {

/// @brief One file (or symlink) baseline row produced by a rootfs walk.
///
/// Field names/types deliberately mirror `fim_file_data` (src/config/include/
/// syscheck-config.h) so this struct maps 1:1 onto the shape FIM already syncs
/// for host files — the only genuinely new fields are the container-context
/// ones, which mirror the container fields already present on `whodata_evt`.
struct FileBaselineRow
{
    std::string path;          ///< Logical in-container path (e.g. "/etc/passwd").
    std::string permissions;   ///< Octal mode string, e.g. "0644".
    std::string uid;
    std::string gid;
    std::string owner;         ///< Left empty: resolving to a name needs the container's
    std::string group;         ///< own /etc/passwd, which is a separate data class (Angle 3).
    int64_t     mtime{0};
    uint64_t    size{0};
    uint64_t    inode{0};
    uint64_t    device{0};
    bool        is_symlink{false};
    std::string hash_md5;      ///< Empty for symlinks/unreadable files.
    std::string hash_sha1;
    std::string hash_sha256;

    // Container context, resolved once per container and shared across rows.
    std::string        container_id;
    ContainerContextPtr container; ///< null until ApplyIdentity() stamps it.
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
///   - Overlay whiteouts (character device, rdev major/minor 0/0) are skipped.
///   - Non-regular / non-directory / non-symlink special files (sockets, fifos,
///     other device nodes) are skipped — they are not meaningful FIM baseline
///     targets and can't be safely hashed.
///   - Symlinks are recorded as metadata-only rows (no hash, not followed) —
///     matches most FIM implementations' treatment of symlinks.
///   - `..`-escaping is impossible by construction: this walks by recursing
///     into directory entries returned by readdir(), never by resolving a
///     caller-supplied path containing "..".
///
/// @param pid Live PID inside the container (from ResolvePidsForContainer()).
/// @param internal_path Absolute in-container path to start the walk at (e.g. "/etc").
/// @param recursion_level Depth limit: 0 = only entries directly in internal_path,
///                         N = N levels of subdirectories, negative = unlimited
///                         (mirrors syscheck directories' recursion_level convention).
/// @param max_files Hard cap on rows returned before the walk stops early and
///                   reports `truncated = true`. 0 = unlimited (use with care).
/// @param max_hash_bytes Passed through to HashFile(): stop hashing a single
///                        file after this many bytes. 0 = unlimited.
WalkResult WalkContainerPath(pid_t              pid,
                              const std::string& internal_path,
                              int                recursion_level,
                              size_t             max_files,
                              size_t             max_hash_bytes);

/// @brief True if `st_mode`/`st_rdev` identify an overlayfs whiteout marker
/// (a character device with major=minor=0), which must never be hashed or
/// reported as if it were real container content.
///
/// Exposed for unit testing.
bool IsOverlayWhiteout(mode_t mode, dev_t rdev);

} // namespace wazuh::container_baseline
