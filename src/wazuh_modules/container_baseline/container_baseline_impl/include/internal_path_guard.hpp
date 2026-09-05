#pragma once

#include <string>

namespace wazuh::container_baseline {

/// @brief Is this in-container path safe to resolve under /proc/<pid>/root?
///
/// Every walk entry point until now took its paths from agent CONFIGURATION,
/// and `rootfs_file_walker.hpp` states the resulting invariant outright:
///
///   "`..`-escaping is impossible by construction: this walks by recursing into
///    directory entries returned by readdir(), never by resolving a
///    caller-supplied path containing `..`."
///
/// The per-container re-read entry point breaks that. It resolves a path the
/// caller supplies, and in the eBPF consumer (#37532) that path arrives in a
/// kernel event emitted by a process running INSIDE the container — so it is
/// chosen by whatever the container is running. A container that creates and
/// touches `/etc/../../../../root/.ssh/id_rsa` would otherwise have the agent
/// resolve that under `/proc/<pid>/root/`, hash whatever it lands on, and store
/// the result as one of that container's files.
///
/// The walker's mount-boundary guard is a second line of defence, but it is
/// aimed at a different threat (a declared mount leading somewhere large or
/// host-owned) and must not be the only one.
///
/// REJECTS rather than normalises, deliberately. Rewriting `/etc/../x` into `/x`
/// would silently accept an escape attempt and quietly scan something else; the
/// caller then has no way to know it happened. A rejection is reported as a
/// partial scan, which suppresses delete detection and leaves a visible signal.
///
/// Accepts only a lexically absolute, already-canonical path:
///   - non-empty, begins with '/';
///   - no `.` or `..` component;
///   - no empty component, so no `//` and no trailing '/' (except the path "/"
///     itself). This is not pedantry: `file_entry` is keyed by path, so
///     admitting both "/etc/passwd" and "/etc/passwd/" would store the same file
///     twice under two keys that never converge;
///   - no embedded NUL, which would truncate at the syscall boundary and make
///     the path that was checked different from the path that gets opened;
///   - at most `kMaxInternalPathLength` bytes.
[[nodiscard]] bool IsSafeInternalPath(const std::string& path);

/// Matches RT_PATH_MAX in the eBPF event contract, which is where these paths
/// come from; anything longer cannot have originated in a real event.
inline constexpr std::size_t kMaxInternalPathLength = 4096;

} // namespace wazuh::container_baseline
