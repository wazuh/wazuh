#pragma once

#include "os_scanner.hpp"
#include "package_scanner.hpp"
#include "user_scanner.hpp"

#include <sys/types.h>

#include <string>
#include <unordered_map>
#include <vector>

namespace wazuh::container_baseline {

/// @brief Cache of the data classes that come from IMMUTABLE IMAGE CONTENT,
/// keyed by image digest and validated by a source-file fingerprint.
///
/// Packages, users, groups and the OS record are read from files that belong to
/// the image's layers, not to the running instance. A Deployment with 20
/// replicas of one image therefore had the same package database parsed 20
/// times per scan — and for RPM that also means copying the whole rpmdb to a
/// temp directory 20 times, since sqlite cannot open it through the
/// /proc/<pid>/root magic symlink. On a node running 100 containers from ~15
/// distinct images this collapses that work by roughly 85%.
///
/// Why a fingerprint and not the digest alone: a container CAN write to these
/// files in its own writable layer, so two containers of the same image are not
/// guaranteed to agree. Reusing rows on a digest match alone would silently
/// report one container's accounts or packages for another. The fingerprint is
/// a stat() of the backing files (size, mtime, inode), so a container that
/// modified any of them misses the cache and is scanned for real — at a cost of
/// a handful of stat() calls instead of a full parse.
///
/// Services are deliberately NOT cached: they are backed by a directory tree
/// whose contents can change without the directory mtime changing, so no cheap
/// fingerprint is sound.
class ImageContentCache
{
    public:
        struct Entry
        {
            std::string                     fingerprint;
            std::vector<UserBaselineRow>    users;
            std::vector<GroupBaselineRow>   groups;
            std::vector<PackageBaselineRow> packages;
            std::vector<OsBaselineRow>      os;
        };

        /// @brief Cached rows for `image_digest`, but only when `fingerprint`
        /// still matches what was cached.
        /// @return nullptr on a miss, a stale fingerprint, or an empty digest.
        [[nodiscard]] const Entry* find(const std::string& image_digest,
                                        const std::string& fingerprint) const;

        /// @brief Store rows for `image_digest`. A no-op for an empty digest,
        /// so a container whose metadata never resolved is always scanned.
        void store(const std::string& image_digest, Entry entry);

        [[nodiscard]] std::size_t hits() const noexcept { return m_hits; }
        [[nodiscard]] std::size_t misses() const noexcept { return m_misses; }

    private:
        std::unordered_map<std::string, Entry> m_byDigest;
        mutable std::size_t                    m_hits{0};
        mutable std::size_t                    m_misses{0};
};

/// @brief Fingerprint the files the cached data classes are read from, inside
/// the container's rootfs.
///
/// Covers /etc/passwd, /etc/group, the os-release candidates and every package
/// database location the scanner probes. A file that is absent contributes a
/// distinct marker, so "the image gained a package DB" is a fingerprint change
/// rather than a silent cache hit.
///
/// Exposed for unit testing.
[[nodiscard]] std::string FingerprintImageSources(pid_t pid);

} // namespace wazuh::container_baseline
