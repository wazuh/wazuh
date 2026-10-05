#pragma once

#include "os_scanner.hpp"
#include "package_scanner.hpp"
#include "user_scanner.hpp"

#include <sys/types.h>

#include <cstdint>
#include <memory>
#include <mutex>

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
        ///
        /// Returns a SHARED pointer rather than a raw one, and that is not
        /// decoration: entries are now evicted, and a caller iterating rows it
        /// had borrowed would be reading freed memory. Holding a reference
        /// keeps that entry alive for exactly as long as it is in use, however
        /// many digests arrive meanwhile.
        ///
        /// @return nullptr on a miss, a stale fingerprint, or an empty digest.
        [[nodiscard]] std::shared_ptr<const Entry> find(const std::string& image_digest,
                                                        const std::string& fingerprint) const;

        /// @brief Store rows for `image_digest`. A no-op for an empty digest,
        /// so a container whose metadata never resolved is always scanned.
        void store(const std::string& image_digest, Entry entry);

        [[nodiscard]] std::size_t hits() const noexcept;
        [[nodiscard]] std::size_t misses() const noexcept;
        [[nodiscard]] std::size_t size() const noexcept;

        /// @brief How many distinct image digests are retained.
        ///
        /// Bounded because this now outlives a single scan: a node that pulls a
        /// new image tag every deploy would otherwise accumulate an entry per
        /// digest for the life of the process, and each holds every user, group
        /// and package row of an image.
        ///
        /// Eviction is least-recently-used, so the images actually running stay
        /// resident and the ones that have been replaced age out. A wrong
        /// eviction costs one re-parse, never a wrong answer.
        static constexpr std::size_t MAX_DIGESTS = 32;

    private:
        struct Slot
        {
            std::shared_ptr<const Entry> entry;
            /// Monotonic stamp of the last find() or store(). A counter rather
            /// than a clock: it only has to order accesses, and a clock would
            /// make the eviction order depend on how fast scans happen to run.
            std::uint64_t used{0};
        };

        void evictIfNeededLocked();

        /// Guards everything below. The cache is shared across whatever calls
        /// into the scanner now that it outlives one invocation, so it can no
        /// longer assume the single-threaded lifetime it was written for.
        mutable std::mutex                     m_mutex;
        /// Mutable because a READ is what makes an entry recently used, so
        /// find() has to record it. The observable state — which rows a digest
        /// maps to — is unchanged by a lookup; only the eviction order moves.
        mutable std::unordered_map<std::string, Slot> m_byDigest;
        mutable std::uint64_t                  m_clock{0};
        mutable std::size_t                    m_hits{0};
        mutable std::size_t                    m_misses{0};
};

/// @brief The process-wide cache.
///
/// It has to outlive a single scan to be worth having at all. A delta-driven
/// pass may scan ONE container, and the whole point of caching by image digest
/// is that twenty replicas of an image parse its package database once — a
/// cache that dies with each invocation gives that back exactly when the
/// delta makes scans smaller and more frequent.
[[nodiscard]] ImageContentCache& SharedImageContentCache();

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
