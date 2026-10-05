#include "image_content_cache.hpp"

#include <sys/stat.h>

#include <string>

namespace wazuh::container_baseline {

namespace {

// Every file the cached data classes are read from. Keep in sync with
// user_scanner.cpp, os_scanner.cpp and package_scanner.cpp — a path that is
// read but not fingerprinted would let a modified file serve a stale cache hit.
constexpr const char* kFingerprintedPaths[] = {
    "/etc/passwd",
    "/etc/group",
    "/etc/os-release",
    "/usr/lib/os-release",
    "/var/lib/dpkg/status",
    "/lib/apk/db/installed",
    "/var/lib/rpm/rpmdb.sqlite",
    "/usr/lib/sysimage/rpm/rpmdb.sqlite",
    "/var/lib/rpm/Packages",
    "/usr/lib/sysimage/rpm/Packages",
};

// The distroless dpkg layout is a DIRECTORY of per-package files. Its own mtime
// changes when packages are added or removed, which is the case that matters
// here; a rewrite of one file's contents without touching the directory is not
// detected, so this path is fingerprinted on a best-effort basis and noted as
// such.
constexpr const char* kDpkgStatusDDir = "/var/lib/dpkg/status.d";

void AppendStat(std::string& out, const std::string& path)
{
    struct stat st {};

    if (::lstat(path.c_str(), &st) != 0)
    {
        out += "-;"; // absent, and distinct from any present state
        return;
    }

    out += std::to_string(static_cast<uint64_t>(st.st_size));
    out += ':';
    out += std::to_string(static_cast<int64_t>(st.st_mtime));
    out += ':';
    out += std::to_string(static_cast<uint64_t>(st.st_ino));
    out += ';';
}

} // namespace

std::string FingerprintImageSources(pid_t pid)
{
    const std::string rootfs = "/proc/" + std::to_string(pid) + "/root";

    std::string fingerprint;
    fingerprint.reserve(sizeof(kFingerprintedPaths) / sizeof(kFingerprintedPaths[0]) * 32);

    for (const auto* path : kFingerprintedPaths)
    {
        AppendStat(fingerprint, rootfs + path);
    }

    AppendStat(fingerprint, rootfs + kDpkgStatusDDir);

    return fingerprint;
}

std::shared_ptr<const ImageContentCache::Entry> ImageContentCache::find(const std::string& image_digest,
                                                                        const std::string& fingerprint) const
{
    if (image_digest.empty())
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++m_misses;
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    const auto it = m_byDigest.find(image_digest);

    if (it == m_byDigest.end() || !it->second.entry || it->second.entry->fingerprint != fingerprint)
    {
        ++m_misses;
        return nullptr;
    }

    // A hit is a use: it is what keeps a running image resident while images
    // that have been replaced age out.
    it->second.used = ++m_clock;
    ++m_hits;
    return it->second.entry;
}

void ImageContentCache::store(const std::string& image_digest, Entry entry)
{
    if (image_digest.empty())
    {
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    auto& slot = m_byDigest[image_digest];
    slot.entry = std::make_shared<const Entry>(std::move(entry));
    slot.used = ++m_clock;

    evictIfNeededLocked();
}

void ImageContentCache::evictIfNeededLocked()
{
    // One at a time: store() is the only growth path, so the map can exceed the
    // bound by at most one entry per call and a loop would never run twice.
    if (m_byDigest.size() <= MAX_DIGESTS)
    {
        return;
    }

    auto oldest = m_byDigest.begin();

    for (auto it = m_byDigest.begin(); it != m_byDigest.end(); ++it)
    {
        if (it->second.used < oldest->second.used)
        {
            oldest = it;
        }
    }

    // Erasing drops this map's reference only. A scan still iterating those
    // rows holds its own and finishes against a consistent snapshot.
    m_byDigest.erase(oldest);
}

std::size_t ImageContentCache::hits() const noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_hits;
}

std::size_t ImageContentCache::misses() const noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_misses;
}

std::size_t ImageContentCache::size() const noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_byDigest.size();
}

ImageContentCache& SharedImageContentCache()
{
    // Function-local static: constructed on first use, which keeps it out of
    // static-initialisation order entirely, and never destroyed, which is what
    // a cache consulted from a scan thread during shutdown needs.
    static ImageContentCache instance;
    return instance;
}

} // namespace wazuh::container_baseline
