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

const ImageContentCache::Entry* ImageContentCache::find(const std::string& image_digest,
                                                        const std::string& fingerprint) const
{
    if (image_digest.empty())
    {
        ++m_misses;
        return nullptr;
    }

    const auto it = m_byDigest.find(image_digest);

    if (it == m_byDigest.end() || it->second.fingerprint != fingerprint)
    {
        ++m_misses;
        return nullptr;
    }

    ++m_hits;
    return &it->second;
}

void ImageContentCache::store(const std::string& image_digest, Entry entry)
{
    if (image_digest.empty())
    {
        return;
    }

    m_byDigest[image_digest] = std::move(entry);
}

} // namespace wazuh::container_baseline
