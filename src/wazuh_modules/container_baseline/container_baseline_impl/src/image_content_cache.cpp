#include "image_content_cache.hpp"

#include "image_source_files.hpp"

#include <dirent.h>
#include <sys/stat.h>

#include <algorithm>
#include <string>
#include <vector>

namespace wazuh::container_baseline {

namespace {

// Bounds a source directory that is not what it claims to be; a distroless
// status.d holds tens of files.
constexpr std::size_t kMaxDirectoryEntries = 4096;

// Nanoseconds: an in-place write keeps size and inode, and a trigger re-scans
// in the same second as the write.
void AppendSizeAndMtime(std::string& out, const struct stat& st)
{
    out += std::to_string(static_cast<uint64_t>(st.st_size));
    out += ':';
    out += std::to_string(static_cast<int64_t>(st.st_mtim.tv_sec));
    out += '.';
    out += std::to_string(static_cast<int64_t>(st.st_mtim.tv_nsec));
}

// stat(), not lstat(): the scanners read through links.
void AppendStat(std::string& out, const std::string& path)
{
    struct stat st {};

    if (::stat(path.c_str(), &st) != 0)
    {
        out += "-;"; // absent, and distinct from any present state
        return;
    }

    AppendSizeAndMtime(out, st);
    out += ':';
    out += std::to_string(static_cast<uint64_t>(st.st_ino));
    out += ';';
}

// The directory itself, then every entry in name order, so a rewritten file
// is a change even when the directory is not.
void AppendDirectory(std::string& out, const std::string& path)
{
    AppendStat(out, path);

    DIR* dir = ::opendir(path.c_str());

    if (dir == nullptr)
    {
        return;
    }

    std::vector<std::string> names;

    while (const dirent* entry = ::readdir(dir))
    {
        const std::string name = entry->d_name;

        if (name == "." || name == "..")
        {
            continue;
        }
        if (names.size() == kMaxDirectoryEntries)
        {
            break;
        }
        names.push_back(name);
    }
    ::closedir(dir);

    std::sort(names.begin(), names.end());

    for (const auto& name : names)
    {
        out += name;
        out += '=';
        AppendStat(out, path + "/" + name);
    }
}

// An empty WAL holds nothing the database lacks, and readers create it, or
// copy it up, separately in each container. So missing and empty read the
// same, and a non-empty one contributes no inode: replicas of one image must
// keep agreeing on their fingerprint.
void AppendWal(std::string& out, const std::string& path)
{
    struct stat st {};

    if (::stat(path.c_str(), &st) != 0 || st.st_size == 0)
    {
        out += "-;";
        return;
    }

    AppendSizeAndMtime(out, st);
    out += ';';
}

} // namespace

std::string FingerprintImageSourcesAt(const std::string& rootfs)
{
    std::size_t count = 0;
    const ImageSourceFile* files = ImageSourceFiles(count);

    std::string fingerprint;
    fingerprint.reserve(count * 48);

    for (std::size_t i = 0; i < count; ++i)
    {
        switch (files[i].kind)
        {
            case ImageSourceKind::directory:
                AppendDirectory(fingerprint, rootfs + files[i].path);
                break;

            case ImageSourceKind::wal:
                AppendWal(fingerprint, rootfs + files[i].path);
                break;

            case ImageSourceKind::file:
            default:
                AppendStat(fingerprint, rootfs + files[i].path);
                break;
        }
    }

    return fingerprint;
}

std::string FingerprintImageSources(pid_t pid)
{
    return FingerprintImageSourcesAt("/proc/" + std::to_string(pid) + "/root");
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
