/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "spoolFile.hpp"

#include <cerrno>
#include <cstdio>
#include <random>
#include <string>
#include <thread>

#ifdef WIN32
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <share.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace
{
    std::string defaultTempDir()
    {
#ifdef WIN32
        const char* candidates[] = {std::getenv("TEMP"), std::getenv("TMP")};
#else
        const char* candidates[] = {std::getenv("TMPDIR"), "/tmp"};
#endif

        for (const char* candidate : candidates)
        {
            if (candidate != nullptr && candidate[0] != '\0')
            {
                return candidate;
            }
        }

        return "."; // LCOV_EXCL_LINE: at least one candidate is always set in practice.
    }

    std::string threadIdHex()
    {
        const auto id = std::hash<std::thread::id> {}(std::this_thread::get_id());
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "%zx", id);
        return buffer;
    }

    std::string pidHex()
    {
#ifdef WIN32
        const auto pid = static_cast<unsigned long>(_getpid());
#else
        const auto pid = static_cast<unsigned long>(::getpid());
#endif
        char buffer[24];
        std::snprintf(buffer, sizeof(buffer), "%lx", pid);
        return buffer;
    }

    std::string randomTokenHex()
    {
        // Thread-local RNG: spool() runs from several module threads at once; a
        // shared generator would need locking. Seeded once per thread from the
        // OS entropy source, so the next spool path is unpredictable.
        static thread_local std::mt19937_64 engine {std::random_device {}()};
        char buffer[24];
        std::snprintf(buffer, sizeof(buffer), "%016llx",
                      static_cast<unsigned long long>(engine()));
        return buffer;
    }

    // Atomic, exclusive create (O_EXCL) with owner-only permissions. Returns a
    // file descriptor, or -1 with errno set (EEXIST when the path already
    // exists). Never follows an existing symlink -- the create simply fails.
    int openExclusive(const std::string& path)
    {
#ifdef WIN32
        int fd = -1;
        _sopen_s(&fd, path.c_str(), _O_CREAT | _O_EXCL | _O_WRONLY | _O_BINARY, _SH_DENYRW,
                 _S_IREAD | _S_IWRITE);
        return fd;
#else
        return ::open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, S_IRUSR | S_IWUSR);
#endif
    }

    bool writeAll(int fd, const uint8_t* buffer, size_t length)
    {
        size_t written = 0;

        while (written < length)
        {
#ifdef WIN32
            const int chunk = _write(fd, buffer + written, static_cast<unsigned int>(length - written));
#else
            const ssize_t chunk = ::write(fd, buffer + written, length - written);
#endif

            if (chunk <= 0)
            {
                return false;
            }

            written += static_cast<size_t>(chunk);
        }

        return true;
    }

    void closeFd(int fd)
    {
#ifdef WIN32
        _close(fd);
#else
        ::close(fd);
#endif
    }
} // namespace

SpoolFile::SpoolFile(std::string path)
    : m_path(std::move(path))
{
}

SpoolFile::~SpoolFile()
{
    removeFile();
}

SpoolFile::SpoolFile(SpoolFile&& other) noexcept
    : m_path(std::move(other.m_path))
{
    other.m_path.clear();
}

SpoolFile& SpoolFile::operator=(SpoolFile&& other) noexcept
{
    if (this != &other)
    {
        removeFile();
        m_path = std::move(other.m_path);
        other.m_path.clear();
    }

    return *this;
}

void SpoolFile::removeFile()
{
    if (!m_path.empty())
    {
        std::remove(m_path.c_str());
    }
}

TempSpoolFactory::TempSpoolFactory(std::string spoolDir)
    : m_spoolDir(spoolDir.empty() ? defaultTempDir() : std::move(spoolDir))
{
}

std::unique_ptr<SpoolFile> TempSpoolFactory::spool(const uint8_t* buffer, size_t length)
{
    // Create the file atomically and exclusively with owner-only permissions.
    // A pre-existing path -- e.g. a symlink an attacker planted in a shared
    // spool dir (/tmp) -- fails the create (EEXIST) instead of being followed
    // and truncated, so it can neither hijack a victim file nor read back the
    // session bytes. The retry loop handles the (essentially impossible)
    // random-name collision; any other error means the dir is unusable.
    constexpr int maxAttempts = 100;
    std::string path;
    int fd = -1;

    for (int attempt = 0; attempt < maxAttempts; attempt++)
    {
        path = uniquePath();
        fd = openExclusive(path);

        if (fd >= 0)
        {
            break;
        }

        if (errno != EEXIST)
        {
            return nullptr; // Unwritable/missing dir, etc.: not a collision.
        }
    }

    if (fd < 0)
    {
        return nullptr; // LCOV_EXCL_LINE: exhausting 100 random names is not reproducible.
    }

    const bool ok = length == 0 || writeAll(fd, buffer, length);
    closeFd(fd);

    if (!ok)
    {
        std::remove(path.c_str()); // LCOV_EXCL_LINE: write failure is not reproducible in tests.
        return nullptr;            // LCOV_EXCL_LINE
    }

    return std::make_unique<SpoolFile>(path);
}

std::string TempSpoolFactory::uniquePath()
{
    // pid + thread id + per-factory counter order the name; a random token
    // makes the next path unpredictable (so it cannot be pre-planted to force
    // the exclusive create to fail). Including the pid keeps the name honestly
    // unique across agent restarts, not merely within one process.
    return m_spoolDir + "/hc_sync_" + pidHex() + "_" + threadIdHex() + "_"
           + std::to_string(m_counter++) + "_" + randomTokenHex() + ".tmp";
}
