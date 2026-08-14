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

#include "exclusiveTempFile.hpp"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <random>
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
        // Thread-local RNG: callers spool/compress from several module threads
        // at once; a shared generator would need locking. Seeded once per
        // thread from the OS entropy source, so the next path is unpredictable.
        static thread_local std::mt19937_64 engine {std::random_device {}()};
        char buffer[24];
        std::snprintf(buffer, sizeof(buffer), "%016llx",
                      static_cast<unsigned long long>(engine()));
        return buffer;
    }

    std::string uniquePath(const std::string& dir, const std::string& prefix)
    {
        // pid + thread id + a monotonic counter (shared across every caller of
        // this function, spool or compress alike) + a random token order the
        // name and make it unpredictable, so it cannot be pre-planted to force
        // the exclusive create below to collide.
        static std::atomic<uint64_t> counter {0};
        return dir + "/" + prefix + pidHex() + "_" + threadIdHex() + "_"
               + std::to_string(counter++) + "_" + randomTokenHex() + ".tmp";
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
} // namespace

int createExclusiveTempFile(const std::string& dir, const std::string& prefix, std::string& outPath)
{
    constexpr int maxAttempts = 100;
    const std::string effectiveDir = dir.empty() ? defaultTempDir() : dir;

    for (int attempt = 0; attempt < maxAttempts; attempt++)
    {
        outPath = uniquePath(effectiveDir, prefix);
        const int fd = openExclusive(outPath);

        if (fd >= 0)
        {
            return fd;
        }

        if (errno != EEXIST)
        {
            return -1; // Unwritable/missing dir, etc.: not a collision.
        }
    }

    return -1; // LCOV_EXCL_LINE: exhausting 100 random names is not reproducible.
}

void closeExclusiveTempFile(int fd)
{
#ifdef WIN32
    _close(fd);
#else
    ::close(fd);
#endif
}
