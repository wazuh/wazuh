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

#include "exclusiveTempFile.hpp"

#include <cstdio>

#ifdef WIN32
#include <io.h>
#else
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
    std::string path;
    const int fd = createExclusiveTempFile(m_spoolDir, "hc_sync_", path);

    if (fd < 0)
    {
        return nullptr;
    }

    const bool ok = length == 0 || writeAll(fd, buffer, length);
    closeExclusiveTempFile(fd);

    if (!ok)
    {
        std::remove(path.c_str()); // LCOV_EXCL_LINE: write failure is not reproducible in tests.
        return nullptr;            // LCOV_EXCL_LINE
    }

    return std::make_unique<SpoolFile>(path);
}
