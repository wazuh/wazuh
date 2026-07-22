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

#include <cstdio>
#include <fstream>
#include <thread>

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
    const std::string path = uniquePath();
    std::ofstream file {path, std::ios::binary | std::ios::trunc};

    if (!file)
    {
        return nullptr;
    }

    if (length > 0)
    {
        file.write(reinterpret_cast<const char*>(buffer), static_cast<std::streamsize>(length));
    }

    file.close();

    if (!file)
    {
        std::remove(path.c_str()); // LCOV_EXCL_LINE: write failure is not reproducible in tests.
        return nullptr;            // LCOV_EXCL_LINE
    }

    return std::make_unique<SpoolFile>(path);
}

std::string TempSpoolFactory::uniquePath()
{
    // Unique without mkstemp: thread id + a per-factory counter. Collisions
    // would only matter across factories in one dir, which does not occur.
    return m_spoolDir + "/hc_sync_" + threadIdHex() + "_" + std::to_string(m_counter++) + ".tmp";
}
