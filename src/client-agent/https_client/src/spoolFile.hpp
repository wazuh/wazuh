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

#ifndef _HC_SPOOL_FILE_HPP
#define _HC_SPOOL_FILE_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

/// A spooled session body on disk. Deletes the file on destruction (RAII), so
/// the temp file never outlives the request even on failure/abort paths.
class SpoolFile
{
    public:
        explicit SpoolFile(std::string path);
        ~SpoolFile();

        SpoolFile(const SpoolFile&) = delete;
        SpoolFile& operator=(const SpoolFile&) = delete;
        SpoolFile(SpoolFile&& other) noexcept;
        SpoolFile& operator=(SpoolFile&& other) noexcept;

        const std::string& path() const
        {
            return m_path;
        }

    private:
        void removeFile();
        std::string m_path;
};

/// Creates spool files from a byte buffer. Injected so tests can force spool
/// failures without touching the filesystem.
class ISpoolFileFactory
{
    public:
        virtual ~ISpoolFileFactory() = default;
        virtual std::unique_ptr<SpoolFile> spool(const uint8_t* buffer, size_t length) = 0;
};

/// Writes the buffer to a uniquely-named temp file under the configured spool
/// directory (portable across POSIX and Windows; no mkstemp dependency).
class TempSpoolFactory final : public ISpoolFileFactory
{
    public:
        explicit TempSpoolFactory(std::string spoolDir);
        std::unique_ptr<SpoolFile> spool(const uint8_t* buffer, size_t length) override;

    private:
        std::string uniquePath();

        std::string m_spoolDir;

        /// Atomic: spools happen from the stateful thread AND the control
        /// thread (config downloads), concurrently.
        std::atomic<uint64_t> m_counter {0};
};

#endif // _HC_SPOOL_FILE_HPP
