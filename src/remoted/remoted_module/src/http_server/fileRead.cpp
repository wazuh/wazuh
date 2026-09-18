/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 16, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fileRead.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <system_error>

namespace remoted::http
{
    namespace
    {
        /// Owns the descriptor for the duration of one read.
        class FileDescriptor final
        {
        public:
            explicit FileDescriptor(int fd) noexcept
                : m_fd {fd}
            {
            }
            ~FileDescriptor()
            {
                if (m_fd >= 0)
                {
                    ::close(m_fd);
                }
            }
            FileDescriptor(const FileDescriptor&) = delete;
            FileDescriptor& operator=(const FileDescriptor&) = delete;

            int get() const noexcept
            {
                return m_fd;
            }

        private:
            int m_fd;
        };
    } // namespace

    ReadResult readFileBounded(const std::string& path, std::size_t maxBytes, std::string& contents)
    {
        contents.clear();

        if (maxBytes == SIZE_MAX)
        {
            return {ReadStatus::ReadError, EINVAL}; // maxBytes + 1 would wrap; no caller means that
        }

        // O_CLOEXEC: remoted forks helpers, and a descriptor on the CA file has no business in them.
        // O_NONBLOCK: this runs under the source's mutex, so a FIFO with no writer or a terminal at
        // the configured path must fail here instead of parking every caller forever.
        const FileDescriptor file {::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK)};
        if (file.get() < 0)
        {
            return {ReadStatus::CannotOpen, errno};
        }

        // Only a regular file is a CA bundle. A directory opens fine and fails at read(2) with
        // EISDIR; anything else that is not a regular file (a FIFO, a device) would read as empty
        // or block, which is not a verdict about the operator's CA.
        struct stat attributes {};
        if (::fstat(file.get(), &attributes) != 0)
        {
            return {ReadStatus::ReadError, errno};
        }
        if (S_ISDIR(attributes.st_mode))
        {
            return {ReadStatus::ReadError, EISDIR};
        }
        if (!S_ISREG(attributes.st_mode))
        {
            return {ReadStatus::ReadError, ENOTSUP};
        }

        // One byte past the cap is the whole trick: if it ever arrives the file is too large, and
        // nothing beyond it is ever requested -- so the memory this costs is the file's real size
        // up to the cap, never whatever size the file happens to be. Small chunks, because the
        // common case is a few KB and a per-request megabyte buffer would be its own regression.
        static constexpr std::size_t kChunk {16U * 1024U};
        const std::size_t limit = maxBytes + 1;
        std::array<char, kChunk> chunk {};
        std::size_t total = 0;

        while (total < limit)
        {
            const std::size_t wanted = std::min(kChunk, limit - total);
            const ssize_t got = ::read(file.get(), chunk.data(), wanted);
            if (got < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                contents.clear();
                return {ReadStatus::ReadError, errno};
            }
            if (got == 0)
            {
                break; // EOF: the whole file fit under the cap.
            }
            contents.append(chunk.data(), static_cast<std::size_t>(got));
            total += static_cast<std::size_t>(got);
        }

        if (total > maxBytes)
        {
            contents.clear();
            return {ReadStatus::TooLarge, 0};
        }

        return {};
    }

    std::string describeReadFailure(const ReadFailure& failure, std::size_t maxBytes)
    {
        switch (failure.status)
        {
            // generic_category().message() is thread-safe on every libstdc++ we build with, unlike
            // strerror() on older glibc; the text is the same.
            case ReadStatus::CannotOpen:
                return "cannot be opened (" + std::generic_category().message(failure.error) + ")";
            case ReadStatus::ReadError:
                return "cannot be read (" + std::generic_category().message(failure.error) + ")";
            case ReadStatus::TooLarge:
            {
                static constexpr std::size_t kMiB {1024U * 1024U};
                return maxBytes % kMiB == 0 ? "is larger than the " + std::to_string(maxBytes / kMiB) + " MiB cap"
                                            : "is larger than the " + std::to_string(maxBytes) + "-byte cap";
            }
            case ReadStatus::Ok: break;
        }
        return "could be read";
    }
} // namespace remoted::http
