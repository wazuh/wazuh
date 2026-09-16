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
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>

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

        // O_CLOEXEC: remoted forks helpers, and a descriptor on the CA file has no business in them.
        const FileDescriptor file {::open(path.c_str(), O_RDONLY | O_CLOEXEC)};
        if (file.get() < 0)
        {
            return {ReadStatus::CannotOpen, errno};
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
            case ReadStatus::CannotOpen: return std::string {"cannot be opened ("} + std::strerror(failure.error) + ")";
            case ReadStatus::ReadError: return std::string {"cannot be read ("} + std::strerror(failure.error) + ")";
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
