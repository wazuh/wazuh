/*
 * Wazuh task manager module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fileHash.hpp"

#include "hashHelper.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cctype>
#include <cerrno>

namespace
{
    /// @brief Read block. Big enough that a 100 MB WPK is ~1500 reads, small enough to stay off the
    ///        worker's stack in any meaningful way.
    constexpr std::size_t BLOCK_SIZE {65536};

    constexpr char HEX_DIGITS[] {"0123456789abcdef"};
} // namespace

namespace task_manager::upgrade
{
    std::optional<FileStamp> stampOf(const std::string& path)
    {
        struct stat info {};

        if (::stat(path.c_str(), &info) != 0 || !S_ISREG(info.st_mode))
        {
            return std::nullopt;
        }

        return FileStamp {static_cast<std::uint64_t>(info.st_size), static_cast<std::int64_t>(info.st_mtime)};
    }

    std::optional<std::string> sha1OfFile(const std::string& path)
    {
        const int fd {::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC)};
        if (fd < 0)
        {
            return std::nullopt;
        }

        auto digest {sha1OfFd(fd)};
        ::close(fd);
        return digest;
    }

    std::optional<std::string> sha1OfFd(const int fd)
    {
        std::string digest;

        try
        {
            Utils::HashData hash {Utils::HashType::Sha1};
            std::array<unsigned char, BLOCK_SIZE> block {};

            for (;;)
            {
                const auto got {::read(fd, block.data(), block.size())};
                if (got == 0)
                {
                    break;
                }
                if (got < 0)
                {
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    // Never report a digest of a truncated read.
                    return std::nullopt;
                }
                hash.update(block.data(), static_cast<std::size_t>(got));
            }

            const auto bytes {hash.hash()};
            digest.reserve(bytes.size() * 2);
            for (const auto byte : bytes)
            {
                digest.push_back(HEX_DIGITS[byte >> 4]);
                digest.push_back(HEX_DIGITS[byte & 0x0F]);
            }
        }
        catch (...)
        {
            return std::nullopt;
        }

        return digest;
    }

    bool sha1Equals(const std::string& left, const std::string& right)
    {
        if (left.size() != right.size())
        {
            return false;
        }

        for (std::size_t index = 0; index < left.size(); ++index)
        {
            if (std::tolower(static_cast<unsigned char>(left[index])) !=
                std::tolower(static_cast<unsigned char>(right[index])))
            {
                return false;
            }
        }

        return true;
    }
} // namespace task_manager::upgrade
