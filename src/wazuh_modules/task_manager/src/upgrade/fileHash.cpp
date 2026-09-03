/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fileHash.hpp"

#include "hashHelper.h"

#include <sys/stat.h>

#include <array>
#include <cctype>
#include <cstdio>

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
        std::FILE* file {std::fopen(path.c_str(), "rb")};
        if (file == nullptr)
        {
            return std::nullopt;
        }

        std::string digest;

        try
        {
            Utils::HashData hash {Utils::HashType::Sha1};
            std::array<unsigned char, BLOCK_SIZE> block {};

            for (;;)
            {
                const auto read {std::fread(block.data(), 1, block.size(), file)};
                if (read > 0)
                {
                    hash.update(block.data(), read);
                }

                if (read < block.size())
                {
                    // Short read: end of file, or an I/O error that must not be reported as a
                    // successful digest of a truncated file.
                    if (std::ferror(file) != 0)
                    {
                        std::fclose(file);
                        return std::nullopt;
                    }
                    break;
                }
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
            std::fclose(file);
            return std::nullopt;
        }

        std::fclose(file);
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
