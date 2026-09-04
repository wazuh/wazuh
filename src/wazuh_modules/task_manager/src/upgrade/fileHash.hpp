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

#ifndef _TASK_MANAGER_UPGRADE_FILE_HASH_HPP
#define _TASK_MANAGER_UPGRADE_FILE_HASH_HPP

#include <cstdint>
#include <optional>
#include <string>

namespace task_manager::upgrade
{
    /**
     * @brief Identity of a file on disk, cheap enough to check on every request.
     */
    struct FileStamp
    {
        std::uint64_t size {0};
        std::int64_t modifiedAt {0};

        bool operator==(const FileStamp& other) const
        {
            return size == other.size && modifiedAt == other.modifiedAt;
        }
    };

    /**
     * @brief stat() a file. Returns nullopt when it does not exist or is not a regular file.
     */
    std::optional<FileStamp> stampOf(const std::string& path);

    /**
     * @brief SHA-1 of a file's contents, as 40 lowercase hex characters.
     *
     * Streamed in fixed-size blocks, never loaded whole: a WPK is 50-100 MB and this runs on a pool
     * worker while other requests are in flight.
     *
     * Replaces OS_SHA1_File(), which lives in libwazuh. Comparison against a repository digest stays
     * CASE-INSENSITIVE, matching the retired strcasecmp -- published `versions` files have used both
     * cases over the years.
     */
    std::optional<std::string> sha1OfFile(const std::string& path);

    /// @brief Case-insensitive digest comparison.
    bool sha1Equals(const std::string& left, const std::string& right);
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_FILE_HASH_HPP
