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

#ifndef _TASK_MANAGER_UPGRADE_VERSIONS_FILE_HPP
#define _TASK_MANAGER_UPGRADE_VERSIONS_FILE_HPP

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace task_manager::upgrade
{
    /**
     * @brief One line of a repository `versions` file.
     */
    struct VersionEntry
    {
        std::string version;
        std::string sha1;
    };

    /**
     * @brief Parse a repository `versions` file.
     *
     * The format is one "<version> <sha1>" per line. A line is kept only if it actually has that
     * SHAPE -- a version starting with 'v' or a digit, and an all-hex digest -- so a repository
     * serving an HTML error page yields no entries rather than nonsense ones. A trailing '\r' is
     * stripped, which the retired C parser did NOT do: it carried the carriage return into the sha1
     * and then failed every integrity check against a CRLF-served file, naming the wrong cause.
     *
     * The retired parser rewrote the buffer in place, punching NUL bytes over the delimiters it
     * found with strchr, and had to repeat the whole match block after the loop to handle a file
     * with no trailing newline. Splitting on views makes the final line ordinary.
     */
    std::vector<VersionEntry> parseVersionsFile(std::string_view body);

    /**
     * @brief Find the sha1 for a version.
     *
     * Matching is a VERSION comparison, not string equality: a repository that lists "4.14.0"
     * answers a request for "v4.14.0", and vice versa. Patch numbers are compared, so 4.14.0 does
     * not match 4.14.1.
     */
    std::optional<std::string> findSha1(const std::vector<VersionEntry>& entries, std::string_view wpkVersion);
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_VERSIONS_FILE_HPP
