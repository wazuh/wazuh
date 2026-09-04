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

#include "versionsFile.hpp"

#include "version.hpp"

#include <cctype>

namespace
{
    /**
     * @brief Whether a line's two fields actually look like a version and a digest.
     *
     * The retired parser accepted any line containing a space, which meant a repository serving an
     * HTML error page produced entries like {"<html>404", "not found</html>"}. Harmless on its own --
     * nothing matches them -- but it turns "the repository is unreachable" into "that version does
     * not exist in the repository", pointing the operator at the wrong problem, and here it would
     * also be cached under that wrong answer for the whole TTL.
     *
     * A digest is hex and a version starts with 'v' or a digit. Both are true of every line any
     * Wazuh repository has ever published, and neither is true of prose.
     */
    bool looksLikeEntry(const std::string_view version, const std::string_view sha1)
    {
        if (version.empty() || sha1.empty())
        {
            return false;
        }

        if (version.front() != 'v' && std::isdigit(static_cast<unsigned char>(version.front())) == 0)
        {
            return false;
        }

        for (const char character : sha1)
        {
            if (std::isxdigit(static_cast<unsigned char>(character)) == 0)
            {
                return false;
            }
        }

        return true;
    }
} // namespace

namespace task_manager::upgrade
{
    std::vector<VersionEntry> parseVersionsFile(const std::string_view body)
    {
        std::vector<VersionEntry> entries;
        std::string_view cursor {body};

        while (!cursor.empty())
        {
            const auto newline {cursor.find('\n')};
            std::string_view line {cursor.substr(0, newline)};
            cursor = newline == std::string_view::npos ? std::string_view {} : cursor.substr(newline + 1);

            if (!line.empty() && line.back() == '\r')
            {
                line.remove_suffix(1);
            }

            const auto space {line.find(' ')};
            if (space == std::string_view::npos)
            {
                continue;
            }

            const std::string_view version {line.substr(0, space)};
            const std::string_view sha1 {line.substr(space + 1)};

            if (!looksLikeEntry(version, sha1))
            {
                continue;
            }

            entries.push_back({std::string {version}, std::string {sha1}});
        }

        return entries;
    }

    std::optional<std::string> findSha1(const std::vector<VersionEntry>& entries, const std::string_view wpkVersion)
    {
        for (const auto& entry : entries)
        {
            if (compareVersions(wpkVersion, entry.version, true) == 0)
            {
                return entry.sha1;
            }
        }

        return std::nullopt;
    }
} // namespace task_manager::upgrade
