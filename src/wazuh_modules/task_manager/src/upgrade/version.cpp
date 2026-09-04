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

#include "version.hpp"

#include <cctype>

namespace
{
    /**
     * @brief Read one decimal component and advance past it and any single trailing '.'.
     *
     * Stops at the first non-digit, so "0-rc1" reads as 0 and leaves the cursor on '-', which then
     * fails the '.' check and ends the walk. Overflow saturates rather than wrapping: a version
     * component long enough to overflow is nonsense either way, and saturating keeps the ordering
     * monotonic instead of flipping its sign.
     */
    int readComponent(std::string_view& cursor)
    {
        long long value {0};
        std::size_t digits {0};

        while (digits < cursor.size() && std::isdigit(static_cast<unsigned char>(cursor[digits])) != 0)
        {
            if (value < 1000000000LL)
            {
                value = value * 10 + (cursor[digits] - '0');
            }
            ++digits;
        }

        cursor.remove_prefix(digits);
        if (!cursor.empty() && cursor.front() == '.')
        {
            cursor.remove_prefix(1);
        }
        else
        {
            cursor = {};
        }

        return static_cast<int>(value);
    }
} // namespace

namespace task_manager::upgrade
{
    SemVersion parseVersion(std::string_view version)
    {
        // The first 'v' ANYWHERE, not a leading-'v' check -- see the header for why.
        const auto marker {version.find('v')};
        std::string_view cursor {marker == std::string_view::npos ? version : version.substr(marker + 1)};

        SemVersion parsed;
        parsed.major = readComponent(cursor);
        parsed.minor = readComponent(cursor);
        parsed.patch = readComponent(cursor);
        return parsed;
    }

    int compareVersions(const std::string_view version1, const std::string_view version2, const bool comparePatch)
    {
        const auto left {parseVersion(version1)};
        const auto right {parseVersion(version2)};

        if (left.major != right.major)
        {
            return left.major > right.major ? 1 : -1;
        }

        if (left.minor != right.minor)
        {
            return left.minor > right.minor ? 1 : -1;
        }

        if (comparePatch && left.patch != right.patch)
        {
            return left.patch > right.patch ? 1 : -1;
        }

        return 0;
    }
} // namespace task_manager::upgrade
