/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 23, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _STD_FILESYSTEM_HELPER_HPP
#define _STD_FILESYSTEM_HELPER_HPP

#include "globHelper.h"
#include <array>
#include <deque>
#include <filesystem>
#include <string>

namespace Utils
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

    static void expandAbsolutePath(const std::string& path, std::deque<std::string>& output)
    {
        // Find the first * or ? from path.
        std::array<char, 2> wildcards {'*', '?'};
        size_t wildcardPos = std::string::npos;

        for (const auto& wildcard : wildcards)
        {
            // Find the first wildcard.
            const auto pos = path.find_first_of(wildcard);

            // If the wildcard is found and it is before the current wildcard, then update the wildcard position.
            if (pos != std::string::npos && (wildcardPos == std::string::npos || pos < wildcardPos))
            {
                wildcardPos = pos;
            }
        }

        if (wildcardPos != std::string::npos)
        {
            const auto parentDirectoryPos {path.find_last_of(std::filesystem::path::preferred_separator, wildcardPos)};

            // The parent directory is the part of the path before the first wildcard.
            // If the wildcard is the first character, then the parent directory is the root directory.
            const auto nextDirectoryPos {
                wildcardPos == 0 ? 0 : path.find_first_of(std::filesystem::path::preferred_separator, wildcardPos)};

            if (parentDirectoryPos == std::string::npos)
            {
                throw std::runtime_error {"Invalid path: " + path};
            }

            // The base directory is the part of the path before the first wildcard.
            // If there is no wildcard, then the base directory is the whole path.
            // If the wildcard is the first character, then the base directory is the root directory.
            std::string baseDir;

            if (wildcardPos == 0)
            {
                baseDir = "";
            }
            else
            {
                baseDir = path.substr(0, parentDirectoryPos);
            }

            // The pattern is the part of the path after the first wildcard.
            // If the wildcard is the last character, then the pattern is the rest of the string.
            // If the wildcard is the first character, then the pattern is the rest of the string, minus the next '\'.
            // If there is no next '\', then the pattern is the rest of the string.
            const auto pattern {
                path.substr(parentDirectoryPos == 0 ? 0 : parentDirectoryPos + 1,
                            nextDirectoryPos == std::string::npos
                                ? std::string::npos
                                : nextDirectoryPos - (parentDirectoryPos == 0 ? 0 : parentDirectoryPos + 1))};

            if (std::filesystem::exists(baseDir))
            {
                for (const auto& entry : std::filesystem::directory_iterator(baseDir))
                {
                    const auto entryName {entry.path().filename().string()};

                    if (patternMatch(entryName, pattern))
                    {
                        std::string nextPath;
                        nextPath += baseDir;
                        nextPath += std::filesystem::path::preferred_separator;
                        nextPath += entryName;
                        nextPath += nextDirectoryPos == std::string::npos ? "" : path.substr(nextDirectoryPos);

                        expandAbsolutePath(nextPath, output);
                    }
                }
            }
        }
        else
        {
            output.push_back(path);
        }
    }
#pragma GCC diagnostic pop
}; // namespace Utils

#endif // _STD_FILESYSTEM_HELPER_HPP
