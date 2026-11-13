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
#include <functional>
#include <string>

namespace Utils
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

    /// @brief Expands the wildcards of an absolute path into the existing paths that match it.
    ///
    /// @param path Absolute path, may contain '*' and '?' in any component.
    /// @param output Matching paths are appended here.
    /// @param skipEntry Entries matched by the first wildcard of the path for which it returns true
    /// are neither matched nor descended into. Deeper levels are not asked about: in a pattern such
    /// as /home/*/... the first wildcard is the level that lists the home directories.
    static void expandAbsolutePath(const std::string& path,
                                   std::deque<std::string>& output,
                                   const std::function<bool(const std::string&)>& skipEntry)
    {
        // Find the first * or ? from path.
        std::array<char, 2> wildcards { '*', '?' };
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
            const auto parentDirectoryPos { path.find_last_of(std::filesystem::path::preferred_separator, wildcardPos) };

            // The parent directory is the part of the path before the first wildcard.
            // If the wildcard is the first character, then the parent directory is the root directory.
            const auto nextDirectoryPos { wildcardPos == 0 ? 0 : path.find_first_of(std::filesystem::path::preferred_separator, wildcardPos) };

            if (parentDirectoryPos == std::string::npos)
            {
                throw std::runtime_error { "Invalid path: " + path };
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
            const auto pattern
            {
                path.substr(parentDirectoryPos == 0 ? 0 : parentDirectoryPos + 1,
                            nextDirectoryPos == std::string::npos ?
                            std::string::npos :
                            nextDirectoryPos - (parentDirectoryPos == 0 ? 0 : parentDirectoryPos + 1))
            };

            if (std::filesystem::exists(baseDir))
            {
                for (const auto& entry : std::filesystem::directory_iterator(baseDir))
                {
                    const auto entryName { entry.path().filename().string()};

                    if (patternMatch(entryName, pattern) && !(skipEntry && skipEntry(entry.path().string())))
                    {
                        std::string nextPath;
                        nextPath += baseDir;
                        nextPath += std::filesystem::path::preferred_separator;
                        nextPath += entryName;
                        nextPath += nextDirectoryPos == std::string::npos ? "" :
                                    path.substr(nextDirectoryPos);

                        expandAbsolutePath(nextPath, output, nullptr);
                    }
                }
            }
        }
        else
        {
            output.push_back(path);
        }
    }

    /// @brief Expands the wildcards of an absolute path into the existing paths that match it.
    ///
    /// @param path Absolute path, may contain '*' and '?' in any component.
    /// @param output Matching paths are appended here.
    static void expandAbsolutePath(const std::string& path, std::deque<std::string>& output)
    {
        expandAbsolutePath(path, output, nullptr);
    }
#pragma GCC diagnostic pop
};


#endif // _STD_FILESYSTEM_HELPER_HPP
