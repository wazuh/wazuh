/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Agoust 11, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _GLOB_HELPER_H
#define _GLOB_HELPER_H

#include <string>

namespace Utils
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

    static bool patternMatch(const std::string& entryName, const std::string& pattern)
    {
        auto match {true};
        // Match the glob pattern without regex
        auto patternPos {0u};

        for (auto i {0u}; i < entryName.size(); ++i)
        {
            if (patternPos < pattern.size())
            {
                // 'x' matches 'x'
                if (entryName.at(i) == pattern.at(patternPos))
                {
                    ++patternPos;
                }
                // '*' matches any number of characters
                else if (pattern.at(patternPos) == '*')
                {
                    // '*' matches zero characters
                    if (patternPos + 1 < pattern.size() && pattern.at(patternPos + 1) == entryName.at(i))
                    {
                        ++patternPos;
                        --i;
                    }
                    // '*' matches one or more characters
                    else if (patternPos + 1 == pattern.size())
                    {
                        break;
                    }
                }
                // '?' matches any single character
                else if (pattern.at(patternPos) == '?')
                {
                    ++patternPos;
                }
                // No match
                else
                {
                    match = false;
                    break;
                }
            }
            else
            {
                match = false;
                break;
            }
        }

        // if the pattern is not fully matched, check if the remaining characters are '*'
        // and if so, the match is successful.
        while (match && patternPos < pattern.size())
        {
            // '*' matches zero characters
            if (pattern.at(patternPos) == '*')
            {
                ++patternPos;
            }
            // No match
            else
            {
                match = false;
            }
        }

        return match;
    }
#pragma GCC diagnostic pop
} // namespace Utils

#endif // _GLOB_HELPER_H
