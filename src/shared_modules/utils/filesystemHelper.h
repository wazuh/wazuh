/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 23, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FILESYSTEM_HELPER_H
#define _FILESYSTEM_HELPER_H

#include <string>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <memory>
#include <sstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <vector>
#include <dirent.h>
#include <filesystem>
#include <algorithm>
#include "stringHelper.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    static void expandAbsolutePath(const std::string& path, std::vector<std::string>& output)
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

                    if (patternMatch(entryName, pattern))
                    {
                        std::string nextPath;
                        nextPath += baseDir;
                        nextPath += std::filesystem::path::preferred_separator;
                        nextPath += entryName;
                        nextPath += nextDirectoryPos == std::string::npos ? "" :
                                    path.substr(nextDirectoryPos);

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

    static bool existsDir(const std::string& path)
    {
        struct stat info {};
        return !stat(path.c_str(), &info) && (info.st_mode & S_IFDIR);
    }
    static bool existsRegular(const std::string& path)
    {
        struct stat info {};
        return !stat(path.c_str(), &info) && (info.st_mode & S_IFREG);
    }
#ifndef WIN32
    static bool existsSocket(const std::string& path)
    {
        struct stat info {};
        return !stat(path.c_str(), &info) && ((info.st_mode & S_IFMT) == S_IFSOCK);
    }
#endif
    struct DirSmartDeleter
    {
        void operator()(DIR* dir)
        {
            closedir(dir);
        }
    };

    static std::vector<std::string> enumerateDir(const std::string& path)
    {
        std::vector<std::string> ret;
        std::unique_ptr<DIR, DirSmartDeleter> spDir{opendir(path.c_str())};

        if (spDir)
        {
            auto entry{readdir(spDir.get())};

            while (entry)
            {
                ret.push_back(entry->d_name);
                entry = readdir(spDir.get());
            }
        }

        return ret;
    }

    static std::string getFileContent(const std::string& filePath)
    {
        std::stringstream content;
        std::ifstream file { filePath, std::ios_base::in };

        if (file.is_open())
        {
            content << file.rdbuf();
        }

        return content.str();
    }

    static std::vector<char> getBinaryContent(const std::string& filePath)
    {
        auto size { 0 };
        std::unique_ptr<char[]> spBuffer;
        std::ifstream file { filePath, std::ios_base::binary };

        if (file.is_open())
        {
            // Get pointer to associated buffer object
            auto buffer { file.rdbuf() };

            if (nullptr != buffer)
            {
                // Get file size using buffer's members
                size = buffer->pubseekoff(0, file.end, file.in);
                buffer->pubseekpos(0, file.in);
                // Allocate memory to contain file data
                spBuffer = std::make_unique<char[]>(size);
                // Get file data
                buffer->sgetn(spBuffer.get(), size);
            }
        }

        return std::vector<char> {spBuffer.get(), spBuffer.get() + size};
    }
}

#pragma GCC diagnostic pop

#endif // _FILESYSTEM_HELPER_H
