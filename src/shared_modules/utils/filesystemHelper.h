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

#include "stringHelper.h"
#include <algorithm>
#include <array>
#include <cstdio>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    static bool existsDir(const std::string& path)
    {
        struct stat info
        {
        };
        return !stat(path.c_str(), &info) && (info.st_mode & S_IFDIR);
    }
    static bool existsRegular(const std::string& path)
    {
        struct stat info
        {
        };
        return !stat(path.c_str(), &info) && (info.st_mode & S_IFREG);
    }
#ifndef WIN32
    static bool existsSocket(const std::string& path)
    {
        struct stat info
        {
        };
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
        std::unique_ptr<DIR, DirSmartDeleter> spDir {opendir(path.c_str())};

        if (spDir)
        {
            auto entry {readdir(spDir.get())};

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
        std::ifstream file {filePath, std::ios_base::in};

        if (file.is_open())
        {
            content << file.rdbuf();
        }

        return content.str();
    }

    static std::vector<char> getBinaryContent(const std::string& filePath)
    {
        auto size {0};
        std::unique_ptr<char[]> spBuffer;
        std::ifstream file {filePath, std::ios_base::binary};

        if (file.is_open())
        {
            // Get pointer to associated buffer object
            auto buffer {file.rdbuf()};

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
} // namespace Utils

#pragma GCC diagnostic pop

#endif // _FILESYSTEM_HELPER_H
