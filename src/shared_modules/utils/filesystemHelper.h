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
#include <algorithm>
#include <array>
#include <cstring>
#include <libgen.h>
#include "stringHelper.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

#ifndef PATH_MAX
    #define PATH_MAX 4096
#endif

namespace Utils
{
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

    static std::string resolvePath(const std::string& baseFile, const std::string& relativePath)
    {
        char baseCopy[PATH_MAX];
        strncpy(baseCopy, baseFile.c_str(), sizeof(baseCopy));
        baseCopy[sizeof(baseCopy) - 1] = '\0';

        std::string dir(dirname(baseCopy));

        if (!dir.empty() && dir.back() != '/')
        {
            dir += '/';
        }

        return dir + relativePath;
    }

    static std::string getFilename(const std::string& path)
    {
        const auto pos = path.find_last_of("/\\");
        if (pos == std::string::npos)
        {
            return path;
        }
        return path.substr(pos + 1);
    }

    static std::string getFileExtension(const std::string& path)
    {
        const std::string fileName = getFilename(path);
        return "." + split(fileName, '.').back();
    }

    static std::string getParentPath(const std::string& path)
    {
        char baseCopy[PATH_MAX] = {'\0'};
        strncpy(baseCopy, path.c_str(), sizeof(baseCopy) - 1);

        std::string parentDir(dirname(baseCopy));
        return parentDir;
    }

    static std::string joinPaths(const std::string& base, const std::string& relative)
    {
        if (base.empty()) return relative;
        if (relative.empty()) return base;

        if (base.back() == '/' && relative.front() == '/')
        {
            return base + relative.substr(1); // Remove extra slash
        }
        else if (base.back() != '/' && relative.front() != '/')
        {
            return base + "/" + relative; // Add missing slash
        }
        else
        {
            return base + relative; // Already properly separated
        }
    }

    static bool isAbsolutePath(const std::string& path)
    {
        if (path.empty()) return false;

    #ifdef _WIN32
        // Absolute if starts with drive letter (e.g., C:\) or UNC path (\\server\share)
        return (path.size() >= 2 && std::isalpha(path[0]) && path[1] == ':') ||
              (path.size() >= 2 && path[0] == '\\' && path[1] == '\\');
    #else
        // Unix absolute path starts with '/'
        return path[0] == '/';
    #endif
    }

    static std::string removePrefix(const std::string& fullPath, const std::string& prefix)
    {
        if (fullPath.compare(0, prefix.size(), prefix) == 0)
        {
            std::string result = fullPath.substr(prefix.size());
            if (!result.empty() && result[0] == '/')
            {
                result.erase(0, 1); // remove leading slash
            }
            return result;
        }
        return fullPath; // prefix not found, return original
    }
}

#pragma GCC diagnostic pop

#endif // _FILESYSTEM_HELPER_H
