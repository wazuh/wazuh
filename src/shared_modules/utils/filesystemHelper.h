/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2020, Wazuh Inc.
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
#include <dirent.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    static bool existsDir(const std::string& path)
    {
        struct stat info{};
        return !stat(path.c_str(), &info) && (info.st_mode & S_IFDIR);
    }
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
        std::ifstream file(filePath, std::ios_base::in);

        if (file.is_open())
        {
            content << file.rdbuf();
        }
        return content.str();
    }
}

#pragma GCC diagnostic pop

#endif // _FILESYSTEM_HELPER_H