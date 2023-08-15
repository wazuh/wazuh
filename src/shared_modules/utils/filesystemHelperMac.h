/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * August 15, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FILESYSTEM_HELPER_MAC_H
#define _FILESYSTEM_HELPER_MAC_H

#include <string>
#include <vector>
#include <dirent.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    static std::vector<std::string> enumerateDirTypeDir(const std::string& path)
    {
        std::vector<std::string> ret;
        std::unique_ptr<DIR, DirSmartDeleter> spDir{opendir(path.c_str())};

        if (spDir)
        {
            auto entry{readdir(spDir.get())};

            while (entry)
            {
                if (entry->d_type == DT_DIR)
                {
                    ret.push_back(entry->d_name);
                }

                entry = readdir(spDir.get());
            }
        }

        return ret;
    }

    static std::vector<std::string> enumerateDirTypeRegular(const std::string& path)
    {
        std::vector<std::string> ret;
        std::unique_ptr<DIR, DirSmartDeleter> spDir{opendir(path.c_str())};

        if (spDir)
        {
            auto entry{readdir(spDir.get())};

            while (entry)
            {
                if (entry->d_type == DT_REG)
                {
                    ret.push_back(entry->d_name);
                }

                entry = readdir(spDir.get());
            }
        }

        return ret;
    }
}

#pragma GCC diagnostic pop

#endif // _FILESYSTEM_HELPER_MAC_H