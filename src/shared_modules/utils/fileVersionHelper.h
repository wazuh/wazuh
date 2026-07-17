/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 13, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#ifndef _FILE_VERSION_HELPER_H
#define _FILE_VERSION_HELPER_H

#include <cstdio>
#include <string>
#include <vector>
#include <winsock2.h>
#include <windows.h>
#include "stringHelper.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    /*
     * @brief Get the ProductVersion string published on the VERSIONINFO resource of a file.
     *
     * The resource is read as plain file data (no code from the target file is executed).
     *
     * @param[in] filePath Path of the file to read.
     *
     * @return Return the product version or an empty string if the file has no readable VERSIONINFO.
     */
    static std::string getFileProductVersion(const std::string& filePath)
    {
        std::string version;
        DWORD handle { 0 };
        const auto size { GetFileVersionInfoSizeA(filePath.c_str(), &handle) };

        if (size)
        {
            std::vector<unsigned char> buffer(size);

            if (GetFileVersionInfoA(filePath.c_str(), 0, size, buffer.data()))
            {
                struct LangCodePage
                {
                    unsigned short language;
                    unsigned short codePage;
                }* translation { nullptr };
                UINT length { 0 };

                if (VerQueryValueA(buffer.data(), "\\VarFileInfo\\Translation", reinterpret_cast<LPVOID*>(&translation), &length)
                        && translation && length >= sizeof(LangCodePage))
                {
                    char subBlock[64] {};
                    snprintf(subBlock, sizeof(subBlock), "\\StringFileInfo\\%04x%04x\\ProductVersion", translation->language, translation->codePage);
                    char* value { nullptr };
                    UINT valueLength { 0 };

                    if (VerQueryValueA(buffer.data(), subBlock, reinterpret_cast<LPVOID*>(&value), &valueLength) && value && valueLength)
                    {
                        version = Utils::trim(std::string(value), " \t");
                    }
                }
            }
        }

        return version;
    }
}

#pragma GCC diagnostic pop

#endif // _FILE_VERSION_HELPER_H

#endif // WIN32
