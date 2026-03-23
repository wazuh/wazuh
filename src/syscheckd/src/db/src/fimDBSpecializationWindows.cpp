/*
 * Wazuh Syscheck
 * Copyright (C) 2022, Wazuh Inc.
 * March 6, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fimDBSpecializationWindows.hpp"
#include "encodingWindowsHelper.h"
#include <map>
#include <windows.h>

#define REG_UNKNOWN 0x0000000C

const std::string WindowsSpecialization::registryTypeToText(const int type)
{
    static const std::map<int, std::string> VALUE_TYPE =
    {
        {REG_NONE, "REG_NONE"},
        {REG_SZ, "REG_SZ"},
        {REG_EXPAND_SZ, "REG_EXPAND_SZ"},
        {REG_BINARY, "REG_BINARY"},
        {REG_DWORD, "REG_DWORD"},
        {REG_DWORD_BIG_ENDIAN, "REG_DWORD_BIG_ENDIAN"},
        {REG_LINK, "REG_LINK"},
        {REG_MULTI_SZ, "REG_MULTI_SZ"},
        {REG_RESOURCE_LIST, "REG_RESOURCE_LIST"},
        {REG_FULL_RESOURCE_DESCRIPTOR, "REG_FULL_RESOURCE_DESCRIPTOR"},
        {REG_RESOURCE_REQUIREMENTS_LIST, "REG_RESOURCE_REQUIREMENTS_LIST"},
        {REG_QWORD, "REG_QWORD"},
        {REG_UNKNOWN, "REG_UNKNOWN"}
    };
    return VALUE_TYPE.at(type);
}

bool WindowsSpecialization::isUTF8String(const std::string& str)
{
    int c = 0;

    for (size_t i = 0; i < str.size(); ++i)
    {
        unsigned char b = static_cast<unsigned char>(str[i]);

        if (c)
        {
            if ((b >> 6) != 0x2) return false;

            --c;
        }
        else if ((b >> 5) == 0x6)
        {
            c = 1;
        }
        else if ((b >> 4) == 0xE)
        {
            c = 2;
        }
        else if ((b >> 3) == 0x1E)
        {
            c = 3;
        }
        else if ((b >> 7))
        {
            return false;
        }
    }

    return c == 0;
}

void WindowsSpecialization::encodeString(std::string& str)
{
    if (!isUTF8String(str))
    {
        str = Utils::EncodingWindowsHelper::stringAnsiToStringUTF8(str);
    }
}
