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

#ifndef _FIMDB_OS_WINDOWS_SPECIALIZATION_H
#define _FIMDB_OS_WINDOWS_SPECIALIZATION_H

#include <string>

class WindowsSpecialization final
{
    public:
        static const std::string registryTypeToText(const int type);
        static bool isUTF8String(const std::string& str);
        static void encodeString(std::string& str);
};

#endif // _FIMDB_OS_WINDOWS_SPECIALIZATION_H
