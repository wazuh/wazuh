/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * December 22, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _UTILS_WRAPPER_LINUX_H
#define _UTILS_WRAPPER_LINUX_H

#include <string>


class UtilsWrapperLinux final
{
    public:
        static std::string exec(const std::string& cmd, const size_t bufferSize = 128);
        static bool existsRegular(const std::string& path);
};

#endif // _UTILS_WRAPPER_LINUX_H
