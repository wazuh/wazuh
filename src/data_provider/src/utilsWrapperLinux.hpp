/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 22, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef DEF_UTILS_WRAPPER_LINUX_HPP
#define DEF_UTILS_WRAPPER_LINUX_HPP

#include <string>


class UtilsWrapper final
{
    public:
        static std::string exec(const std::string& cmd, const size_t bufferSize = 128);
        static bool existsRegular(const std::string& path);
};

#endif // DEF_UTILS_WRAPPER_LINUX_HPP
