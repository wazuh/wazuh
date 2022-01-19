/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * November 9, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYS_INFO_INTERFACE
#define _SYS_INFO_INTERFACE

#include "json.hpp"

class ISysInfo
{
    public:
        ISysInfo() = default;
        // LCOV_EXCL_START
        virtual ~ISysInfo() = default;
        // LCOV_EXCL_STOP
        virtual nlohmann::json hardware() = 0;
        virtual nlohmann::json packages() = 0;
        virtual nlohmann::json os() = 0;
        virtual nlohmann::json processes() = 0;
        virtual nlohmann::json networks() = 0;
        virtual nlohmann::json ports() = 0;
        virtual nlohmann::json hotfixes() = 0;
        virtual void packages(std::function<void(nlohmann::json&)>) = 0;
        virtual void processes(std::function<void(nlohmann::json&)>) = 0;

};

#endif //_SYS_INFO_INTERFACE
