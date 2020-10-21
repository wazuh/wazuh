/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 8, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYS_INFO_HPP
#define _SYS_INFO_HPP
#include "json.hpp"

constexpr auto KByte{1024};

class SysInfo
{
public:
    SysInfo() = default;
    virtual ~SysInfo() = default;
    nlohmann::json hardware();
    nlohmann::json packages();
private:
    virtual std::string getSerialNumber() const;
    virtual std::string getCpuName() const;
    virtual int getCpuMHz() const;
    virtual int getCpuCores() const;
    virtual void getMemory(nlohmann::json& info) const;
    virtual nlohmann::json getPackages();
};


#endif //_SYS_INFO_HPP