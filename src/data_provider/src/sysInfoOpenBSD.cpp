/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sysInfo.hpp"
#include "cmdHelper.h"
#include "timeHelper.h"
#include "osinfo/sysOsParsers.h"
#include "stringHelper.h"
#include "sharedDefs.h"
#include <sys/sysctl.h>
#include <sys/utsname.h>

void SysInfo::getMemory(nlohmann::json& info) const
{
    uint64_t ram{0};
    const std::vector<int> mib{CTL_HW, HW_PHYSMEM};
    size_t len{sizeof(ram)};
    auto ret{sysctl(const_cast<int*>(mib.data()), mib.size(), &ram, &len, nullptr, 0)};
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading total RAM."
        };
    }
    const auto ramTotal{ram/KByte};
    info["ram_total"] = ramTotal;
    info["ram_free"] = 0;
    info["ram_usage"] = 0;
}

int SysInfo::getCpuMHz() const
{
    unsigned long cpuMHz{0};
    const std::vector<int> mib{CTL_HW, HW_CPUSPEED};
    size_t len{sizeof(cpuMHz)};
    const auto ret{sysctl(const_cast<int*>(mib.data()), mib.size(), &cpuMHz, &len, nullptr, 0)};
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading cpu frequency."
        };
    }
    return cpuMHz;
}

std::string SysInfo::getSerialNumber() const
{
    const std::vector<int> mib{CTL_HW, HW_SERIALNO};
    size_t len{0};
    auto ret{sysctl(const_cast<int*>(mib.data()), mib.size(), nullptr, &len, nullptr, 0)};
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error getting board serial size."
        };
    }
    const auto spBuff{std::make_unique<char[]>(len+1)};
    if(!spBuff)
    {
        throw std::runtime_error
        {
            "Error allocating memory to read the board serial."
        };
    }
    ret = sysctl(const_cast<int*>(mib.data()), mib.size(), spBuff.get(), &len, nullptr, 0);
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error getting board serial"
       };
    }
    spBuff.get()[len] = 0;
    return std::string{reinterpret_cast<const char*>(spBuff.get())};
}

nlohmann::json SysInfo::getProcessesInfo() const
{
    // Currently not supported for this OS
    return nlohmann::json {};
}

nlohmann::json SysInfo::getPackages() const
{
    // Currently not supported for this OS
    return nlohmann::json {};
}

nlohmann::json SysInfo::getOsInfo() const
{
    nlohmann::json ret;
    struct utsname uts{};
    const auto spParser{FactorySysOsParser::create("bsd")};
    if(!spParser->parseUname(Utils::exec("uname -r"), ret))
    {
        ret["os_name"] = "BSD";
        ret["os_platform"] = "bsd";
        ret["os_version"] = UNKNOWN_VALUE;
    }
    if (uname(&uts) >= 0)
    {
        ret["sysname"] = uts.sysname;
        ret["hostname"] = uts.nodename;
        ret["version"] = uts.version;
        ret["architecture"] = uts.machine;
        ret["release"] = uts.release;
    }
    return ret;
}

nlohmann::json SysInfo::getPorts() const
{
    // Currently not supported for this OS
    return nlohmann::json {};
}