/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sysInfo.hpp"
#include "cmdHelper.h"
#include "stringHelper.h"
#include "filesystemHelper.h"
#include <sys/sysctl.h>

constexpr auto MAC_APPS_PATH{"/Applications"};

void SysInfo::getMemory(nlohmann::json& info) const
{
    constexpr auto vmPageSize{"vm.pagesize"};
    constexpr auto vmPageFreeCount{"vm.page_free_count"};
    uint64_t ram{0};
    const std::vector<int> mib{CTL_HW, HW_MEMSIZE};
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
    u_int pageSize{0};
    len = sizeof(pageSize);
    ret = sysctlbyname(vmPageSize, &pageSize, &len, nullptr, 0);
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading page size."
        };
    }
    uint64_t freePages{0};
    len = sizeof(freePages);
    ret = sysctlbyname(vmPageFreeCount, &freePages, &len, nullptr, 0);
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading free pages."
        };
    }
    const auto ramFree{(freePages * pageSize)/KByte};
    info["ram_free"] = ramFree;
    info["ram_usage"] = 100 - (100 * ramFree / ramTotal);
}

int SysInfo::getCpuMHz() const
{
    constexpr auto MHz{1000000};
    unsigned long cpuMHz{0};
    constexpr auto clockRate{"hw.cpufrequency"};
    size_t len{sizeof(cpuMHz)};
    const auto ret{sysctlbyname(clockRate, &cpuMHz, &len, nullptr, 0)};
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading cpu frequency."
        };
    }
    return cpuMHz/MHz;
}

std::string SysInfo::getSerialNumber() const
{
    const auto rawData{Utils::exec("system_profiler SPHardwareDataType | grep Serial")};
    return Utils::trim(rawData.substr(rawData.find(":")), " :\t\r\n");
}

nlohmann::json SysInfo::getPackages() const
{
    nlohmann::json ret;
    const auto apps{Utils::enumerateDir(MAC_APPS_PATH)};
    for(const auto& app : apps)
    {
        std::cout << app << std::endl;
    }
    return ret;
}