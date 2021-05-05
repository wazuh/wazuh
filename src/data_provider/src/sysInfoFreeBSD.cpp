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
#include "stringHelper.h"
#include "osinfo/sysOsParsers.h"
#include <sys/sysctl.h>
#include <sys/vmmeter.h>
#include <sys/utsname.h>
#include "sharedDefs.h"

void SysInfo::getMemory(nlohmann::json& info) const
{
    constexpr auto vmPageSize{"vm.stats.vm.v_page_size"};
    constexpr auto vmTotal{"vm.vmtotal"};
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
    struct vmtotal vmt{};
    len = sizeof(vmt);
    ret = sysctlbyname(vmTotal, &vmt, &len, nullptr, 0);
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading total memory."
        };
    }
    const auto ramFree{(vmt.t_free * pageSize)/KByte};
    info["ram_free"] = ramFree;
    info["ram_usage"] = 100 - (100 * ramFree / ramTotal);
}


int SysInfo::getCpuMHz() const
{
    unsigned long cpuMHz{0};
    constexpr auto clockRate{"hw.clockrate"};
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
    return cpuMHz;
}

std::string SysInfo::getSerialNumber() const
{
    return UNKNOWN_VALUE;
}

nlohmann::json SysInfo::getPackages() const
{
    nlohmann::json ret;
    const auto query{Utils::exec(R"(pkg query -a "%n|%m|%v|%q|%c")")};
    if (!query.empty())
    {
        const auto lines{Utils::split(query, '\n')};
        for (const auto& line : lines)
        {
            const auto data{Utils::split(line, '|')};
            nlohmann::json package;
            package["name"] = data[0];
            package["vendor"] = data[1];
            package["version"] = data[2];
            package["architecture"] = data[3];
            package["description"] = data[4];
            package["format"] = "pkg";
            ret.push_back(package);
        }
    }
    return ret;
}

nlohmann::json SysInfo::getProcessesInfo() const
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