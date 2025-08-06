/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
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

static void getMemory(nlohmann::json& info)
{
    constexpr auto vmPageSize{"vm.stats.vm.v_page_size"};
    constexpr auto vmTotal{"vm.vmtotal"};
    uint64_t ram{0};
    const std::vector<int> mib{CTL_HW, HW_PHYSMEM};
    size_t len{sizeof(ram)};
    auto ret{sysctl(const_cast<int*>(mib.data()), mib.size(), &ram, &len, nullptr, 0)};

    if (ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading total RAM."
        };
    }

    const auto ramTotal{ram / KByte};
    info["ram_total"] = ramTotal;
    u_int pageSize{0};
    len = sizeof(pageSize);
    ret = sysctlbyname(vmPageSize, &pageSize, &len, nullptr, 0);

    if (ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading page size."
        };
    }

    struct vmtotal vmt {};

    len = sizeof(vmt);

    ret = sysctlbyname(vmTotal, &vmt, &len, nullptr, 0);

    if (ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading total memory."
        };
    }

    const auto ramFree{(vmt.t_free * pageSize) / KByte};
    info["ram_free"] = ramFree;
    info["ram_usage"] = 100 - (100 * ramFree / ramTotal);
}


static int getCpuMHz()
{
    unsigned long cpuMHz{0};
    constexpr auto clockRate{"hw.clockrate"};
    size_t len{sizeof(cpuMHz)};
    const auto ret{sysctlbyname(clockRate, &cpuMHz, &len, nullptr, 0)};

    if (ret)
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

static std::string getSerialNumber()
{
    return UNKNOWN_VALUE;
}

static int getCpuCores()
{
    int cores{0};
    size_t len{sizeof(cores)};
    const std::vector<int> mib{CTL_HW, HW_NCPU};
    const auto ret{sysctl(const_cast<int*>(mib.data()), mib.size(), &cores, &len, nullptr, 0)};

    if (ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading cpu cores number."
        };
    }

    return cores;
}

static std::string getCpuName()
{
    const std::vector<int> mib{CTL_HW, HW_MODEL};
    size_t len{0};
    auto ret{sysctl(const_cast<int*>(mib.data()), mib.size(), nullptr, &len, nullptr, 0)};

    if (ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error getting cpu name size."
        };
    }

    const auto spBuff{std::make_unique<char[]>(len + 1)};

    if (!spBuff)
    {
        throw std::runtime_error
        {
            "Error allocating memory to read the cpu name."
        };
    }

    ret = sysctl(const_cast<int*>(mib.data()), mib.size(), spBuff.get(), &len, nullptr, 0);

    if (ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error getting cpu name"
        };
    }

    spBuff.get()[len] = 0;
    return std::string{reinterpret_cast<const char*>(spBuff.get())};
}

nlohmann::json SysInfo::getHardware() const
{
    nlohmann::json hardware;
    hardware["board_serial"] = getSerialNumber();
    hardware["cpu_name"] = getCpuName();
    hardware["cpu_cores"] = getCpuCores();
    hardware["cpu_mhz"] = double(getCpuMHz());
    getMemory(hardware);
    return hardware;
}

nlohmann::json SysInfo::getPackages() const
{
    nlohmann::json ret;
    getPackages([&ret](nlohmann::json & data)
    {
        ret.push_back(data);
    });
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
    struct utsname uts {};
    const auto spParser{FactorySysOsParser::create("bsd")};

    if (!spParser->parseUname(Utils::exec("uname -r"), ret))
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
    // Currently not supported for this OS.
    return nlohmann::json {};
}

void SysInfo::getProcessesInfo(std::function<void(nlohmann::json&)> /*callback*/) const
{
    // Currently not supported for this OS.
}

void SysInfo::getPackages(std::function<void(nlohmann::json&)> callback) const
{
    const auto query{Utils::exec(R"(pkg query -a "%n|%m|%v|%q|%c")")};

    if (!query.empty())
    {
        const auto lines{Utils::split(query, '\n')};

        for (const auto& line : lines)
        {
            const auto data{Utils::split(line, '|')};
            nlohmann::json package;
            std::string vendor       { UNKNOWN_VALUE };
            std::string email        { UNKNOWN_VALUE };

            Utils::splitMaintainerField(data[1], vendor, email);

            package["name"] = data[0];
            package["vendor"] = vendor;
            package["version"] = data[2];
            package["install_time"] = UNKNOWN_VALUE;
            package["location"] = UNKNOWN_VALUE;
            package["architecture"] = data[3];
            package["groups"] = UNKNOWN_VALUE;
            package["description"] = data[4];
            package["size"] = 0;
            package["priority"] = UNKNOWN_VALUE;
            package["source"] = UNKNOWN_VALUE;
            package["format"] = "pkg";
            // The multiarch field won't have a default value

            callback(package);
        }
    }
}

nlohmann::json SysInfo::getHotfixes() const
{
    // Currently not supported for this OS.
    return nlohmann::json();
}
