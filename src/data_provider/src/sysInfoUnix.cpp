/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * November 23, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <fstream>
#include <sys/utsname.h>
#include "osinfo/sysOsParsers.h"
#include "sysInfo.hpp"
#include "cmdHelper.h"
#include "timeHelper.h"
#include "sharedDefs.h"

static void getOsInfoFromUname(nlohmann::json& info)
{
    bool result{false};
    std::string platform;
    const auto osPlatform{Utils::exec("uname")};

    if (!result)
    {
        info["os_name"] = "Unix";
        info["os_platform"] = "Unix";
        info["os_version"] = UNKNOWN_VALUE;
    }
}


static std::string getSerialNumber()
{
    return UNKNOWN_VALUE;
}

static std::string getCpuName()
{
    return UNKNOWN_VALUE;
}

static int getCpuMHz()
{
    return 0;
}

static int getCpuCores()
{
    return 0;
}

static void getMemory(nlohmann::json& /*info*/)
{

}

nlohmann::json SysInfo::getHardware() const
{
    nlohmann::json hardware;
    hardware["serial_number"] = getSerialNumber();
    hardware["cpu_name"] = getCpuName();
    hardware["cpu_cores"] = getCpuCores();
    hardware["cpu_speed"] = double(getCpuMHz());
    getMemory(hardware);
    return hardware;
}

nlohmann::json SysInfo::getPackages() const
{
    return nlohmann::json {};
}
nlohmann::json SysInfo::getOsInfo() const
{
    nlohmann::json ret;
    struct utsname uts {};
    getOsInfoFromUname(ret);

    if (uname(&uts) >= 0)
    {
        ret["os_kernel_name"] = uts.sysname;
        ret["hostname"] = uts.nodename;
        ret["os_kernel_version"] = uts.version;
        ret["architecture"] = uts.machine;
        ret["os_kernel_release"] = uts.release;
    }

    return ret;
}
nlohmann::json SysInfo::getProcessesInfo() const
{
    return nlohmann::json();
}
nlohmann::json SysInfo::getNetworks() const
{
    return nlohmann::json();
}
nlohmann::json SysInfo::getPorts() const
{
    return nlohmann::json();
}
void SysInfo::getProcessesInfo(std::function<void(nlohmann::json&)> /*callback*/) const
{
    // TODO
}

void SysInfo::getPackages(std::function<void(nlohmann::json&)> /*callback*/) const
{
    // TODO
}

nlohmann::json SysInfo::getHotfixes() const
{
    // Currently not supported for this OS.
    return nlohmann::json();
}

nlohmann::json SysInfo::getGroups() const
{
    //TODO: Pending implementation.
    return nlohmann::json();
}

nlohmann::json SysInfo::getUsers() const
{
    //TODO: Pending implementation.
    return nlohmann::json();
}

nlohmann::json SysInfo::getServices() const
{
    //TODO: Pending implementation.
    return nlohmann::json();
}

nlohmann::json SysInfo::getBrowserExtensions() const
{
    //TODO: Pending implementation.
    return nlohmann::json();
}
