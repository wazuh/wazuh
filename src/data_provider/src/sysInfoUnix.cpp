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

    if (osPlatform.find("SunOS") != std::string::npos)
    {
        constexpr auto SOLARIS_RELEASE_FILE{"/etc/release"};
        const auto spParser{FactorySysOsParser::create("solaris")};
        std::fstream file{SOLARIS_RELEASE_FILE, std::ios_base::in};
        result = spParser && file.is_open() && spParser->parseFile(file, info);
    }
    else if (osPlatform.find("HP-UX") != std::string::npos)
    {
        const auto spParser{FactorySysOsParser::create("hp-ux")};
        result = spParser && spParser->parseUname(Utils::exec("uname -r"), info);
    }

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
    hardware["board_serial"] = getSerialNumber();
    hardware["cpu_name"] = getCpuName();
    hardware["cpu_cores"] = getCpuCores();
    hardware["cpu_mhz"] = double(getCpuMHz());
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
        ret["sysname"] = uts.sysname;
        ret["hostname"] = uts.nodename;
        ret["version"] = uts.version;
        ret["architecture"] = uts.machine;
        ret["release"] = uts.release;
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
