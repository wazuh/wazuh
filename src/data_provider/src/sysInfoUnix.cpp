/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2020, Wazuh Inc.
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
    else if(osPlatform.find("HP-UX") != std::string::npos)
    {
        const auto spParser{FactorySysOsParser::create("hp-ux")};
        result = spParser && spParser->parseUname(Utils::exec("uname -r"), info);
    }
    if(!result)
    {
        info["os_name"] = "Unix";
        info["os_platform"] = "Unix";
        info["os_version"] = "unknown";
    }
}


std::string SysInfo::getSerialNumber() const
{
    return "unknown";
}
std::string SysInfo::getCpuName() const
{
    return "unknown";
}
int SysInfo::getCpuMHz() const
{
    return 0;
}
int SysInfo::getCpuCores() const
{
    return 0;
}
void SysInfo::getMemory(nlohmann::json& /*info*/) const
{
    
}
nlohmann::json SysInfo::getPackages() const
{
    return nlohmann::json {};
}
nlohmann::json SysInfo::getOsInfo() const
{
    nlohmann::json ret;
    struct utsname uts{};
    getOsInfoFromUname(ret);
    if (uname(&uts) >= 0)
    {
        ret["sysname"] = uts.sysname;
        ret["host_name"] = uts.nodename;
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