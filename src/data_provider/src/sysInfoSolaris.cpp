/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2021, Wazuh Inc.
 * January 11, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <fstream>
#include <sys/utsname.h>

#include "osinfo/sysOsParsers.h"
#include "sharedDefs.h"
#include "sysInfo.hpp"
#include "cmdHelper.h"
#include "filesystemHelper.h"
#include "packages/packageSolaris.h"
#include "packages/solarisWrapper.h"
#include "packages/packageFamilyDataAFactory.h"

constexpr auto SUN_APPS_PATH {"/var/sadm/pkg/"};


static void getOsInfoFromUname(nlohmann::json& info)
{
    bool result{false};
    std::string platform;
    const auto osPlatform{Utils::exec("uname")};

    constexpr auto SOLARIS_RELEASE_FILE{"/etc/release"};
    const auto spParser{FactorySysOsParser::create("solaris")};
    std::fstream file{SOLARIS_RELEASE_FILE, std::ios_base::in};
    result = spParser && file.is_open() && spParser->parseFile(file, info);

    if (!result)
    {
        info["os_name"] = "Unix";
        info["os_platform"] = "Unix";
        info["os_version"] = UNKNOWN_VALUE;
    }
}


std::string SysInfo::getSerialNumber() const
{
    return UNKNOWN_VALUE;
}
std::string SysInfo::getCpuName() const
{
    return UNKNOWN_VALUE;
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

static void getPackagesFromPath(const std::string& pkgDirectory, std::function<void(nlohmann::json&)> callback)
{
    const auto packages { Utils::enumerateDir(pkgDirectory) };

    for (const auto& package : packages)
    {
        nlohmann::json jsPackage;
        const auto fullPath {  pkgDirectory + package };
        const auto pkgWrapper{ std::make_shared<SolarisWrapper>(fullPath) };

        FactoryPackageFamilyCreator<OSType::SOLARIS>::create(pkgWrapper)->buildPackageData(jsPackage);

        if (!jsPackage.at("name").get_ref<const std::string&>().empty())
        {
            // Only return valid content packages
            callback(jsPackage);
        }
    }
}

nlohmann::json SysInfo::getPackages() const
{
    nlohmann::json packages;

    getPackages([&packages](nlohmann::json & data)
    {
        packages.push_back(data);
    });

    return packages;
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

void SysInfo::getPackages(std::function<void(nlohmann::json&)> callback) const
{
    const auto pkgDirectory { SUN_APPS_PATH };

    if (Utils::existsDir(pkgDirectory))
    {
        getPackagesFromPath(pkgDirectory, callback);
    }
}

nlohmann::json SysInfo::getHotfixes() const
{
    // Currently not supported for this OS.
    return nlohmann::json();
}

