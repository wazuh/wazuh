/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * January 11, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <fstream>
#include <sys/utsname.h>
#include <unistd.h>

#include "osinfo/sysOsParsers.h"
#include "sharedDefs.h"
#include "sysInfo.hpp"
#include "cmdHelper.h"
#include "timeHelper.h"
#include <filesystem_wrapper.hpp>
#include "packages/packageSolaris.h"
#include "packages/solarisWrapper.h"
#include "packages/packageFamilyDataAFactory.h"
#include "network/networkSolarisHelper.hpp"
#include "network/networkSolarisWrapper.hpp"
#include "network/networkFamilyDataAFactory.h"
#include "UtilsWrapperUnix.hpp"
#include "uniqueFD.hpp"

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

static void getPackagesFromPath(const std::string& pkgDirectory, std::function<void(nlohmann::json&)> callback)
{
    const file_system::FileSystemWrapper fs;

    const auto packages { fs.list_directory(pkgDirectory) };

    for (const auto& package : packages)
    {
        nlohmann::json jsPackage;
        const auto fullPath {  pkgDirectory + package.string()};
        const auto pkgWrapper{ std::make_shared<SolarisWrapper>(fullPath) };

        FactoryPackageFamilyCreator<OSPlatformType::SOLARIS>::create(pkgWrapper)->buildPackageData(jsPackage);

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
    nlohmann::json networks;
    Utils::UniqueFD socketV4 ( UtilsWrapperUnix::createSocket(AF_INET, SOCK_DGRAM, 0) );
    Utils::UniqueFD socketV6 ( UtilsWrapperUnix::createSocket(AF_INET6, SOCK_DGRAM, 0) );
    const auto interfaceCount { NetworkSolarisHelper::getInterfacesCount(socketV4.get(), AF_UNSPEC) };

    if (interfaceCount > 0)
    {
        std::vector<lifreq> buffer(interfaceCount);
        lifconf lifc =
        {
            AF_UNSPEC,
            0,
            static_cast<int>(buffer.size() * sizeof(lifreq)),
            reinterpret_cast<caddr_t>(buffer.data())
        };

        NetworkSolarisHelper::getInterfacesConfig(socketV4.get(), lifc);

        std::map<std::string, std::vector<std::pair<lifreq*, uint64_t>>> interfaces;

        for (auto& item : buffer)
        {
            struct lifreq interfaceReq = {};
            std::memcpy(interfaceReq.lifr_name, item.lifr_name, sizeof(item.lifr_name));

            if (-1 != UtilsWrapperUnix::ioctl(AF_INET == item.lifr_addr.ss_family ? socketV4.get() : socketV6.get(),
                                              SIOCGLIFFLAGS,
                                              reinterpret_cast<char*>(&interfaceReq)))
            {
                if ((IFF_UP & interfaceReq.lifr_flags) && !(IFF_LOOPBACK & interfaceReq.lifr_flags))
                {
                    interfaces[item.lifr_name].push_back(std::make_pair(&item, interfaceReq.lifr_flags));
                }
            }
        }

        for (const auto& item : interfaces)
        {
            if (item.second.size())
            {
                const auto firstItem { item.second.front() };
                const auto firstItemFD { AF_INET == firstItem.first->lifr_addr.ss_family ? socketV4.get() : socketV6.get() };

                nlohmann::json network;

                for (const auto& itemr : item.second)
                {
                    if (AF_INET == itemr.first->lifr_addr.ss_family)
                    {
                        // IPv4 data
                        const auto wrapper { std::make_shared<NetworkSolarisInterface>(AF_INET, socketV4.get(), itemr) };
                        FactoryNetworkFamilyCreator<OSPlatformType::SOLARIS>::create(wrapper)->buildNetworkData(network);
                    }
                    else if (AF_INET6 == itemr.first->lifr_addr.ss_family)
                    {
                        // IPv6 data
                        const auto wrapper { std::make_shared<NetworkSolarisInterface>(AF_INET6, socketV6.get(), itemr) };
                        FactoryNetworkFamilyCreator<OSPlatformType::SOLARIS>::create(wrapper)->buildNetworkData(network);
                    }
                }

                const auto wrapper { std::make_shared<NetworkSolarisInterface>(AF_UNSPEC, firstItemFD, firstItem) };
                FactoryNetworkFamilyCreator<OSPlatformType::SOLARIS>::create(wrapper)->buildNetworkData(network);

                networks["iface"].push_back(network);
            }
        }
    }

    return networks;
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

    const file_system::FileSystemWrapper fs;

    if (fs.is_directory(pkgDirectory))
    {
        getPackagesFromPath(pkgDirectory, callback);
    }
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
