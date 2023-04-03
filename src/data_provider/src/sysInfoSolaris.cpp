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
#include "filesystemHelper.h"
#include "packages/packageSolaris.h"
#include "packages/solarisWrapper.h"
#include "packages/packageFamilyDataAFactory.h"
#include "network/networkSolarisHelper.hpp"
#include "network/networkSolarisWrapper.hpp"
#include "network/networkFamilyDataAFactory.h"
#include "ports/portSolarisHelper.hpp"
#include "ports/portSolarisWrapper.h"
#include "ports/portImpl.h"
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
                        FactoryNetworkFamilyCreator<OSType::SOLARIS>::create(wrapper)->buildNetworkData(network);
                    }
                    else if (AF_INET6 == itemr.first->lifr_addr.ss_family)
                    {
                        // IPv6 data
                        const auto wrapper { std::make_shared<NetworkSolarisInterface>(AF_INET6, socketV6.get(), itemr) };
                        FactoryNetworkFamilyCreator<OSType::SOLARIS>::create(wrapper)->buildNetworkData(network);
                    }
                }

                const auto wrapper { std::make_shared<NetworkSolarisInterface>(AF_UNSPEC, firstItemFD, firstItem) };
                FactoryNetworkFamilyCreator<OSType::SOLARIS>::create(wrapper)->buildNetworkData(network);

                networks["iface"].push_back(network);
            }
        }
    }

    return networks;
}

nlohmann::json SysInfo::getPorts() const
{
    nlohmann::json ports{};
    std::vector<mib_item_t> items;

    // Open /dev/arp and push into ioctl()
    int sd = PortSolarisHelper::mibOpen();

    if (sd != -1)
    {
        mib2_tcpConnEntry_t* tp;
        mib2_tcp6ConnEntry_t* tp6;
        mib2_udpEntry_t* ud;
        mib2_udp6Entry_t* ud6;

        // Get all connections available
        PortSolarisHelper::mibGetItems(sd, items);

        // Extract constant sizes - need do once only
        PortSolarisHelper::mibGetConstants(items);

        for (auto item : items)
        {
            if (item.group == MIB2_TCP)
            {
                for (tp = (mib2_tcpConnEntry_t*)item.val.get();
                        (char*)tp < (char*)item.val.get() + item.length;
                        tp = (mib2_tcpConnEntry_t*)((char*)tp + PortSolarisHelper::tcpConnEntrySize))
                {
                    nlohmann::json port {};
                    std::make_unique<PortImpl>(std::make_shared<SolarisPortWrapper>(tp))->buildPortData(port);
                    ports.push_back(port);
                }
            }
            else if (item.group == MIB2_TCP6)
            {
                for (tp6 = (mib2_tcp6ConnEntry_t*)item.val.get();
                        (char*)tp6 < (char*)item.val.get() + item.length;
                        tp6 = (mib2_tcp6ConnEntry_t*)((char*)tp6 + PortSolarisHelper::tcp6ConnEntrySize))
                {
                    nlohmann::json port {};
                    std::make_unique<PortImpl>(std::make_shared<SolarisPortWrapper>(tp6))->buildPortData(port);
                    ports.push_back(port);
                }
            }
            else if (item.group == MIB2_UDP)
            {
                for (ud = (mib2_udpEntry_t*)item.val.get();
                        (char*)ud < (char*)item.val.get() + item.length;
                        ud = (mib2_udpEntry_t*)((char*)ud + PortSolarisHelper::udpEntrySize))
                {
                    nlohmann::json port {};
                    std::make_unique<PortImpl>(std::make_shared<SolarisPortWrapper>(ud))->buildPortData(port);
                    ports.push_back(port);
                }
            }
            else if (item.group == MIB2_UDP6)
            {
                for (ud6 = (mib2_udp6Entry_t*)item.val.get();
                        (char*)ud6 < (char*)item.val.get() + item.length;
                        ud6 = (mib2_udp6Entry_t*)((char*)ud6 + PortSolarisHelper::udp6EntrySize))
                {
                    nlohmann::json port {};
                    std::make_unique<PortImpl>(std::make_shared<SolarisPortWrapper>(ud6))->buildPortData(port);
                    ports.push_back(port);
                }
            }
        }

        close(sd);
    }

    return ports;
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
