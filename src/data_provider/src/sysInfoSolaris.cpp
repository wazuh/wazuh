/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 16, 2021.
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
#include "networkSolarisHelper.hpp"
#include "network/networkFamilyDataAFactory.h"

struct SocketDeleter
{
    void ()(const int fd)
    {
        if (-1 != fd)
        {
            close(fd);
        }
    }

};

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
    nlohmann::json networks;
    const std::unique_ptr<int, SocketDeleter> spSocket { UtilsWrapperUnix::createSocket(AF_INET, SOCK_DGRAM, 0) };
    const auto interfaceCount { NetworkSolarisHelper::getInterfacesCount(spSocket.get()) };

    // Get IPv4 address
    struct lifconf configurationInterface = { .lifc_family = AF_INET, .lifc_len = interfaceCount * sizeof(struct lifreq) };
    auto buffer1 { std::vector<char *>(configurationInterface.lifc_len) };
    configurationInterface.lifc_buf = buffer1.data();

    if (NetworkSolarisHelper::getInterfaces(spSocket.get(), &configurationInterface))
    {
        nlohmann::json ifaddr {};

        for (auto index = 0; index < interfaceCount; index++)
        {
            const auto networkInterfacePtr { FactoryNetworkFamilyCreator<OSType::SOLARIS>::create(std::make_shared<NetworkSolarisInterface>(spSocket.get(), index, &configurationInterface)) };

            if (networkInterfacePtr)
            {
                networkInterfacePtr->buildNetworkData(ifaddr);
            }
        }

        networks["iface"].push_back(ifaddr);
    }

    // Get IPv6 address
    const std::unique_ptr<int, SocketDeleter> spSocketV6 { UtilsWrapperUnix::createSocket(AF_INET6, SOCK_DGRAM, 0) };
    const auto interfaceV6Count { NetworkSolarisHelper::getInterfacesV6Count(spSocketV6.get()) };
    struct lifconf configurationInterfaceV6 = { .lifc_family = AF_INET6, .lifc_len = interfaceV6Count * sizeof(struct lifreq) };
    auto buffer2 { std::vector<char *>(configurationInterfaceV6.lifc_len) };
    configurationInterfaceV6.lifc_buf = buffer2.data();

    if (NetworkSolarisHelper::getInterfaces(spSocketV6.get(), &configurationInterfaceV6))
    {
        nlohmann::json ifaddr {};

        for (auto index = 0; index < interfaceV6Count; index++)
        {
            const auto networkInterfacePtr { FactoryNetworkFamilyCreator<OSType::SOLARIS>::create(std::make_shared<NetworkSolarisInterface>(spSocketV6.get(), index, &configurationInterfaceV6) };

            if (networkInterfacePtr)
            {
                networkInterfacePtr->buildNetworkData(ifaddr);
            }
        }

        networks["iface"].push_back(ifaddr);
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

void SysInfo::getPackages(std::function<void(nlohmann::json&)> /*callback*/) const
{
    // TODO
}

nlohmann::json SysInfo::getHotfixes() const
{
    // Currently not supported for this OS.
    return nlohmann::json();
}
