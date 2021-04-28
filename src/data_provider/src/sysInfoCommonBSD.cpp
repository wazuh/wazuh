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
#include <sys/types.h>
#include <sys/sysctl.h>
#include "sysInfo.hpp"
#include "cmdHelper.h"
#include "stringHelper.h"
#include "filesystemHelper.h"
#include "networkUnixHelper.h"
#include "network/networkBSDWrapper.h"
#include "network/networkFamilyDataAFactory.h"

int SysInfo::getCpuCores() const
{
    int cores{0};
    size_t len{sizeof(cores)};
    const std::vector<int> mib{CTL_HW, HW_NCPU};
    const auto ret{sysctl(const_cast<int*>(mib.data()), mib.size(), &cores, &len, nullptr, 0)};
    if(ret)
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

std::string SysInfo::getCpuName() const
{
    const std::vector<int> mib{CTL_HW, HW_MODEL};
    size_t len{0};
    auto ret{sysctl(const_cast<int*>(mib.data()), mib.size(), nullptr, &len, nullptr, 0)};
    if(ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error getting cpu name size."
        };
    }
    const auto spBuff{std::make_unique<char[]>(len+1)};
    if(!spBuff)
    {
        throw std::runtime_error
        {
            "Error allocating memory to read the cpu name."
        };
    }
    ret = sysctl(const_cast<int*>(mib.data()), mib.size(), spBuff.get(), &len, nullptr, 0);
    if(ret)
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

nlohmann::json SysInfo::getNetworks() const
{
    nlohmann::json networks;

    std::unique_ptr<ifaddrs, Utils::IfAddressSmartDeleter> interfacesAddress;
    std::map<std::string, std::vector<ifaddrs*>> networkInterfaces;
    Utils::NetworkUnixHelper::getNetworks(interfacesAddress, networkInterfaces);

    for(const auto& interface : networkInterfaces)
    {
        nlohmann::json ifaddr {};
        for (const auto addr : interface.second)
        {
            FactoryNetworkFamilyCreator<OSType::BSDBASED>::create(std::make_shared<NetworkBSDInterface>(addr))->buildNetworkData(ifaddr);
        }
        networks["iface"].push_back(ifaddr);
    }

    return networks;
}

