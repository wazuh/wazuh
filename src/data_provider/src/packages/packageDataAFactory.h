/*
 * Wazuh SYSINFO
 * Copyright (C) 2015-2021, Wazuh Inc.
 * April 16, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGE_DATA_A_FACTORY_H
#define _PACKAGE_DATA_A_FACTORY_H

#include <memory>
#include "json.hpp"
#include "sharedDefs.h"
#include "packagesLinux.h"


template <LinuxType linuxType>
class FactoryPackagesCreator final
{
public:
    static void getPackages(nlohmann::json&/* packages*/)
    {
        throw std::runtime_error
        {
            "Error creating package data retriever." // ???????????
        };
    }
};

template <>
class FactoryPackagesCreator<LinuxType::ALL> final
{
public:
    static void getPackages(nlohmann::json& packages)
    {
        if (Utils::existsDir(DPKG_PATH))
        {
            getDpkgInfo(DPKG_STATUS_PATH, packages);
        }
        if (Utils::existsDir(PACMAN_PATH))
        {
            getPacmanInfo(PACMAN_PATH, packages);
        }
        if (Utils::existsDir(RPM_PATH))
        {
            getRpmInfo(packages);
        }
    }
};


template <>
class FactoryPackagesCreator<LinuxType::CENTOS5> final
{
public:
    static void getPackages(nlohmann::json& packages)
    {
        if (Utils::existsDir(DPKG_PATH))
        {
            getDpkgInfo(DPKG_STATUS_PATH, packages);
        }
        if (Utils::existsDir(RPM_PATH))
        {
            getRpmInfo(packages);
        }
    }
};

#endif // _PACKAGE_DATA_A_FACTORY_H