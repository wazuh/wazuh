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

#ifndef _PACKAGE_LINUX_DATA_RETRIEVER_H
#define _PACKAGE_LINUX_DATA_RETRIEVER_H

#include <memory>
#include "json.hpp"
#include "sharedDefs.h"

/**
 * @brief Fills a JSON object with all available pacman-related information
 * @param libPath Path to pacman's database directory
 * @param jsonPackages JSON to be filled
 */
void getPacmanInfo(const std::string& libPath, nlohmann::json& jsonPackages);

/**
 * @brief Fills a JSON object with all available rpm-related information
 * @param jsonPackages JSON to be filled
 */
void getRpmInfo(nlohmann::json& jsonPackages);

/**
 * @brief Fills a JSON object with all available dpkg-related information
 * @param libPath Path to dpkg's database directory
 * @param jsonPackages JSON to be filled
 */
void getDpkgInfo(const std::string& libPath, nlohmann::json& jsonPackages);


// Exception template
template <LinuxType linuxType>
class FactoryPackagesCreator final
{
    public:
        static void getPackages(nlohmann::json& /* packages*/)
        {
            throw std::runtime_error
            {
                "Error creating package data retriever."
            };
        }
};

// Standard template to extract package information in fully compatible Linux systems
template <>
class FactoryPackagesCreator<LinuxType::STANDARD> final
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

// Template to extract package information in partially incompatible Linux systems
template <>
class FactoryPackagesCreator<LinuxType::LEGACY> final
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

#endif // _PACKAGE_LINUX_DATA_RETRIEVER_H
