/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
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
#include <unordered_set>
#include <filesystem_wrapper.hpp>
#include "json.hpp"
#include "sharedDefs.h"
#include "utilsWrapperLinux.hpp"

/**
 * @brief Fills a JSON object with all available pacman-related information
 * @param libPath  Path to pacman's database directory
 * @param callback Callback to be called for every single element being found
 */
void getPacmanInfo(const std::string& libPath, std::function<void(nlohmann::json&)> callback);

/**
 * @brief Fills a JSON object with all available rpm-related information
 * @param callback Callback to be called for every single element being found
 */
void getRpmInfo(std::function<void(nlohmann::json&)> callback);

/**
 * @brief Get all python packages installed by rpm
 * @param pythonPackages Set to be filled with all python packages found
 */
void getRpmPythonPackages(std::unordered_set<std::string>& pythonPackages);

/**
 * @brief Fills a JSON object with all available rpm-related information for legacy Linux.
 * @param callback Callback to be called for every single element being found
 */
void getRpmInfoLegacy(std::function<void(nlohmann::json&)> callback);

/**
 * @brief Fills a JSON object with all available dpkg-related information
 * @param libPath  Path to dpkg's database directory
 * @param callback Callback to be called for every single element being found
 */
void getDpkgInfo(const std::string& libPath, std::function<void(nlohmann::json&)> callback);

/**
 * @brief Get all python packages installed by dpkg
 * @param pythonPackages Set to be filled with all python packages found
 */
void getDpkgPythonPackages(std::unordered_set<std::string>& pythonPackages);

/**
 * @brief Fills a JSON object with all available apk-related information
 * @param libPath Path to apk's database directory
 * @param callback Callback to be called for every single element being found
 */
void getApkInfo(const std::string& libPath, std::function<void(nlohmann::json&)> callback);


/**
 * @brief Fills a JSON object with all available snap-related information
 * @param callback Callback to be called for every single element being found
 */
void getSnapInfo(std::function<void(nlohmann::json&)> callback);

// Exception template
template <LinuxType linuxType>
class FactoryPackagesCreator final
{
    public:
        static void getPackages(std::function<void(nlohmann::json&)> /*callback*/)
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
        static void getPackages(std::function<void(nlohmann::json&)> callback)
        {
            const file_system::FileSystemWrapper fs;
            if (fs.is_directory(DPKG_PATH))
            {
                getDpkgInfo(DPKG_STATUS_PATH, callback);
            }

            if (fs.is_directory(PACMAN_PATH))
            {
                getPacmanInfo(PACMAN_PATH, callback);
            }

            if (fs.is_directory(RPM_PATH))
            {
                getRpmInfo(callback);
            }

            if (fs.is_directory(APK_PATH))
            {
                getApkInfo(APK_DB_PATH, callback);
            }

            if (fs.is_directory(SNAP_PATH))
            {
                getSnapInfo(callback);
            }
        }

        static void getPythonPackages(std::unordered_set<std::string>& pythonPackages)
        {
            const file_system::FileSystemWrapper fs;
            if (fs.is_directory(DPKG_PATH))
            {
                getDpkgPythonPackages(pythonPackages);
            }

            if (fs.is_directory(RPM_PATH))
            {
                getRpmPythonPackages(pythonPackages);
            }
        }
};

// Template to extract package information in partially incompatible Linux systems
template <>
class FactoryPackagesCreator<LinuxType::LEGACY> final
{
    public:
        static void getPackages(std::function<void(nlohmann::json&)> callback)
        {
            const file_system::FileSystemWrapper fs;
            if (fs.is_directory(RPM_PATH))
            {
                getRpmInfoLegacy(callback);
            }
        }
        static void getPythonPackages(std::unordered_set<std::string>&) {};
};

#endif // _PACKAGE_LINUX_DATA_RETRIEVER_H
