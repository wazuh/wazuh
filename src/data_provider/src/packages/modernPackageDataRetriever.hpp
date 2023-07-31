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

#ifndef _MODERN_PACKAGE_DATA_RETRIEVER_PP
#define _MODERN_PACKAGE_DATA_RETRIEVER_PP

#include "packagesNPM.hpp"
#include "packagesPYPI.hpp"

// Exception template
template <class T, StandardType standardType>
class ModernFactoryPackagesCreator final
{
    public:
        static void getPackages(const std::set<std::string>& /*paths*/, std::function<void(nlohmann::json&)> /*callback*/)
        {
            throw std::runtime_error{"Error creating modern package data retriever."};
        }
};

// Standard template to extract package information in fully compatible Linux
// systems
template <class T>
class ModernFactoryPackagesCreator<T, StandardType::CPP17> final
{
    public:
        static void getPackages(const std::set<std::string>& paths, std::function<void(nlohmann::json&)> callback)
        {
            T().getPackages(paths, callback);
        }
};

// Template to extract package information in partially incompatible Linux
// systems
template <class T>
class ModernFactoryPackagesCreator<T, StandardType::OLDEST> final
{
    public:

        static void getPackages(const std::set<std::string>& /*paths*/, std::function<void(nlohmann::json&)> /*callback*/)
        {
        }
};

#endif  // _MODERN_PACKAGE_DATA_RETRIEVER_HPP
