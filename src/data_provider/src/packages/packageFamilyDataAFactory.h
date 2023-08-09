/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * December 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGE_FAMILY_DATA_AFACTORY_H
#define _PACKAGE_FAMILY_DATA_AFACTORY_H

#include <memory>
#include "json.hpp"
#include "packageMac.h"
#include "packageSolaris.h"
#include "sharedDefs.h"

template <OSPlatformType osType>
class FactoryPackageFamilyCreator final
{
    public:
        static std::shared_ptr<IPackage> create(const std::pair<PackageContext, int>& /*ctx*/)
        {
            throw std::runtime_error
            {
                "Error creating package data retriever."
            };
        }

        static std::shared_ptr<IPackage> create(const std::shared_ptr<IPackageWrapper>& /*pkgwrapper*/)
        {
            throw std::runtime_error
            {
                "Error creating package data retriever."
            };
        }
};

template <>
class FactoryPackageFamilyCreator<OSPlatformType::BSDBASED> final
{
    public:
        static std::shared_ptr<IPackage> create(const std::pair<PackageContext, int>& ctx)
        {
            return FactoryBSDPackage::create(ctx);
        }
        static std::shared_ptr<IPackage> create(const std::pair<SQLite::IStatement&, const int>& ctx)
        {
            return FactoryBSDPackage::create(ctx);
        }
};

template <>
class FactoryPackageFamilyCreator<OSPlatformType::SOLARIS> final
{
    public:
        static std::shared_ptr<IPackage> create(const std::shared_ptr<IPackageWrapper>& packageWrapper)
        {
            return FactorySolarisPackage::create(packageWrapper);
        }
};

#endif // _PACKAGE_FAMILY_DATA_AFACTORY_H
