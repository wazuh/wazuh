/*
 * Wazuh SYSINFO
 * Copyright (C) 2015-2021, Wazuh Inc.
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
#include "sharedDefs.h"

template <OSType osType>
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
};

template <>
class FactoryPackageFamilyCreator<OSType::BSDBASED> final
{
public:
    static std::shared_ptr<IPackage> create(const std::pair<PackageContext, int>& ctx)
    {
        return FactoryBSDPackage::create(ctx);
    }
};

#endif // _PACKAGE_FAMILY_DATA_AFACTORY_H