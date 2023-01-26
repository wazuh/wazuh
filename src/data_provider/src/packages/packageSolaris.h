/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * January 11, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#ifndef _PACKAGE_SOLARIS_H
#define _PACKAGE_SOLARIS_H

#include "ipackageInterface.h"
#include "ipackageWrapper.h"

class FactorySolarisPackage
{
    public:
        static std::shared_ptr<IPackage>create(const std::shared_ptr<IPackageWrapper>& pkgWrapper);
};

class SolarisPackageImpl final : public IPackage
{
        const std::shared_ptr<IPackageWrapper> m_packageWrapper;

    public:
        explicit SolarisPackageImpl(const std::shared_ptr<IPackageWrapper>& packageWrapper);

        // LCOV_EXCL_START
        ~SolarisPackageImpl() = default;
        // LCOV_EXCL_STOP

        void buildPackageData(nlohmann::json& packge) override;
};

#endif // _PACKAGE_SOLARIS_H
