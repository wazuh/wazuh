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

#ifndef _PACKAGE_MAC_H
#define _PACKAGE_MAC_H

#include "ipackageInterface.h"
#include "ipackageWrapper.h"
#include "sqliteWrapperTemp.h"

struct PackageContext
{
    std::string filePath;
    std::string package;
    std::string version;
};

class FactoryBSDPackage
{
    public:
        static std::shared_ptr<IPackage>create(const std::pair<PackageContext, int>& ctx);
        static std::shared_ptr<IPackage>create(const std::pair<SQLite::IStatement&, const int>& ctx);
};

class BSDPackageImpl final : public IPackage
{
        const std::shared_ptr<IPackageWrapper> m_packageWrapper;
    public:
        explicit BSDPackageImpl(const std::shared_ptr<IPackageWrapper>& packageWrapper);

        void buildPackageData(nlohmann::json& package) override;
};

#endif // _PACKAGE_MAC_H
