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

#include "packageMac.h"
#include "sharedDefs.h"
#include "brewWrapper.h"
#include "pkgWrapper.h"
#include "macportsWrapper.h"
#include "timeHelper.h"

std::shared_ptr<IPackage> FactoryBSDPackage::create(const std::pair<PackageContext, int>& ctx)
{
    std::shared_ptr<IPackage> ret;

    if (ctx.second == BREW)
    {
        ret = std::make_shared<BSDPackageImpl>(std::make_shared<BrewWrapper>(ctx.first));
    }
    else if (ctx.second == PKG || ctx.second == RCP)
    {
        ret = std::make_shared<BSDPackageImpl>(std::make_shared<PKGWrapper>(ctx.first));
    }
    else
    {
        throw std::runtime_error { "Error creating BSD package data retriever." };
    }

    return ret;
}

std::shared_ptr<IPackage> FactoryBSDPackage::create(const std::pair<SQLite::IStatement&, const int>& ctx)
{
    std::shared_ptr<IPackage> ret;

    if (ctx.second == MACPORTS)
    {
        ret = std::make_shared<BSDPackageImpl>(std::make_shared<MacportsWrapper>(ctx.first));
    }
    else
    {
        throw std::runtime_error { "Error creating BSD package data retriever." };
    }

    return ret;
}

BSDPackageImpl::BSDPackageImpl(const std::shared_ptr<IPackageWrapper>& packageWrapper)
    : m_packageWrapper(packageWrapper)
{ }

void BSDPackageImpl::buildPackageData(nlohmann::json& package)
{
    package["name"] = m_packageWrapper->name();
    package["version_"] = m_packageWrapper->version();
    package["category"] = m_packageWrapper->groups();
    package["description"] = m_packageWrapper->description();
    package["architecture"] = m_packageWrapper->architecture();
    package["type"] = m_packageWrapper->format();
    package["source"] = m_packageWrapper->source();
    package["path"] = m_packageWrapper->location();
    package["priority"] = m_packageWrapper->priority();
    package["size"] = m_packageWrapper->size();
    package["vendor"] = m_packageWrapper->vendor();
    auto installed = Utils::timestampToISO8601(m_packageWrapper->install_time());
    package["installed"] = installed.empty() ? UNKNOWN_VALUE : installed;
    package["multiarch"] = m_packageWrapper->multiarch();
}
