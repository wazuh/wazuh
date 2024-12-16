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
    package["version"] = m_packageWrapper->version();
    package["groups"] = m_packageWrapper->groups();
    package["description"] = m_packageWrapper->description();
    package["architecture"] = m_packageWrapper->architecture();
    package["format"] = m_packageWrapper->format();
    package["source"] = m_packageWrapper->source();
    package["location"] = m_packageWrapper->location();
    package["priority"] = m_packageWrapper->priority();
    package["size"] = m_packageWrapper->size();
    package["vendor"] = m_packageWrapper->vendor();
    package["install_time"] = m_packageWrapper->install_time();
    package["multiarch"] = m_packageWrapper->multiarch();
}
