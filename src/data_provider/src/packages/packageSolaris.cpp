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

#include "packageSolaris.h"
#include "sharedDefs.h"
#include "timeHelper.h"

std::shared_ptr<IPackage> FactorySolarisPackage::create(const std::shared_ptr<IPackageWrapper>& pkgWrapper)
{
    return std::make_shared<SolarisPackageImpl>(pkgWrapper);
}

SolarisPackageImpl::SolarisPackageImpl(const std::shared_ptr<IPackageWrapper>& packageWrapper)
    : m_packageWrapper(packageWrapper)
{ }

void SolarisPackageImpl::buildPackageData(nlohmann::json& package)
{
    package["name"] = m_packageWrapper->name();
    package["version"] = m_packageWrapper->version();
    package["category"] = m_packageWrapper->groups();
    package["description"] = m_packageWrapper->description();
    package["architecture"] = m_packageWrapper->architecture();
    package["type"] = m_packageWrapper->format();
    package["source"] = m_packageWrapper->source();
    package["path"] = m_packageWrapper->location();
    package["priority"] = m_packageWrapper->priority();
    package["size"] = m_packageWrapper->size();
    package["vendor"] = m_packageWrapper->vendor();
    auto installed = m_packageWrapper->install_time();
    package["installed"] = installed == UNKNOWN_VALUE ? UNKNOWN_VALUE : Utils::timestampToISO8601(installed);
    // The multiarch field won't have a default value
}
