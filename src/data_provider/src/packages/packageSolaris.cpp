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
    // The multiarch field won't have a default value
}
