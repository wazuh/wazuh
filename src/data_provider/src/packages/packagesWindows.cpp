/*
 * Wazuh SYSINFO
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "packagesWindows.h"
#include "sharedDefs.h"
#include "timeHelper.h"

WindowsPackageImpl::WindowsPackageImpl(const std::shared_ptr<IPackageWrapper>& packageWrapper)
    : m_packageWrapper(packageWrapper)
{ }

void WindowsPackageImpl::buildPackageData(nlohmann::json& package)
{
    package["name"] = m_packageWrapper->name();
    package["version_"] = m_packageWrapper->version();
    package["vendor"] = m_packageWrapper->vendor();
    auto installed = m_packageWrapper->install_time();
    package["installed"] = installed == UNKNOWN_VALUE ? UNKNOWN_VALUE : Utils::timestampToISO8601(installed, true);
    package["path"] = m_packageWrapper->location();
    package["architecture"] = m_packageWrapper->architecture();
    package["category"] = m_packageWrapper->groups();
    package["description"] = m_packageWrapper->description();
    package["size"] = m_packageWrapper->size();
    package["priority"] = m_packageWrapper->priority();
    package["source"] = m_packageWrapper->source();
    package["type"] = m_packageWrapper->format();
}
