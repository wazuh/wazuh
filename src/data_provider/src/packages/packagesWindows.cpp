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

WindowsPackageImpl::WindowsPackageImpl(const std::shared_ptr<IPackageWrapper>& packageWrapper)
    : m_packageWrapper(packageWrapper)
{ }

void WindowsPackageImpl::buildPackageData(nlohmann::json& package)
{
    package["name"] = m_packageWrapper->name();
    package["version_"] = m_packageWrapper->version();
    package["vendor"] = m_packageWrapper->vendor();
    package["installed"] = m_packageWrapper->install_time();
    package["path"] = m_packageWrapper->location();
    package["architecture"] = m_packageWrapper->architecture();
    package["category"] = m_packageWrapper->groups();
    package["description"] = m_packageWrapper->description();
    // An unknown size leaves the key out of the document entirely. The sync layer only
    // compares and updates columns that are present, so omitting it keeps whatever a previous
    // scan established instead of overwriting it with a zero that would churn the checksum and
    // surface as a transient null.
    const auto packageSize {m_packageWrapper->size()};

    if (packageSize.has_value())
    {
        package["size"] = *packageSize;
    }

    package["priority"] = m_packageWrapper->priority();
    package["source"] = m_packageWrapper->source();
    package["type"] = m_packageWrapper->format();
}
