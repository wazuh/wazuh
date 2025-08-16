/*
 * Wazuh Inventory Harvester - Upsert element
 * Copyright (C) 2015, Wazuh Inc.
 * August 16, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _BROWSER_EXTENSION_ELEMENT_HPP
#define _BROWSER_EXTENSION_ELEMENT_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/inventoryBrowserExtensionHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include "../policyHarvesterManager.hpp"
#include <stdexcept>

template<typename TContext>
class BrowserExtensionElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~BrowserExtensionElement() = default;
    // LCOV_EXCL_STOP

    static DataHarvester<InventoryBrowserExtensionHarvester> build(TContext* data)
    {
        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("BrowserExtensionElement::build: Agent ID is empty.");
        }

        auto packageName = data->browserExtensionPackageName();
        if (packageName.empty())
        {
            throw std::runtime_error("BrowserExtensionElement::build: Package name is empty.");
        }

        DataHarvester<InventoryBrowserExtensionHarvester> element;

        // Key
        element.id = agentId;
        element.id += "_";
        element.id += packageName;

        // Operation
        element.operation = "INSERTED";

        // Agent
        element.data.agent.id = agentId;
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();
        if (auto agentIp = data->agentIp(); agentIp.compare("any") != 0)
        {
            element.data.agent.host.ip = agentIp;
        }

        // Browser
        element.data.browser.name = data->browserName();
        element.data.browser.profile.name = data->browserProfileName();
        element.data.browser.profile.path = data->browserProfilePath();
        element.data.browser.profile.referenced = data->browserProfileReferenced();

        // File
        element.data.file.hash.sha256 = data->browserExtensionFileHashSha256();

        // Package
        element.data.package.autoupdate = data->browserExtensionPackageAutoupdate();
        element.data.package.build_version = data->browserExtensionPackageBuildVersion();
        element.data.package.description = data->browserExtensionPackageDescription();
        element.data.package.enabled = data->browserExtensionPackageEnabled();
        element.data.package.from_webstore = data->browserExtensionPackageFromWebstore();
        element.data.package.id = data->browserExtensionPackageID();
        element.data.package.installed = data->browserExtensionPackageInstalled();
        element.data.package.name = packageName;
        element.data.package.path = data->browserExtensionPackagePath();
        element.data.package.permissions = data->browserExtensionPackagePermissions();
        element.data.package.persistent = data->browserExtensionPackagePersistent();
        element.data.package.reference = data->browserExtensionPackageReference();
        element.data.package.type = data->browserExtensionPackageType();
        element.data.package.vendor = data->browserExtensionPackageVendor();
        element.data.package.version = data->browserExtensionPackageVersion();

        // User
        element.data.user.id = data->browserExtensionUserID();

        // Wazuh cluster information
        auto& instancePolicyManager = PolicyHarvesterManager::instance();
        element.data.wazuh.cluster.name = instancePolicyManager.getClusterName();
        if (instancePolicyManager.getClusterStatus())
        {
            element.data.wazuh.cluster.node = instancePolicyManager.getClusterNodeName();
        }

        return element;
    }

    static NoDataHarvester deleteElement(TContext* data)
    {
        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("BrowserExtensionElement::deleteElement: Agent ID is empty.");
        }

        auto packageName = data->browserExtensionPackageName();
        if (packageName.empty())
        {
            throw std::runtime_error("BrowserExtensionElement::deleteElement: Package name is empty.");
        }

        NoDataHarvester element;
        // Key
        element.id = agentId;
        element.id += "_";
        element.id += packageName;

        // Operation
        element.operation = "DELETED";

        return element;
    }
};

#endif // _BROWSER_EXTENSION_ELEMENT_HPP
