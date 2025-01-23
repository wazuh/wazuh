/*
 * Wazuh Vulnerability scanner - Scan Orchestrator
 * Copyright (C) 2015, Wazuh Inc.
 * January 22, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGE_ELEMENT_HPP
#define _PACKAGE_ELEMENT_HPP

#include "../../wcsModel/inventoryPackageHarvester.hpp"

template<typename TContext>
class PackageElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~PackageElement() = default;
    // LCOV_EXCL_STOP

    static InventoryPackageHarvester build(TContext* data)
    {
        InventoryPackageHarvester process;

        // TO-DO
        // Field population based on the context.

        return process;
    }
};

#endif // _PACKAGE_ELEMENT_HPP
