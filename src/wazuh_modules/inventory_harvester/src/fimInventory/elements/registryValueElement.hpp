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

#ifndef _REGISTRY_VALUE_ELEMENT_HPP
#define _REGISTRY_VALUE_ELEMENT_HPP

#include "../../wcsModel/fimRegistryHarvester.hpp"

template<typename TContext>
class RegistryValueElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~RegistryValueElement() = default;
    // LCOV_EXCL_STOP

    static FimRegistryInventoryHarvester build(TContext* data)
    {
        FimRegistryInventoryHarvester registry;

        // TO-DO
        // Field population based on the context.

        return registry;
    }
};

#endif // _REGISTRY_VALUE_ELEMENT_HPP
