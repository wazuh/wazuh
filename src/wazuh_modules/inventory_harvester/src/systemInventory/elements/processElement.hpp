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

#ifndef _PROCESS_ELEMENT_HPP
#define _PROCESS_ELEMENT_HPP

#include "../../wcsModel/inventoryProcessHarvester.hpp"

template<typename TContext>
class ProcessElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~ProcessElement() = default;
    // LCOV_EXCL_STOP

    static InventoryProcessHarvester build(TContext* data)
    {
        InventoryProcessHarvester process;

        // TO-DO
        // Field population based on the context.

        return process;
    }
};

#endif // _PROCESS_ELEMENT_HPP
