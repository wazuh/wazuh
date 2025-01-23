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

#ifndef _FILE_ELEMENT_HPP
#define _FILE_ELEMENT_HPP

#include "../../wcsModel/fimFileHarvester.hpp"

template<typename TContext>
class FileElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~FileElement() = default;
    // LCOV_EXCL_STOP

    static FimFileInventoryHarvester build(TContext* data)
    {
        FimFileInventoryHarvester file;

        // TO-DO
        // Field population based on the context.

        return file;
    }
};

#endif // _FILE_ELEMENT_HPP
