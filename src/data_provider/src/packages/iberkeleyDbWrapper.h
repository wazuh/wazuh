/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * March 16, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _IBERKELEY_DB_WRAPPER_H
#define _IBERKELEY_DB_WRAPPER_H

#include <memory>
#include <cstring>
#include "db.h"

class IBerkeleyDbWrapper
{
    public:
        virtual int32_t getRow(DBT& key, DBT& data) = 0;
        // LCOV_EXCL_START
        virtual ~IBerkeleyDbWrapper() = default;
        // LCOV_EXCL_STOP
        IBerkeleyDbWrapper() = default;
};

#endif // _IBERKELEY_DB_WRAPPER_H
