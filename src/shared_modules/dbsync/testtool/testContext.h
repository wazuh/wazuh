/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _TEST_CONTEXT_H
#define _TEST_CONTEXT_H
#include "dbsync.h"
#include "dbsync.hpp"

struct TestContext
{
    DBSYNC_HANDLE handle;
    TXN_HANDLE txnContext;
    size_t currentId;
    std::string outputPath;
};

#endif //_TEST_CONTEXT_H