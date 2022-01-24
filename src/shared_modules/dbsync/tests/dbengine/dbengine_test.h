/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * July 16, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DBENGINE_TEST_H
#define _DBENGINE_TEST_H
#include "gtest/gtest.h"

class DBEngineTest : public ::testing::Test
{
    protected:

        DBEngineTest() = default;
        virtual ~DBEngineTest() = default;
};

#endif //_DBENGINE_TEST_H