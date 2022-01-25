/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * June 20, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SQLITE_TEST_H
#define _SQLITE_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class SQLiteTest : public ::testing::Test
{

    protected:

        SQLiteTest() = default;
        virtual ~SQLiteTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_SQLITE_TEST_H