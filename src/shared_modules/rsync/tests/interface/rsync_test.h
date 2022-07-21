/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RYSNC_TEST_H
#define _RYSNC_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "commonDefs.h"

class RSyncTest : public ::testing::Test
{
    protected:

        RSyncTest() = default;
        virtual ~RSyncTest() = default;

        void SetUp() override;
        void TearDown() override;
};


#endif // _RYSNC_TEST_H
