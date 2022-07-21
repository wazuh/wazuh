/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * September 13, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RYSNCIMPLEMENTATION_TEST_H
#define _RYSNCIMPLEMENTATION_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "commonDefs.h"

class RSyncImplementationTest : public ::testing::Test
{
    protected:

        RSyncImplementationTest() = default;
        virtual ~RSyncImplementationTest() = default;

        void SetUp() override;
        void TearDown() override;
};


#endif // _RYSNCIMPLEMENTATION_TEST_H
