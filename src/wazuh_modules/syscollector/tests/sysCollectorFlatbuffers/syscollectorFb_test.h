/*
 * Wazuh SyscollectorFlatbuffers
 * Copyright (C) 2015, Wazuh Inc.
 * August 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYSCOLLECTOR_FB_TEST_H
#define _SYSCOLLECTOR_FB_TEST_H
#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/idl.h"
#include "flatbuffers/util.h"
#include <fstream>
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class SyscollectorFbTest : public ::testing::Test
{
    protected:

        SyscollectorFbTest() = default;
        virtual ~SyscollectorFbTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_SYSCOLLECTOR_FB_TEST_H

