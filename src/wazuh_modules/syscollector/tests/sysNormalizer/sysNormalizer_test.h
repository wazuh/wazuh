/*
 * Wazuh SyscollectorNormalizer
 * Copyright (C) 2015, Wazuh Inc.
 * January 12, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYS_NORMALIZER_TEST_H
#define _SYS_NORMALIZER_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class SysNormalizerTest : public ::testing::Test
{
    protected:

        SysNormalizerTest() = default;
        virtual ~SysNormalizerTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_SYS_NORMALIZER_TEST_H