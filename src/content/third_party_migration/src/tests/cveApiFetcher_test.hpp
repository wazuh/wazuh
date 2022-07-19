/*
 * Wazuh app - Command line helper
 * Copyright (C) 2015, Wazuh Inc.
 * July 14, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CVE_API_FETCHER_TEST_H
#define _CVE_API_FETCHER_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"

class CveApiFetcherTest : public ::testing::Test
{
    protected:
        CveApiFetcherTest() = default;
        virtual ~CveApiFetcherTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_CVE_API_FETCHER_TEST_H