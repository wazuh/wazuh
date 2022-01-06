/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 31, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FILE_TEST_H
#define _FILE_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"


class FileTest : public testing::Test {
    protected:
        FileTest() = default;
        virtual ~FileTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_FILE_TEST_H
