/*
 * Wazuh SysInfo
 * Copyright (C) Wazuh Inc.
 * November 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYSINFO_PACKAGE_DB_PARSER_TEST_H
#define _SYSINFO_PACKAGE_DB_PARSER_TEST_H

#include "gmock/gmock.h"
#include "gtest/gtest.h"

class SysInfoPackageDbParserTest : public ::testing::Test
{
    protected:

        SysInfoPackageDbParserTest() = default;
        virtual ~SysInfoPackageDbParserTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif // _SYSINFO_PACKAGE_DB_PARSER_TEST_H
