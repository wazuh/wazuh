/*
 * Wazuh Vulnerability Scanner - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * January 21, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../../../src/scannerHelper.hpp"
#include "gtest/gtest.h"

class ScannerHelperTest : public ::testing::Test
{
protected:
    // LCOV_EXCL_START
    ScannerHelperTest() = default;
    ~ScannerHelperTest() override = default;
    // LCOV_EXCL_STOP
};

/*
 * @brief Test if the function isCPE() returns true when the CPE is valid.
 */
TEST_F(ScannerHelperTest, isCPE)
{
    EXPECT_TRUE(ScannerHelper::isCPE("cpe:/a:apache:http_server:2.2.22"));
    EXPECT_TRUE(ScannerHelper::isCPE("cpe:2.3:a:apache:http_server:2.2.22"));
    EXPECT_TRUE(ScannerHelper::isCPE("cpe:2.3:a:apache:http_server:2.2.22:*:*:*:*:*:*:*"));
    EXPECT_FALSE(ScannerHelper::isCPE("aaa"));
    EXPECT_FALSE(ScannerHelper::isCPE(""));
}

/*
 * @brief Test CPE parsing.
 */
TEST_F(ScannerHelperTest, parseCPE)
{
    // Test CPE 2.2
    auto CPE = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.22");
    EXPECT_EQ(CPE.part, "a");
    EXPECT_EQ(CPE.vendor, "apache");
    EXPECT_EQ(CPE.product, "http_server");
    EXPECT_EQ(CPE.version, "2.2.22");
    EXPECT_EQ(CPE.update, "");
    EXPECT_EQ(CPE.edition, "");
    EXPECT_EQ(CPE.language, "");
    EXPECT_EQ(CPE.swEdition, "");
    EXPECT_EQ(CPE.targetSw, "");
    EXPECT_EQ(CPE.targetHw, "");
    EXPECT_EQ(CPE.other, "");

    // Test CPE 2.3
    CPE = ScannerHelper::parseCPE("cpe:2.3:a:apache:http_server:2.2.22");
    EXPECT_EQ(CPE.part, "a");
    EXPECT_EQ(CPE.vendor, "apache");
    EXPECT_EQ(CPE.product, "http_server");
    EXPECT_EQ(CPE.version, "2.2.22");
    EXPECT_EQ(CPE.update, "");
    EXPECT_EQ(CPE.edition, "");
    EXPECT_EQ(CPE.language, "");
    EXPECT_EQ(CPE.swEdition, "");
    EXPECT_EQ(CPE.targetSw, "");
    EXPECT_EQ(CPE.targetHw, "");
    EXPECT_EQ(CPE.other, "");
}

/*
 * @brief Test CPE comparison.
 */
TEST_F(ScannerHelperTest, compareCPE)
{
    auto CPE1 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.22");
    auto CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.22");
    EXPECT_TRUE(ScannerHelper::compareCPE(CPE1, CPE2));

    CPE1 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.22");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23");
    EXPECT_FALSE(ScannerHelper::compareCPE(CPE1, CPE2));

    CPE1 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.22");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.21");
    EXPECT_FALSE(ScannerHelper::compareCPE(CPE1, CPE2));

    CPE1 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.22");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.22:*:*:*:*:*:*:*");
    EXPECT_TRUE(ScannerHelper::compareCPE(CPE1, CPE2));

    CPE1 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.22:*:*:*:*:*:*:*");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.22");
    EXPECT_TRUE(ScannerHelper::compareCPE(CPE1, CPE2));

    // Test CPE 2.3 and 2.2
    CPE1 = ScannerHelper::parseCPE("cpe:2.3:a:apache:http_server:2.2.22");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.22");
    EXPECT_TRUE(ScannerHelper::compareCPE(CPE1, CPE2));

    CPE1 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.22");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:other:http_server:2.2.22");
    EXPECT_FALSE(ScannerHelper::compareCPE(CPE1, CPE2));

    CPE1 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.22:*:*:*:*:*:*:*");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.22:up1");
    EXPECT_TRUE(ScannerHelper::compareCPE(CPE1, CPE2));

    CPE1 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23:*:*:*:*:*:*:*");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.22:up1");
    EXPECT_FALSE(ScannerHelper::compareCPE(CPE1, CPE2));

    // Different part
    CPE1 = ScannerHelper::parseCPE("cpe:/o:micrososft:windows_10:*");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23");
    EXPECT_FALSE(ScannerHelper::compareCPE(CPE1, CPE2));

    // Different product
    CPE1 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:apache_server:2.2.23");
    EXPECT_FALSE(ScannerHelper::compareCPE(CPE1, CPE2));

    // Different update
    CPE1 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23:up1:*:*:*:*:*:*");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.22:up2");
    EXPECT_FALSE(ScannerHelper::compareCPE(CPE1, CPE2));

    // Different edition
    CPE1 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23:up:ed1");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23:up:ed2");
    EXPECT_FALSE(ScannerHelper::compareCPE(CPE1, CPE2));

    // Different language
    CPE1 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23:up:ed:lang1");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23:up:ed:lang2");
    EXPECT_FALSE(ScannerHelper::compareCPE(CPE1, CPE2));

    // Different swEdition
    CPE1 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23:up:ed:lang:sw1");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23:up:ed:lang:sw2");
    EXPECT_FALSE(ScannerHelper::compareCPE(CPE1, CPE2));

    // Different targetSw
    CPE1 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23:up:ed:lang:sw:ts1");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23:up:ed:lang:sw:ts2");
    EXPECT_FALSE(ScannerHelper::compareCPE(CPE1, CPE2));

    // Different targetHw
    CPE1 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23:up:ed:lang:sw:ts:th1");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23:up:ed:lang:sw:ts:th2");
    EXPECT_FALSE(ScannerHelper::compareCPE(CPE1, CPE2));

    // Different other
    CPE1 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23:up:ed:lang:sw:ts:th:other1");
    CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.23:up:ed:lang:sw:ts:th:other2");
    EXPECT_FALSE(ScannerHelper::compareCPE(CPE1, CPE2));
}

/*
 * @brief Test CPE comparison.
 */
TEST_F(ScannerHelperTest, compareInvalidCPE)
{
    CPE CPE1;
    auto CPE2 = ScannerHelper::parseCPE("cpe:/a:apache:http_server:2.2.22");
    EXPECT_FALSE(ScannerHelper::compareCPE(CPE1, CPE2));
}
